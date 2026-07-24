#!/usr/bin/env python3
"""
pii_guard.py — fail-closed secret/PII scanner for text leaving your machine.

Purpose:
    Scan text you are about to send to a third-party LLM provider (especially a
    data-residency-sensitive one) for secrets (API keys, passwords, private keys,
    JWTs, ...) and PII (email addresses, phone numbers, bank keywords, card
    numbers, ...). A single hit blocks the send.

Usage:
    python3 pii_guard.py <file1> [file2 ...]   # scan file contents
    echo "<full prompt>" | python3 pii_guard.py  # scan stdin
    python3 pii_guard.py --self-test             # run the built-in tests

Exit codes:
    0 = safe to send (no hits) / all self-tests passed
    1 = self-test failure
    2 = blocked (hits found; reasons printed as JSON)
    3 = input error (unreadable file etc.)

Design:
    Err on the side of over-blocking (falling back to another model is cheap;
    a leak is irreversible). Put your own names, addresses, and project
    codenames in denylist.local.txt (one term per line, # for comments) —
    that file is gitignored and must never be committed.

    Fail-closed rules: input that cannot be strictly decoded as UTF-8 (or that
    contains NUL bytes) is blocked as `undecodable_input`; a missing
    denylist.local.txt is itself a blocking finding (`denylist_not_configured`)
    because the denylist carries your personal terms — set
    PII_GUARD_ALLOW_NO_DENYLIST=1 to override (e.g. in CI).

NOTE: the self-test section contains deliberately fake, synthetic credential
lookalikes so the patterns can be tested. They are not real secrets. Phone
fixtures use all-zero subscriber blocks, which are not assigned.
"""

import json
import math
import os
import re
import sys
from pathlib import Path

DENYLIST_PATH = Path(__file__).resolve().parent / "denylist.local.txt"

# (label, regex) — one hit blocks the send
PATTERNS = (
    # --- generic assignment shapes ---
    ("api_key_assignment", re.compile(r"(?i)\b(api[_-]?key|secret|token|credential|passwd|password)\b\s*[:=]\s*['\"]?\S{4,}")),
    ("secret_suffix_assignment", re.compile(r"(?i)\b\w*(secret|token|apikey|api_key|passwd|password)\b\s*[:=]\s*['\"]?\S{4,}")),
    ("password_ja", re.compile(r"パスワード\s*[:：=]?\s*\S{4,}")),
    ("password_phrase", re.compile(r"(?i)\bpassword\s+(is|was)\s*[:：]?\s*\S{4,}")),
    ("env_assignment", re.compile(r"(?im)\b[A-Z][A-Z0-9_]{4,}\s*=\s*['\"]?[^\s'\"]{8,}")),
    ("auth_header", re.compile(r"(?i)\bauthorization\s*:\s*(bearer|basic|token)\s+\S{8,}")),
    ("basic_auth_url", re.compile(r"\b[a-z][a-z0-9+.-]*://[^/\s:@]{1,64}:[^/\s:@]{4,}@")),
    # --- vendor-specific keys ---
    ("openai_anthropic_key", re.compile(r"\bsk-(ant-|proj-)?[A-Za-z0-9_-]{16,}")),
    ("xai_groq_key", re.compile(r"\b(xai|gsk)_[A-Za-z0-9_-]{20,}")),
    ("github_token", re.compile(r"\b(ghp_[A-Za-z0-9]{20,}|gho_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})")),
    ("gitlab_token", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}")),
    ("aws_access_key", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("aws_secret_assignment", re.compile(r"(?i)aws.{0,24}(secret|session).{0,12}[:=]\s*['\"]?[A-Za-z0-9/+=]{32,}")),
    ("slack_token", re.compile(r"\bxox[baprse]-[A-Za-z0-9-]{10,}")),
    ("slack_webhook", re.compile(r"hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]+")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{30,}")),
    ("google_oauth_token", re.compile(r"\bya29\.[A-Za-z0-9_-]{20,}|\b1//[A-Za-z0-9_-]{28,}")),
    ("stripe_key", re.compile(r"\b(sk|rk|pk)_(live|test)_[A-Za-z0-9]{16,}|\bwhsec_[A-Za-z0-9]{24,}")),
    ("twilio_sid_or_key", re.compile(r"\b(AC|SK)[0-9a-f]{32}\b")),
    ("sendgrid_key", re.compile(r"\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}")),
    ("npm_token", re.compile(r"\bnpm_[A-Za-z0-9]{30,}")),
    ("digitalocean_token", re.compile(r"\bdop_v1_[0-9a-f]{60,}")),
    ("huggingface_replicate_key", re.compile(r"\b(hf|r8)_[A-Za-z0-9]{28,}")),
    ("telegram_bot_token", re.compile(r"\b\d{8,10}:AA[A-Za-z0-9_-]{30,}")),
    ("discord_webhook", re.compile(r"discord(app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]{30,}")),
    ("jwt_like", re.compile(r"\beyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}")),
    ("private_key_block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----|PuTTY-User-Key-File")),
    ("long_hex_secret", re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{48,}(?![0-9a-fA-F])")),  # 48+ hex (keys; 40-hex git SHAs pass)
    # --- general PII ---
    # bounded quantifiers: the unbounded form backtracked polynomially on adversarial input
    ("email_address", re.compile(r"(?<![\w.+-])[\w.+-]{1,64}@[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{2,63}){1,8}")),
    # local home paths reveal usernames (and often client/project names)
    ("home_path_username", re.compile(r"/(?:Users|home)/(?!Shared\b|shared\b)[A-Za-z0-9._-]{2,}")),
    # 2nd digit 1-9 (JP numbers; avoids false hits on UUID fragments like 0041-)
    ("jp_phone_number", re.compile(r"\b0[1-9]\d{0,3}-\d{1,4}-\d{3,4}\b|(?<!\d)0[5789]0\d{8}(?!\d)|\+81[-\s]?\d{1,4}[-\s]?\d{1,4}[-\s]?\d{3,4}")),
    ("bank_account_ja", re.compile(r"(口座番号|支店コード|振込先|普通預金|当座預金)")),
    ("mynumber_ja", re.compile(r"(マイナンバー|個人番号)\D{0,10}\d{4}[- ]?\d{4}[- ]?\d{4}")),
)

# High-entropy detection: base64-like tokens containing upper+lower+digit.
# `/` is excluded from candidate chars: including it would turn whole file paths
# into single candidates and cause false positives; real keys with `/` separators
# are still caught per 28+-char segment.
ENTROPY_CANDIDATE = re.compile(r"[A-Za-z0-9+=_-]{28,}")
# AWS-style 40-char secrets contain `/`, which splits the candidate above below
# the 28-char floor — catch exactly-40-char base64-with-slash runs separately.
AWS_STYLE_CANDIDATE = re.compile(r"(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])")
ENTROPY_THRESHOLD = 4.5

# Card number candidates (Luhn-validated; 13-19 digits covers 2-series MC and long PANs)
CARD_CANDIDATE = re.compile(r"(?<![\dA-Za-z])(?:\d[ -]?){12,18}\d(?![\dA-Za-z])")


def shannon_entropy(token: str) -> float:
    """Shannon entropy (bits/char) from character frequencies."""
    counts = tuple(token.count(ch) for ch in set(token))
    total = len(token)
    return -sum(c / total * math.log2(c / total) for c in counts)


def is_high_entropy_token(token: str) -> bool:
    """True for base64-like tokens with mixed case + digits above the entropy threshold."""
    has_mix = (
        any(c.islower() for c in token)
        and any(c.isupper() for c in token)
        and any(c.isdigit() for c in token)
    )
    return has_mix and shannon_entropy(token) >= ENTROPY_THRESHOLD


def luhn_valid(digits: str) -> bool:
    """Luhn check-digit validation."""
    total = sum(
        d if i % 2 == 0 else (d * 2 - 9 if d * 2 > 9 else d * 2)
        for i, d in enumerate(map(int, reversed(digits)))
    )
    return total % 10 == 0


def find_card_numbers(text: str) -> bool:
    """True if a 13-16 digit run with a known IIN prefix passes Luhn."""
    candidates = (
        re.sub(r"[ -]", "", m.group(0)) for m in CARD_CANDIDATE.finditer(text)
    )
    return any(
        13 <= len(c) <= 19
        and re.match(r"^(4|5[1-5]|2[2-7]|3[47]|35|6)", c)
        and luhn_valid(c)
        for c in candidates
    )


def load_denylist():
    """Read the local denylist (one term per line, # comments). Terms need 4+ chars,
    or 2+ chars if non-ASCII (CJK surnames are 2-3 chars). Returns None if the file
    is absent — the caller treats that as 'not configured' and blocks."""
    if not DENYLIST_PATH.exists():
        return None
    words = []
    for line in DENYLIST_PATH.read_text(encoding="utf-8", errors="replace").splitlines():
        w = line.strip()
        if not w or w.startswith("#"):
            continue
        if len(w) >= 4 or (len(w) >= 2 and any(ord(c) > 127 for c in w)):
            words.append(w)
    return tuple(words)


def scan(text: str) -> tuple:
    """Run all detectors; return a tuple of hit labels (never the matched values)."""
    regex_hits = tuple(label for label, pattern in PATTERNS if pattern.search(text))
    entropy_hits = ("high_entropy_token",) if any(
        is_high_entropy_token(m.group(0)) for m in ENTROPY_CANDIDATE.finditer(text)
    ) or any(
        is_high_entropy_token(m.group(0)) for m in AWS_STYLE_CANDIDATE.finditer(text)
    ) else ()
    card_hits = ("credit_card_number",) if find_card_numbers(text) else ()
    denylist = load_denylist()
    if denylist is None:
        denylist_hits = () if os.environ.get("PII_GUARD_ALLOW_NO_DENYLIST") == "1" \
            else ("denylist_not_configured",)
    else:
        denylist_hits = ("local_denylist",) if any(w in text for w in denylist) else ()
    return regex_hits + entropy_hits + card_hits + denylist_hits


def decode_or_none(raw: bytes):
    """Strict UTF-8 decode. None (= block as undecodable_input) on NUL bytes or
    decode failure — encoding tricks like UTF-16 must not slip past the patterns."""
    if b"\x00" in raw:
        return None
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return None


def read_inputs(argv: tuple) -> tuple:
    """Return (source, raw_bytes) pairs for argument files, or stdin if no arguments."""
    if argv:
        return tuple((path, Path(path).read_bytes()) for path in argv)
    return (("stdin", sys.stdin.buffer.read()),)


# --- built-in self-test (all values are fake/synthetic, for pattern matching only) ---
def self_test() -> int:
    global DENYLIST_PATH
    os.environ["PII_GUARD_ALLOW_NO_DENYLIST"] = "1"  # denylist tested separately below
    fake_b64 = "Qx7" + "aB9" * 11  # mixed 33 chars but repetitive -> low entropy
    random_b64 = "kJ8mQ2xVn4Rp7sWt1yZb5cDf9gHl3NoP"  # mixed 32 chars, non-repetitive
    cases = (
        # (text, should_block, description)
        ("The weather is fine today. Starting the summarization task.", False, "harmless English"),
        ("この関数をリファクタリングして def foo(): return 1", False, "harmless code+Japanese"),
        ("api_key = abcd1234efgh5678", True, "generic key assignment"),
        ("パスワード: hunter2xx", True, "Japanese password"),
        ("sk-ant-" + "a1B2" * 6, True, "Anthropic-style key"),
        ("sk-proj-" + "Zx9y" * 6, True, "OpenAI project key"),
        ("ghp_" + "A1b2C3d4E5" * 3, True, "GitHub token"),
        ("AKIA" + "ABCDEFGHIJKLMNOP", True, "AWS access key"),
        ("sk_live_" + "9zY8xW7vU6tS5rQ4", True, "Stripe key"),
        ("AC" + "0123456789abcdef" * 2, True, "Twilio SID"),
        ("SG.aB1cD2eF3gH4iJ5kL6m.nO7pQ8rS9tU0vW1xY2z", True, "SendGrid key"),
        ("dop_v1_" + "0123456789abcdef" * 4, True, "DigitalOcean token"),
        ("hooks.slack.com/services/T0AAA/B0BBB/x1y2z3", True, "Slack webhook"),
        ("discord.com/api/webhooks/1234567890/aBcDeFgHiJkLmNoPqRsTuVwXyZ012345", True, "Discord webhook"),
        ("Authorization: Bearer abc123def456", True, "auth header"),
        ("https://user:p4ssw0rd@example.com/path", True, "basic auth in URL"),
        ("-----BEGIN RSA PRIVATE KEY-----", True, "private key block"),
        ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIx", True, "JWT-like"),
        ("contact: test@example.com", True, "email address"),
        ("電話は 090-0000-0000 です", True, "JP phone (hyphenated, all-zero unassigned block)"),
        ("電話は 09000000000 です", True, "JP mobile (no hyphen, all-zero unassigned block)"),
        ("振込先は次の通りです", True, "bank keyword"),
        ("マイナンバーは 1234 5678 9012 です", True, "my-number"),
        ("カードは 4111 1111 1111 1111 です", True, "card number (Luhn pass)"),
        ("番号 4111 1111 1111 1112 は無効です", False, "Luhn fail passes"),
        ("commit 3f2a9c1e8b7d6f5a4c3b2a1908f7e6d5c4b3a291", False, "40-hex git SHA passes"),
        ("cat /tmp/session/bf830913-0041-4622-9364-ea9a8572cfdf/scratch/clean.txt", False, "UUID path passes"),
        ("client_secret=aB3xYz90kLmn", True, "client_secret assignment"),
        ('OPENAI_API_KEY="sk-xxxxYYYYzzzz1111"', True, "quoted env var"),
        ("CLIENT_TOKEN = superlongtokenvalue123", True, "uppercase env assignment"),
        ("hash: " + "a1b2c3d4" * 6, True, "48+ hex secret-like"),
        ("電話 +81-90-0000-0000 まで", True, "international JP phone (all-zero unassigned block)"),
        ("普通の文章です。関数を書いてください。", False, "harmless Japanese"),
        ("md5 5d41402abc4b2a76b9719d911017c592", False, "MD5 (32 hex) passes"),
        (random_b64, True, "high-entropy token"),
        (fake_b64, False, "repetitive string passes"),
        # previously-untested detectors
        # fixtures are concatenated at runtime so this source file never contains a
        # contiguous secret-shaped literal (keeps GitHub push protection quiet for
        # this repo and every fork; the scanner under test sees the joined string)
        ("glpat-" + "aB3dE5fG7hJ9kL1mN3pQ", True, "GitLab token"),
        ("AIza" + "SyA1b2C3d4E5f6G7h8I9j0K1l2M3n4o", True, "Google API key"),
        ("ya29." + "a0AbCdEfGhIjKlMnOpQrSt", True, "Google OAuth token"),
        ("hf_" + "AbCdEfGhIjKlMnOpQrStUvWxYzAb", True, "Hugging Face token"),
        ("npm_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5", True, "npm token"),
        ("xoxb-" + "1234567890-abcDEF", True, "Slack token"),
        ("xai_" + "Ab1Cd2Ef3Gh4Ij5Kl6Mn7Op8", True, "xAI key"),
        ("987654321:" + "AAH1a2B3c4D5e6F7g8H9i0J1k2L3m4N5o", True, "Telegram bot token"),
        ("aws_secret_access_key = " + "wJalrXUtnFEMI/K7MDENG/" + "bPxRfiCYEXAMPLEKEY", True, "AWS secret assignment (official docs example value)"),
        ("wJalrXUtnFEMI/K7MDENG/" + "bPxRfiCYEXAMPLEKEY", True, "bare 40-char AWS-style secret with slash"),
        # audit-driven additions
        ("password is hunter2xx", True, "password phrase"),
        ("see /Users/johndoe/project/main.py", True, "home path reveals username"),
        ("ls /Users/Shared/workspace", False, "shared home path passes"),
        ("カードは 2223 0000 4841 0010 です", True, "Mastercard 2-series (Luhn test PAN)"),
    )
    failures = list(
        (desc, expect_block, hits)
        for text, expect_block, desc in cases
        if bool(hits := scan(text)) != expect_block
    )

    # denylist functional test (temp file, then restore)
    import tempfile
    saved = DENYLIST_PATH
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8") as tf:
        tf.write("# test terms\nproject-neptune\n山田\n")
        tmp_path = Path(tf.name)
    DENYLIST_PATH = tmp_path
    dl_cases = (
        ("about the project-neptune launch", True, "denylist ascii term"),
        ("山田さんに送る文面です", True, "denylist 2-char CJK term"),
        ("nothing sensitive here", False, "denylist no hit"),
    )
    failures.extend(
        (desc, expect_block, hits)
        for text, expect_block, desc in dl_cases
        if bool(hits := scan(text)) != expect_block
    )
    DENYLIST_PATH = saved
    tmp_path.unlink()

    # fail-closed decoding tests
    dec_cases = (
        ("héllo".encode("utf-16"), True, "utf-16 input blocks as undecodable"),
        (b"abc\x00def", True, "NUL bytes block as undecodable"),
        ("普通のUTF-8テキスト".encode(), False, "valid utf-8 decodes"),
    )
    failures.extend(
        (desc, expect_block, ("undecodable_input",))
        for raw, expect_block, desc in dec_cases
        if (decode_or_none(raw) is None) != expect_block
    )

    total = len(cases) + len(dl_cases) + len(dec_cases)
    for desc, expect_block, hits in failures:
        print(f"FAIL: {desc} — expected {'block' if expect_block else 'pass'}, hits={list(hits)}")
    print(f"self-test: {total - len(failures)}/{total} passed")
    return 0 if not failures else 1


def main() -> int:
    if sys.argv[1:] == ["--self-test"]:
        return self_test()

    try:
        inputs = read_inputs(tuple(sys.argv[1:]))
    except OSError as err:
        print(json.dumps({"result": "error", "detail": str(err)}, ensure_ascii=False))
        return 3

    findings = []
    for source, raw in inputs:
        text = decode_or_none(raw)
        hits = ("undecodable_input",) if text is None else scan(text)
        if hits:
            findings.append({"source": source, "hits": list(hits)})

    if findings:
        print(json.dumps({"result": "blocked", "findings": list(findings)}, ensure_ascii=False))
        return 2

    print(json.dumps({"result": "pass"}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
