# claude-code-model-router

**A dispatch policy for multi-model Claude Code work: route each task to the cheapest model
that can do it safely, guard what leaves your machine, and never trust a delegate's "done".**

Three ideas, extracted from a production single-operator setup:

1. **Tiered routing with "don't dispatch" as the default.** Frontier models for decisions
   that are expensive to get wrong; mid-tier for mainline implementation; small models for
   mechanical bulk; second-opinion routes to a different model lineage (e.g. Codex) so
   reviews don't share the implementer's blind spots. Delegation has real overhead
   (writing the brief, handing over context, verifying the result) — if the gain isn't
   clearly larger, the main loop does the work itself.

2. **A fail-closed PII/secret guard for data-residency-sensitive providers.** Before any
   text is sent to a provider you don't want secrets or personal data reaching, it passes
   a scanner ([`scripts/pii_guard.py`](scripts/pii_guard.py)): ~40 vendor-specific secret
   patterns, generic credential assignments, JWTs and private-key blocks, high-entropy
   token detection, Luhn-validated card numbers, Japanese PII patterns (phone / bank /
   my-number), plus a local denylist file for your own names, addresses, and project
   codenames. One hit blocks the send. In the original setup the guard is enforced in
   three layers: a manual pre-check, a CLI wrapper that refuses to launch, and a
   PreToolUse hook that rejects the tool call itself.

3. **An independent verification protocol.** The implementer never verifies itself.
   A delegate's completion report is checked by a *different* lineage (a reviewer CLI from
   another vendor, or a higher-tier model) against raw outputs — opening the produced
   files, running the code — before the main loop declares completion. A confident "it
   works" from the model that wrote it is treated as a claim, not a fact.

## Files

| File | What it is |
|---|---|
| [`SKILL.md`](SKILL.md) | The router skill: classify → guard → dispatch → verify → log |
| [`routing-table.example.yaml`](routing-table.example.yaml) | Data-driven routing table — edit this, not the skill |
| [`scripts/pii_guard.py`](scripts/pii_guard.py) | Fail-closed secret/PII scanner (stdlib only, `--self-test` included) |
| [`scripts/denylist.example.txt`](scripts/denylist.example.txt) | Template for your local denylist (never commit the real one) |
| [`delegation-rules.md`](delegation-rules.md) | Code-of-conduct block to append to every delegate's prompt |

## Install

```bash
cp -r . ~/.claude/skills/model-router
cp scripts/denylist.example.txt ~/.claude/skills/model-router/scripts/denylist.local.txt
# then edit denylist.local.txt with YOUR names/addresses/codenames (it is gitignored)
python3 ~/.claude/skills/model-router/scripts/pii_guard.py --self-test
```

The guard **fails closed until the denylist exists**: without `denylist.local.txt` every
scan blocks with `denylist_not_configured`, because the denylist is where your personal
terms live. Set `PII_GUARD_ALLOW_NO_DENYLIST=1` only in contexts like CI where that is a
deliberate choice.

Adapt `routing-table.example.yaml` to the models and CLIs you actually have. The table is
the single source of truth; the skill just executes it.

## Usage

```bash
# check content before it goes to a guarded provider
# exit 0 = pass / exit 2 = blocked (reasons as JSON)
python3 scripts/pii_guard.py prompt.txt file1.md file2.py
python3 scripts/pii_guard.py < prompt.txt    # or via stdin redirection

Every dispatch appends one JSON line to a log (`state/dispatch_log.jsonl`):

```json
{"ts":"2026-07-24T12:00:00+0900","task":"bulk summarize 100 docs","route":"budget-bulk","model":"<cheap-model>","reason":"no secrets, high volume","guard":"pass","outcome":"ok"}
```

Review the log weekly: routes with frequent `fail`/`fallback` outcomes get their
`use_for` signals adjusted in the table.

## Known limitations (measured, not hidden)

The guard is one fail-closed layer, not a guarantee. An independent adversarial review by
a different model lineage probed it before release; what it found was either fixed or is
listed here:

- **Fixed after review**: undecodable input (e.g. UTF-16) now blocks instead of slipping
  past the patterns; a missing denylist now blocks instead of silently scanning without
  your personal terms; 40-char AWS-style secrets containing `/` are now caught; Mastercard
  2-series and up-to-19-digit PANs are Luhn-checked; prose password disclosures are
  caught; `/Users/<name>` paths (username leaks) are caught; the email regex uses bounded
  quantifiers (polynomial-backtracking fix); CJK denylist terms work from 2 characters.
- **Inherent gaps to know about**: a bare unlabeled 12-digit number (e.g. a Japanese
  My Number without surrounding label text) is not checksum-detected; hyphen-less landline
  numbers are indistinguishable from ordinary numeric IDs; deliberately obfuscated secrets
  (base64-of-base64, string concatenation, homoglyphs) pass. For those, rely on the
  denylist, provider isolation, and human review — not this scanner alone.

## Isolation recommendations for guarded providers

Run data-residency-sensitive CLIs isolated, in addition to the guard: a separate config
directory (no personal memory, hooks, or MCP servers), a clean environment (`env -i`, so
other API keys are not inherited), a dedicated workspace directory (so ancestor config
files aren't read), and with shell/network/subagent tools disabled. Files go in only via
guard-checked copies into the workspace.

## 日本語での説明

タスクを「間違えると高くつく判断＝最上位モデル / 通常実装＝中位 / 機械的物量＝下位 /
第二意見＝別系統(Codex等)」に振り分けるルーターです。既定値は「振り分けない」。
国外プロバイダ等へ送るテキストは fail-closed のPII/シークレットガード（約40種の
ベンダーキー・高エントロピー検出・Luhn検証・ローカル禁止語）を必ず通し、1件ヒットで
送信禁止。委譲先の「できました」は鵜呑みにせず、実装者と別系統のモデルが生データで
再検証してから完了宣言する「独立検証プロトコル」を含みます。

## Related

- [fable-mode](https://github.com/okazaky/fable-mode) — behavior signature extracted from archived frontier-model sessions
- [claude-code-memory-recall](https://github.com/okazaky/claude-code-memory-recall) — two-layer memory index + auto-recall hook

## License

MIT © 2026 Yoshiaki Okazaki ([@okazaky](https://github.com/okazaky))
