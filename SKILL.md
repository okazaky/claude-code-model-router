---
name: model-router
description: >-
  Multi-model dispatch control tower: classify each task, route it to the right
  model tier (frontier / mid / small) or external CLI (second-opinion lineage,
  budget bulk providers), guard outbound text with a fail-closed PII/secret
  scanner, and independently verify every delegate's result before declaring
  completion. Trigger on "route this", "use the best model for", "model router",
  "split this across models", "cheapest model that can do this", or when several
  independent subtasks could run cost-efficiently in parallel.
---

# model-router (multi-model dispatch control tower)

Classify the task, dispatch to the best route, verify and integrate the results.

## Principles (check before dispatching anything)

1. **Not dispatching is the default.** Delegation has overhead: writing the brief,
   handing over context, verifying the result. Dispatch only when the subtask is
   self-contained and the gain clearly exceeds that overhead. When in doubt, do it
   yourself in the main loop.
2. **Nothing confidential leaves for guarded providers.** Any prompt or file headed to a
   data-residency-sensitive provider must pass `scripts/pii_guard.py`. Never skip it.
   If blocked, remove the sensitive content or use the fallback route.
3. **Verify delegate results against the real thing before reporting.** Never relay a
   delegate's "done" untested: open the produced files, run the code, check the output.
   Prefer a verifier from a different model lineage than the implementer.
4. **The main loop's own model cannot switch itself** (that is a user setting). If
   frontier-tier work is needed while the main loop runs a lower tier, delegate to a
   subagent with an explicit frontier `model:` override.

## Procedure

### Step 1: Classify
Read `routing-table.example.yaml` (or your local copy). Split multi-part tasks and
classify each part into a route. If nothing fits, don't dispatch (`default: no_dispatch`).

### Step 2: Guard (mandatory for guarded routes)
Run everything you are about to send — prompt text plus any attached file contents —
through the guard:

```bash
python3 scripts/pii_guard.py <file...>         # files as arguments
python3 scripts/pii_guard.py "$PROMPT_FILE"    # the prompt file you will dispatch (Step 3)
```

Exit 0 = safe to send. Exit 2 = blocked, with reasons as JSON. On block: strip the
sensitive content or fall back. For defense in depth, also enforce the guard in a CLI
wrapper and a PreToolUse hook so a forgotten manual check cannot leak.

### Step 3: Dispatch
Use the invocation defined per route in the table. **Never template prompt text directly
into a shell string** — `$()`, backticks, quotes, and newlines inside the prompt would be
evaluated by the shell before the CLI ever sees them (command injection). Write the prompt
to a file first and pass the file's content as a single argument:

```bash
PROMPT_FILE=$(mktemp)
cat > "$PROMPT_FILE" <<'PROMPT'
...prompt text...
PROMPT
codex exec --skip-git-repo-check "$(cat "$PROMPT_FILE")"
```

Launch mutually independent tasks in parallel (same message / same block). Run guarded
providers isolated: separate config dir, clean env, dedicated workspace, no
shell/web/subagent tools.

### Step 4: Verify & integrate
Check each result against the real artifact (principle 3) before integrating and
reporting. On quota/billing errors from a route (e.g. HTTP 402 from a shared pool):
don't stop to ask — switch to the route's declared fallback, continue, and log
`outcome: fallback`.

### Step 5: Log
Append one line to `state/dispatch_log.jsonl`:

```json
{"ts":"<ISO8601>","task":"<short label>","route":"<route id>","model":"<model>","reason":"<why this route>","guard":"pass|blocked|n/a","outcome":"ok|fail|fallback"}
```

## Review loop

Weekly, read `state/dispatch_log.jsonl`. Routes with frequent `fail` or `fallback`
outcomes get their `use_for` signals adjusted in the routing table. The routing criteria
live in the YAML — the skill text should not need editing.
