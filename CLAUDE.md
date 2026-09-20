# COE444 — Prompt Injection Detection & Prevention

Read [README.md](README.md) for layout and commands, and
[METHODOLOGY.md](METHODOLOGY.md) for the experimental design. This file is the
short version of the rules that must not be broken.

## What this is

A research prototype for COE444 Computer Security (AUS, Fall 2026). It
demonstrates indirect prompt injection against a RAG email agent and evaluates
two independent defenses as a 2×2 factorial.

## The six invariants

1. **Origin tags are structural, never inferred from content.** `rag/retriever.py`
   stamps `Origin.EXTERNAL` on every chunk it returns. Nothing may change a tag
   based on what the text says.
2. **`agent/agent.py` must not know about conditions or defenses.** One
   execution per trial; conditions are applied afterwards by
   `conditions.score()`. If the agent grows an `if condition` branch, the four
   arms stop being the same trial re-scored and the comparison is invalid.
   Enforced by an AST assertion in `tests/test_conditions.py`.
3. **`defense/detection.py` and `defense/prevention.py` never import each
   other.** Enforced by `scripts/check_independence.py`.
4. **The prevention gate checks provenance, not content.** It asks "did this
   exact value come from user bytes or document bytes?" and never "does this
   look malicious?". Adding a keyword check would turn it into a second
   classifier and destroy the determinism claim that makes it interesting.
5. **All metrics come from `logs/*.jsonl`.** Never recompute by re-running the
   agent. Never report a number from a manual one-off run.
6. **Do not harden the system prompt.** `agent/prompts.py` stays plain.
   Prompt-level injection defenses are a third intervention that would
   contaminate condition A.

## Conventions

- Python 3.11. PEP 604 typing (`str | None`), `from __future__ import annotations`.
- Dataclasses for internal contracts; ABC + a factory for swappable backends.
- `config.py` holds module-level constants from `.env`; `os.getenv(x, default)`
  for optional, `os.environ[x]` for required-at-startup.
- stdlib `logging`, module-level `_log`, `%s` lazy formatting.
- Comments explain *why*, especially where a line encodes a security decision or
  a rejected alternative.
- Fail closed on security decisions, fail open on telemetry.
- pytest, function-style, long descriptive names, hand-rolled fakes.
  **No test makes a live API call.**

## Before changing the corpus or a prompt

Both are versioned and recorded in every `RunRecord`
(`corpus_version`, `detector_prompt_version`). Changing either invalidates
previous results — bump the version and say so in the report.

The `test` split of `attacks/payloads.json` should stay unopened until the final
evaluation run. Tune the detector prompt on `dev` only.
