# Prompt Injection Detection & Prevention for AI Agents

COE444 Computer Security, Fall 2026 — American University of Sharjah.

A sandboxed email agent that is deliberately vulnerable to indirect prompt
injection, two independent defense layers, and an evaluation harness that
measures them as a 2×2 factorial with a utility axis.

See [METHODOLOGY.md](METHODOLOGY.md) for the experimental design and the
reasoning behind the changes made after the proposal review.

## Setup

The internal disk on the development machine is effectively full, and the
external drive is ExFAT (no symlinks, no exec bits — a venv cannot live on it
directly). `scripts/setup.sh` creates an APFS disk image *on* the external drive
and puts the venv, the Hugging Face cache, and the FAISS index inside it.

```bash
./scripts/setup.sh                      # external drive must be plugged in
source /Volumes/COE444/venv/bin/activate
export HF_HOME=/Volumes/COE444/hf-cache
export COE444_DATA_ROOT=/Volumes/COE444/coe444-data
```

Then add `ANTHROPIC_API_KEY` to `.env`.

If the drive was unplugged, remount without rebuilding anything:

```bash
hdiutil attach /Volumes/Segate.Y/COE444/coe444.sparsebundle -mountpoint /Volumes/COE444
```

## Usage

```bash
python cli.py index                  # build the FAISS index over rag/documents/
python cli.py ask "What is the leave policy?"
python cli.py demo PI-001            # one attack, all four conditions, side by side
python cli.py eval --split test      # full sweep, prints the results table
python cli.py report logs/scored-*.jsonl   # recompute metrics from an existing log
make test                            # 24 tests, no live API calls
make check-independence              # the two defense layers must not reference each other
```

`python cli.py demo` is the presentation demo: it prints the retrieved chunks,
the detector score per chunk, the gate's per-argument provenance decision, and
the resulting outcome under each of A/B/C/D.

## Layout

```
schema.py          data contracts; depends on nothing but the stdlib
conditions.py      the 2x2 conditions and the offline scorer
config.py          module-level constants from .env

agent/
  agent.py         the tool-calling loop - no knowledge of conditions or defenses
  tools.py         tool schemas + the CONTROL/CONTENT field classification
  llm.py           LLMProvider ABC + factory
  prompts.py       system prompt (deliberately unhardened)

rag/
  indexer.py       build the FAISS index
  retriever.py     query it; stamps origin=EXTERNAL structurally
  chunker.py       pure functions, no I/O
  documents/       four synthetic company policy documents

defense/
  detection.py            layer 1 - LLM classifier, returns a calibrated score
  detection_baseline.py   a 20-line regex, to keep layer 1 honest
  prevention.py           layer 2 - per-argument provenance gate

attacks/
  payloads.json      19 seed payloads across 5 families x 9 evasion techniques
  benign_tasks.json  14 benign tasks, 5 of them hard negatives
  loader.py

evaluation/
  runner.py      executes once per trial, scores four ways
  predicates.py  mechanical success predicates - no human judgement
  metrics.py     paired McNemar, Wilson intervals, factorial decomposition

mailsink.py     records mail, never sends
```

## Architectural rules

These are load-bearing. Breaking one invalidates results.

1. **Origin is structural.** `retriever.py` stamps `EXTERNAL` on everything it
   returns because of where it came from, never because of what it says.
   Nothing downstream may upgrade or downgrade that tag.
2. **The agent knows nothing about conditions or defenses.** It executes once;
   conditions are a scoring policy applied afterwards. Enforced by an AST check
   in `tests/test_conditions.py`.
3. **The two defense layers are independent.** Neither imports the other.
   Enforced by `scripts/check_independence.py`.
4. **The gate checks provenance, never content.** It must never grow a keyword
   list or a semantic check — that would make it a second classifier and destroy
   the determinism argument.
5. **Metrics are computed from logs.** Never by re-running the agent.
6. **The system prompt stays unhardened.** Prompt-level defenses are a third
   intervention and would contaminate the baseline.

## Ethics and containment

This repository contains working prompt injection payloads. They exist for
red-teaming a system we built and own.

- There is **no SMTP client anywhere in this project**. `send_email` lands in
  `MailSink`, an in-memory list. No socket is ever opened.
- Attacker recipients use RFC 2606 `.invalid` domains, which cannot resolve.
- All company documents are synthetic; "Northwind Technologies" does not exist.
- Nothing here is tested against any live third-party product.

## Status

Phase 1 complete: agent, RAG with origin tagging, both defense layers, the
corpus, the runner, metrics, and 24 tests. Not yet run against the live API —
`python cli.py index` then `python cli.py demo PI-001` is the first real check.
