# Prompt Injection Detection & Prevention for AI Agents

COE444 Computer Security, Fall 2026 — American University of Sharjah.

A sandboxed email agent that is deliberately vulnerable to indirect prompt
injection, slots for two independent defense layers, and an evaluation harness
that measures them as a 2×2 factorial with a utility axis.

The two defenses are **starter stubs** that let everything through: each is a
teammate's job. `make spec-detection` and `make spec-prevention` show which of
their requirements pass, and the Mailbox page's switches show the effect live.

See [METHODOLOGY.md](METHODOLOGY.md) for the experimental design and the
reasoning behind the changes made after the proposal review.

## Setup

```bash
./scripts/setup.sh            # picks external or local automatically
source scripts/activate.sh    # each session
python cli.py index           # once, or after editing rag/documents/
```

Then add `GROQ_API_KEY` (the agent, `openai/gpt-oss-20b` on Groq) and
`CEREBRAS_API_KEY` (the detector's model, `gpt-oss-120b`) to `.env`.

Two modes. `setup.sh` uses the external drive if `/Volumes/Segate.Y` is mounted
and the project directory otherwise; force one with `MODE=local ./scripts/setup.sh`.

The external mode creates an **APFS disk image on** the external drive rather
than using it directly, because that drive is ExFAT — no symlinks, no POSIX exec
bits, so a venv cannot live on it. Local mode needs about 1.1 GB (871 MB venv +
~90 MB model cache + index).

Note the venv dies with the drive if you unplug it mid-run. `run_all` flushes
each record to `logs/` as it goes, so a partial sweep is still analysable.

## Usage

```bash
python interface/app.py              # web UI: http://127.0.0.1:5000 (Mailbox) and /lab
python cli.py index                  # build the FAISS index over rag/documents/
python cli.py ask "What is the leave policy?"
python cli.py demo PI-101            # one attack, all four conditions, side by side
python cli.py eval --split test      # full sweep, prints the results table
python cli.py report logs/scored-*.jsonl   # recompute metrics from an existing log
make test                            # framework tests, no live API calls
make spec-detection                  # the detection teammate's requirements
make spec-prevention                 # the prevention teammate's requirements
make check-independence              # the two defense layers must not reference each other
```

The **Mailbox** page is a live playground: you are an employee with an inbox,
the AI assistant acts for you, and you can play the attacker by emailing the
employee from outside or hiding an instruction in a company document. Two
switches turn detection and prevention on for that run, and the timeline shows
what the assistant read, what each defense decided, and what actually left the
mailbox.

The **Lab** page and `python cli.py demo` are the research view: the agent runs
once with both defenses observing, and that one run is scored under A/B/C/D.
Reported numbers come only from `make eval` logs.

Cerebras rate-limits bursts (about 4 requests, then a 60-second wait on HTTP
429), so a detector that makes one call per excerpt makes runs slow.

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
  payloads.json      23 payloads across 6 families x 9 evasion techniques
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

Foundation complete: agent (Groq), RAG with origin tagging, the corpus, the
runner, metrics, the Mailbox and Lab pages, and spec tests for both defenses.
Detection and prevention are starter stubs, to be built by the team. The final
test-split evaluation waits until the defenses are built.
