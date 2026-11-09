# Prompt Injection Detection & Prevention for AI Agents

COE444 Computer Security, Fall 2026 — American University of Sharjah.

A bounded AI agent chooses tools to carry out a user goal. An attacker can try
to redirect its decisions through retrieved text. We study that security problem
in a sandboxed email environment, comparing a text detector and a recipient-source
gate while measuring attack success and legitimate task completion.

The model selects tool calls and arguments over up to six turns. The new protected
live-send review is an additional supervised boundary, not evidence that every
action can be authorized autonomously. See [the team guide](docs/TEAM_GUIDE.md)
for the implemented agent loop, a recorded attack example and scope limits.

Both defenses are implemented. `make spec-detection` and `make spec-prevention`
check their requirements. With prevention enabled, the live Mailbox strips or
rejects unsupported recipients and queues surviving messages for explicit user
review. Review shows the exact recipients, subject and body; approve sends once,
reject sends nothing. Directory provenance alone does not authorize an action.
The baseline with prevention disabled remains deliberately unguarded.

See [METHODOLOGY.md](METHODOLOGY.md) for the experimental design and the
reasoning behind the changes made after the proposal review.

## Team progress materials

Start with [TEAM_START_HERE.md](TEAM_START_HERE.md) for the current team guide, presentation files, source map and AI study prompt. The older onboarding and assignment notes describe an earlier project stage.

## Setup

```bash
./scripts/setup.sh            # picks external or local automatically
source scripts/activate.sh    # each session
python cli.py index           # once, or after editing rag/documents/
```

Then add `NOUS_API_KEY` to `.env`. Both models run on the Nous Research
inference API (OpenAI-compatible): the agent is `openai/gpt-oss-20b` and the
detector is `openai/gpt-oss-120b`, asked three times per excerpt with the
highest score kept (`DETECTOR_SAMPLES=3`). Every record logs which host served
each model (`agent_host`, `detector_host`, `detector_samples`). The history of
hosts — Cerebras until 8 Nov 2026 (free tier withdrawn), Groq for a few hours
(daily cap), Nous since — is in METHODOLOGY.md section 5A; `GROQ_API_KEY` is
needed only for the Prompt Guard 2 comparison arm, `CEREBRAS_API_KEY` only to
reproduce October logs.

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
python cli.py eval-live --split dev  # dev sweep, defenses in the loop (composition-v2); advanced: --split advanced
make eval-live-final                 # the held-out test split, once, live B,C,D (asks for "final")
python cli.py rescore-live logs/live-*.jsonl [--write]   # re-score a live log, no API call
python cli.py detector-eval [--external] [--promptguard]  # detector on dev / Microsoft LLMail excerpts
make test                            # all 338 checks incl. the defense specs, no live API calls
make spec-detection                  # the detection teammate's requirements
make spec-prevention                 # the prevention teammate's requirements
make check-independence              # the two defense layers must not reference each other
```

The **Mailbox** page is a live playground: you are an employee with an inbox,
the AI assistant acts for you, and you can play the attacker by emailing the
employee from outside or hiding an instruction in a company document. Two
switches turn detection and prevention on for that run, and the timeline shows
what the assistant read, what each defense decided, and what actually left the
mailbox. Protected emails remain unsent until you click Approve and send.
This review is an additional live safeguard, outside the historical A/B/C/D protocol.

The **Lab** page and `python cli.py demo` are the research view: the agent runs
once with both defenses observing, and that one run is scored under A/B/C/D.
Reported numbers come only from `make eval` logs.

Reported numbers come only from `logs/*.jsonl`; `docs/CHANGELOG_FINAL.md` is the
dated record of every change since the progress report and why it was made.

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

Complete as of 9 Nov 2026 (`METHODOLOGY.md` §5A, `docs/CHANGELOG_FINAL.md`):
agent-v3 with an inbox channel; sanitize-v1 → detector-v3a (max-of-3) → gate-v3.1
→ human review; composition-v2 (defenses in the loop, B/C/D executed live);
corpus v0.2.1 (dev + sealed test) and v0.3-advanced (18 attacks in 9 realistic
families); scorer-v2. Development results (`results/frozen_stack_summary.md`,
re-scored): dev A 70 % → D 0 % (0/30 trials), advanced A 71 % → D 0 % (0/52),
benign 100 % everywhere; external Microsoft LLMail excerpts: detector FNR 5/50,
FPR 0/203. The held-out test split is the one confirmatory run
(`results/final_test_summary.md` once it exists). The October 13 figures (A 60 %
as presented / 70 % re-scored, D 10 %) describe the abort-based gate-v1 design
and are kept as the before-picture.

Document retrieval defaults to `OMP_NUM_THREADS=1` before native libraries load,
following a reproduced macOS crash and a successful single-thread retrieval check.
You may explicitly override this environment variable if your platform supports it.
