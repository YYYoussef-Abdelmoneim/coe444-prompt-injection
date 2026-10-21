# COE444 team start here

The main branch contains the reviewed project code, the progress presentation and a simple-English study guide for all five team members. The project studies an AI agent choosing tools to carry out a user goal, and an attacker trying to redirect its decisions through outside text. Simulated email is the controlled test environment.

## Read these first

1. [Team guide in simple English](docs/TEAM_GUIDE.md): the project, one speaker per slide, speaking scripts and likely professor questions with answers.
2. [Progress evidence](docs/PROGRESS_EVIDENCE.md): what the counts mean and where the results came from.
3. [Current README](README.md): setup, commands and architecture.
4. [Research methodology](METHODOLOGY.md): experiment design and limitations.
5. [Code rules](CLAUDE.md): invariants to preserve when making changes.

## Presentation files

- [Five-slide progress presentation](docs/presentation/COE444_Progress_Report_Final.pptx)
- [Editable Word team guide](docs/presentation/COE444_Team_Presentation_Guide.docx)
- [Development trial outcomes](docs/presentation/Development_Results_Evidence.csv)

Choose one speaker for each of the five slides and update the presenter labels to match your chosen split. Credit actual technical work separately from speaking assignments.

## Get this version

```sh
git clone https://github.com/YYYoussef-Abdelmoneim/coe444-prompt-injection.git
cd coe444-prompt-injection
```

If you already cloned it, commit or stash your own changes before switching:

```sh
git fetch origin
git switch main
git pull --ff-only origin main
```

The default main branch includes the reviewed progress code and team materials. The earlier progress branches remain available as historical checkpoints.

## What the implementation demonstrates

`Agent.run` lets the model choose tool calls and inputs, feeds tool results back to it, and repeats for up to six model turns. This is bounded autonomy, not an unrestricted background worker. The saved PI-101 run shows document search followed by a send proposal with an attacker CC. Our detector checks text and our gate checks email-recipient sources. The new live review makes the final protected send supervised; it does not establish fully autonomous action authorization. The guide maps these statements to code and explains the limits.

## Current status

- The assistant, document search, contact lookup, detector, recipient gate and simulated mailbox are implemented.
- With prevention ON in the live mailbox, surviving email drafts wait for a real approval or rejection. The model cannot approve its own drafts through its tools. This is additional live protection, outside the old scoring protocol.
- Document retrieval defaults to one native thread to avoid the locally reproduced startup crash. Local retrieval passed with this setting.
- The updated suite has 256 passing checks, including all 61 original defense specification checks.
- There are 223 stored attack examples: 23 custom examples (10 development and 13 held out) plus 200 external examples.
- The old main comparison uses ten development attacks and seven normal tasks, each repeated three times. Its attack-success results are A 60%, B 10%, C 30%, D 10%.
- A separate saved agent experiment covers 50 external examples. A separate detector check covers 50 attack excerpts and 203 clean emails.
- These are preliminary historical results. They do not establish the final below-5% target or measure the new review flow.
- Fresh hosted-model checks, a full rehearsal and final held-out evaluation remain pending.

## Run software checks

After installing the dependencies into your own environment:

```sh
python -B -m pytest tests/ --spec -q -p no:cacheprovider
python -B scripts/check_independence.py
```

These checks make no live model API calls. Do not confuse them with attack-effectiveness experiments.

For a local setup, use `MODE=local ./scripts/setup.sh`, edit your ignored `.env` with your own model-service keys and local data path, then run `python cli.py index`. The script prints activation instructions for your environment. Once the local `.venv` is ready, `./scripts/run_ui.sh` starts the mailbox. The initial dependency/model download needs internet access. Review the setup script before running it on your machine.

## Where each part lives

| Part | Files |
|---|---|
| Assistant and tools | `agent/agent.py`, `agent/tools.py`, `agent/llm.py` |
| Document search | `rag/retriever.py`, `rag/indexer.py`, `rag/chunker.py` |
| Company contacts | `directory.py`, `data/directory.json` |
| Attack detection | `defense/detection.py`, `tests/spec/test_detection_spec.py` |
| Recipient source checks | `defense/prevention.py`, `tests/spec/test_prevention_spec.py` |
| Live mailbox and real review | `interface/playground.py`, `interface/app.py`, `interface/ui/mail.html`, `tests/test_live_review.py` |
| Experiment records and scoring | `evaluation/runner.py`, `evaluation/logs.py`, `evaluation/predicates.py`, `evaluation/metrics.py`, `conditions.py` |
| Attack inventory and reports | `attacks/`, `results/`, tracked `logs/` |

The legacy ONBOARDING.md and TEAM-PLAN.md retain earlier project-stage instructions. Their statements about empty defenses, old test counts and unfinished log loading describe the earlier stage, not this branch's current state.

## A useful prompt for your own AI assistant

> Read TEAM_START_HERE.md, docs/TEAM_GUIDE.md, docs/PROGRESS_EVIDENCE.md and CLAUDE.md. I am presenting slide [number]. Explain that slide and its relevant code in simple English, then ask me likely professor questions. Separate implemented behavior from historical measurements and pending evaluation. Do not open or tune against the held-out attack texts, print .env or credentials, or call paid or external APIs without my authorization. Start with the relevant code and saved development evidence.

Use your own model-service keys locally. Never put keys or private documents in commits. All email in this project remains simulated.
