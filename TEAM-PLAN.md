# Who does what

Four owners, one file each, plus Youssef on integration. Read `ONBOARDING.md`
first — this page is only the split and the schedule.

Nobody is blocked on anybody in week 1. Only one person spends API quota.

## The five slices

| | Owner | Owns | Cost to start |
|---|---|---|---|
| **1** | Detection | `defense/detection.py` | none — runs on fakes |
| **2** | Prevention | `defense/prevention.py` | none — pure Python |
| **3** | Evidence store | `evaluation/logs.py` (new), `cli.py rescore` | none — reads existing logs |
| **4** | Corpus, runs, stats, report | `attacks/`, `METHODOLOGY.md`, the report | this is the one who spends quota |
| **5** | Youssef | `schema.py`, `conditions.py`, `agent/`, `rag/` | — |

Your definition of done is a command, not an opinion.

---

## 1 — Detection

`make spec-detection` → **25 passed**. It's 22 failed / 3 passed today.

**This week, do not write a prompt and do not use an API key.** The whole spec
runs on a fake provider. Start with the malformed-score validator: 11 of the 25
cases are one parametrized test over `nan`, `"nan"`, `-0.3`, `±inf`, `1.7`,
`None`, `False`, `"high"`, `[0.1]`. Two traps — `isinstance(False, (int, float))`
is `True` in Python, so exclude `bool` explicitly; and `float("nan")` is a valid
float, so check `isnan`/`isinf` separately. Clamping turns NaN into "clean",
which is the wrong direction to fail.

**Spec-green is not "it works."** A detector that returns a constant `1.0`
passes 24 of the 25 cases, because everything runs through a fake. Your real
deliverable is three things the spec cannot check:

- a test for the **batched** `scan_all` path — one result per excerpt, and
  per-excerpt fail-closed when the batched answer comes back short
- **429 handling with real backoff.** Cerebras allows roughly 4 requests then a
  60-second wait. `RETRIEVAL_K=4`, and an inbox read plus a search is eight
  excerpts, so an unbatched detector makes 240–480 classifier calls for the
  test split — one to two hours of pure sleep. `agent/llm.py` sets
  `max_retries=3` on default backoff, which does not span 60 seconds.
- a dev-split comparison against the 20-line regex in
  `defense/detection_baseline.py`, including the honest sentence if the regex
  matches you

You are on the critical path. See the note at the bottom.

## 2 — Prevention

`make spec-prevention` → **21 passed**. It's 13 failed / 8 passed today. The 8
that pass are ALLOW cases — regression guards against over-blocking, not free
wins.

**Go straight to the hardest test**, not the easiest:
`test_an_address_the_parser_cannot_read_does_not_ride_along`. The obvious
implementation fails it. Given

```
manager@northwind.example; "audit"@nw-audit.invalid
```

a normal email regex matches nothing inside the quoted local part, so a
"find the addresses, subtract the bad ones" gate concludes there is nothing to
remove and allows the whole field. The design that passes is the inversion:
split on comma **and** semicolon, keep a token only if that token traces to the
user's own bytes or to a known contact, drop every other token whole. That also
handles the source-route case `@nw-records.invalid:x@y.invalid`.

Then: `SANITIZE` must preserve subject and body byte-for-byte and keep the
user's own recipient; `is_required("send_email", "to")` is `True`, so an emptied
`to` must `DENY` rather than send to nobody.

Zero API cost, instant feedback, fully deterministic — **this slice will finish
first.** From week 3 you take `interface/app.py` and write the first
`tests/test_app.py`.

## 3 — Evidence store

Nothing in this project can read a log back. That is your slice.

**First task:** `evaluation/logs.py` with `load_records(path) -> list[RunRecord]`.
Develop against the real log already on disk,
`logs/run-20260921T091032Z.jsonl`. `RunRecord.to_json` uses
`dataclasses.asdict`, so nested objects come back as plain dicts — you have to
rebuild them.

**Done when** `python cli.py rescore logs/run-*.jsonl --threshold 0.3` prints
the scored table from a raw log **with no API call**, and reproduces the
original numbers exactly at the default threshold.

Then the ROC curve over the dev log, and a **detector-failure-rate column** in
the metrics — see the warning at the bottom, that column is what catches a
corrupted sweep.

Your one-line defence in the viva is strong: invariant 5 says all metrics come
from logs, and before this slice there was no code that could read one.

## 4 — Corpus, runs, statistics, report

**Today, and you are the only one spending quota this week:** run `make eval-dev`
with **both stubs still in place**. This is not filler. The stub detector never
calls its provider and the stub gate is pure Python, so 51 runs cost agent
tokens only. It produces the first properly logged, citable **condition-A
baseline**, which does not currently exist.

Week 2 you freeze the corpus. After Friday 10 Oct nothing in `attacks/` changes
— a corpus change invalidates every earlier result, and Detection cannot tune a
prompt against a moving target. Bump `CORPUS_VERSION` and say so.

Then the statistics, `METHODOLOGY` §6, the report and the slides. **Say the
conflict of interest out loud in the report:** you write the payloads and you
report the numbers.

## 5 — Youssef (integration)

Sole merger to `main`. Review authority on every shared file.

**Monday, before anyone clones**, three small fixes:
`interface/app.py:218` and `222-223` call `fp.field_class.value`. Change to
`getattr(fp.field_class, "value", fp.field_class)` — **not** `str()`, which
returns `'FieldClass.CONTROL'` instead of `'control'`. Without this, Prevention
gets a 500 the first time they return a plain string, *after* their tokens are
spent.

---

## Schedule

| When | What |
|---|---|
| **Week 1** (27 Sep–3 Oct) | Four parallel starts, no dependencies. Monday kickoff: run the plant-and-send demo live. |
| **Week 2** (4–10 Oct) | **Corpus freeze, Fri 10 Oct — all hands review the diff.** Prevention done. Detection spec-green. Loader lands. Detection gets its Cerebras key Friday, not before. |
| **Weeks 3–5** (11–31 Oct) | The long pole: Detection tunes on **dev only**. Others ship ROC, fixtures, `test_app.py`, and the report sections that need no numbers. Freeze `evaluation/runner.py` end of week 5. |
| **Week 6** (1–7 Nov) | **Mid-point. Partial results must exist.** Full dev rehearsal with both real defenses on. Exit criterion is **zero `DetectionResult.error` rows**, not "it ran". |
| **Week 7** (8–14 Nov) | **The single test-split run.** `make eval --split test`, once, Teammate 4 alone. Total API freeze for everyone else that week — agreed at kickoff, in writing. |
| **Weeks 8–9** | Analysis. Tables, ROC, McNemar with Holm, Wilson intervals. |
| **Week 10** | Slides and report draft. **Week 11: buffer — do not plan work into it.** |

## Where you will collide

The two defense owners never collide in their own files —
`scripts/check_independence.py` makes it a build error. They collide in four
shared places, ruled now rather than in week 5:

1. **`interface/app.py`** — three people want it. Youssef fixes the two bugs
   Monday; **Teammate 2 owns it outright from week 3**; the others file
   requests.
2. **`tests/conftest.py`** — `FakeProvider` is Detection's, the `chunk` fixture
   is everyone's. **Any change comes through Youssef.**
3. **`tests/test_metrics.py`** — the non-obvious trap.
   `tests/spec/test_prevention_spec.py` imports four private helpers from it, so
   refactoring it silently breaks Prevention's spec. **Run both spec targets
   before touching it.**
4. **`schema.py`** — Youssef only.

## The two things that decide this project

**`evaluation/metrics.py:28` is `CONFIRMATORY = (("A","B"), ("C","D"))`.** Both
pre-registered contrasts hold prevention fixed and toggle detection. So
detection is in both pre-registered tests and prevention is in neither. If
detection slips there is **no confirmatory result at all**; if prevention slips,
C collapses onto A and D onto B, and the two contrasts become the same data
twice. Both are needed; only detection is on the critical path.

**The failure that would actually sink this** is not someone going quiet — it's
a corrupted final sweep that looks publishable. Three links exist in the code
today: `conditions._any_flagged` counts `d.failed` as a detection (correct
security, dangerous measurement); a Cerebras 429 surfaces as an exception; and
there is no detector-failure-rate metric. Together, a rate-limited detector
reports as **near-perfect recall with collapsed utility in exactly conditions B
and D** — the two arms carrying both contrasts. It is the result you would most
like to see, arriving for the wrong reason.

Three mitigations, all assigned: batched `scan_all` with real backoff (T1, wk 3),
the failure-rate column (T3, wks 3–5), and the stub sweep now plus the week-6
rehearsal (T4).
