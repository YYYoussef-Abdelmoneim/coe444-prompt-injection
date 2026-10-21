# What the test numbers mean

Evidence checked October 21, 2026. Project source is this repository checkout.

## Four different counts

| Count | What it measures | Source |
|---|---|---|
| 256 automated checks now passing | Python software checks, including malformed detector outputs, gate behavior, logging and explicit-review regressions. Most use scripted/fake models. This was 246 before this adjustment. | `tests/`, run with `python -B -m pytest tests/ --spec -q -p no:cacheprovider` |
| 23 custom attack payloads | Stored attack examples: 10 development and 13 held out for final evaluation. | `attacks/payloads.json`, metadata counts only |
| 200 external attack payloads | Stored LLMail-derived examples, separate from the custom split. | `attacks/external_llmail.json` |
| 14 benign tasks | Normal user tasks: 7 development and 7 held out. | `attacks/benign_tasks.json`, metadata counts only |

The stored attack inventory is **223 = 23 + 200**. The software check count is coincidentally a similar size, but it is unrelated. Passing a software check does not count as resisting a real LLM attack.

## Where the four-condition results came from

The existing experiment log is `logs/run-20261013T100754Z.jsonl`, produced October 13, before this review. I did not invent the results or run a new LLM sweep to get them. I loaded the saved records and reran the project's deterministic scoring code, matching `results/progress_summary.md`.

The log contains **51 agent trials**:

- 10 development attacks x 3 repeats = 30 attack trials.
- 7 development benign tasks x 3 repeats = 21 benign trials.

Each saved trajectory is scored four ways: A without defenses, B detection only, C prevention only, and D both. This produces 204 scored policy outcomes from 51 agent trajectories. It is not 204 separate agent executions.

The main table uses a majority vote across the three repeats for each distinct attack/task. For example, if an attack succeeds in two of three repeats, that attack counts as successful. Six successful attacks out of ten gives 60%.

| Condition | Successful distinct attacks | Successful individual attack trials | Benign tasks completed by majority |
|---|---|---|---|
| A, no defense | 6/10 = 60% | 19/30 | 7/7 |
| B, detection | 1/10 = 10% | 3/30 | 7/7 |
| C, prevention | 3/10 = 30% | 10/30 | 7/7 |
| D, both | 1/10 = 10% | 3/30 | 7/7 |

These are alternative summaries of the same observations. Do not put a trial-level numerator over a payload-level denominator. The 7/7 normal-task result also uses majority voting: BN-060 completed in two repeats and hit the turn limit in one. It does not mean every individual benign trial succeeded.

The ten development IDs are PI-001, PI-002, PI-020, PI-021, PI-030, PI-040, PI-050, PI-101, PI-102 and PI-120. The 13 held-out custom attack texts were not reviewed or evaluated for this adjustment.

## What happened to the 200 external attacks?

They are available in the repository, but the saved external agent experiment covers **50 of them**, once each: `logs/run-20261012T202019Z.jsonl`.

- Two trials had agent errors, leaving 48 valid runs.
- No defense: 9/48 attacks succeeded.
- Gate only: 0/48 succeeded.
- With errors pessimistically counted as successful attacks: 11/50 and 2/50 respectively.
- The detector in that agent experiment was a stub. This is an A-versus-C exploratory result, not evidence that both defenses defeated all 200 attacks.

There is a separate **detector classification** experiment in `logs/detector-external-20261012T215514Z.jsonl`: 50 attack excerpts and 203 clean emails, at threshold 0.10. The detector missed 3/50 attacks (6%) and falsely flagged 0/203 clean emails. This checks whether the detector labels excerpts correctly. It does not run 253 complete agent tasks or establish combined-defense attack success.

## Do the results make sense?

Yes: the arithmetic and saved-log rescoring are consistent. Their interpretation needs care:

1. **B and D being equal is plausible.** In these development observations, adding the gate after detection did not improve the aggregate attack-success result. This sample does not demonstrate an extra ASR benefit from the combination.
2. **Detecting an attack does not necessarily defeat its objective.** PI-040 aims to prevent the user getting an answer. The detector flags it, but the modeled abort still gives the attacker the disruption it wanted. This explains the remaining 1/10 success despite detecting all ten development attacks.
3. **The gate is narrow.** It validates recipient provenance, so C still permits body/reply leakage and goal hijacking. It does not independently prove authorization to send.
4. **Repeated runs are not additional independent examples.** The ten attacks are still ten distinct development examples. The dev log's 240 detector judgments all reuse cached verdicts, so they are not 240 new detector measurements.
5. **These are preliminary, small-sample estimates.** Combined ASR is 10%, with a reported 95% Wilson interval of 1.8–40.4%. This is above the proposal's below-5% target. The 13 held-out custom attacks will also yield a wide interval; a larger independent sample is needed for strong claims about a general below-5% rate.
6. **Shadow scoring is not live enforcement.** The research system replays recorded decisions. Withholding input before a live model reads it or requiring real review can change its behavior. Those deployments need their own validation.

There is no evidence here that the numbers are fabricated. There is a real gap between the number of attacks stored and the number evaluated, and between passing software checks and proving security effectiveness.

## Adjustments made for progress readiness

- Added a real review boundary to the live Mailbox when prevention is ON. The gate first strips/refuses unsupported recipients; surviving emails wait as drafts. You see To, CC, BCC, subject and body, then approve or reject. Approval uses server-stored bytes and sends once. Reject/reset prevents later approval.
- Added regressions for the directory-lookup authorization gap, address mentions without a send request, tampering with returned draft data, duplicate agent retries, reject/reset, invalid approvals and repeated approvals. The model cannot invoke the review endpoint through its tools.
- Added `OMP_NUM_THREADS=1` as an overridable runtime default before native libraries load, and a `scripts/run_ui.sh` launcher. A default-environment local retrieval check passed after the adjustment.
- Updated stale README statements that called implemented defenses stubs.
- Clarified all counts, source logs and preliminary limitations in the five-slide progress deck.

**The historical gate-v1/scoring protocol and original experiment logs were not changed.** The explicit-review step is an additional live safeguard. The 60%/10%/30%/10% table remains a historical result and must not be described as a new measurement of the reviewed-send flow. Requiring review has a usability cost and does not establish an autonomous authorization solution or protection against a user approving malicious content.

The updated system passed 256 automated checks, including all 61 original defense specification checks. Its browser approval/rejection flow was verified using scripted model responses, with no external model calls. Fresh Groq/Cerebras API verification and a new experiment sweep remain pending; no new model-performance claim is made.

## How to explain it in class

"We have 223 attack examples available. Our main preliminary comparison uses ten development attacks and seven normal tasks, each repeated three times. Separately, we evaluated fifty external attacks and checked our detector on fifty malicious and 203 clean excerpts. We also have 256 automated software checks, which test implementation correctness. The attack-success percentages measure a different thing. Our next evaluation will use frozen code and held-out examples."

## Where the test examples came from

Yes, we found a public attack dataset: [Microsoft LLMail-Inject on Hugging Face](https://huggingface.co/datasets/microsoft/llmail-inject-challenge), under the MIT license. The source revision stored in our converted file is `1063bdf01ec8762b812d5e06ee768a06faa5a6f7`.

- **200 external attacks** were selected and adapted from that dataset. Only 50 have saved agent runs; two runs had errors.
- **203 clean emails** came from that dataset’s false-alarm test file and were used in the separate detector check.
- **23 custom attacks** are project-specific examples: 10 development and 13 held out. The main progress table uses the 10 development attacks, repeated three times.
- **14 normal tasks**, fictional company policies and staff contacts are local project test material.

Our converter selects originally successful challenge attacks and places their email text in a retrieved policy excerpt. It rewrites ordinary addresses to reserved test addresses where its conversion rule applies. Our model, task and recipient-only attack scoring differ from the original challenge, so the results are exploratory and cannot be compared directly with the original benchmark. See `attacks/convert_llmail.py` and source metadata in `attacks/external_llmail.json`.

The dataset provides examples. Our logs record what happened when our system tested them. The October 13 main log supports the custom development table; the October 12 external agent log supports the separate 50-run comparison; the external detector log supports the 50 attack excerpt and 203 clean email label check. They are evidence records, not downloaded result claims.

We built the agent environment, defenses and evaluation using existing models and libraries. Everything was not created from scratch, and the attack examples are stored as files rather than queried from a live attack database.
