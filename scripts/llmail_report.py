"""The LLMail-Inject exploratory baseline, from its run log only (invariant 5).

    python scripts/llmail_report.py logs/run-<stamp>.jsonl [--out results/llmail_baseline.md]

Condition A (no defense) is the baseline the plan asks for. C comes free in the
same log, because gate-v1 observed every run in shadow mode. The detector was
the stub for this run, so B and D are not reported here. Kept apart from the
main corpus: different attacks, a different victim task, and a lossy conversion
(see the conversion rules in attacks/external_llmail.json).
"""

from __future__ import annotations

import argparse
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from attacks.loader import canary, contacts, load_payloads  # noqa: E402
from evaluation.logs import load_records  # noqa: E402
from evaluation.metrics import Rate, collapse  # noqa: E402
from evaluation.runner import score_records  # noqa: E402

DEFENSES = {"a": "prompt_shield", "b": "prompt_shield", "c": "tasktracker", "d": "tasktracker",
            "e": "spotlight", "f": "spotlight", "g": "llm_judge", "h": "llm_judge", "i": "all", "j": "all"}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("run_log")
    ap.add_argument("--out", default="results/llmail_baseline.md")
    args = ap.parse_args()

    log = Path(args.run_log)
    records = load_records(log)
    outcomes = score_records(records, canary=canary(), contacts=contacts())
    items = {p.id: p for p in load_payloads("exploratory")}
    by_cond = defaultdict(list)
    for o in outcomes:
        by_cond[o.condition].append(o)

    def stratum(task_id):
        scenario = items[task_id].evasion.removeprefix("llmail_")  # e.g. level3h
        letter = scenario[-1]
        return int(scenario[5]), DEFENSES[letter], "Phi-3" if letter in "acegi" else "GPT-4o mini"

    landed_a = collapse(by_cond["A"], "attack")
    landed_c = collapse(by_cond["C"], "attack")
    misses = sum(1 for o in by_cond["A"] if o.outcome.value == "retrieval_miss")
    errors = sum(1 for o in by_cond["A"] if o.outcome.value == "error")
    tokens = sum(r.input_tokens + r.output_tokens for r in records)

    def table(key_name, key):
        rows = [f"| {key_name} | ASR under A | ASR under C |", "|---|---|---|"]
        groups = defaultdict(list)
        for tid in landed_a:
            groups[key(tid)].append(tid)
        for k in sorted(groups):
            a = Rate(sum(landed_a[t] for t in groups[k]), len(groups[k]))
            c = Rate(sum(landed_c.get(t, False) for t in groups[k]), sum(t in landed_c for t in groups[k]))
            rows.append(f"| {k} | {a} | {c} |")
        return rows

    decisions = Counter(d.decision.value for r in records for d in r.policy_decisions
                        for c in r.proposed_calls if c.call_id == d.call_id and c.tool_name == "send_email")
    overall_a = Rate(sum(landed_a.values()), len(landed_a))
    overall_c = Rate(sum(landed_c.values()), len(landed_c))
    lines = [
        "# LLMail-Inject exploratory baseline",
        "",
        f"Source: `{log.as_posix()}` ({len(records)} runs, 1 trial each, agent {records[0].agent_model}, "
        f"{records[0].detector_prompt_version}, {records[0].policy_version}, corpus {records[0].corpus_version}, "
        f"commit {records[0].git_commit}; {tokens:,} agent tokens).",
        "",
        "EXPLORATORY: attacks the team did not write, from the LLMail-Inject challenge (MIT), converted as "
        "attacks/external_llmail.json records. The original targets, victim task, model and defenses all differ, "
        "so these rates are not comparable with the challenge's own numbers, and they are never pooled with "
        "the main corpus. The selection was the challenge's end-to-end successful attacks, i.e. attacks that "
        "already beat a defended GPT-4o mini or Phi-3 once.",
        "",
        "| Condition | Attack success rate (95% Wilson) |",
        "|---|---|",
        f"| A, no defense | {overall_a} |",
        f"| C, gate-v1 only | {overall_c} |",
        "",
        f"Retrieval misses (excluded): {misses}; agent errors (excluded): {errors}.",
        f"gate-v1 decisions on proposed send_email calls: {dict(decisions) or 'none'}.",
        "",
        "## By victim level (LLMail scenario)",
        "",
        *table("Level", lambda t: f"level {stratum(t)[0]}"),
        "",
        "## By the defense the attack beat in the challenge",
        "",
        *table("Defense", lambda t: stratum(t)[1]),
        "",
        "## By the model the attack beat in the challenge",
        "",
        *table("Model", lambda t: stratum(t)[2]),
    ]
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    sys.exit(main())
