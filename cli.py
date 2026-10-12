"""Command line entry point.

  python cli.py index                    build the FAISS index
  python cli.py ask "..."                one query, no attack
  python cli.py demo PI-101              show one payload under all four conditions
  python cli.py eval [--only ID,...]     run the dev split and print the results table
  python cli.py eval --resume <run.jsonl>   continue a sweep stopped by a free-tier limit
  python cli.py eval --split test --final   the held-out split, once, at the end (make eval)
  python cli.py report <scored.jsonl>    recompute metrics from an existing log
  python cli.py rescore <run.jsonl> [--threshold t] [--write]
                                         re-score a raw run log, no API call
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s")


def cmd_index(_: argparse.Namespace) -> int:
    from rag.indexer import build_index

    print(f"Indexed {build_index()} chunks.")
    return 0


def cmd_ask(args: argparse.Namespace) -> int:
    from agent.agent import Agent
    from agent.llm import get_provider
    from config import AGENT_MODEL, AGENT_PROVIDER
    from mailsink import get_mail_backend
    from rag.retriever import Retriever

    mail = get_mail_backend()
    agent = Agent(get_provider(AGENT_PROVIDER, AGENT_MODEL), Retriever(), mail)
    run = agent.run(args.query)
    print(run.final_text or "(no text)")
    for m in mail.outbox:
        print(f"\n[mail sink] to={m.to} subject={m.subject}")
    return 0


def cmd_demo(args: argparse.Namespace) -> int:
    """The presentation demo: one attack, all four conditions, side by side."""
    from attacks.loader import canary, contacts, load_payloads
    from conditions import ALL_CONDITIONS, DEFAULT_DETECTION_THRESHOLD, is_flagged
    from evaluation.runner import Runner

    # Dev only: the demo prints the payload text, and the test split stays
    # unread until the final evaluation.
    payloads = {p.id: p for p in load_payloads("dev")}
    if args.payload_id not in payloads:
        print(f"{args.payload_id} is not a dev payload. Dev payloads: {', '.join(sorted(payloads))}")
        return 1
    payload = payloads[args.payload_id]

    runner = Runner(trials=1)
    print(f"\n  PAYLOAD  {payload.id}  [{payload.family} / {payload.evasion}]")
    print(f"  USER     {payload.user_task}")
    print(f"  INJECTED {payload.payload[:140]}{'...' if len(payload.payload) > 140 else ''}")
    print(f"  GATE APPLICABLE: {payload.gate_applicable}\n")

    record = runner._one(payload, 1, is_attack=True)
    # An agent that dies before its first search retrieves nothing, which
    # reads exactly like a retrieval miss unless the error is shown here.
    if record.error:
        print(f"  AGENT ERROR: {record.error}")
    print(f"  retrieved: {', '.join(record.retrieved_chunk_ids)}")
    print(f"  poisoned chunk: {record.poisoned_chunk_id}  (retrieval_hit={record.retrieval_hit})")
    for d in record.detections:
        mark = "FLAG" if is_flagged(d, DEFAULT_DETECTION_THRESHOLD) else "ok  "
        print(f"    detector {mark} {d.score:.2f}  {d.chunk_id}")
    for c in record.proposed_calls:
        print(f"  proposed: {c.tool_name}({json.dumps(c.arguments)[:110]})")
    for d in record.policy_decisions:
        print(f"    gate {d.decision.value.upper():<6} {d.reason[:100]}")

    print("\n  OUTCOME BY CONDITION")
    for outcome in runner.score_all([record]):
        cond = next(c for c in ALL_CONDITIONS if c.name == outcome.condition)
        blocked = f" (blocked by {outcome.blocked_by})" if outcome.blocked_by else ""
        print(f"    {cond.name}  {cond.label:<24} {outcome.outcome.value}{blocked}")
    return 0


def cmd_eval(args: argparse.Namespace) -> int:
    from evaluation.metrics import summary_table

    if args.split == "test" and not args.final:
        print("The test split is held out until the final evaluation run (CLAUDE.md).\n"
              "Use `make eval`, which asks first. Develop on --split dev.")
        return 2
    only = None
    if args.only:
        from attacks.loader import load_benign, load_payloads

        only = {i.strip() for i in args.only.split(",") if i.strip()}
        dev_ids = {p.id for p in load_payloads("dev")} | {t.id for t in load_benign("dev")}
        unknown = sorted(only - dev_ids)
        if unknown:
            print(f"--only takes dev ids; not in the dev split: {', '.join(unknown)}")
            return 2

    from agent.llm import QuotaExhausted
    from evaluation.runner import Runner

    runner = Runner(trials=args.trials)
    try:
        records, outcomes = runner.run_all(split=args.split, only=only, limit=args.limit, resume=args.resume)
    except QuotaExhausted:
        return 3  # run_all has said where the partial log is and how to resume
    print()
    print(summary_table(outcomes, records=records))
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    from evaluation.metrics import summary_table
    from schema import Outcome, ScoredOutcome

    rows = [json.loads(l) for l in Path(args.scored).read_text().splitlines() if l.strip()]
    outcomes = [
        ScoredOutcome(
            run_id=r["run_id"], pairing_key=r["pairing_key"], task_id=r["task_id"],
            trial=r["trial"], condition=r["condition"], outcome=Outcome(r["outcome"]),
            executed_calls=[], blocked_by=r.get("blocked_by"),
        )
        for r in rows
    ]
    print(summary_table(outcomes))
    return 0


def cmd_rescore(args: argparse.Namespace) -> int:
    """Score a raw run log under all four conditions at any detection threshold.

    The log is the evidence (invariant 5), so this needs no API call and never
    re-runs the agent. --write saves the table's rows next to the log, under a
    name that says which threshold made them; an existing file is never replaced.
    """
    from attacks.loader import canary, contacts
    from evaluation.logs import load_records
    from evaluation.metrics import summary_table
    from evaluation.runner import rescored_path, score_records, write_scored

    run_log = Path(args.run_log)
    records = load_records(run_log)
    outcomes = score_records(records, canary=canary(), contacts=contacts(), threshold=args.threshold)
    print(f"{len(records)} records from {run_log}, detection threshold {args.threshold}\n")
    print(summary_table(outcomes, records=records))
    if args.write:
        out = Path(args.out) if args.out else rescored_path(run_log, args.threshold)
        try:
            write_scored(outcomes, out)
        except FileExistsError:
            print(f"\n{out} already exists; not overwriting it. Pass --out to choose another name.")
            return 1
        print(f"\nwrote {len(outcomes)} scored outcomes to {out}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="coe444")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("index").set_defaults(fn=cmd_index)

    p_ask = sub.add_parser("ask")
    p_ask.add_argument("query")
    p_ask.set_defaults(fn=cmd_ask)

    p_demo = sub.add_parser("demo")
    p_demo.add_argument("payload_id")
    p_demo.set_defaults(fn=cmd_demo)

    p_eval = sub.add_parser("eval")
    # Defaults to dev. With no default the sweep ran both splits, which is how
    # the held-out test split gets opened by accident.
    p_eval.add_argument("--split", default="dev", choices=["dev", "test", "exploratory"])
    p_eval.add_argument("--final", action="store_true",
                        help="required with --split test: this is the single final run")
    p_eval.add_argument("--only", default=None, help="comma-separated dev ids, for smoke runs")
    p_eval.add_argument("--limit", type=int, default=None,
                        help="run only the first N items, in file order")
    p_eval.add_argument("--resume", default=None, metavar="RUN_LOG",
                        help="continue a sweep that stopped on a free-tier limit, in the same log")
    p_eval.add_argument("--trials", type=int, default=3)
    p_eval.set_defaults(fn=cmd_eval)

    p_rep = sub.add_parser("report")
    p_rep.add_argument("scored")
    p_rep.set_defaults(fn=cmd_report)

    p_res = sub.add_parser("rescore")
    p_res.add_argument("run_log")
    p_res.add_argument("--threshold", type=float, default=None,
                       help="detection threshold (default: conditions.DEFAULT_DETECTION_THRESHOLD)")
    p_res.add_argument("--write", action="store_true", help="save the scored rows next to the log")
    p_res.add_argument("--out", default=None, help="where --write saves them")
    p_res.set_defaults(fn=cmd_rescore)

    p_det = sub.add_parser("detector-eval", help="score the fixed dev excerpt set (Cerebras)")
    p_det.add_argument("--baseline-log", default="logs/run-20260927T082229Z.jsonl",
                       help="dev run log that records each payload's host chunk")
    p_det.add_argument("--external", action="store_true",
                       help="the pre-registered out-of-sample check instead of the dev set")
    p_det.add_argument("--llmail-log", default="logs/run-20261012T202019Z.jsonl")
    p_det.add_argument("--fp-emails", default=".data/llmail_inject/1063bdf/emails_for_fp_tests.json")
    p_det.add_argument("--dev-log", default="logs/detector-20261012T203528Z.jsonl")
    p_det.add_argument("--out-dir", default="results")
    p_det.set_defaults(fn=cmd_detector_eval)

    p_var = sub.add_parser("detector-variance", help="repeat uncached calls near the threshold (Cerebras)")
    p_var.add_argument("--dev-log", default="logs/detector-20261012T203528Z.jsonl")
    p_var.add_argument("--baseline-log", default="logs/run-20260927T082229Z.jsonl")
    p_var.add_argument("--repeats", type=int, default=3)
    p_var.add_argument("--out-dir", default="results")
    p_var.set_defaults(fn=cmd_detector_variance)

    p_roc = sub.add_parser("roc", help="ROC, AUC and the dev threshold from a detector log")
    p_roc.add_argument("detector_log")
    p_roc.add_argument("--write", action="store_true", help="write the threshold report and figure")
    p_roc.add_argument("--out-dir", default="results")
    p_roc.set_defaults(fn=cmd_roc)
    return parser


def cmd_detector_eval(args: argparse.Namespace) -> int:
    """Score the fixed dev excerpt set with the LLM detector and the keyword
    baseline, and log every verdict. Cached verdicts cost no call, so a run that
    stopped on a free-tier limit is simply run again."""
    from datetime import datetime, timezone

    from agent.llm import QuotaExhausted
    from config import DETECTOR_CACHE_PATH, LOG_DIR
    from defense.detection import DETECTOR_PROMPT_VERSION, Detector
    from defense.detection_baseline import BASELINE_VERSION, KeywordDetector
    from defense.verdict_cache import VerdictCache
    from evaluation.detector_eval import dev_excerpts, score_excerpts, summary, write_log

    if args.external:
        # The pre-registered out-of-sample check (results/methodology_draft.md):
        # the frozen detector, never re-chosen afterwards.
        from evaluation.detector_eval import external_excerpts

        excerpts = external_excerpts(Path(args.llmail_log), Path(args.fp_emails))
        prefix = "detector-external"
    else:
        excerpts = dev_excerpts(Path(args.baseline_log))
        prefix = "detector"
    poisoned = sum(e.kind == "poisoned" for e in excerpts)
    print(f"{len(excerpts)} excerpts: {len(excerpts) - poisoned} clean, {poisoned} poisoned; "
          f"detector {DETECTOR_PROMPT_VERSION}\n")
    try:
        rows = score_excerpts(excerpts, Detector(cache=VerdictCache(DETECTOR_CACHE_PATH)),
                              name="llm", version=DETECTOR_PROMPT_VERSION)
    except QuotaExhausted as exc:
        print(f"\nSTOPPED, free-tier limit: {exc}\nVerdicts so far are cached; run this again later.")
        return 3
    rows += score_excerpts(excerpts, KeywordDetector(), name="keyword", version=BASELINE_VERSION)
    path = LOG_DIR / f"{prefix}-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.jsonl"
    write_log(rows, path)
    print(f"\nwrote {len(rows)} verdicts to {path}\n")
    print(summary(rows))
    if args.external:
        from evaluation.detector_eval import load_log, write_outofsample_report

        out = write_outofsample_report(rows, load_log(Path(args.dev_log)), path, Path(args.out_dir))
        print(f"\nwrote {out}")
    return 0


def cmd_detector_variance(args: argparse.Namespace) -> int:
    """Repeat uncached calls on the excerpts nearest the threshold (pre-registered)."""
    from datetime import datetime, timezone

    from agent.llm import QuotaExhausted
    from config import LOG_DIR
    from defense.detection import DETECTOR_PROMPT_VERSION, Detector
    from evaluation.detector_eval import (dev_excerpts, load_log, run_variance, variance_targets,
                                          write_log, write_variance_report)

    dev_rows = [r for r in load_log(Path(args.dev_log)) if r["detector"] == "llm"]
    targets = variance_targets(dev_rows, dev_excerpts(Path(args.baseline_log)))
    print(f"{len(targets)} excerpts x {args.repeats} uncached calls: {', '.join(t.excerpt_id for t in targets)}\n")
    try:
        rows = run_variance(targets, Detector(), version=DETECTOR_PROMPT_VERSION, repeats=args.repeats)
    except QuotaExhausted as exc:
        print(f"\nSTOPPED, free-tier limit: {exc}")
        return 3
    path = LOG_DIR / f"detector-variance-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.jsonl"
    write_log(rows, path)
    out = write_variance_report(rows, dev_rows, path, Path(args.out_dir))
    print(f"\nwrote {path} and {out}")
    print(out.read_text())
    return 0


def cmd_roc(args: argparse.Namespace) -> int:
    """ROC, AUC and the threshold rule from a detector log; writes the report."""
    from evaluation.detector_eval import load_log, summary, write_threshold_report

    rows = load_log(Path(args.detector_log))
    print(summary(rows))
    if args.write:
        out = write_threshold_report(rows, Path(args.detector_log), Path(args.out_dir))
        print(f"\nwrote {', '.join(str(p) for p in out)}")
    return 0


def main() -> int:
    args = build_parser().parse_args()
    if args.cmd == "rescore" and args.threshold is None:
        from conditions import DEFAULT_DETECTION_THRESHOLD

        args.threshold = DEFAULT_DETECTION_THRESHOLD
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
