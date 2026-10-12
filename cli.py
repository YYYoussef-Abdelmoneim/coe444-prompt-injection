"""Command line entry point.

  python cli.py index                    build the FAISS index
  python cli.py ask "..."                one query, no attack
  python cli.py demo PI-101              show one payload under all four conditions
  python cli.py eval [--split test]      run the corpus and print the results table
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
    from mailsink import MailSink
    from rag.retriever import Retriever

    mail = MailSink()
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

    payloads = {p.id: p for p in load_payloads()}
    if args.payload_id not in payloads:
        print(f"Unknown payload {args.payload_id}. Available: {', '.join(sorted(payloads))}")
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
    from evaluation.runner import Runner

    runner = Runner(trials=args.trials)
    _, outcomes = runner.run_all(split=args.split)
    print()
    print(summary_table(outcomes))
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


def main() -> int:
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
    p_eval.add_argument("--split", default=None, choices=["dev", "test"])
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

    args = parser.parse_args()
    if getattr(args, "threshold", None) is None and args.cmd == "rescore":
        from conditions import DEFAULT_DETECTION_THRESHOLD

        args.threshold = DEFAULT_DETECTION_THRESHOLD
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
