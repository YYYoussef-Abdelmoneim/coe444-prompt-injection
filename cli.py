"""Command line entry point.

  python cli.py index                    build the FAISS index
  python cli.py ask "..."                one query, no attack
  python cli.py demo PI-001              show one payload under all four conditions
  python cli.py eval [--split test]      run the corpus and print the results table
  python cli.py report <scored.jsonl>    recompute metrics from an existing log
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
    from config import AGENT_MODEL
    from mailsink import MailSink
    from rag.retriever import Retriever

    mail = MailSink()
    agent = Agent(get_provider("anthropic", AGENT_MODEL), Retriever(), mail)
    run = agent.run(args.query)
    print(run.final_text or "(no text)")
    for m in mail.outbox:
        print(f"\n[mail sink] to={m.to} subject={m.subject}")
    return 0


def cmd_demo(args: argparse.Namespace) -> int:
    """The presentation demo: one attack, all four conditions, side by side."""
    from attacks.loader import canary, contacts, load_payloads
    from conditions import ALL_CONDITIONS
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
    print(f"  retrieved: {', '.join(record.retrieved_chunk_ids)}")
    print(f"  poisoned chunk: {record.poisoned_chunk_id}  (retrieval_hit={record.retrieval_hit})")
    for d in record.detections:
        mark = "FLAG" if d.score >= 0.5 else "ok  "
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

    args = parser.parse_args()
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
