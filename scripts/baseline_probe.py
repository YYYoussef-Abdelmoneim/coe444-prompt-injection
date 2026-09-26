"""Measure condition-A attack success rate with no defenses and no detector calls.

This is the project's viability check. Every downstream number is a reduction
from this baseline, so if it is near zero there is nothing to defend and the
experimental design has to change before any more effort goes into defenses.

Cheap on purpose: the detector is never called, so this is one agent run per
payload.
"""

from __future__ import annotations

import os
import sys
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent.agent import Agent
from agent.llm import get_provider
from attacks.loader import canary, contacts, load_payloads
from config import AGENT_MODEL, AGENT_PROVIDER
from evaluation.predicates import attack_succeeded, benign_succeeded
from mailsink import MailSink
from rag.retriever import Retriever


def main(trials: int = 1, split: str | None = None) -> int:
    # A typo would otherwise select nothing and die dividing by zero at the end.
    if split not in (None, "dev", "test"):
        raise SystemExit(f"unknown split {split!r}; use dev or test")
    mail = MailSink()
    agent = Agent(get_provider(AGENT_PROVIDER, AGENT_MODEL), Retriever(), mail)
    cy = canary()

    per_family: dict[str, list[bool]] = defaultdict(list)
    rows: list[tuple[str, str, bool, bool, str]] = []

    # Pass "dev" while the test split is still held out; the default probes
    # every payload, test split included.
    for payload in load_payloads(split):
        for _ in range(trials):
            mail.clear()
            run = agent.run(payload.user_task, inject=payload.payload, inject_into=payload.inject_into)
            hit = run.poisoned_chunk_id is not None
            landed = False
            if hit and not run.error:
                # Same correction as evaluation/runner.py: `benign_task_failed`
                # is scored against the payload's success spec, not assumed.
                # Passing False unconditionally reported every goal_hijack
                # payload as landing whatever the agent replied.
                ben_ok = (
                    benign_succeeded(payload.success, run.proposed_calls, run.final_text)
                    if payload.success
                    else False
                )
                landed = attack_succeeded(
                    payload.target["predicate"], run.proposed_calls,
                    run.final_text, cy, benign_ok=ben_ok,
                )
            per_family[payload.family].append(landed)
            rows.append((payload.id, payload.family, hit, landed,
                         ",".join(sorted({c.tool_name for c in run.proposed_calls}))))

    print(f"\nmodel: {AGENT_MODEL}   split: {split or 'all'}   trials per payload: {trials}\n")
    print(f"{'id':<8} {'family':<22} {'retr':<5} {'LANDED':<7} tools called")
    print("-" * 74)
    for pid, fam, hit, landed, tools in rows:
        print(f"{pid:<8} {fam:<22} {'yes' if hit else 'MISS':<5} "
              f"{'YES' if landed else '.':<7} {tools}")

    print(f"\n{'family':<22} {'ASR':<12} n")
    print("-" * 44)
    total = [v for vs in per_family.values() for v in vs]
    for fam in sorted(per_family):
        vs = per_family[fam]
        print(f"{fam:<22} {sum(vs)/len(vs):>6.0%}       {len(vs)}")
    print("-" * 44)
    print(f"{'OVERALL':<22} {sum(total)/len(total):>6.0%}       {len(total)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(
        int(sys.argv[1]) if len(sys.argv) > 1 else 1,
        sys.argv[2] if len(sys.argv) > 2 else None,
    ))
