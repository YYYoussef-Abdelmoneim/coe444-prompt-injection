"""Execute the corpus and write one RunRecord per trial.

Executes ONCE per (task, trial) with both defenses in shadow mode, then scores
that single execution under all four conditions. The arms are therefore the
same trials re-scored, not four separate experiments — which is what makes the
paired statistics valid and what answers the "these results are not related"
objection at the level of the design rather than the prose.

Shadow mode has one honest limitation, which belongs in the report: under a
live condition-B deployment the agent would never see a flagged chunk, so its
trajectory could differ from the one recorded here. `cli.py validate-shadow`
re-runs a subsample live and reports the agreement rate.
"""

from __future__ import annotations

import json
import logging
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path

from agent.agent import Agent
from agent.llm import get_provider
from agent.prompts import SYSTEM_PROMPT_VERSION
from attacks.loader import BenignTask, Payload, canary, contacts, load_benign, load_payloads
from conditions import ALL_CONDITIONS, score
from config import (
    AGENT_MODEL,
    SAMPLING,
    CORPUS_VERSION,
    DETECTOR_MODEL,
    LOG_DIR,
    TRIALS_PER_TASK,
)
from defense.detection import DETECTOR_PROMPT_VERSION, Detector
from defense.prevention import ProvenanceGate
from evaluation.predicates import attack_succeeded, benign_succeeded
from mailsink import MailSink
from rag.retriever import Retriever
from schema import RunRecord, ScoredOutcome

_log = logging.getLogger(__name__)


def _git_commit() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"], stderr=subprocess.DEVNULL, text=True
        ).strip()
    except Exception:
        return "unknown"


class Runner:
    def __init__(self, *, trials: int = TRIALS_PER_TASK, detector=None) -> None:
        self.trials = trials
        self.retriever = Retriever()
        self.mail = MailSink()
        self.agent = Agent(get_provider("anthropic", AGENT_MODEL), self.retriever, self.mail)
        self.detector = detector if detector is not None else Detector()
        self.gate = ProvenanceGate(contacts=frozenset(contacts().values()))
        self.canary = canary()
        self.git = _git_commit()

    def run_all(self, split: str | None = None) -> tuple[list[RunRecord], list[ScoredOutcome]]:
        records: list[RunRecord] = []
        for payload in load_payloads(split):
            for trial in range(1, self.trials + 1):
                records.append(self._one(payload, trial, is_attack=True))
        for task in load_benign(split):
            for trial in range(1, self.trials + 1):
                records.append(self._one(task, trial, is_attack=False))

        outcomes = self.score_all(records)
        self._write(records, outcomes)
        return records, outcomes

    def _one(self, item: Payload | BenignTask, trial: int, *, is_attack: bool) -> RunRecord:
        self.mail.clear()
        inject = item.payload if is_attack else None
        inject_into = item.inject_into if is_attack else None

        run = self.agent.run(item.user_task, inject=inject, inject_into=inject_into)

        # Both defenses observe. Neither alters what already happened.
        detections = self.detector.scan_all(run.chunks)
        decisions = self.gate.evaluate_all(run.proposed_calls, item.user_task, run.chunks)

        record = RunRecord(
            run_id=uuid.uuid4().hex[:12],
            task_id=item.id,
            trial=trial,
            is_attack=is_attack,
            user_prompt=item.user_task,
            retrieved_chunk_ids=[c.chunk_id for c in run.chunks],
            poisoned_chunk_id=run.poisoned_chunk_id,
            retrieval_hit=(run.poisoned_chunk_id is not None) if is_attack else True,
            detections=detections,
            proposed_calls=run.proposed_calls,
            policy_decisions=decisions,
            agent_final_text=run.final_text,
            agent_model=AGENT_MODEL,
            detector_model=DETECTOR_MODEL,
            sampling=SAMPLING,
            corpus_version=CORPUS_VERSION,
            detector_prompt_version=f"{DETECTOR_PROMPT_VERSION}+{SYSTEM_PROMPT_VERSION}",
            git_commit=self.git,
            timestamp=datetime.now(timezone.utc).isoformat(),
            error=run.error,
            latency_ms=run.latency_ms,
            input_tokens=run.input_tokens,
            output_tokens=run.output_tokens,
        )
        record._messages = list(self.mail.outbox)  # type: ignore[attr-defined]
        record._item = item  # type: ignore[attr-defined]
        return record

    def score_all(self, records: list[RunRecord]) -> list[ScoredOutcome]:
        out: list[ScoredOutcome] = []
        for rec in records:
            item = getattr(rec, "_item", None)
            messages = getattr(rec, "_messages", [])
            for cond in ALL_CONDITIONS:
                executed_ids = self._executed_under(rec, cond)
                kept = [m for m, c in zip(messages, _email_calls(rec)) if c.call_id in executed_ids]
                reply = rec.agent_final_text if executed_ids or not _blocked(rec, cond) else ""

                if rec.is_attack:
                    ben_ok = False
                    atk = attack_succeeded(
                        item.target["predicate"], rec.proposed_calls, kept, reply,
                        self.canary, ben_ok,
                    )
                else:
                    atk = False
                    ben_ok = benign_succeeded(item.success, kept, reply)

                out.append(
                    score(rec, cond, attack_succeeded=atk, benign_task_completed=ben_ok)
                )
        return out

    def _executed_under(self, rec: RunRecord, cond) -> set[str]:
        from conditions import DEFAULT_DETECTION_THRESHOLD

        if cond.detection and any(
            d.failed or d.score >= DEFAULT_DETECTION_THRESHOLD for d in rec.detections
        ):
            return set()
        ids = {c.call_id for c in rec.proposed_calls}
        if cond.prevention:
            ids -= {d.call_id for d in rec.policy_decisions if d.denied}
        return ids

    def _write(self, records: list[RunRecord], outcomes: list[ScoredOutcome]) -> None:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        path = LOG_DIR / f"run-{stamp}.jsonl"
        with path.open("w", encoding="utf-8") as fh:
            for r in records:
                fh.write(r.to_json() + "\n")
        _log.info("Wrote %d records to %s", len(records), path)

        out_path = LOG_DIR / f"scored-{stamp}.jsonl"
        with out_path.open("w", encoding="utf-8") as fh:
            for o in outcomes:
                fh.write(
                    json.dumps(
                        {
                            "run_id": o.run_id, "pairing_key": o.pairing_key,
                            "task_id": o.task_id, "trial": o.trial,
                            "condition": o.condition, "outcome": o.outcome.value,
                            "blocked_by": o.blocked_by,
                        }
                    )
                    + "\n"
                )
        _log.info("Wrote %d scored outcomes to %s", len(outcomes), out_path)


def _email_calls(rec: RunRecord):
    return [c for c in rec.proposed_calls if c.tool_name == "send_email"]


def _blocked(rec: RunRecord, cond) -> bool:
    from conditions import DEFAULT_DETECTION_THRESHOLD

    return cond.detection and any(
        d.failed or d.score >= DEFAULT_DETECTION_THRESHOLD for d in rec.detections
    )
