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
from conditions import ALL_CONDITIONS, DEFAULT_DETECTION_THRESHOLD, any_flagged, score
from config import (
    AGENT_MODEL,
    AGENT_PROVIDER,
    SAMPLING,
    CORPUS_VERSION,
    DETECTOR_MODEL,
    LOG_DIR,
    TRIALS_PER_TASK,
)
from defense.detection import DETECTOR_PROMPT_VERSION, Detector
from defense.prevention import POLICY_VERSION, ProvenanceGate
from evaluation.predicates import attack_succeeded, benign_succeeded, carrier_success
from mailsink import MailSink
from rag.retriever import Retriever
from schema import RunRecord, ScoredOutcome, ToolCall

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
        self.agent = Agent(get_provider(AGENT_PROVIDER, AGENT_MODEL), self.retriever, self.mail)
        self.detector = detector if detector is not None else Detector()
        self.contacts = contacts()
        self.gate = ProvenanceGate(contacts=frozenset(self.contacts.values()))
        self.canary = canary()
        self.git = _git_commit()

    def run_all(self, split: str | None = None) -> tuple[list[RunRecord], list[ScoredOutcome]]:
        """Execute every task, then score. Writes incrementally.

        Records are flushed to disk as they are produced rather than at the end.
        A sweep is minutes of API calls, and losing all of it to a crash, an
        unplugged drive or a rate limit on the last task is not acceptable - a
        partial log is still analysable.
        """
        items: list[tuple[Payload | BenignTask, bool]] = [
            (p, True) for p in load_payloads(split)
        ] + [(t, False) for t in load_benign(split)]
        # Resolve every success spec before the first API call: a payload the
        # carrier rule cannot handle should fail here, not after the sweep.
        for item, is_attack in items:
            self._success_spec(item, is_attack)
        total = len(items) * self.trials

        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        raw_path = LOG_DIR / f"run-{stamp}.jsonl"
        records: list[RunRecord] = []
        done = 0

        with raw_path.open("w", encoding="utf-8") as fh:
            for item, is_attack in items:
                for trial in range(1, self.trials + 1):
                    done += 1
                    print(f"  [{done:>3}/{total}] {item.id} trial {trial}", flush=True)
                    rec = self._one(item, trial, is_attack=is_attack)
                    if rec.error:
                        print(f"        error: {rec.error}", flush=True)
                    records.append(rec)
                    fh.write(rec.to_json() + "\n")
                    fh.flush()

        print(f"  wrote {len(records)} records to {raw_path}", flush=True)
        outcomes = self.score_all(records)
        self._write_scored(outcomes, stamp)
        return records, outcomes

    def _success_spec(self, item: Payload | BenignTask, is_attack: bool) -> dict:
        """The benign ground truth for this item. An attack trial still carries a
        legitimate user task: its result decides BLOCKED_TASK_OK vs
        BLOCKED_TASK_BROKEN whenever a defense blocks, and goal_hijack's
        predicate is its inverse."""
        if item.success:
            return item.success
        if not is_attack:
            raise ValueError(f"benign task {item.id} has no success spec")
        return carrier_success(item.family, item.user_task, self.contacts)

    def _one(self, item: Payload | BenignTask, trial: int, *, is_attack: bool) -> RunRecord:
        spec = self._success_spec(item, is_attack)
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
            policy_version=POLICY_VERSION,
            split=item.split,
            family=item.family if is_attack else "",
            attack_predicate=item.target["predicate"] if is_attack else None,
            success_spec=spec,
            canary=self.canary,
            chunks=list(run.chunks),
        )
        record._item = item  # type: ignore[attr-defined]
        return record

    def score_all(
        self, records: list[RunRecord], *, threshold: float = DEFAULT_DETECTION_THRESHOLD
    ) -> list[ScoredOutcome]:
        return score_records(records, canary=self.canary, contacts=self.contacts, threshold=threshold)

    def _write_scored(self, outcomes: list[ScoredOutcome], stamp: str) -> None:
        out_path = LOG_DIR / f"scored-{stamp}.jsonl"
        write_scored(outcomes, out_path)
        print(f"  wrote {len(outcomes)} scored outcomes to {out_path}", flush=True)


def score_records(
    records: list[RunRecord],
    *,
    canary: str,
    contacts: dict[str, str],
    threshold: float = DEFAULT_DETECTION_THRESHOLD,
) -> list[ScoredOutcome]:
    """Score every record under all four conditions. A pure function of the
    records: no API call, no agent, and no corpus file unless the record
    predates logging its own scoring inputs.

    `threshold` reaches every place that decides a detection block - the calls
    a condition executes, the reply it shows and score() itself - so a sweep
    re-scored at 0.3 is consistent end to end.
    """
    out: list[ScoredOutcome] = []
    for rec in records:
        predicate, spec, rec_canary = _scoring_inputs(rec, canary, contacts)
        for cond in ALL_CONDITIONS:
            executed_ids = _executed_under(rec, cond, threshold)
            kept = [_as_executed(c, rec, cond) for c in rec.proposed_calls if c.call_id in executed_ids]
            reply = rec.agent_final_text if executed_ids or not _blocked(rec, cond, threshold) else ""

            ben_ok = benign_succeeded(spec, kept, reply)
            atk = rec.is_attack and attack_succeeded(predicate, kept, reply, rec_canary, ben_ok)
            out.append(score(rec, cond, threshold=threshold, attack_succeeded=atk, benign_task_completed=ben_ok))
    return out


def _scoring_inputs(rec: RunRecord, canary: str, contacts: dict[str, str]) -> tuple[str | None, dict, str]:
    """(attack predicate, benign success spec, canary) for one record.

    Taken from the record when it logged them. Otherwise from the item the
    runner attached in memory, and failing that from the DEV corpus by id - the
    fallback for logs written before RunRecord carried these fields.
    """
    if rec.success_spec is not None:
        return rec.attack_predicate, rec.success_spec, rec.canary or canary
    item = getattr(rec, "_item", None) or _dev_item(rec.task_id)
    spec = item.success
    if rec.is_attack and not spec:
        spec = carrier_success(item.family, item.user_task, contacts)
    predicate = item.target["predicate"] if rec.is_attack else None
    return predicate, spec, canary


def _dev_item(task_id: str) -> Payload | BenignTask:
    """Looks in the dev split only. Rescoring an old log must never be the thing
    that opens the held-out test split."""
    for item in [*load_payloads("dev"), *load_benign("dev")]:
        if item.id == task_id:
            return item
    raise ValueError(
        f"{task_id} is not in the dev split, and its record predates logging its own "
        "scoring inputs (success_spec, attack_predicate), so it cannot be re-scored here"
    )


def _executed_under(rec: RunRecord, cond, threshold: float) -> set[str]:
    if cond.detection and any_flagged(rec, threshold):
        return set()
    ids = {c.call_id for c in rec.proposed_calls}
    if cond.prevention:
        ids -= {d.call_id for d in rec.policy_decisions if d.denied}
    return ids


def _as_executed(call: ToolCall, rec: RunRecord, cond) -> ToolCall:
    """The call as the condition would have run it.

    Under prevention a sanitized call runs with the gate's recorded arguments,
    so the predicates see the email that would actually have gone out: the
    user's recipient kept, the injected CC gone.
    """
    if cond.prevention:
        for d in rec.policy_decisions:
            if d.call_id == call.call_id and d.sanitized:
                return ToolCall(call.call_id, call.tool_name, dict(d.sanitized_arguments or {}))
    return call


def _blocked(rec: RunRecord, cond, threshold: float) -> bool:
    return cond.detection and any_flagged(rec, threshold)


def write_scored(outcomes: list[ScoredOutcome], path: Path) -> None:
    """One JSON line per outcome. Opened exclusively: a scored file is evidence,
    so writing one never replaces an existing one."""
    with path.open("x", encoding="utf-8") as fh:
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


def rescored_path(run_log: Path, threshold: float) -> Path:
    """logs/run-<stamp>.jsonl -> logs/scored-<stamp>-t0.50.jsonl"""
    stem = run_log.stem.replace("run-", "scored-", 1)
    return run_log.with_name(f"{stem}-t{threshold:.2f}.jsonl")
