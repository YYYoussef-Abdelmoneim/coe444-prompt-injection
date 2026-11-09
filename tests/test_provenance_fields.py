"""Experiment provenance in every record (9 Nov 2026, review M3).

The same open-weight model string is served by several hosts with different
scores, and one detector draw is not three. A log that cannot say which it was
cannot be the record of the final run, and a resume must refuse to mix them.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import evaluation.runner as R
from evaluation.runner import _check_resumable
from schema import RunRecord


def _rec(**over):
    base = dict(
        run_id="r", task_id="PI-101", trial=1, is_attack=True, user_prompt="u",
        retrieved_chunk_ids=[], poisoned_chunk_id=None, retrieval_hit=True, detections=[],
        proposed_calls=[], policy_decisions=[], agent_final_text="", agent_model=R.AGENT_MODEL,
        detector_model=R.DETECTOR_MODEL, sampling=R.SAMPLING, corpus_version=R.corpus_version("dev"),
        detector_prompt_version=f"{R.DETECTOR_PROMPT_VERSION}+{R.SYSTEM_PROMPT_VERSION}",
        policy_version=R.POLICY_VERSION, git_commit="g", timestamp="t", split="dev",
        agent_host=R.AGENT_PROVIDER, detector_host=R.DETECTOR_PROVIDER, detector_samples=R.DETECTOR_SAMPLES,
    )
    base.update(over)
    return RunRecord(**base)


def test_a_log_from_the_same_stack_can_be_resumed():
    _check_resumable([_rec()], "dev", Path("x.jsonl"))


def test_a_log_with_a_different_detector_draw_count_cannot_be_resumed():
    other = 1 if R.DETECTOR_SAMPLES != 1 else 3
    with pytest.raises(ValueError, match="detector_samples"):
        _check_resumable([_rec(detector_samples=other)], "dev", Path("x.jsonl"))


def test_a_log_from_another_detector_host_cannot_be_resumed():
    with pytest.raises(ValueError, match="detector_host"):
        _check_resumable([_rec(detector_host="some-other-host")], "dev", Path("x.jsonl"))


def test_records_from_before_9_nov_have_empty_provenance_and_are_refused_too():
    # Old logs carry no host/sample fields (defaults). They are a different,
    # unknowable configuration; they must not be extended by a new sweep.
    with pytest.raises(ValueError):
        _check_resumable([_rec(detector_host="", detector_samples=0)], "dev", Path("x.jsonl"))


def test_both_runners_pass_the_provenance_fields_to_every_record():
    """Static: the RunRecord(...) call in each runner names all three fields,
    so a record without them cannot be written by this code."""
    for path in ("evaluation/runner.py", "evaluation/live.py"):
        src = Path(path).read_text(encoding="utf-8")
        for field in ("agent_host=", "detector_host=", "detector_samples="):
            assert field in src, f"{path} does not set {field}"
