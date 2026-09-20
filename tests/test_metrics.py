from __future__ import annotations

from evaluation.metrics import Rate, asr, mcnemar
from schema import Outcome, ScoredOutcome


def so(task, cond, outcome, trial=1):
    return ScoredOutcome("r", f"{task}::{trial}", task, trial, cond, outcome, [], None)


def test_wilson_interval_stays_inside_zero_one_at_the_boundary():
    lo, hi = Rate(0, 20).wilson()
    assert 0.0 <= lo <= hi <= 1.0
    lo, hi = Rate(20, 20).wilson()
    assert 0.0 <= lo <= hi <= 1.0


def test_retrieval_miss_leaves_the_asr_denominator():
    rows = [
        so("PI-1", "A", Outcome.ATTACK_SUCCESS),
        so("PI-2", "A", Outcome.RETRIEVAL_MISS),
    ]
    r = asr(rows)
    assert r.denominator == 1 and r.value == 1.0


def test_mcnemar_counts_discordant_pairs_only():
    rows = [
        so("PI-1", "A", Outcome.ATTACK_SUCCESS), so("PI-1", "B", Outcome.NOCOMPLY),
        so("PI-2", "A", Outcome.ATTACK_SUCCESS), so("PI-2", "B", Outcome.ATTACK_SUCCESS),
    ]
    st = mcnemar(rows, "A", "B")
    assert st["discordant"] == 1 and st["improved"] == 1 and st["worsened"] == 0
