"""detector max-of-N sampling (DETECTOR_SAMPLES). Fakes only."""

from __future__ import annotations

from defense.detection import Detector
from tests.conftest import FakeProvider


def _v(score, span=""):
    return {"score": score, "label": "injection" if score >= 0.5 else "clean", "span": span}


def test_one_sample_is_the_pre_registered_single_call(chunk):
    p = FakeProvider(verdicts=[_v(0.05), _v(0.9)])
    d = Detector(provider=p, samples=1)
    assert d.scan(chunk()).score == 0.05 and len(p.classify_calls) == 1


def test_max_of_n_keeps_the_highest_score_and_its_span(chunk):
    p = FakeProvider(verdicts=[_v(0.05), _v(0.6, "bad span"), _v(0.1)])
    d = Detector(provider=p, samples=3)
    r = d.scan(chunk())
    assert r.score == 0.6 and r.span == "bad span" and len(p.classify_calls) == 3


def test_a_malformed_draw_among_n_fails_closed(chunk):
    p = FakeProvider(verdicts=[_v(0.05), {"score": "high"}, _v(0.05)])
    r = Detector(provider=p, samples=3).scan(chunk())
    assert r.score == 1.0 and r.failed


def test_samples_below_one_are_clamped_to_one(chunk):
    p = FakeProvider(verdicts=[_v(0.2)])
    assert Detector(provider=p, samples=0).scan(chunk()).score == 0.2 and len(p.classify_calls) == 1


def test_cache_separates_single_draw_from_max_of_n(chunk, tmp_path):
    from defense.verdict_cache import VerdictCache
    cache = VerdictCache(tmp_path / "c.sqlite")
    Detector(provider=FakeProvider(verdicts=[_v(0.05)]), samples=1, cache=cache).scan(chunk())
    # A fresh 3-sample detector must not see the cached 1-sample verdict.
    p = FakeProvider(verdicts=[_v(0.05), _v(0.7), _v(0.05)])
    r = Detector(provider=p, samples=3, cache=cache).scan(chunk())
    assert r.score == 0.7 and not r.cached and len(p.classify_calls) == 3
