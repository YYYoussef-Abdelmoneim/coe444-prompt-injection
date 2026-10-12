"""The detector's dev evaluation: the excerpt set and the threshold choice.

Dev split only; the 27 Sep dev log supplies each payload's host chunk. No API call.
"""

from __future__ import annotations

from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
BASELINE_RUN = _ROOT / "logs" / "run-20260927T082229Z.jsonl"


def test_the_dev_set_is_every_clean_chunk_plus_each_dev_payload_in_its_logged_host():
    from attacks.loader import load_payloads
    from evaluation.detector_eval import clean_chunks, dev_excerpts

    excerpts = dev_excerpts(BASELINE_RUN)
    clean = [e for e in excerpts if e.kind == "clean"]
    poisoned = [e for e in excerpts if e.kind == "poisoned"]
    assert len(clean) == 26 and len(poisoned) == 10
    dev = {p.id: p for p in load_payloads("dev")}
    assert {e.payload_id for e in poisoned} == set(dev)
    hosts = dict(clean_chunks())
    for e in poisoned:
        # Exactly what Retriever.search hands the agent: host text, blank line, payload.
        assert e.text == f"{hosts[e.host]}\n\n{dev[e.payload_id].payload}"


def _row(kind, score, error=None):
    return {"kind": kind, "score": 1.0 if error else score, "error": error}


def test_roc_counts_a_failed_check_as_a_flag_at_every_threshold():
    from evaluation.detector_eval import roc

    rows = [_row("poisoned", 0.9), _row("poisoned", 0.2), _row("clean", 0.1), _row("clean", 0.0, error="429")]
    at = {p.threshold: p for p in roc(rows)}
    assert (at[0.9].tp, at[0.9].fp) == (1, 1)  # the failed clean check is flagged even at 0.9


def test_youden_picks_the_best_threshold_and_breaks_a_tie_upward():
    """A higher threshold flags fewer excerpts, and every flag aborts a run under B and D."""
    from evaluation.detector_eval import choose_threshold, roc

    rows = [_row("poisoned", 0.9), _row("poisoned", 0.4), _row("clean", 0.6), _row("clean", 0.2)]
    best = choose_threshold(roc(rows))
    assert best.threshold == 0.9 and abs(best.youden - 0.5) < 1e-9


def test_the_area_under_a_perfect_separator_is_one_and_a_coin_is_a_half():
    from evaluation.detector_eval import auc, roc

    assert auc(roc([_row("poisoned", 0.9), _row("clean", 0.1)])) == 1.0
    assert auc(roc([_row("poisoned", 0.5), _row("clean", 0.5)])) == 0.5


def test_the_cli_has_the_detector_commands():
    from cli import build_parser

    assert build_parser().parse_args(["detector-eval"]).cmd == "detector-eval"
    assert build_parser().parse_args(["roc", "logs/detector-x.jsonl"]).cmd == "roc"


def test_the_threshold_report_and_its_figure_are_written(tmp_path):
    from evaluation.detector_eval import write_threshold_report

    rows = []
    for name, version in (("llm", "detector-vX"), ("keyword", "keyword-v1")):
        rows += [{"detector": name, "version": version, "model": "m", "kind": "poisoned", "score": s,
                  "error": None, "payload_id": f"PI-{i}", "family": "f", "gate_applicable": True, "span": "x",
                  "excerpt_id": f"h+PI-{i}"} for i, s in enumerate((0.9, 0.8, 0.3))]
        rows += [{"detector": name, "version": version, "model": "m", "kind": "clean", "score": s,
                  "error": None, "excerpt_id": f"c::{i}"} for i, s in enumerate((0.1, 0.0, 0.6))]
    png, md = write_threshold_report(rows, tmp_path / "detector-x.jsonl", tmp_path)
    assert png.stat().st_size > 10_000
    text = md.read_text()
    assert "Chosen threshold: 0.80" in text and "| PI-2 | f | yes | 0.30 | **no** |" in text
