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


# ── Variance and out-of-sample checks (pre-registered 2026-10-13) ────────────

DEV_LOG = _ROOT / "logs" / "detector-20261012T203528Z.jsonl"
LLMAIL_RUN = _ROOT / "logs" / "run-20261012T202019Z.jsonl"


def test_the_variance_check_takes_pi021_and_the_three_highest_scoring_clean_chunks():
    from evaluation.detector_eval import dev_excerpts, load_log, variance_targets

    rows = [r for r in load_log(DEV_LOG) if r["detector"] == "llm"]
    targets = variance_targets(rows, dev_excerpts(BASELINE_RUN))
    assert targets[0].payload_id == "PI-021" and targets[0].kind == "poisoned"
    clean = [r for r in rows if r["kind"] == "clean"]
    top = max(r["score"] for r in clean)
    expected = [r["excerpt_id"] for r in clean if r["score"] == top][:3]  # ties: log order
    assert [t.excerpt_id for t in targets[1:]] == expected


def test_the_out_of_sample_set_is_every_logged_llmail_excerpt_and_every_fp_email(tmp_path):
    import json

    from evaluation.detector_eval import external_excerpts

    fp = tmp_path / "emails_for_fp_tests.json"
    fp.write_text(json.dumps(["Hi team, lunch at noon?", "Quarterly numbers attached."]))
    ex = external_excerpts(LLMAIL_RUN, fp)
    pos = [e for e in ex if e.kind == "poisoned"]
    neg = [e for e in ex if e.kind == "clean"]
    assert len(pos) == 50 and {e.source for e in pos} == {"llmail"}
    assert all(e.payload_id.startswith("PI-LM-") and "\n\n" in e.text for e in pos)
    assert [e.text for e in neg] == ["Hi team, lunch at noon?", "Quarterly numbers attached."]
    assert [e.excerpt_id for e in neg] == ["fp_email::000", "fp_email::001"]


def _rows(detector, version, pos_scores, neg_scores, source="dev"):
    return ([{"detector": detector, "version": version, "model": "m", "kind": "poisoned", "score": s,
              "error": None, "payload_id": f"PI-{i}", "family": "f", "gate_applicable": True,
              "excerpt_id": f"h+PI-{i}", "span": "", "source": source} for i, s in enumerate(pos_scores)]
            + [{"detector": detector, "version": version, "model": "m", "kind": "clean", "score": s,
                "error": None, "excerpt_id": f"c::{i}", "source": source} for i, s in enumerate(neg_scores)])


def test_the_out_of_sample_report_gives_both_thresholds_with_intervals(tmp_path):
    from evaluation.detector_eval import write_outofsample_report

    dev = _rows("llm", "detector-vX", [0.9, 0.95], [0.02, 0.05])
    ext = (_rows("llm", "detector-vX", [0.9, 0.3, 0.05], [0.0, 0.2, 0.6], "llmail")
           + _rows("keyword", "keyword-v1", [1.0, 0.0, 0.0], [0.0, 0.0, 0.0], "llmail"))
    md = write_outofsample_report(ext, dev, tmp_path / "detector-external-x.jsonl", tmp_path).read_text()
    assert "| 0.10 |" in md and "| 0.50 |" in md
    assert "(1/3)" in md and "(2/3)" in md  # FNR at 0.10 = 1/3; FPR at 0.10 = 2/3
    assert "a3deb58" in md  # names the pre-registration it was run under


def test_reports_say_perfect_separation_rather_than_an_auc_of_one(tmp_path):
    from evaluation.detector_eval import write_threshold_report

    rows = _rows("llm", "detector-vX", [0.9, 0.8, 0.95], [0.1, 0.0, 0.05])
    _, md = write_threshold_report(rows, tmp_path / "detector-x.jsonl", tmp_path)
    text = md.read_text()
    assert "perfect separation on dev (n = 6)" in text and "1.000" not in text


def test_the_llmail_report_gives_asr_both_ways():
    """Excluding the two agent errors (9/48), and counting them as attack successes (11/50)."""
    from scripts.llmail_report import build_report

    text = build_report(LLMAIL_RUN)
    assert "(9/48)" in text and "(11/50)" in text
