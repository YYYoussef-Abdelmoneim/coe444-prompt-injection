"""The held-out test split cannot be opened by accident.

CLAUDE.md: the test split stays unopened until the final evaluation run. These
tests never read it either: the web checks spy on the loader's `split` argument,
and every id used here is a dev id or one that exists nowhere.
"""

from __future__ import annotations

import argparse

import pytest


def test_eval_defaults_to_the_dev_split():
    from cli import build_parser

    assert build_parser().parse_args(["eval"]).split == "dev"


def _eval_args(**overrides) -> argparse.Namespace:
    from cli import build_parser

    args = build_parser().parse_args(["eval"])
    for k, v in overrides.items():
        setattr(args, k, v)
    return args


def _no_runner(monkeypatch):
    import evaluation.runner

    def boom(*a, **k):
        raise AssertionError("a Runner was built, so API calls could have started")

    monkeypatch.setattr(evaluation.runner, "Runner", boom)


def test_the_test_split_needs_the_final_flag(monkeypatch):
    from cli import cmd_eval

    _no_runner(monkeypatch)
    assert cmd_eval(_eval_args(split="test")) != 0


def test_only_takes_dev_ids(monkeypatch):
    from cli import cmd_eval

    _no_runner(monkeypatch)
    assert cmd_eval(_eval_args(only="PI-101,PI-NOT-A-DEV-ID")) != 0


def test_demo_refuses_an_id_outside_the_dev_split(monkeypatch):
    from cli import cmd_demo

    _no_runner(monkeypatch)
    assert cmd_demo(argparse.Namespace(payload_id="PI-NOT-A-DEV-ID")) != 0


def test_the_baseline_probe_only_runs_on_dev():
    import inspect

    from scripts import baseline_probe

    assert inspect.signature(baseline_probe.main).parameters["split"].default == "dev"
    with pytest.raises(SystemExit):
        baseline_probe.main(1, "test")


@pytest.fixture
def loader_spy(monkeypatch):
    """Replaces the corpus loaders with spies that record the split asked for."""
    import attacks.loader

    asked: list[object] = []

    def spy(split=None):
        asked.append(split)
        return []

    monkeypatch.setattr(attacks.loader, "load_payloads", spy)
    monkeypatch.setattr(attacks.loader, "load_benign", spy)
    return asked


def test_the_web_api_lists_only_dev_payloads_and_tasks(loader_spy):
    from interface.app import app

    client = app.test_client()
    assert client.get("/api/payloads").status_code == 200
    assert client.get("/api/benign").status_code == 200
    assert loader_spy == ["dev", "dev"]


def test_the_mailbox_verdict_looks_up_dev_payloads_only(loader_spy):
    from interface.app import _judge

    _judge("PI-101", {"sent": [], "reply": ""})
    assert loader_spy == ["dev"]
