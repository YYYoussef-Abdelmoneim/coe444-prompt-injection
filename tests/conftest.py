"""Shared fakes. No test in this suite makes a live API call."""

from __future__ import annotations

import copy
from pathlib import Path

import pytest

from schema import Origin, TaggedChunk

_SPEC_DIR = Path(__file__).parent / "spec"
_CLEAN = {"score": 0.0, "label": "clean"}


def pytest_addoption(parser):
    parser.addoption(
        "--spec", action="store_true", default=False,
        help="run the defense requirement tests in tests/spec/",
    )


def pytest_collection_modifyitems(config, items):
    # The specs describe defenses the team has not built yet, so against the
    # starter stubs they fail by design. Skipped unless asked for, so
    # `make test` stays a green check of the framework itself.
    if config.getoption("--spec", default=False):
        return
    skip = pytest.mark.skip(reason="defense spec: run make spec-detection / make spec-prevention")
    for item in items:
        if _SPEC_DIR in Path(item.path).parents:
            item.add_marker(skip)


class FakeProvider:
    """Returns scripted responses. Records what it was asked.

    `verdicts` are returned by classify() in order; once they run out, every
    call gets `default_verdict`. A spec passes a malformed default_verdict to
    stand in for a model that keeps giving the same bad answer, so a detector
    that retries still sees it.
    """

    def __init__(self, responses=None, verdicts=None, default_verdict=_CLEAN):
        self.responses = list(responses or [])
        self.verdicts = list(verdicts or [])
        self.default_verdict = default_verdict
        self.classify_calls = []
        self.classify_systems = []

    def generate(self, messages, tools, system):
        from agent.llm import LLMResponse

        return self.responses.pop(0) if self.responses else LLMResponse(text="done")

    def classify(self, system, user_text, schema):
        self.classify_calls.append(user_text)
        self.classify_systems.append(system)
        if self.verdicts:
            return self.verdicts.pop(0)
        # A copy, so a detector that mutates its answer cannot change the next one.
        return copy.deepcopy(self.default_verdict)


@pytest.fixture
def chunk():
    def make(text="Annual leave is 22 days.", chunk_id="doc::0", poisoned=False):
        return TaggedChunk(
            chunk_id=chunk_id, document_id="doc", text=text,
            origin=Origin.EXTERNAL, similarity=0.9, is_poisoned=poisoned,
        )
    return make
