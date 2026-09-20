"""Shared fakes. No test in this suite makes a live API call."""

from __future__ import annotations

import pytest

from schema import Origin, TaggedChunk


class FakeProvider:
    """Returns scripted responses. Records what it was asked."""

    def __init__(self, responses=None, verdicts=None):
        self.responses = list(responses or [])
        self.verdicts = list(verdicts or [])
        self.classify_calls = []

    def generate(self, messages, tools, system):
        from agent.llm import LLMResponse

        return self.responses.pop(0) if self.responses else LLMResponse(text="done")

    def classify(self, system, user_text, schema):
        self.classify_calls.append(user_text)
        return self.verdicts.pop(0) if self.verdicts else {
            "injection_probability": 0.0, "rationale": "clean"
        }


@pytest.fixture
def chunk():
    def make(text="Annual leave is 22 days.", chunk_id="doc::0", poisoned=False):
        return TaggedChunk(
            chunk_id=chunk_id, document_id="doc", text=text,
            origin=Origin.EXTERNAL, similarity=0.9, is_poisoned=poisoned,
        )
    return make
