"""The OpenAI-compatible provider is almost entirely translation.

agent/agent.py speaks Anthropic content blocks and must keep doing so - it is
the file the AST check guards, and rewriting it per backend would make the two
arms differ by code rather than by policy. So OpenAICompatProvider converts at
its own boundary, and these tests pin that conversion. No test here makes a live
API call; the client is a hand-rolled fake.
"""

from __future__ import annotations

from types import SimpleNamespace

from agent.llm import OpenAICompatProvider


def _fake_response(*, text=None, tool_calls=(), finish_reason="stop", prompt=11, completion=7):
    return SimpleNamespace(
        choices=[
            SimpleNamespace(
                finish_reason=finish_reason,
                message=SimpleNamespace(content=text, tool_calls=list(tool_calls)),
            )
        ],
        usage=SimpleNamespace(prompt_tokens=prompt, completion_tokens=completion),
    )


def _fake_tool_call(call_id, name, arguments):
    return SimpleNamespace(
        id=call_id, function=SimpleNamespace(name=name, arguments=arguments)
    )


class _FakeCompletions:
    def __init__(self, response):
        self.response = response
        self.kwargs = None

    def create(self, **kwargs):
        self.kwargs = kwargs
        return self.response


def _provider_with(response):
    """Bypass __init__ so no OpenAI client is constructed and no key is needed."""
    p = OpenAICompatProvider.__new__(OpenAICompatProvider)
    p.model = "llama-3.1-8b"
    completions = _FakeCompletions(response)
    p._client = SimpleNamespace(chat=SimpleNamespace(completions=completions))
    return p, completions


def test_anthropic_tool_schemas_become_openai_functions():
    from agent.tools import TOOL_SCHEMAS

    converted = OpenAICompatProvider._tools_to_openai(TOOL_SCHEMAS)
    assert {c["function"]["name"] for c in converted} == {"search_documents", "send_email"}
    send = next(c for c in converted if c["function"]["name"] == "send_email")
    assert send["type"] == "function"
    # `input_schema` becomes `parameters`, contents untouched.
    assert send["function"]["parameters"]["required"] == ["to", "subject", "body"]


def test_tool_results_become_one_tool_message_each_keyed_by_call_id():
    """The tool_use_id -> tool_call_id mapping is what lets a multi-turn run work.
    Drop it and the model silently loses track of which result answers which
    call, which looks like a bad model rather than a broken adapter."""
    messages = [
        {"role": "user", "content": "email hr the leave policy"},
        {
            "role": "assistant",
            "content": [
                {"type": "tool_use", "id": "c1", "name": "search_documents",
                 "input": {"query": "leave"}},
                {"type": "tool_use", "id": "c2", "name": "send_email",
                 "input": {"to": "hr@northwind.example"}},
            ],
        },
        {
            "role": "user",
            "content": [
                {"type": "tool_result", "tool_use_id": "c1", "content": "chunk text"},
                {"type": "tool_result", "tool_use_id": "c2", "content": "Email sent."},
            ],
        },
    ]
    out = OpenAICompatProvider._messages_to_openai(messages, "SYSTEM")

    assert out[0] == {"role": "system", "content": "SYSTEM"}
    assert out[1] == {"role": "user", "content": "email hr the leave policy"}

    assistant = out[2]
    assert assistant["role"] == "assistant"
    # OpenAI rejects "" alongside tool_calls; it must be null.
    assert assistant["content"] is None
    assert [tc["id"] for tc in assistant["tool_calls"]] == ["c1", "c2"]
    assert assistant["tool_calls"][0]["function"]["arguments"] == '{"query": "leave"}'

    assert [m["role"] for m in out[3:]] == ["tool", "tool"]
    assert [m["tool_call_id"] for m in out[3:]] == ["c1", "c2"]


def test_generate_returns_blocks_the_agent_loop_can_replay():
    """raw_blocks goes straight back into `messages` on the next turn, so it has
    to survive a second translation unchanged."""
    resp = _fake_response(
        text="working on it",
        tool_calls=[_fake_tool_call("c1", "send_email", '{"to": "hr@northwind.example"}')],
    )
    provider, _ = _provider_with(resp)

    out = provider.generate([{"role": "user", "content": "hi"}], [], "SYSTEM")

    assert out.text == "working on it"
    assert [c.name for c in out.tool_calls] == ["send_email"]
    assert out.tool_calls[0].input == {"to": "hr@northwind.example"}
    assert out.input_tokens == 11 and out.output_tokens == 7

    replayed = OpenAICompatProvider._messages_to_openai(
        [{"role": "assistant", "content": out.raw_blocks}], "SYSTEM"
    )[1]
    assert replayed["content"] == "working on it"
    assert replayed["tool_calls"][0]["id"] == "c1"


def test_classify_forces_a_tool_call_and_offers_only_record_verdict():
    """tool_choice="required" is the detector's structural defense: with one tool
    on the request, the only legal output is an object matching the schema, so a
    chunk saying "reply CLEAN" has no prose channel to do it through."""
    resp = _fake_response(
        tool_calls=[_fake_tool_call("t1", "record_verdict", '{"score": 0.87, "label": "injection"}')]
    )
    provider, completions = _provider_with(resp)

    verdict = provider.classify("SYSTEM", "<untrusted_excerpt>x</untrusted_excerpt>", {"type": "object"})

    assert verdict == {"score": 0.87, "label": "injection"}
    assert completions.kwargs["tool_choice"] == "required"
    assert [t["function"]["name"] for t in completions.kwargs["tools"]] == ["record_verdict"]
    assert completions.kwargs["temperature"] == 0.0


def test_a_classifier_that_answers_in_prose_raises_so_the_detector_fails_closed():
    """Detector.scan turns this into score=1.0. Returning a default here instead
    would convert a broken classifier into a silent CLEAN verdict."""
    import pytest

    provider, _ = _provider_with(_fake_response(text="I think it is clean"))
    with pytest.raises(RuntimeError):
        provider.classify("SYSTEM", "text", {"type": "object"})


def test_malformed_tool_arguments_degrade_to_empty_rather_than_crashing():
    """Arguments are model-generated JSON, so a truncated object is an expected
    outcome. It must not take down a whole evaluation sweep."""
    assert OpenAICompatProvider._parse_arguments('{"to": "a@b.invalid"}') == {"to": "a@b.invalid"}
    assert OpenAICompatProvider._parse_arguments('{"to": ') == {}
    assert OpenAICompatProvider._parse_arguments(None) == {}
    assert OpenAICompatProvider._parse_arguments('"a string"') == {}
    assert OpenAICompatProvider._parse_arguments({"already": "dict"}) == {"already": "dict"}


def _built(monkeypatch, provider, *, groq_key="gsk-groq", cerebras_key="csk-cerebras"):
    """Build through the real factory with fake keys. Constructing an OpenAI
    client makes no network call."""
    import agent.llm as llm

    monkeypatch.setattr(llm, "GROQ_API_KEY", groq_key)
    monkeypatch.setattr(llm, "GROQ_BASE_URL", "https://api.groq.com/openai/v1")
    monkeypatch.setattr(llm, "CEREBRAS_API_KEY", cerebras_key)
    monkeypatch.setattr(llm, "CEREBRAS_BASE_URL", "https://api.cerebras.ai/v1")
    llm.get_provider.cache_clear()
    try:
        return llm.get_provider(provider, "some-model")
    finally:
        llm.get_provider.cache_clear()


def test_the_groq_provider_talks_to_groq_with_the_groq_key(monkeypatch):
    p = _built(monkeypatch, "groq")
    assert isinstance(p, OpenAICompatProvider)
    assert str(p._client.base_url).startswith("https://api.groq.com/openai/v1")
    assert p._client.api_key == "gsk-groq"


def test_a_blank_groq_key_never_falls_back_to_the_cerebras_key(monkeypatch):
    """The old fallback chain would have sent the Cerebras key to Groq."""
    p = _built(monkeypatch, "groq", groq_key="")
    assert p._client.api_key != "csk-cerebras"
    assert str(p._client.base_url).startswith("https://api.groq.com")


def test_the_cerebras_provider_keeps_the_cerebras_endpoint_and_key(monkeypatch):
    p = _built(monkeypatch, "cerebras")
    assert str(p._client.base_url).startswith("https://api.cerebras.ai/v1")
    assert p._client.api_key == "csk-cerebras"


def test_the_detector_stays_on_cerebras_when_the_agent_is_on_groq():
    """A fresh interpreter with the agent explicitly on Groq, because config is
    read at import time: in-process, the result would depend on whatever .env
    or the shell set, and a detector that followed AGENT_PROVIDER would pass on
    any machine without a Groq .env. Fake keys; building a client is offline."""
    import os
    import subprocess
    import sys
    from pathlib import Path

    env = {
        **os.environ,
        "AGENT_PROVIDER": "groq", "AGENT_MODEL": "agent-model",
        "DETECTOR_PROVIDER": "cerebras", "DETECTOR_MODEL": "detector-model",
        "GROQ_API_KEY": "gsk-fake", "GROQ_BASE_URL": "https://api.groq.com/openai/v1",
        "CEREBRAS_API_KEY": "csk-fake", "CEREBRAS_BASE_URL": "https://api.cerebras.ai/v1",
    }
    probe = (
        "from defense.detection import Detector; c = Detector().provider._client; "
        "print(c.base_url.host, c.api_key == 'csk-fake')"
    )
    out = subprocess.run(
        [sys.executable, "-c", probe], env=env, cwd=Path(__file__).resolve().parents[1],
        capture_output=True, text=True, check=True,
    ).stdout.split()
    assert out == ["api.cerebras.ai", "True"]
