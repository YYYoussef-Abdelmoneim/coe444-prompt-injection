"""Framework pieces the prevention gate builds on.

The gate's own behaviour is specified in tests/spec/test_prevention_spec.py
(make spec-prevention); those tests fail against the starter stub by design.
What stays here must hold whoever writes the gate.
"""

from __future__ import annotations

from schema import FieldClass


def test_unclassified_argument_defaults_to_control():
    from agent.tools import field_class

    assert field_class("send_email", "reply_to") is FieldClass.CONTROL
    assert field_class("send_email", "body") is FieldClass.CONTENT


def test_the_tool_schema_says_which_fields_cannot_be_emptied():
    """`to` is required, so a gate cannot repair an email by emptying it."""
    from agent.tools import is_required

    assert is_required("send_email", "to")
    assert not is_required("send_email", "cc") and not is_required("send_email", "bcc")
    assert is_required("some_unknown_tool", "anything")  # unknown tools fail closed


def test_the_starter_gate_keeps_the_interface_the_harness_calls(chunk):
    """Runner, CLI and Mailbox all call evaluate_all and read one decision per call."""
    from defense.prevention import ProvenanceGate
    from schema import ToolCall

    calls = [ToolCall("c1", "send_email", {"to": "a@b.example"}), ToolCall("c2", "search_documents", {"query": "q"})]
    decisions = ProvenanceGate(contacts=frozenset({"A@B.example"})).evaluate_all(calls, "hi", [chunk()])
    assert [d.call_id for d in decisions] == ["c1", "c2"]
