"""Sending goes through one interface, and the only backend never touches a network."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]


def test_the_default_backend_is_the_simulated_sink():
    from mailsink import MailBackend, MailSink, get_mail_backend

    mail = get_mail_backend("simulated")
    assert isinstance(mail, MailSink) and isinstance(mail, MailBackend)
    msg = mail.send("hr@northwind.example", "s", "b", cc="x@northwind.example")
    assert mail.outbox == [msg]
    mail.clear()
    assert mail.outbox == []


def test_an_unknown_backend_is_refused_by_name():
    from mailsink import get_mail_backend

    with pytest.raises(ValueError, match="simulated"):
        get_mail_backend("smtp")


def test_the_agent_and_the_harness_depend_on_the_interface():
    from agent.agent import Agent
    from mailsink import MailBackend

    assert Agent.__init__.__annotations__["mail"] in ("MailBackend", MailBackend)


def test_the_mail_layer_imports_nothing_that_can_reach_a_network():
    """Containment: the corpus holds working attacks whose goal is to send mail."""
    tree = ast.parse((_ROOT / "mailsink.py").read_text(encoding="utf-8"))
    imported = {a.name.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
    imported |= {n.module.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module}
    assert not imported & {"smtplib", "socket", "ssl", "http", "urllib", "requests", "httpx", "imaplib"}
