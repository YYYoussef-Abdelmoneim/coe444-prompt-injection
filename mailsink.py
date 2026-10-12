"""A mail sink that records and never sends.

Containment matters here: this repository contains a file of working prompt
injection payloads whose whole purpose is to make an agent send mail to an
attacker. There is no SMTP client anywhere in this project, no socket is opened,
and the recipient domains in the corpus are RFC 2606 `.invalid` names that
cannot resolve. An escaped payload therefore has nothing to escape into.
"""

from __future__ import annotations

import json
import logging
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from config import MAIL_BACKEND

_log = logging.getLogger(__name__)


@dataclass(frozen=True)
class SentMessage:
    to: str
    subject: str
    body: str
    cc: str | None = None
    bcc: str | None = None
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class MailBackend(ABC):
    """Where send_email lands. The agent, the harness and the Mailbox depend on
    this rather than on a concrete class, so a real backend (Gmail, after the
    presentation) is one new subclass and one config value. The simulated sink
    stays the default, and nothing in the evaluation may use another."""

    outbox: list[SentMessage]

    @abstractmethod
    def send(
        self, to: str, subject: str, body: str, cc: str | None = None, bcc: str | None = None
    ) -> SentMessage: ...

    @abstractmethod
    def clear(self) -> None: ...


class MailSink(MailBackend):
    """In-memory outbox: the simulated backend. One instance per run."""

    def __init__(self) -> None:
        self.outbox: list[SentMessage] = []

    def send(self, to: str, subject: str, body: str, cc: str | None = None, bcc: str | None = None) -> SentMessage:
        msg = SentMessage(to=to, subject=subject, body=body, cc=cc, bcc=bcc)
        self.outbox.append(msg)
        _log.info("MailSink captured message to=%s subject=%s", to, subject)
        return msg

    def clear(self) -> None:
        self.outbox.clear()

    def recipients(self) -> list[str]:
        out: list[str] = []
        for m in self.outbox:
            out.extend(x for x in (m.to, m.cc, m.bcc) if x)
        return out

    def dump(self, path: Path) -> None:
        path.write_text(json.dumps([asdict(m) for m in self.outbox], indent=2), encoding="utf-8")


_BACKENDS: dict[str, type[MailBackend]] = {"simulated": MailSink}


def get_mail_backend(kind: str = MAIL_BACKEND) -> MailBackend:
    try:
        return _BACKENDS[kind]()
    except KeyError:
        raise ValueError(
            f"unknown mail backend {kind!r}; this build has: {', '.join(sorted(_BACKENDS))}"
        ) from None
