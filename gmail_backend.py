"""Gmail backend — DEMO ONLY. Never used by the evaluation harness.

The whole evaluation (cli.py eval, eval-live, every log under logs/) runs on the
in-memory MailSink. This module exists so the Mailbox UI can be shown against a
real inbox once, on a throwaway Google account, for the presentation.

Containment, in order of what stops an escaped payload:
  1. An allow-list. Every address in To/CC/BCC must be on GMAIL_ALLOWED_RECIPIENTS
     (comma-separated, from .env). An address not on the list is NOT silently
     dropped — the whole send is refused, so the Mailbox shows the refusal. This
     holds in every condition, including "defenses off": the demo's undefended
     mode shows the attacker's address in the proposed email, it never delivers to it.
  2. The OAuth token is for one throwaway account; its credentials live in
     .secrets/ (git-ignored) and are never read by anything but this module.
  3. Everything sent is also kept in `outbox`, like MailSink, so the UI and the
     security notice work unchanged.

Scopes: gmail.send (send) and gmail.readonly (read the inbox for `read_inbox`).
"""

from __future__ import annotations

import base64
import logging
import os
import re
from email.message import EmailMessage
from pathlib import Path

from mailsink import MailBackend, SentMessage

_log = logging.getLogger(__name__)

SCOPES = ["https://www.googleapis.com/auth/gmail.send", "https://www.googleapis.com/auth/gmail.readonly"]
SECRETS = Path(__file__).resolve().parent / ".secrets"
CREDENTIALS = SECRETS / "credentials.json"
TOKEN = SECRETS / "token.json"

_ADDR = re.compile(r"[A-Za-z0-9._%+\-']+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")


class RecipientNotAllowed(PermissionError):
    """Raised for ANY recipient outside the allow-list. The send does not happen."""


def directory_map() -> dict[str, str]:
    """GMAIL_DIRECTORY = "sara.khan=someone@gmail.com,manager=other@gmail.com" -
    which real mailbox plays each Northwind colleague in the demo. The key is
    the local part (or role) of the fictional address. Demo only."""
    raw = os.getenv("GMAIL_DIRECTORY", "")
    out: dict[str, str] = {}
    for pair in raw.split(","):
        if "=" in pair:
            k, v = pair.split("=", 1)
            if k.strip() and v.strip():
                out[k.strip().lower()] = v.strip().lower()
    return out


def allowed_recipients() -> frozenset[str]:
    raw = os.getenv("GMAIL_ALLOWED_RECIPIENTS", "")
    return frozenset(a.strip().lower() for a in raw.split(",") if a.strip())


def _addresses(*fields: str | None) -> list[str]:
    out: list[str] = []
    for f in fields:
        if f:
            out.extend(a.lower() for a in _ADDR.findall(f))
    return out


def check_allowed(to: str, cc: str | None = None, bcc: str | None = None) -> None:
    """Pure function, unit-tested: refuses if any recipient is off-list or if the list is empty."""
    allow = allowed_recipients()
    if not allow:
        raise RecipientNotAllowed("GMAIL_ALLOWED_RECIPIENTS is empty: the Gmail backend refuses every send.")
    bad = sorted(set(a for a in _addresses(to, cc, bcc) if a not in allow))
    if bad:
        raise RecipientNotAllowed(
            "Gmail demo backend refused to send: recipient(s) not on the allow-list: " + ", ".join(bad)
        )
    if not _addresses(to):
        raise RecipientNotAllowed("Gmail demo backend refused to send: no valid To address.")


class GmailBackend(MailBackend):
    """Real sends through the Gmail API, caged by the allow-list above."""

    def __init__(self) -> None:
        self.outbox: list[SentMessage] = []
        self._service = None
        self.address: str | None = None

    # ── auth ──
    def _svc(self):
        if self._service is not None:
            return self._service
        from google.auth.transport.requests import Request
        from google.oauth2.credentials import Credentials
        from google_auth_oauthlib.flow import InstalledAppFlow
        from googleapiclient.discovery import build

        creds = None
        if TOKEN.exists():
            creds = Credentials.from_authorized_user_file(str(TOKEN), SCOPES)
        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(Request())
            else:
                if not CREDENTIALS.exists():
                    raise FileNotFoundError(f"Put the OAuth client file at {CREDENTIALS}")
                flow = InstalledAppFlow.from_client_secrets_file(str(CREDENTIALS), SCOPES)
                creds = flow.run_local_server(port=0, open_browser=True)   # user signs in; we never see the password
            SECRETS.mkdir(exist_ok=True)
            TOKEN.write_text(creds.to_json(), encoding="utf-8")
            os.chmod(TOKEN, 0o600)
        self._service = build("gmail", "v1", credentials=creds, cache_discovery=False)
        self.address = self._service.users().getProfile(userId="me").execute().get("emailAddress")
        _log.info("Gmail backend signed in as %s", self.address)
        return self._service

    # ── MailBackend ──
    def send(self, to: str, subject: str, body: str, cc: str | None = None, bcc: str | None = None) -> SentMessage:
        check_allowed(to, cc, bcc)            # the cage: before any network call
        svc = self._svc()
        msg = EmailMessage()
        msg["To"] = to
        if cc: msg["Cc"] = cc
        if bcc: msg["Bcc"] = bcc
        msg["Subject"] = subject
        msg["From"] = self.address or "me"
        msg.set_content(body)
        raw = base64.urlsafe_b64encode(msg.as_bytes()).decode()
        svc.users().messages().send(userId="me", body={"raw": raw}).execute()
        sent = SentMessage(to=to, subject=subject, body=body, cc=cc, bcc=bcc)
        self.outbox.append(sent)
        _log.info("Gmail sent to=%s cc=%s bcc=%s subject=%s", to, cc, bcc, subject)
        return sent

    def clear(self) -> None:
        self.outbox.clear()

    # ── inbox (for read_inbox) ──
    def fetch_inbox(self, limit: int = 10) -> list[dict]:
        """Newest `limit` messages in INBOX as {sender, subject, body, date, gmail_id}."""
        svc = self._svc()
        ids = svc.users().messages().list(userId="me", labelIds=["INBOX"], maxResults=limit).execute().get("messages", [])
        out = []
        for m in ids:
            full = svc.users().messages().get(userId="me", id=m["id"], format="full").execute()
            headers = {h["name"].lower(): h["value"] for h in full["payload"].get("headers", [])}
            out.append({
                "gmail_id": m["id"],
                "sender": headers.get("from", ""),
                "subject": headers.get("subject", "(no subject)"),
                "date": headers.get("date", ""),
                "body": _plain_body(full["payload"]) or full.get("snippet", ""),
            })
        return out


def _plain_body(payload: dict) -> str:
    """text/plain part if present, else stripped text/html, else ''."""
    def walk(p):
        mime = p.get("mimeType", "")
        data = (p.get("body") or {}).get("data")
        if data and mime in ("text/plain", "text/html"):
            yield mime, base64.urlsafe_b64decode(data + "===").decode("utf-8", "replace")
        for part in p.get("parts", []) or []:
            yield from walk(part)
    parts = list(walk(payload))
    for mime, text in parts:
        if mime == "text/plain":
            return text
    for mime, text in parts:
        if mime == "text/html":
            return re.sub(r"<[^>]+>", "", text)
    return ""
