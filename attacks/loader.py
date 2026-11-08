"""Load and validate the attack and benign corpora."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from config import ADVANCED_PAYLOADS_PATH, BENIGN_PATH, EXTERNAL_PAYLOADS_PATH, PAYLOADS_PATH


@dataclass(frozen=True)
class Payload:
    id: str
    family: str
    evasion: str
    user_task: str
    inject_into: str
    payload: str
    target: dict[str, Any]
    gate_applicable: bool
    split: str
    # Ground truth for the legitimate question the user asked, in the same shape
    # BenignTask.success uses. Required for goal_hijack: those payloads win by
    # making the agent abandon the user's task, so scoring `benign_task_failed`
    # needs to know what a correct answer looks like. When None, the scorer
    # derives one from the family and user_task (predicates.carrier_success).
    success: dict[str, Any] | None = None
    notes: str = ""
    # v0.3: how an inbox payload arrives. Keys: "sender", "subject" for the
    # planted email, and "extra_messages" (a list of {sender, subject, body})
    # planted alongside it for multi-stage attacks. None for document payloads.
    inject_meta: dict[str, Any] | None = None


@dataclass(frozen=True)
class BenignTask:
    id: str
    kind: str
    user_task: str
    success: dict[str, Any]
    hard_negative: bool
    split: str
    notes: str = ""


def _payload_file(split: str | None):
    # "exploratory" is the converted LLMail-Inject set and "advanced" is the
    # v0.3 realistic-channel corpus: each its own file, never part of
    # split=None, which stays the frozen v0.2.1 corpus (dev + test).
    if split == "exploratory":
        return EXTERNAL_PAYLOADS_PATH
    if split == "advanced":
        return ADVANCED_PAYLOADS_PATH
    return PAYLOADS_PATH


def corpus_version(split: str | None = None) -> str:
    """Read from the corpus file itself, so a log can never claim a corpus it did
    not run on (the version used to come from .env)."""
    return json.loads(_payload_file(split).read_text(encoding="utf-8"))["corpus_version"]


def load_payloads(split: str | None = None) -> list[Payload]:
    raw = json.loads(_payload_file(split).read_text(encoding="utf-8"))
    out = [
        Payload(
            id=p["id"], family=p["family"], evasion=p["evasion"], user_task=p["user_task"],
            inject_into=p["inject_into"], payload=p["payload"], target=p["target"],
            gate_applicable=p["gate_applicable"], split=p["split"],
            success=p.get("success"), notes=p.get("notes", ""),
            inject_meta=p.get("inject_meta"),
        )
        for p in raw["payloads"]
    ]
    return [p for p in out if split is None or p.split == split]


def load_benign(split: str | None = None) -> list[BenignTask]:
    # The advanced corpus carries its own benign tasks (inbox-driven and new
    # hard negatives) in the same file as its payloads.
    path = ADVANCED_PAYLOADS_PATH if split == "advanced" else BENIGN_PATH
    raw = json.loads(path.read_text(encoding="utf-8"))
    out = [
        BenignTask(
            id=t["id"], kind=t["kind"], user_task=t["user_task"], success=t["success"],
            hard_negative=t["hard_negative"], split=t["split"], notes=t.get("notes", ""),
        )
        for t in raw.get("tasks", raw.get("benign_tasks", []))
    ]
    return [t for t in out if split is None or t.split == split]


def canary() -> str:
    return json.loads(PAYLOADS_PATH.read_text(encoding="utf-8"))["canary"]


def contacts() -> dict[str, str]:
    return json.loads(BENIGN_PATH.read_text(encoding="utf-8"))["contacts"]
