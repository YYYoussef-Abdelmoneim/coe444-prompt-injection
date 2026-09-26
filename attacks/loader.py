"""Load and validate the attack and benign corpora."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from config import BENIGN_PATH, PAYLOADS_PATH


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


@dataclass(frozen=True)
class BenignTask:
    id: str
    kind: str
    user_task: str
    success: dict[str, Any]
    hard_negative: bool
    split: str
    notes: str = ""


def load_payloads(split: str | None = None) -> list[Payload]:
    raw = json.loads(PAYLOADS_PATH.read_text(encoding="utf-8"))
    out = [
        Payload(
            id=p["id"], family=p["family"], evasion=p["evasion"], user_task=p["user_task"],
            inject_into=p["inject_into"], payload=p["payload"], target=p["target"],
            gate_applicable=p["gate_applicable"], split=p["split"],
            success=p.get("success"), notes=p.get("notes", ""),
        )
        for p in raw["payloads"]
    ]
    return [p for p in out if split is None or p.split == split]


def load_benign(split: str | None = None) -> list[BenignTask]:
    raw = json.loads(BENIGN_PATH.read_text(encoding="utf-8"))
    out = [
        BenignTask(
            id=t["id"], kind=t["kind"], user_task=t["user_task"], success=t["success"],
            hard_negative=t["hard_negative"], split=t["split"], notes=t.get("notes", ""),
        )
        for t in raw["tasks"]
    ]
    return [t for t in out if split is None or t.split == split]


def canary() -> str:
    return json.loads(PAYLOADS_PATH.read_text(encoding="utf-8"))["canary"]


def contacts() -> dict[str, str]:
    return json.loads(BENIGN_PATH.read_text(encoding="utf-8"))["contacts"]
