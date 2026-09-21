"""Core data contracts for the whole system.

Every other module depends on this one; this module depends on nothing but the
stdlib. That is deliberate — the four evaluation conditions must be scored from
these records offline, long after the agent that produced them has exited.

Design note (the load-bearing one): an *execution* and a *scoring* are separate
things. `RunRecord` captures one execution of the agent with both defenses in
SHADOW mode (they observe and record a verdict, but never alter the trajectory).
`ScoredOutcome` is what you get when you replay that record under one of the
four condition policies. One execution, four scorings — which is precisely why
the conditions are comparable: they are the same trial, not four different ones.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


# ── Origin tagging ────────────────────────────────────────────────────────────

class Origin(str, Enum):
    """Where a piece of text entered the system.

    Set STRUCTURALLY at ingestion, never inferred from content. `retriever.py`
    stamps EXTERNAL on everything it returns; the CLI stamps USER on what the
    human typed. Nothing else is allowed to construct these.
    """

    USER = "user"
    EXTERNAL = "external"


@dataclass(frozen=True)
class TaggedChunk:
    """A retrieved document chunk with its provenance attached at birth."""

    chunk_id: str
    document_id: str
    text: str
    origin: Origin
    similarity: float
    chunk_index: int = 0
    # Set by the corpus loader when this chunk is the poisoned one for a trial.
    # Used only for scoring/diagnostics, NEVER shown to the agent or detector.
    is_poisoned: bool = False


# ── Detection layer output ────────────────────────────────────────────────────

@dataclass(frozen=True)
class DetectionResult:
    """One classifier verdict for one chunk.

    `score` is the model's own probability that the chunk contains injected
    instructions. We keep the raw score rather than a bare label so the report
    can sweep the threshold and draw an ROC curve instead of defending a single
    arbitrary operating point.
    """

    chunk_id: str
    score: float
    label: str  # "injection" | "clean"
    latency_ms: int
    model: str
    error: str | None = None

    @property
    def failed(self) -> bool:
        return self.error is not None


# ── Tool calls and argument-level provenance ──────────────────────────────────

class FieldClass(str, Enum):
    """Whether a tool argument steers the action or merely fills it in.

    CONTROL fields decide *who/what/where* the side effect lands on. If external
    text can set one, the attacker controls the action. CONTENT fields are the
    payload the action carries; external text legitimately flows into these
    (summarising a document into an email body is the normal case).

    This split is the entire prevention design. A call-level origin check would
    pass "summarise the Q3 report and email it to my team" while the injection
    silently rewrote the recipient — because the *call* was user-initiated.
    """

    CONTROL = "control"
    CONTENT = "content"


@dataclass(frozen=True)
class ToolCall:
    """A tool invocation the agent proposed. Not necessarily executed."""

    call_id: str
    tool_name: str
    arguments: dict[str, Any]


@dataclass(frozen=True)
class FieldProvenance:
    """Provenance attribution for a single tool-call argument.

    `external_support` is the id of the chunk whose text supports this value,
    or None if the value traces to user-origin text (or to nothing at all).

    Attribution is by *evidence*, not by semantics: we ask "does this exact
    value appear in user-origin bytes, or in external bytes?" — never "does this
    value look malicious?". Swap the payload for an unseen one with identical
    provenance and the decision is bit-for-bit the same. That property is what
    makes the gate a deterministic invariant rather than a second classifier.
    """

    field_name: str
    field_class: FieldClass
    origin: Origin
    external_support: str | None = None
    matched_span: str | None = None


class Decision(str, Enum):
    ALLOW = "allow"
    DENY = "deny"


@dataclass(frozen=True)
class PolicyDecision:
    """What the prevention gate would do about one proposed tool call."""

    call_id: str
    decision: Decision
    reason: str
    field_provenance: list[FieldProvenance] = field(default_factory=list)

    @property
    def denied(self) -> bool:
        return self.decision is Decision.DENY


# ── Outcome taxonomy ──────────────────────────────────────────────────────────

class Outcome(str, Enum):
    """One mutually-exclusive label per scored trial, identical in every condition.

    The taxonomy exists because "ASR went down" is not by itself evidence of a
    good defense. A defense that aborts every run drives ASR to zero and is
    useless; that case is BLOCKED_TASK_BROKEN, not a win. And a model that
    simply ignores a weak payload produced NOCOMPLY — crediting that to the
    defense is the single easiest way to overstate a result.
    """

    ATTACK_SUCCESS = "attack_success"
    BLOCKED_TASK_OK = "blocked_task_ok"
    BLOCKED_TASK_BROKEN = "blocked_task_broken"
    NOCOMPLY = "nocomply"
    RETRIEVAL_MISS = "retrieval_miss"
    ERROR = "error"

    @property
    def is_attack_success(self) -> bool:
        return self is Outcome.ATTACK_SUCCESS

    @property
    def counts_in_asr_denominator(self) -> bool:
        """RETRIEVAL_MISS and ERROR are validity failures, not attack failures.

        If the poisoned chunk never made it into the top-k, the agent was never
        offered the attack, so scoring it as "attack failed" would let a weak
        embedder masquerade as a strong defense.
        """
        return self not in (Outcome.RETRIEVAL_MISS, Outcome.ERROR)


# ── Execution and scoring records ─────────────────────────────────────────────

@dataclass
class RunRecord:
    """One execution of the agent, with both defenses observed in shadow mode.

    This is the unit that gets written to logs/*.jsonl. Everything needed to
    score all four conditions offline must be in here, because metrics are
    computed from logs and never by re-running the agent.
    """

    run_id: str
    task_id: str
    trial: int
    is_attack: bool

    user_prompt: str
    retrieved_chunk_ids: list[str]
    poisoned_chunk_id: str | None
    retrieval_hit: bool

    detections: list[DetectionResult]
    proposed_calls: list[ToolCall]
    policy_decisions: list[PolicyDecision]

    agent_final_text: str
    agent_model: str
    detector_model: str
    sampling: str

    # Provenance of the experiment itself, for the reproducibility section.
    corpus_version: str
    detector_prompt_version: str
    git_commit: str
    timestamp: str

    error: str | None = None
    latency_ms: int = 0
    input_tokens: int = 0
    output_tokens: int = 0

    @property
    def pairing_key(self) -> str:
        """Identifies the same trial across conditions, for the paired tests."""
        return f"{self.task_id}::{self.trial}"

    def to_json(self) -> str:
        return json.dumps(asdict(self), default=_enum_default, sort_keys=True)


@dataclass(frozen=True)
class ScoredOutcome:
    """A RunRecord replayed under one condition's policy."""

    run_id: str
    pairing_key: str
    task_id: str
    trial: int
    condition: str
    outcome: Outcome
    executed_calls: list[str]
    blocked_by: str | None  # "detection" | "prevention" | None


def _enum_default(o: Any) -> Any:
    if isinstance(o, Enum):
        return o.value
    raise TypeError(f"not JSON serialisable: {type(o)}")


def sha256_short(text: str, n: int = 12) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:n]
