"""A cross-vendor comparison detector: Meta Llama Prompt Guard 2 (86M) via Groq.

WHY
Limitation 6 in METHODOLOGY: the agent (gpt-oss-20b) and our detector
(gpt-oss-120b) share a training lineage, so their failures may be correlated
and the detector's recall optimistic. The instructor-facing answer is a
measurement, not a sentence. Prompt Guard 2 is a purpose-built injection
classifier trained by a different vendor (Meta) on a different objective; it
is free on Groq and returns a probability as its text, so it drops into the
same Detector interface and the same excerpt sets with no new scoring code.

WHAT IT IS NOT
A replacement for detector-v3a. It is a second arm scored on the same excerpts
(dev 36, out-of-sample 253) so the two can be compared per excerpt, paired.
It never imports defense/prevention.py and is never used by the runners.
"""

from __future__ import annotations

import logging
import time

from agent.llm import QuotaExhausted, get_provider
from config import GROQ_API_KEY
from schema import DetectionResult, TaggedChunk

_log = logging.getLogger(__name__)

PROMPTGUARD_VERSION = "promptguard2-86m"
MODEL = "meta-llama/llama-prompt-guard-2-86m"


class PromptGuardDetector:
    """Classification only: no system prompt, no tool call, the model's text is
    the probability that the input is a prompt injection."""

    implemented = True

    def __init__(self, provider=None, model: str = MODEL) -> None:
        self.model = model
        self._provider = provider

    @property
    def provider(self):
        if self._provider is None:
            if not GROQ_API_KEY:
                raise RuntimeError("GROQ_API_KEY is required for the Prompt Guard arm")
            self._provider = get_provider("groq", self.model)
        return self._provider

    def scan(self, chunk: TaggedChunk) -> DetectionResult:
        started = time.monotonic()
        try:
            # Direct call: the model emits one number and caps max_tokens at
            # 512, so the agent provider's defaults (2048) are rejected.
            resp = self.provider._create(
                model=self.model,
                messages=[{"role": "user", "content": chunk.text}],
                max_tokens=8,
                temperature=0.0,
            )
            text = (resp.choices[0].message.content or "").strip()
            score = float(text)
            if not 0.0 <= score <= 1.0:
                raise ValueError(f"score {score!r} outside [0, 1]")
        except QuotaExhausted:
            raise
        except Exception as exc:  # noqa: BLE001 - fail closed like the main detector
            _log.warning("Prompt Guard failed on %s: %s", chunk.chunk_id, exc)
            return DetectionResult(chunk.chunk_id, 1.0, "injection", _ms(started), self.model,
                                   error=f"{type(exc).__name__}: {exc}")
        return DetectionResult(chunk.chunk_id, score, "injection" if score >= 0.5 else "clean",
                               _ms(started), self.model)

    def scan_all(self, chunks: list[TaggedChunk]) -> list[DetectionResult]:
        return [self.scan(c) for c in chunks]


def _ms(started: float) -> int:
    return int((time.monotonic() - started) * 1000)
