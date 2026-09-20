"""A deliberately dumb keyword detector.

This exists to keep the LLM classifier honest. If a 20-line regex matches the
Llama/Claude classifier's recall on the corpus, the "LLM meta-classifier"
contribution collapses, and the report needs to say so. Reporting the LLM
detector without a trivial comparator is the most common way a result of this
shape gets overstated.
"""

from __future__ import annotations

import re
import time

from schema import DetectionResult, TaggedChunk

BASELINE_VERSION = "keyword-v1"

_PATTERNS = [
    r"ignore (all |any |your |previous |prior )*(instructions|rules|guidelines)",
    r"disregard (all |any |the |your )*(above|previous|prior|instructions)",
    r"you are now",
    r"new (instruction|task|directive|system prompt)",
    r"system\s*[:>]",
    r"\bAI\s+(assistant|agent)\b.*\b(must|should|now)\b",
    r"do not (tell|inform|mention|alert) the user",
    r"forward (all|any|the) ",
    r"send (an? )?email to\b",
]
_RX = [re.compile(p, re.IGNORECASE) for p in _PATTERNS]


class KeywordDetector:
    model = BASELINE_VERSION

    def scan(self, chunk: TaggedChunk) -> DetectionResult:
        started = time.monotonic()
        hits = sum(1 for rx in _RX if rx.search(chunk.text))
        score = min(1.0, hits / 2.0)
        return DetectionResult(
            chunk_id=chunk.chunk_id,
            score=score,
            label="injection" if score >= 0.5 else "clean",
            latency_ms=int((time.monotonic() - started) * 1000),
            model=BASELINE_VERSION,
        )

    def scan_all(self, chunks: list[TaggedChunk]) -> list[DetectionResult]:
        return [self.scan(c) for c in chunks]
