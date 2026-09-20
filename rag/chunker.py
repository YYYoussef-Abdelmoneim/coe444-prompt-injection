"""Document chunking. Pure functions, no I/O, no model — so it is trivially testable."""

from __future__ import annotations

import re
from pathlib import Path

from config import MAX_CHUNK_CHARS, MIN_CHUNK_CHARS, OVERLAP_CHARS

_HEADING = re.compile(r"^#{1,6}\s+.*$", re.MULTILINE)


def canonical_document_id(path: Path) -> str:
    """Filename normalised into a stable, dedupe-safe id."""
    return re.sub(r"[^a-z0-9]+", "_", path.stem.lower()).strip("_")


def chunk_document(text: str, document_id: str) -> list[tuple[str, str]]:
    """Split into (chunk_id, chunk_text). Sections first, size-capped fallback.

    Splitting on headings keeps an injected paragraph inside one chunk most of
    the time. That matters: a payload split across a chunk boundary is a
    genuinely harder detection case, and we want it to be a deliberate attack
    variant rather than an accident of the chunker.
    """
    sections = _split_sections(text)
    chunks: list[str] = []
    for section in sections:
        section = section.strip()
        if len(section) <= MAX_CHUNK_CHARS:
            if len(section) >= MIN_CHUNK_CHARS:
                chunks.append(section)
            continue
        start = 0
        while start < len(section):
            piece = section[start : start + MAX_CHUNK_CHARS]
            if len(piece) >= MIN_CHUNK_CHARS:
                chunks.append(piece.strip())
            start += MAX_CHUNK_CHARS - OVERLAP_CHARS
    return [(f"{document_id}::{i}", c) for i, c in enumerate(chunks)]


def _split_sections(text: str) -> list[str]:
    positions = [m.start() for m in _HEADING.finditer(text)]
    if not positions:
        return [text]
    if positions[0] != 0:
        positions.insert(0, 0)
    positions.append(len(text))
    return [text[positions[i] : positions[i + 1]] for i in range(len(positions) - 1)]
