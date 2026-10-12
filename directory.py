"""The company directory behind the lookup_contact tool.

Data, not policy. Every entry a lookup returns leaves this module as a chunk
stamped Origin.DIRECTORY, at the point the text enters the system, the same way
rag/retriever.py stamps EXTERNAL (invariant 1). The gate trusts an address only
when a lookup returned it in that run: membership alone grants nothing, so an
address a document merely mentions still needs confirming.

A lookup that finds nothing returns nothing. It never echoes the query back,
because an echoed query would come back stamped DIRECTORY, which is a way to
launder an injected address into trusted text.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from pathlib import Path

from config import DIRECTORY_PATH
from schema import Origin, TaggedChunk

_log = logging.getLogger(__name__)


@dataclass(frozen=True)
class Entry:
    name: str
    role: str
    email: str
    domain: str
    clearance: str  # PUBLIC | INTERNAL | CONFIDENTIAL; read by nothing yet
    aliases: tuple[str, ...] = ()

    def text(self) -> str:
        """What the agent reads: directory bytes only, never the query."""
        return f"{self.name} ({self.role}) <{self.email}>"

    def matches(self, query: str) -> bool:
        keys = {self.email, self.role, self.name.lower(), *self.aliases}
        # Whole words only, so "hr" does not match "three".
        return any(re.search(rf"(?<![\w@.]){re.escape(k)}(?![\w@.])", query) for k in keys)


@dataclass(frozen=True)
class Directory:
    version: str
    internal_domains: frozenset[str]
    entries: tuple[Entry, ...]

    @classmethod
    def load(cls, path: Path | str = DIRECTORY_PATH) -> Directory:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        entries = tuple(
            Entry(
                name=e["name"], role=e["role"].lower(), email=e["email"].lower(),
                domain=e["domain"].lower(), clearance=e["clearance"],
                aliases=tuple(a.lower() for a in e.get("aliases", [])),
            )
            for e in raw["entries"]
        )
        return cls(raw["directory_version"], frozenset(d.lower() for d in raw["internal_domains"]), entries)

    def addresses(self) -> frozenset[str]:
        return frozenset(e.email for e in self.entries)

    def lookup(self, query: str) -> list[Entry]:
        q = " ".join(query.lower().split())
        return [e for e in self.entries if e.matches(q)] if q else []

    def search(self, query: str) -> list[TaggedChunk]:
        return [
            TaggedChunk(
                chunk_id=f"directory::{e.email}",
                document_id="directory",
                text=e.text(),
                origin=Origin.DIRECTORY,  # structural: it came from the directory
                similarity=1.0,
            )
            for e in self.lookup(query)
        ]
