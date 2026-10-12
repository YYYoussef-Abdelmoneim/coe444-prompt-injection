"""A cache of detector verdicts, keyed by (excerpt text, prompt version, model).

Free-tier quota is the binding constraint. The same excerpts recur across trials
and across runs: a dev sweep reads ~240 excerpts but only ~33 distinct texts. At
temperature 0 the same model gives the same verdict, so each distinct text costs
one call per prompt version. Only validated verdicts are stored: a failure is
retried next time, never replayed.

Telemetry, not a security decision, so it fails open: if the cache file is
missing, locked or corrupt, the detector simply calls the model.
"""

from __future__ import annotations

import hashlib
import logging
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path

_log = logging.getLogger(__name__)


class VerdictCache:
    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()
        self._db: sqlite3.Connection | None = None
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            db = sqlite3.connect(str(self.path), check_same_thread=False)
            db.execute(
                "CREATE TABLE IF NOT EXISTS verdicts ("
                " key TEXT PRIMARY KEY, score REAL NOT NULL, span TEXT, reason TEXT, created TEXT NOT NULL)"
            )
            db.commit()
            self._db = db
        except (sqlite3.Error, OSError) as exc:
            _log.warning("detector verdict cache unavailable at %s: %s", self.path, exc)

    @staticmethod
    def key(text: str, prompt_version: str, model: str) -> str:
        return hashlib.sha256("\x00".join((prompt_version, model, text)).encode("utf-8")).hexdigest()

    def get(self, key: str) -> tuple[float, str, str] | None:
        if self._db is None:
            return None
        try:
            with self._lock:
                row = self._db.execute("SELECT score, span, reason FROM verdicts WHERE key = ?", (key,)).fetchone()
        except sqlite3.Error as exc:
            _log.warning("detector verdict cache read failed: %s", exc)
            return None
        return (float(row[0]), row[1] or "", row[2] or "") if row else None

    def put(self, key: str, score: float, span: str, reason: str) -> None:
        if self._db is None:
            return
        try:
            with self._lock:
                self._db.execute(
                    "INSERT OR REPLACE INTO verdicts VALUES (?, ?, ?, ?, ?)",
                    (key, score, span, reason, datetime.now(timezone.utc).isoformat()),
                )
                self._db.commit()
        except sqlite3.Error as exc:
            _log.warning("detector verdict cache write failed: %s", exc)
