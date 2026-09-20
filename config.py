"""Configuration. Module-level constants, populated from .env.

Optional settings use os.getenv(name, default); anything the system cannot run
without uses os.environ[name] so it fails loudly at import rather than three
minutes into an evaluation sweep.
"""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

BASE_DIR = Path(__file__).parent

# ── Models ────────────────────────────────────────────────────────────────────
# The proposal slide says Llama 3.1-8B. That model needs ~5 GB of disk and ~6 GB
# of RAM; this laptop has neither, so the detector runs on a hosted model behind
# the DetectorProvider ABC. Swapping back to Llama is one env var once a Groq or
# HF token exists — see defense/detection.py.
#
# Agent and detector are deliberately different models. If the thing policing
# the agent shares the agent's failure modes, a prompt that fools one tends to
# fool the other, and the detector's measured recall is optimistic.
AGENT_MODEL: str = os.getenv("AGENT_MODEL", "claude-sonnet-5")
DETECTOR_MODEL: str = os.getenv("DETECTOR_MODEL", "claude-haiku-4-5")
DETECTOR_PROVIDER: str = os.getenv("DETECTOR_PROVIDER", "anthropic")

AGENT_TEMPERATURE: float = float(os.getenv("AGENT_TEMPERATURE", "0.0"))
AGENT_MAX_TOKENS: int = int(os.getenv("AGENT_MAX_TOKENS", "2048"))
DETECTOR_MAX_TOKENS: int = int(os.getenv("DETECTOR_MAX_TOKENS", "256"))

# ── Retrieval ─────────────────────────────────────────────────────────────────
EMBEDDING_MODEL: str = os.getenv("EMBEDDING_MODEL", "sentence-transformers/all-MiniLM-L6-v2")
RETRIEVAL_K: int = int(os.getenv("RETRIEVAL_K", "4"))
MAX_CHUNK_CHARS: int = 900
OVERLAP_CHARS: int = 120
MIN_CHUNK_CHARS: int = 50

# ── Paths ─────────────────────────────────────────────────────────────────────
# Large artefacts live on the external drive when it is mounted, because the
# internal disk is effectively full. Everything here degrades to a local path so
# the code still imports with the drive unplugged.
EXTERNAL_ROOT = Path(os.getenv("COE444_DATA_ROOT", str(BASE_DIR / ".data")))

DOCUMENTS_DIR = Path(os.getenv("DOCUMENTS_DIR", str(BASE_DIR / "rag" / "documents")))
FAISS_INDEX_PATH = Path(os.getenv("FAISS_INDEX_PATH", str(EXTERNAL_ROOT / "faiss_index")))
LOG_DIR = Path(os.getenv("LOG_DIR", str(BASE_DIR / "logs")))
RESULTS_DIR = Path(os.getenv("RESULTS_DIR", str(BASE_DIR / "results")))

PAYLOADS_PATH = BASE_DIR / "attacks" / "payloads.json"
BENIGN_PATH = BASE_DIR / "attacks" / "benign_tasks.json"

# ── Experiment identity ───────────────────────────────────────────────────────
CORPUS_VERSION: str = os.getenv("CORPUS_VERSION", "v0.1-dev")
TRIALS_PER_TASK: int = int(os.getenv("TRIALS_PER_TASK", "3"))

# ── Attacker constants ────────────────────────────────────────────────────────
# RFC 2606 reserves .invalid so these can never resolve to a real host, even if
# a payload escapes the sandbox. The mail sink refuses to send regardless.
ATTACKER_DOMAINS: frozenset[str] = frozenset({"evil.invalid", "exfil.invalid", "attacker.invalid"})

for _d in (LOG_DIR, RESULTS_DIR):
    _d.mkdir(parents=True, exist_ok=True)
