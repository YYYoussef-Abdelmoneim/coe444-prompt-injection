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

# ── Providers ─────────────────────────────────────────────────────────────────
# Agent and detector each pick a provider, all speaking the OpenAI-compatible
# chat-completions API (agent/llm.py:OpenAICompatProvider). The split setup
# runs the agent on Groq and the detector on Cerebras; each provider's key is
# only ever sent to its own base URL.
CEREBRAS_BASE_URL: str = os.getenv("CEREBRAS_BASE_URL", "https://api.cerebras.ai/v1")
CEREBRAS_API_KEY: str = os.getenv("CEREBRAS_API_KEY", "")
GROQ_BASE_URL: str = os.getenv("GROQ_BASE_URL", "https://api.groq.com/openai/v1")
GROQ_API_KEY: str = os.getenv("GROQ_API_KEY", "")

AGENT_PROVIDER: str = os.getenv("AGENT_PROVIDER", "cerebras")
DETECTOR_PROVIDER: str = os.getenv("DETECTOR_PROVIDER", "cerebras")

# ANTHROPIC_API_KEY is deliberately NOT read here and is not required. The
# Anthropic provider is retained so the Claude arm can be reproduced
# (AGENT_PROVIDER=anthropic AGENT_MODEL=claude-haiku-4-5), and it builds its
# client lazily, so nothing breaks when the key is absent.

# ── Models ────────────────────────────────────────────────────────────────────
# Hosted rather than local: even an 8B model needs ~5 GB of disk and ~6 GB of
# RAM this laptop does not have.
#
# Agent and detector are deliberately different models. If the thing policing
# the agent shares the agent's failure modes, a prompt that fools one tends to
# fool the other, and the detector's measured recall is optimistic. Qwen and
# gpt-oss come from different vendors, which restores the cross-vendor
# separation the Llama 8B/70B pairing had lost. Those two Llama IDs were
# retired by Cerebras in 2026 and now 404.
#
# NOTE: every ASR figure in METHODOLOGY.md sections 6.1, 6.3 and 6.4 was
# measured on claude-haiku-4-5 (39% baseline) and claude-sonnet-5 (13%). Those
# numbers do not carry over to the Cerebras models and must be re-measured
# before they are reported again.
#
# The agent is the smallest model the endpoint serves, so attacks have room to
# land in condition A.
#
# The split setup in .env.example overrides this with openai/gpt-oss-20b on
# Groq: qwen-3.8-27b refused every dev payload, and Groq's smaller models
# either lack tool calling (allam-2-7b) or are gone (llama-3.1-8b-instant).
# gpt-oss-20b shares the detector's lineage, which gives up the cross-vendor
# separation above - report that as a limitation.
AGENT_MODEL: str = os.getenv("AGENT_MODEL", "qwen-3.8-27b")
# The detector is the largest, so it does not share the agent's failure modes.
# A guard that fails wherever the thing it guards fails reports optimistic
# recall. "Largest" is by total parameters: gpt-oss-120b is a mixture of
# experts with ~5B active per token, so state its size that way in the report.
DETECTOR_MODEL: str = os.getenv("DETECTOR_MODEL", "gpt-oss-120b")

# Sampling IS expressible again. The Anthropic Messages API dropped
# `temperature`, which is why the proposal's "N trials at temperature = 0"
# protocol had to be abandoned; an OpenAI-compatible endpoint restores it.
# Default 0.0 for the most reproducible runs available — still not a
# determinism guarantee, so keep reporting per-payload variance across trials.
AGENT_TEMPERATURE: float = float(os.getenv("AGENT_TEMPERATURE", "0.0"))
SAMPLING: str = f"temperature={AGENT_TEMPERATURE} (openai-compatible endpoint)"
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
# Two groups. The transparently hostile names are used by the naive_standalone
# family; the plausible-looking ones are used by the ride-along families, where
# the whole point is that the address does not look alarming to the model.
ATTACKER_DOMAINS: frozenset[str] = frozenset({
    "evil.invalid", "exfil.invalid", "attacker.invalid",
    "nw-records.invalid", "nw-audit.invalid", "nw-partner.invalid", "nw-soc.invalid",
})

for _d in (LOG_DIR, RESULTS_DIR):
    _d.mkdir(parents=True, exist_ok=True)
