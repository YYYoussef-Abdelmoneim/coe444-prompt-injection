"""Query the FAISS index and return origin-tagged chunks.

The single most important line in this file is `origin=Origin.EXTERNAL`. Every
chunk that leaves this module is stamped external, unconditionally, because of
where it came from — not because of anything about its text. Nothing downstream
may upgrade that tag, and no content inspection may downgrade it.

Injecting a payload for a trial happens here too, via `inject`. The poisoned
text is spliced into a real document chunk so that retrieval has to actually
surface it; if it does not make the top-k, the trial is scored RETRIEVAL_MISS
rather than silently counted as an attack the agent resisted.
"""

from __future__ import annotations

import functools
import json
import logging

from config import EMBEDDING_MODEL, FAISS_INDEX_PATH, RETRIEVAL_K
from schema import Origin, TaggedChunk

_log = logging.getLogger(__name__)


@functools.lru_cache(maxsize=1)
def _load():
    import faiss
    from sentence_transformers import SentenceTransformer

    index_file = FAISS_INDEX_PATH / "index.faiss"
    chunks_file = FAISS_INDEX_PATH / "chunks.json"
    if not index_file.exists():
        raise RuntimeError(
            f"No FAISS index at {index_file}. Build it first:  python -m rag.indexer"
        )
    index = faiss.read_index(str(index_file))
    records = json.loads(chunks_file.read_text(encoding="utf-8"))
    return index, records, SentenceTransformer(EMBEDDING_MODEL)


class Retriever:
    """Wraps the index. One instance per evaluation run; the model load is cached."""

    def __init__(self, k: int = RETRIEVAL_K) -> None:
        self.k = k

    def search(
        self,
        query: str,
        *,
        inject: str | None = None,
        inject_into: str | None = None,
    ) -> tuple[list[TaggedChunk], str | None]:
        """Return (chunks, poisoned_chunk_id).

        `inject` splices payload text into the document named by `inject_into`
        (or the top hit when unspecified), simulating an attacker who can edit a
        document the agent is entitled to read.
        """
        index, records, model = _load()
        import numpy as np

        vector = model.encode([query], normalize_embeddings=True).astype("float32")
        scores, indices = index.search(vector, self.k)

        chunks: list[TaggedChunk] = []
        poisoned_id: str | None = None
        for rank, (idx, score) in enumerate(zip(indices[0], scores[0])):
            if idx < 0:
                continue
            rec = records[idx]
            text = rec["text"]
            is_poisoned = False
            if inject is not None and poisoned_id is None:
                target_matches = inject_into is None or rec["document_id"] == inject_into
                if target_matches:
                    text = f"{text}\n\n{inject}"
                    is_poisoned = True
                    poisoned_id = rec["chunk_id"]
            chunks.append(
                TaggedChunk(
                    chunk_id=rec["chunk_id"],
                    document_id=rec["document_id"],
                    text=text,
                    origin=Origin.EXTERNAL,  # structural, never inferred
                    similarity=float(score),
                    chunk_index=rank,
                    is_poisoned=is_poisoned,
                )
            )
        return chunks, poisoned_id
