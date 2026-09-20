"""Build the FAISS index from rag/documents/.

Run: python -m rag.indexer
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from config import DOCUMENTS_DIR, EMBEDDING_MODEL, FAISS_INDEX_PATH
from rag.chunker import canonical_document_id, chunk_document

_log = logging.getLogger(__name__)


def build_index(documents_dir: Path = DOCUMENTS_DIR, out_dir: Path = FAISS_INDEX_PATH) -> int:
    import faiss
    import numpy as np
    from sentence_transformers import SentenceTransformer

    paths = sorted(p for p in documents_dir.iterdir() if p.suffix in {".txt", ".md"})
    if not paths:
        raise RuntimeError(f"No .txt/.md documents in {documents_dir}")

    records: list[dict[str, object]] = []
    for path in paths:
        doc_id = canonical_document_id(path)
        for chunk_id, chunk_text in chunk_document(path.read_text(encoding="utf-8"), doc_id):
            records.append({"chunk_id": chunk_id, "document_id": doc_id, "text": chunk_text})

    _log.info("Embedding %d chunks from %d documents", len(records), len(paths))
    model = SentenceTransformer(EMBEDDING_MODEL)
    vectors = model.encode(
        [r["text"] for r in records], normalize_embeddings=True, show_progress_bar=False
    ).astype("float32")

    # Inner product on L2-normalised vectors == cosine similarity.
    index = faiss.IndexFlatIP(vectors.shape[1])
    index.add(vectors)

    out_dir.mkdir(parents=True, exist_ok=True)
    faiss.write_index(index, str(out_dir / "index.faiss"))
    (out_dir / "chunks.json").write_text(json.dumps(records, indent=2), encoding="utf-8")
    _log.info("Wrote index with %d vectors to %s", index.ntotal, out_dir)
    return index.ntotal


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    print(f"Indexed {build_index()} chunks -> {FAISS_INDEX_PATH}")
