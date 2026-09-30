import json
import logging
import pickle
from pathlib import Path

import numpy as np
from crateshield.config import ROOT

logger = logging.getLogger(__name__)

KB_DIR = ROOT / "data" / "knowledge_base"
EMBEDDINGS_CACHE = ROOT / "data" / "rag_embeddings_cache.pkl"

_MODEL = None
_CORPUS_EMBEDDINGS = None
_CORPUS_DOCS = None


def _get_model():
    global _MODEL
    if _MODEL is None:
        from sentence_transformers import SentenceTransformer

        logger.info("Loading sentence-transformers/all-MiniLM-L6-v2...")
        _MODEL = SentenceTransformer("all-MiniLM-L6-v2")
    return _MODEL


def _load_corpus():
    global _CORPUS_EMBEDDINGS, _CORPUS_DOCS
    if _CORPUS_EMBEDDINGS is not None and _CORPUS_DOCS is not None:
        return _CORPUS_EMBEDDINGS, _CORPUS_DOCS

    if not KB_DIR.exists():
        logger.warning(f"KB directory {KB_DIR} not found.")
        return None, None

    docs = []
    texts_to_embed = []

    for f in KB_DIR.glob("*.json"):
        try:
            doc = json.loads(f.read_text(encoding="utf-8"))
            docs.append(doc)
            # Create a rich semantic representation for embedding
            text = f"{doc.get('title', '')}. {doc.get('summary', '')}"
            texts_to_embed.append(text)
        except Exception as e:
            logger.warning(f"Failed to load {f}: {e}")

    if not docs:
        return None, None

    # Load cache if possible
    if EMBEDDINGS_CACHE.exists():
        try:
            with open(EMBEDDINGS_CACHE, "rb") as f:
                cache = pickle.load(f)
            # Basic cache validation
            if (
                len(cache["docs"]) == len(docs)
                and cache["docs"][0]["id"] == docs[0]["id"]
            ):
                _CORPUS_EMBEDDINGS = cache["embeddings"]
                _CORPUS_DOCS = cache["docs"]
                return _CORPUS_EMBEDDINGS, _CORPUS_DOCS
        except Exception as e:
            logger.warning(f"Failed to load embeddings cache: {e}")

    model = _get_model()
    logger.info(f"Computing embeddings for {len(docs)} KB documents...")
    embeddings = model.encode(texts_to_embed, convert_to_numpy=True)

    # Save cache
    EMBEDDINGS_CACHE.parent.mkdir(parents=True, exist_ok=True)
    with open(EMBEDDINGS_CACHE, "wb") as f:
        pickle.dump({"embeddings": embeddings, "docs": docs}, f)

    _CORPUS_EMBEDDINGS = embeddings
    _CORPUS_DOCS = docs

    return _CORPUS_EMBEDDINGS, _CORPUS_DOCS


def generate_nl_query(signals: dict) -> str:
    parts = []
    build_rs = signals.get("build_rs", {})
    if build_rs.get("has_build_rs"):
        parts.append("contains custom build script")
        for s in build_rs.get("signals", []):
            parts.append(s.replace("_", " "))

    unsafe = signals.get("unsafe_ffi", {})
    if unsafe.get("unsafe_per_kloc", 0) > 10:
        parts.append("high unsafe block density")
    if unsafe.get("ffi_declarations"):
        parts.append("contains FFI declarations")

    pm = signals.get("proc_macro", {})
    if pm.get("is_proc_macro"):
        parts.append("is a procedural macro")
        if pm.get("proc_macro_suspicious_imports"):
            parts.append("suspicious procedural macro imports")

    ts = signals.get("typosquatting", {})
    if ts.get("flagged"):
        parts.append(f"typosquats popular crate {ts.get('target')}")

    if not parts:
        return "Rust crate with standard behavior."

    return f"Rust crate {', '.join(parts)}."


def retrieve(signals: dict, k: int = 3) -> list[dict]:
    corpus_emb, docs = _load_corpus()
    if corpus_emb is None or len(docs) == 0:
        return []

    from sklearn.metrics.pairwise import cosine_similarity

    query_text = generate_nl_query(signals)
    model = _get_model()
    query_emb = model.encode([query_text], convert_to_numpy=True)

    sims = cosine_similarity(query_emb, corpus_emb)[0]
    top_indices = np.argsort(sims)[::-1][:k]

    results = []
    for idx in top_indices:
        # thresholding
        if sims[idx] > 0.05:
            doc = docs[idx].copy()
            doc["similarity_score"] = float(sims[idx])
            results.append(doc)

    return results
