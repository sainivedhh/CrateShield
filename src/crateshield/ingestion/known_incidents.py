import csv
import functools
from pathlib import Path

from crateshield.config import ROOT

CSV_PATH = ROOT / "data" / "reference" / "known_supply_chain_incidents.csv"

@functools.lru_cache(maxsize=1)
def load_incidents() -> dict[str, dict]:
    """Loads the known incidents CSV and returns a dictionary keyed by package name."""
    if not CSV_PATH.exists():
        return {}
    
    incidents = {}
    with open(CSV_PATH, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            package_raw = row.get("package", "")
            if not package_raw:
                continue
            
            # strip anything after " (" and lowercase
            package_clean = package_raw.split(" (")[0].strip().lower()
            incidents[package_clean] = row
            
    return incidents

def check_known_incident(crate_name: str) -> dict | None:
    """Checks if a crate is in the known incidents blocklist."""
    incidents = load_incidents()
    return incidents.get(crate_name.lower().strip())

@functools.lru_cache(maxsize=1)
def _build_tfidf_index():
    incidents = load_incidents()
    if not incidents:
        return [], None, None
    
    docs = []
    rows = []
    for row in incidents.values():
        text = f"{row.get('package', '')} {row.get('description', '')} {row.get('advisory_id', '')}"
        docs.append(text)
        rows.append(row)
        
    try:
        from sklearn.feature_extraction.text import TfidfVectorizer
        vectorizer = TfidfVectorizer(stop_words="english", lowercase=True)
        tfidf_matrix = vectorizer.fit_transform(docs)
        return rows, vectorizer, tfidf_matrix
    except ImportError:
        return rows, None, None

def search_incidents_tfidf(query_text: str, top_k: int = 2) -> list[dict]:
    """Retrieves the top_k most similar incidents using TF-IDF."""
    rows, vectorizer, tfidf_matrix = _build_tfidf_index()
    if not vectorizer or not query_text.strip():
        return []
        
    query_vec = vectorizer.transform([query_text])
    
    try:
        from sklearn.metrics.pairwise import cosine_similarity
        import numpy as np
        sims = cosine_similarity(query_vec, tfidf_matrix).flatten()
        top_indices = np.argsort(sims)[-top_k:][::-1]
        
        results = []
        for idx in top_indices:
            if sims[idx] > 0.05: # Minimal similarity threshold
                results.append(rows[idx])
        return results
    except ImportError:
        return []
