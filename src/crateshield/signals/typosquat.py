from __future__ import annotations

from crateshield.config import TYPOSQUAT_MAX_DISTANCE, TYPOSQUAT_THRESHOLD


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _norm(name: str) -> str:
    return name.lower().replace("-", "_")


def analyze_typosquatting(name: str, top_crates: list[str]) -> dict:
    best = {
        "score": 0.0,
        "target": None,
        "edit_distance": None,
        "substitution_pattern": None,
        "target_rank": None,
    }
    if not top_crates:
        return best

    n = _norm(name)
    for rank, target in enumerate(top_crates, 1):
        if _norm(target) == n:
            continue
        t = _norm(target)
        dist = levenshtein(n, t)
        score = 1 - (dist / max(len(n), len(t), 1))
        hyphen = name.replace("-", "_") == target.replace("-", "_") and name != target
        if hyphen:
            pattern = "hyphen_for_underscore"
            score = max(score, 0.9)
            dist = min(dist, 1)
        else:
            pattern = None
        if score > best["score"] and dist <= TYPOSQUAT_MAX_DISTANCE:
            best = {
                "score": round(score, 3),
                "target": target,
                "edit_distance": dist,
                "substitution_pattern": pattern,
                "target_rank": rank,
                "flagged": score >= TYPOSQUAT_THRESHOLD,
            }
    if "flagged" not in best:
        best["flagged"] = False
    return best
