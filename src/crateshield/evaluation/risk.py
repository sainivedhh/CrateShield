from __future__ import annotations

import pickle
from pathlib import Path

from crateshield.config import RESULTS_DIR
from crateshield.evaluation.train import extract_features

FEATURE_NAMES = [
    "has_build_rs", "build_network", "build_env", "build_spawn",
    "unsafe_blocks", "unsafe_kloc", "typo_score", "dep_count", "suspicious_deps",
]

# Rule-based fallback so the web app is usable even before `crateshield train`
# has been run. Weights are intentionally simple/explainable, not tuned.
_RULE_WEIGHTS = {
    "build_network": 0.50,
    "sensitive_env": 0.40,
    "build_spawn": 0.30,
    "typo_score": 0.50,
    "unsafe_kloc": 0.20,
    "proc_macro_suspicious": 0.40,
}


def _rule_based_score(signal: dict) -> tuple[float, list[dict]]:
    build = signal.get("build_rs", {})
    unsafe = signal.get("unsafe_ffi", {})
    typo = signal.get("typosquatting", {})
    pm = signal.get("proc_macro", {})

    contributions = []
    score = 0.0

    def add(key: str, present: bool, note: str):
        nonlocal score
        w = _RULE_WEIGHTS[key]
        val = w if present else 0.0
        score += val
        contributions.append({"signal": key, "weight": w, "triggered": present, "note": note})

    add("build_network", bool(build.get("network_calls")),
        f"{len(build.get('network_calls', []))} outbound network call(s) in build.rs")
    add("sensitive_env", bool(build.get("sensitive_env_reads")),
        f"reads env vars: {', '.join(build.get('sensitive_env_reads', [])) or 'none'}")
    add("build_spawn", bool(build.get("process_spawns")),
        f"{len(build.get('process_spawns', []))} process spawn(s) in build.rs")
    add("typo_score", (typo.get("score") or 0) >= 0.85,
        f"typosquat score {typo.get('score', 0)} vs '{typo.get('target')}'" if typo.get("target") else "no close match to popular crates")
    add("unsafe_kloc", (unsafe.get("unsafe_per_kloc") or 0) > 15,
        f"{unsafe.get('unsafe_per_kloc', 0)} unsafe ops/KLOC")
    add("proc_macro_suspicious", bool(pm.get("proc_macro_suspicious_imports")),
        f"proc-macro imports: {', '.join(pm.get('proc_macro_suspicious_imports', [])) or 'none'}")

    return round(min(score, 1.0), 3), contributions


def _risk_level(score: float) -> str:
    if score >= 0.70:
        return "CRITICAL"
    if score >= 0.40:
        return "HIGH"
    if score >= 0.20:
        return "MEDIUM"
    return "LOW"


def assess_risk(signal: dict) -> dict:
    """Combine the trained RandomForest model (if available) with a transparent
    rule-based score. Always returns a result, even with no trained model."""
    rule_score, contributions = _rule_based_score(signal)

    model_result = None
    model_path = RESULTS_DIR / "rf_model.pkl"
    if model_path.exists():
        try:
            with open(model_path, "rb") as f:
                rf = pickle.load(f)
            features = extract_features(signal)
            proba = rf.predict_proba([features])[0]
            malicious_idx = list(rf.classes_).index(1) if 1 in rf.classes_ else -1
            model_score = float(proba[malicious_idx]) if malicious_idx >= 0 else float(proba[-1])
            importances = list(zip(FEATURE_NAMES, rf.feature_importances_.tolist()))
            importances.sort(key=lambda x: x[1], reverse=True)
            model_result = {
                "malicious_probability": round(model_score, 3),
                "feature_values": dict(zip(FEATURE_NAMES, features)),
                "feature_importances": [{"feature": n, "importance": round(i, 3)} for n, i in importances],
            }
        except Exception:
            model_result = None

    final_score = (
        round(0.5 * rule_score + 0.5 * model_result["malicious_probability"], 3)
        if model_result else rule_score
    )

    return {
        "risk_score": final_score,
        "risk_level": _risk_level(final_score),
        "source": "model+rules" if model_result else "rules-only (train the model for higher accuracy)",
        "rule_based": {"score": rule_score, "contributions": contributions},
        "model": model_result,
    }
