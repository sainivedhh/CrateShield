from __future__ import annotations

import pickle
from pathlib import Path

from crateshield.config import RESULTS_DIR
from crateshield.evaluation.train import extract_features
from crateshield.ingestion.known_incidents import check_known_incident

FEATURE_NAMES = [
    "has_build_rs",
    "build_network",
    "build_env",
    "build_spawn",
    "unsafe_blocks",
    "unsafe_kloc",
    "typo_score",
    "dep_count",
    "suspicious_deps",
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
        contributions.append(
            {"signal": key, "weight": w, "triggered": present, "note": note}
        )

    add(
        "build_network",
        bool(build.get("network_calls")),
        f"{len(build.get('network_calls', []))} outbound network call(s) in build.rs",
    )
    add(
        "sensitive_env",
        bool(build.get("sensitive_env_reads")),
        f"reads env vars: {', '.join(build.get('sensitive_env_reads', [])) or 'none'}",
    )
    add(
        "build_spawn",
        bool(build.get("process_spawns")),
        f"{len(build.get('process_spawns', []))} process spawn(s) in build.rs",
    )
    add(
        "typo_score",
        (typo.get("score") or 0) >= 0.85,
        f"typosquat score {typo.get('score', 0)} vs '{typo.get('target')}'"
        if typo.get("target")
        else "no close match to popular crates",
    )
    add(
        "unsafe_kloc",
        (unsafe.get("unsafe_per_kloc") or 0) > 15,
        f"{unsafe.get('unsafe_per_kloc', 0)} unsafe ops/KLOC",
    )
    add(
        "proc_macro_suspicious",
        bool(pm.get("proc_macro_suspicious_imports")),
        f"proc-macro imports: {', '.join(pm.get('proc_macro_suspicious_imports', [])) or 'none'}",
    )

    return round(min(score, 1.0), 3), contributions


def _risk_level(score: float) -> str:
    if score >= 0.70:
        return "CRITICAL"
    if score >= 0.40:
        return "HIGH"
    if score >= 0.20:
        return "MEDIUM"
    return "LOW"


import xgboost as xgb
import numpy as np

def assess_risk(signal: dict) -> dict:
    crate_name = signal.get("crate") or signal.get("metadata", {}).get("name", "")
    known = check_known_incident(crate_name) if crate_name else None

    rule_score, contributions = _rule_based_score(signal)

    model_result = None
    model_path = RESULTS_DIR / "xgb_model.json"
    if model_path.exists():
        try:
            model = xgb.XGBClassifier()
            model.load_model(model_path)
            
            features = np.array([extract_features(signal)])
            proba = model.predict_proba(features)[0]
            malicious_idx = list(model.classes_).index(1) if 1 in model.classes_ else -1
            model_score = float(proba[malicious_idx]) if malicious_idx >= 0 else float(proba[-1])
            
            booster = model.get_booster()
            
            # Use built-in SHAP values from XGBoost
            dmatrix = xgb.DMatrix(features, feature_names=FEATURE_NAMES)
            shap_values = booster.predict(dmatrix, pred_contribs=True)[0]
            
            # The last element is the bias term
            feature_contributions = shap_values[:-1]
            
            # Sort features by absolute contribution to the decision
            top_indices = np.argsort(np.abs(feature_contributions))[::-1][:3]
            top_features = []
            
            for idx in top_indices:
                if abs(feature_contributions[idx]) > 0.01:
                    top_features.append({
                        "feature": FEATURE_NAMES[idx],
                        "value": float(features[0][idx]),
                        "shap_contribution": round(float(feature_contributions[idx]), 3)
                    })

            model_result = {
                "malicious_probability": round(model_score, 3),
                "feature_values": dict(zip(FEATURE_NAMES, features[0].tolist())),
                "top_shap_features": top_features,
            }
        except Exception as e:
            model_result = None

    final_score = (
        round(0.5 * rule_score + 0.5 * model_result["malicious_probability"], 3)
        if model_result
        else rule_score
    )
    
    risk_level = _risk_level(final_score)
    
    # If High or Critical, add explainability
    explanation = None
    if risk_level in ["HIGH", "CRITICAL"] and model_result and model_result["top_shap_features"]:
        explanation = "The model flagged this crate due to the following main factors: "
        factors = []
        for feat in model_result["top_shap_features"]:
            direction = "increased" if feat["shap_contribution"] > 0 else "decreased"
            factors.append(f"{feat['feature']} (value: {feat['value']}) {direction} the risk score by {abs(feat['shap_contribution'])}")
        explanation += ", ".join(factors) + "."

    result = {
        "risk_score": final_score,
        "risk_level": risk_level,
        "source": "model+rules"
        if model_result
        else "rules-only (train the model for higher accuracy)",
        "rule_based": {"score": rule_score, "contributions": contributions},
        "model": model_result,
        "explanation": explanation,
        "known_incident": None,
    }

    if known:
        result["risk_score"] = 1.0
        result["risk_level"] = "CRITICAL"
        result["source"] = "known-incident match (overrides model/rules)"
        result["known_incident"] = {
            "ecosystem": known.get("ecosystem"),
            "attack_category": known.get("attack_category"),
            "technical_mechanism": known.get("technical_mechanism"),
            "source": known.get("source"),
            "registry_status": known.get("registry_status_verified")
            or known.get("registry_status_reported"),
        }

    return result
