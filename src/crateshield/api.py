from __future__ import annotations

import json
import re

import numpy as np
import xgboost as xgb
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from crateshield.config import RESULTS_DIR, SIGNALS_DIR, WORK_DIR, ensure_dirs
from crateshield.evaluation.train import FEATURE_NAMES, extract_features
from crateshield.ingestion.downloader import fetch_crate_metadata

app = FastAPI(title="CrateShield API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # allow all localhost ports (dev)
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Load XGBoost model ONCE at startup — not on every request
# ---------------------------------------------------------------------------
_xgb_model: xgb.XGBClassifier | None = None

@app.on_event("startup")
def _load_models():
    global _xgb_model
    model_path = RESULTS_DIR / "xgb_model.json"
    if model_path.exists():
        _xgb_model = xgb.XGBClassifier()
        _xgb_model.load_model(model_path)
        print(f"[startup] Loaded XGBoost model from {model_path}")
    else:
        print("[startup] No XGBoost model found — using rules-only scoring")


@app.get("/api/dataset")
def get_dataset():
    ds_path = WORK_DIR / "dataset.json"
    if not ds_path.exists():
        ds_path = WORK_DIR / "dataset_mini.json"
    if not ds_path.exists():
        raise HTTPException(status_code=404, detail="Dataset not found")
    return json.loads(ds_path.read_text(encoding="utf-8"))


@app.get("/api/ablation")
def get_ablation():
    res_path = WORK_DIR / "results" / "ablation.json"
    if not res_path.exists():
        res_path = WORK_DIR / "results" / "ablation_mini.json"
    if not res_path.exists():
        raise HTTPException(status_code=404, detail="Ablation results not found")
    return json.loads(res_path.read_text(encoding="utf-8"))


def is_valid_crate_name(name: str) -> bool:
    return bool(re.fullmatch(r"[a-zA-Z0-9_-]+", name))


@app.get("/api/crate/{name}")
def get_crate_metadata(name: str):
    """Basic crates.io metadata lookup used by the frontend."""
    if not is_valid_crate_name(name):
        raise HTTPException(status_code=400, detail="Invalid crate name")
    try:
        meta = fetch_crate_metadata(name)
    except Exception as exc:
        raise HTTPException(status_code=404, detail=f"Crate '{name}' not found on crates.io ({exc})") from exc
    crate = meta.get("crate", {})
    return {
        "name": crate.get("id"),
        "max_version": crate.get("max_version"),
        "newest_version": crate.get("newest_version") or crate.get("max_version"),
        "description": crate.get("description"),
        "downloads": crate.get("downloads"),
        "repository": crate.get("repository"),
        "homepage": crate.get("homepage"),
        "created_at": crate.get("created_at"),
        "updated_at": crate.get("updated_at"),
        "versions_count": len(meta.get("versions", [])),
        "yanked_versions": [v["num"] for v in meta.get("versions", []) if v.get("yanked")],
        "keywords": [k.get("id") for k in meta.get("keywords", [])] if meta.get("keywords") else [],
    }


@app.get("/api/predict")
def predict(name: str, version: str | None = None):
    """Extract signals and return the rule/model risk assessment for a crate."""
    if not is_valid_crate_name(name):
        raise HTTPException(status_code=400, detail="Invalid crate name")
    ensure_dirs()
    from crateshield.pipeline import extract_only
    from crateshield.evaluation.risk import assess_risk

    if not version:
        try:
            meta = fetch_crate_metadata(name)
            version = meta.get("crate", {}).get("max_version")
        except Exception as exc:
            raise HTTPException(status_code=404, detail=f"Could not resolve latest version for '{name}' ({exc})") from exc
        if not version:
            raise HTTPException(status_code=404, detail=f"No published version found for '{name}'")

    # -----------------------------------------------------------------------
    # Cache hit: if signals already extracted, skip download + tree-sitter
    # -----------------------------------------------------------------------
    cached_signal_file = SIGNALS_DIR / f"{name}-{version}.json"
    if cached_signal_file.exists():
        signals = json.loads(cached_signal_file.read_text(encoding="utf-8"))
    else:
        try:
            signals = extract_only(name, version)
        except Exception as exc:
            raise HTTPException(status_code=422, detail=f"Failed to fetch/parse {name}@{version}: {exc}") from exc

    risk = assess_risk(signals)

    # Use the already-loaded model (startup), no re-loading per request
    if _xgb_model is not None:
        try:
            X_pred = np.array([extract_features(signals)])
            probabilities = _xgb_model.predict_proba(X_pred)[0]
            malicious_index = list(_xgb_model.classes_).index(1) if 1 in _xgb_model.classes_ else 0
            importance_dict = _xgb_model.get_booster().get_score(importance_type="gain")
            importances = [
                {"feature": FEATURE_NAMES[int(k[1:])], "importance": float(v)}
                for k, v in importance_dict.items()
                if k.startswith("f") and k[1:].isdigit() and int(k[1:]) < len(FEATURE_NAMES)
            ]
            risk["model"] = {
                "malicious_probability": float(probabilities[malicious_index]),
                "feature_importances": sorted(importances, key=lambda x: x["importance"], reverse=True),
            }
        except Exception as exc:
            print(f"Warning: XGBoost inference failed: {exc}")

    return {"crate": name, "version": version, "risk": risk, "signals": signals}


class RunRequest(BaseModel):
    command: str


@app.post("/api/run")
def run_command(req: RunRequest):
    if req.command not in {"ingest-rustsec", "ablation", "train"}:
        raise HTTPException(status_code=400, detail="Invalid command")
    try:
        if req.command == "ingest-rustsec":
            from crateshield.ingestion.rustsec import main as ingest_main
            ingest_main()
        elif req.command == "ablation":
            from crateshield.evaluation.ablation import main as ablation_main
            ablation_main()
        else:
            from crateshield.evaluation.train import train_and_evaluate_xgb
            dataset = WORK_DIR / "dataset.json"
            if not dataset.exists():
                dataset = WORK_DIR / "dataset_mini.json"
            if not dataset.exists():
                raise FileNotFoundError("No dataset.json or dataset_mini.json found")
            train_and_evaluate_xgb(dataset, SIGNALS_DIR)
        return {"status": "completed", "command": req.command}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
