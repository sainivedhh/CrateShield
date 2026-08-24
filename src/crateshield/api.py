from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from crateshield.config import ROOT, WORK_DIR, ensure_dirs
from crateshield.ingestion.downloader import fetch_crate_metadata

app = FastAPI(title="CrateShield API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


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


@app.get("/api/crate/{name}")
def get_crate_metadata(name: str):
    """Basic crates.io metadata lookup — used by the frontend to resolve the
    latest version and show registry info (downloads, description, repo)."""
    try:
        meta = fetch_crate_metadata(name)
    except Exception as exc:
        raise HTTPException(status_code=404, detail=f"Crate '{name}' not found on crates.io ({exc})")
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
    """Full analysis for one crate: resolves latest version if not given,
    extracts all five signal families, and returns a risk score/level plus
    the full signal breakdown for the UI to render."""
    ensure_dirs()
    from crateshield.pipeline import extract_only
    from crateshield.evaluation.risk import assess_risk

    if not version:
        try:
            meta = fetch_crate_metadata(name)
            version = meta.get("crate", {}).get("max_version")
        except Exception as exc:
            raise HTTPException(status_code=404, detail=f"Could not resolve latest version for '{name}' ({exc})")
        if not version:
            raise HTTPException(status_code=404, detail=f"No published version found for '{name}'")

    try:
        signals = extract_only(name, version)
    except Exception as exc:
        raise HTTPException(status_code=422, detail=f"Failed to fetch/parse {name}@{version}: {exc}")

    risk = assess_risk(signals)

    from crateshield.config import RESULTS_DIR
    from crateshield.evaluation.train import extract_features, FEATURE_NAMES
    import xgboost as xgb
    import numpy as np

    model_path = RESULTS_DIR / "xgb_model.json"
    if model_path.exists():
        try:
            model = xgb.XGBClassifier()
            model.load_model(model_path)
            features = extract_features(signals)
            X_pred = np.array([features])
            prob = float(model.predict_proba(X_pred)[0][1])
            
            importance_dict = model.get_booster().get_score(importance_type='gain')
            importances = [{"feature": FEATURE_NAMES[int(k[1:])], "importance": float(v)} for k, v in importance_dict.items()]
            importances.sort(key=lambda x: x["importance"], reverse=True)
            
            risk["model"] = {
                "malicious_probability": prob,
                "feature_importances": importances
            }
        except Exception as e:
            print(f"Warning: Failed to load/run XGBoost model: {e}")

    sev_model_path = RESULTS_DIR / "xgb_severity_model.json"
    if sev_model_path.exists():
        try:
            from crateshield.evaluation.train import SEVERITY_LEVELS
            sev_model = xgb.XGBClassifier()
            sev_model.load_model(sev_model_path)
            features = extract_features(signals)
            X_pred = np.array([features])
            pred_idx = int(sev_model.predict(X_pred)[0])
            probs = sev_model.predict_proba(X_pred)[0]
            
            risk["severity_model"] = {
                "predicted_severity": SEVERITY_LEVELS[pred_idx],
                "probabilities": [{"severity": sev, "probability": float(p)} for sev, p in zip(SEVERITY_LEVELS, probs)]
            }
        except Exception as e:
            print(f"Warning: Failed to load/run XGBoost severity model: {e}")

    return {
        "crate": name,
        "version": version,
        "risk": risk,
        "signals": signals,
    }


class RunRequest(BaseModel):
    command: str


@app.post("/api/run")
def run_command(req: RunRequest):
    allowed_commands = ["ingest-rustsec", "ablation", "train"]
    if req.command not in allowed_commands:
        raise HTTPException(status_code=400, detail="Invalid command")
    try:
        subprocess.Popen([sys.executable, "-m", "crateshield", req.command], cwd=str(ROOT))
        return {"status": "started", "command": req.command}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
