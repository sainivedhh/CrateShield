from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Optional

from crateshield.config import RESULTS_DIR, SIGNALS_DIR, ensure_dirs
from crateshield.ingestion.downloader import download_crate
from crateshield.ingestion.extractor import extract_crate
from crateshield.llm.client import classify_with_vote
from crateshield.llm.prompt import build_prompt
from crateshield.signals.extractor import extract_all_signals

logger = logging.getLogger(__name__)


def extract_only(name: str, version: str, work_dir: Path | None = None) -> dict:
    ensure_dirs()
    tarball = download_crate(name, version)
    crate_dir = extract_crate(tarball)
    signals = extract_all_signals(name, version, crate_dir)
    out = SIGNALS_DIR / f"{name}-{version}.json"
    out.write_text(json.dumps(signals, indent=2), encoding="utf-8")
    logger.info("Wrote %s", out)
    return signals


def analyze_crate(
    name: str,
    version: str,
    work_dir: Path | None = None,
    ground_truth_label: Optional[str] = None,
) -> dict:
    logger.info("Analyzing %s v%s", name, version)
    signals = extract_only(name, version, work_dir)
    snippets = signals.get("build_rs", {}).get("flagged_snippets") or []
    classification = classify_with_vote(build_prompt(signals, snippets))

    result = {
        "crate": name,
        "version": version,
        "signals": signals,
        "classification": classification,
        "ground_truth": ground_truth_label,
        "correct": (
            classification["classification"] == ground_truth_label
            if ground_truth_label
            else None
        ),
    }
    out = RESULTS_DIR / f"{name}-{version}.json"
    out.write_text(json.dumps(result, indent=2), encoding="utf-8")
    return result
