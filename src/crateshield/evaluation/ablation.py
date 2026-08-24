from __future__ import annotations

import concurrent.futures
import json
import logging
from pathlib import Path

from crateshield.config import RAW_LLM_TOKEN_CAP
from crateshield.evaluation.baseline_cargo import run_cargo_audit
from crateshield.evaluation.metrics import compute_metrics, print_ablation_table
from crateshield.ingestion.downloader import download_crate
from crateshield.ingestion.extractor import collect_rs_files, extract_crate
from crateshield.llm.client import classify_with_vote
from crateshield.llm.prompt import build_prompt
from crateshield.pipeline import analyze_crate


def _truncate(text: str, cap: int = RAW_LLM_TOKEN_CAP) -> tuple[str, bool]:
    # rough 4 chars/token
    limit = cap * 4
    if len(text) <= limit:
        return text, False
    return text[:limit], True


def run_condition_b(name: str, version: str, crate_dir: Path) -> dict:
    chunks = []
    build = crate_dir / "build.rs"
    if build.exists():
        chunks.append("// FILE: build.rs\n" + build.read_text(encoding="utf-8", errors="replace"))
    toml = crate_dir / "Cargo.toml"
    if toml.exists():
        chunks.append("// FILE: Cargo.toml\n" + toml.read_text(encoding="utf-8", errors="replace"))
    for p in collect_rs_files(crate_dir)[:30]:
        chunks.append(f"// FILE: {p.relative_to(crate_dir)}\n" + p.read_text(encoding="utf-8", errors="replace"))
    raw, truncated = _truncate("\n\n".join(chunks))
    pred = classify_with_vote(build_prompt({}, raw_source=raw))
    pred["truncated"] = truncated
    return pred


import time

logger = logging.getLogger(__name__)

def _process_single_crate(item: dict, work_dir: Path) -> dict | None:
    name, version, gt = item["name"], item.get("version") or "0.1.0", item["label"]
    if version == "yanked" or not version:
        logger.warning("SKIPPED %s: version is 'yanked' or empty — not resolved in dataset", name)
        return None
    try:
        result_a = analyze_crate(name, version, work_dir, ground_truth_label=gt)
        tarball = download_crate(name, version)
        crate_dir = extract_crate(tarball)
        result_b = run_condition_b(name, version, crate_dir)
        result_c = run_cargo_audit(crate_dir)
        return {
            "a": {"ground_truth": gt, "prediction": result_a["classification"]["classification"]},
            "b": {"ground_truth": gt, "prediction": result_b["classification"]},
            "c": {"ground_truth": gt, "prediction": result_c["prediction"]},
        }
    except Exception as exc:
        logger.warning("SKIPPED %s@%s: %s", name, version, exc)
        return None


def run_ablation(dataset_path: Path, work_dir: Path, max_workers: int = 5) -> dict:
    dataset = json.loads(dataset_path.read_text(encoding="utf-8"))
    a, b, c = [], [], []

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(_process_single_crate, item, work_dir): item for item in dataset["crates"]}
        for future in concurrent.futures.as_completed(futures):
            res = future.result()
            if res:
                a.append(res["a"])
                b.append(res["b"])
                c.append(res["c"])

    metrics = {
        "condition_a": compute_metrics(a),
        "condition_b": compute_metrics(b),
        "condition_c": compute_metrics(c),
    }
    n_total = len(dataset["crates"])
    n_evaluated = len(a)
    logger.info("Ablation complete: %d/%d crates evaluated (%d skipped)",
                n_evaluated, n_total, n_total - n_evaluated)
    print_ablation_table(metrics)
    return {"metrics": metrics, "n_evaluated": n_evaluated, "n_total": n_total,
            "n_skipped": n_total - n_evaluated}
