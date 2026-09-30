from __future__ import annotations

import concurrent.futures
import json
import logging
from pathlib import Path

from crateshield.config import RAW_LLM_TOKEN_CAP, ROOT
from crateshield.evaluation.baseline_cargo import run_cargo_audit
from crateshield.evaluation.metrics import compute_metrics, print_ablation_table
from crateshield.ingestion.downloader import download_crate
from crateshield.ingestion.extractor import collect_rs_files, extract_crate
from crateshield.llm.client import classify_with_vote
from crateshield.llm.prompt import build_prompt
from crateshield.pipeline import analyze_crate

logger = logging.getLogger(__name__)

# Try to import torch and transformers for the fine-tuned model, but allow it to fail gracefully if not installed
try:
    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer
    HAS_ML = True
except ImportError:
    HAS_ML = False
    logger.warning("ML dependencies not found. Fine-tuned model ablation will be mocked or skipped.")

def _truncate(text: str, cap: int = RAW_LLM_TOKEN_CAP) -> tuple[str, bool]:
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

# Global cache for the fine-tuned model to avoid reloading
_ft_model = None
_ft_tokenizer = None

def get_finetuned_prediction(instruction: str, input_json: str) -> str:
    global _ft_model, _ft_tokenizer
    if not HAS_ML:
        return "BENIGN" # Stub if no ML env
        
    model_path = ROOT / "models" / "finetuned" / "final"
    if not model_path.exists():
        logger.warning(f"Fine-tuned model not found at {model_path}. Returning default BENIGN.")
        return "BENIGN"
        
    if _ft_model is None:
        logger.info("Loading fine-tuned model for evaluation...")
        _ft_tokenizer = AutoTokenizer.from_pretrained(str(model_path))
        _ft_model = AutoModelForCausalLM.from_pretrained(str(model_path), torch_dtype=torch.float16, device_map="auto")
        
    prompt = f"Instruction: {instruction}\nInput: {input_json}\nOutput: "
    inputs = _ft_tokenizer(prompt, return_tensors="pt").to(_ft_model.device)
    
    with torch.no_grad():
        outputs = _ft_model.generate(**inputs, max_new_tokens=100)
    
    response = _ft_tokenizer.decode(outputs[0][inputs.input_ids.shape[1]:], skip_special_tokens=True)
    
    if "MALICIOUS" in response.upper():
        return "MALICIOUS"
    return "BENIGN"

def _process_single_test_record(item: dict, work_dir: Path) -> dict | None:
    # item comes from test.jsonl
    name = item["crate"]
    gt = item["label"]
    version = "0.1.0" # Simplification for test records, in reality we should trace version
    
    try:
        # A: Structured + Gemini
        # We can just run it or read from cache (analyze_crate does cache logic if we implemented it, or we just call it)
        result_a = analyze_crate(name, version, work_dir, ground_truth_label=gt)
        
        # B: Structured + FineTuned Model
        pred_b = get_finetuned_prediction(item.get("instruction", ""), item.get("input", "{}"))
        
        # C: Raw Code + Gemini
        tarball = download_crate(name, version)
        crate_dir = extract_crate(tarball)
        result_c = run_condition_b(name, version, crate_dir)
        
        # D: Cargo-Audit
        result_d = run_cargo_audit(crate_dir)
        
        return {
            "a_structured_gemini": {"ground_truth": gt, "prediction": result_a["classification"]["classification"]},
            "b_structured_finetuned": {"ground_truth": gt, "prediction": pred_b},
            "c_raw_gemini": {"ground_truth": gt, "prediction": result_c["classification"]},
            "d_cargo_audit": {"ground_truth": gt, "prediction": result_d["prediction"]},
        }
    except Exception as exc:
        logger.warning("SKIPPED %s: %s", name, exc)
        return None

def run_ablation(test_jsonl_path: Path, work_dir: Path, max_workers: int = 2) -> dict:
    records = []
    with open(test_jsonl_path, "r", encoding="utf-8") as f:
        for line in f:
            records.append(json.loads(line))
            
    a, b, c, d = [], [], [], []
    
    # We use fewer workers to avoid OOM if loading the ML model locally
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(_process_single_test_record, item, work_dir): item for item in records}
        for future in concurrent.futures.as_completed(futures):
            res = future.result()
            if res:
                a.append(res["a_structured_gemini"])
                b.append(res["b_structured_finetuned"])
                c.append(res["c_raw_gemini"])
                d.append(res["d_cargo_audit"])

    metrics = {
        "condition_a_structured_gemini": compute_metrics(a),
        "condition_b_structured_finetuned": compute_metrics(b),
        "condition_c_raw_gemini": compute_metrics(c),
        "condition_d_cargo_audit": compute_metrics(d),
    }
    
    n_total = len(records)
    n_evaluated = len(a)
    logger.info("Ablation complete: %d/%d crates evaluated (%d skipped)",
                n_evaluated, n_total, n_total - n_evaluated)
    print_ablation_table(metrics)
    
    return {"metrics": metrics, "n_evaluated": n_evaluated, "n_total": n_total,
            "n_skipped": n_total - n_evaluated}
