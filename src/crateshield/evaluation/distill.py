import json
import logging
from pathlib import Path

from crateshield.config import ROOT, RESULTS_DIR
from crateshield.pipeline import analyze_crate

logger = logging.getLogger(__name__)

DISTILL_DIR = ROOT / "data" / "distillation"

def build_distillation_corpus(dataset_path: Path):
    DISTILL_DIR.mkdir(parents=True, exist_ok=True)
    out_file = DISTILL_DIR / "corpus.jsonl"
    
    if not dataset_path.exists():
        logger.error(f"Dataset not found at {dataset_path}")
        return

    dataset = json.loads(dataset_path.read_text(encoding="utf-8"))
    crates = dataset.get("crates", [])
    
    processed_count = 0
    skipped_count = 0
    
    with open(out_file, "w", encoding="utf-8") as f:
        for crate in crates:
            name = crate["name"]
            version = crate.get("version", "0.1.0")
            is_synthetic = crate.get("is_synthetic", False)
            ground_truth = crate["label"]
            source = crate.get("source", "unknown")
            
            result_file = RESULTS_DIR / f"{name}-{version}.json"
            
            # Use cached result if available, otherwise analyze
            if result_file.exists():
                try:
                    result = json.loads(result_file.read_text(encoding="utf-8"))
                except Exception:
                    result = analyze_crate(name, version, ground_truth_label=ground_truth)
            else:
                try:
                    result = analyze_crate(name, version, ground_truth_label=ground_truth)
                except Exception as e:
                    logger.warning(f"Failed to analyze {name}@{version}: {e}")
                    skipped_count += 1
                    continue
            
            signals = result.get("signals", {})
            classification_data = result.get("classification", {})
            
            gemini_label = classification_data.get("classification")
            gemini_reasoning = classification_data.get("reasoning", "")
            snippets = signals.get("build_rs", {}).get("flagged_snippets", [])
            
            # For real crates, Gemini must agree with Ground Truth to be useful for distillation.
            # If it disagreed on a REAL crate, we exclude it to prevent poisoning the fine-tuned model
            # with hallucinated labels on verified data.
            if not is_synthetic and gemini_label != ground_truth:
                logger.debug(f"Skipping {name}@{version}: Gemini predicted {gemini_label} but real label is {ground_truth}")
                skipped_count += 1
                continue
                
            # If it's synthetic, we trust Gemini's label since we don't have perfect ground truth for every random synthetic generation
            final_label = ground_truth if not is_synthetic else gemini_label
            
            # Format as an instruction-tuning pair
            prompt = {
                "crate": name,
                "is_synthetic": is_synthetic,
                "source": source,
                "label": final_label,
                "instruction": "Analyze the following Rust crate signals and source code snippets to determine if it is MALICIOUS or BENIGN.",
                "input": json.dumps({"signals": signals, "snippets": snippets}),
                "output": json.dumps({"classification": final_label, "reasoning": gemini_reasoning})
            }
            
            f.write(json.dumps(prompt) + "\n")
            processed_count += 1

    logger.info(f"Distillation complete. Wrote {processed_count} pairs to {out_file} (Skipped {skipped_count})")
