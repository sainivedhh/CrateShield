import json
import logging
import random
from collections import defaultdict
from pathlib import Path

from crateshield.config import ROOT

logger = logging.getLogger(__name__)

DISTILL_DIR = ROOT / "data" / "distillation"

def perform_split(val_ratio=0.15, test_ratio=0.15, seed=42):
    """
    Splits corpus.jsonl into train.jsonl, val.jsonl, and test.jsonl.
    Enforces that test.jsonl contains ONLY real (non-synthetic) crates.
    Enforces group-aware splitting for synthetic crates so families do not leak.
    """
    corpus_file = DISTILL_DIR / "corpus.jsonl"
    if not corpus_file.exists():
        logger.error(f"Cannot find {corpus_file}")
        return

    random.seed(seed)
    
    with open(corpus_file, "r", encoding="utf-8") as f:
        records = [json.loads(line) for line in f]
        
    real_records = [r for r in records if not r.get("is_synthetic")]
    syn_records = [r for r in records if r.get("is_synthetic")]
    
    # 1. Split Real Records (Train, Val, Test)
    # Stratify real records by (label, source)
    real_strata = defaultdict(list)
    for r in real_records:
        stratum = (r.get("label"), r.get("source"))
        real_strata[stratum].append(r)
        
    train_out, val_out, test_out = [], [], []
    
    for stratum, items in real_strata.items():
        random.shuffle(items)
        n = len(items)
        n_test = int(n * test_ratio)
        n_val = int(n * val_ratio)
        
        test_out.extend(items[:n_test])
        val_out.extend(items[n_test:n_test + n_val])
        train_out.extend(items[n_test + n_val:])
        
    # 2. Split Synthetic Records (Train, Val ONLY)
    # Group by synthetic family
    syn_families = defaultdict(list)
    for r in syn_records:
        name = r.get("crate", "")
        # e.g., syn_buildrs_123 -> syn_buildrs
        parts = name.split("_")
        family = "_".join(parts[:2]) if len(parts) >= 2 else name
        syn_families[family].append(r)
        
    # We want roughly val_ratio of synthetic items in validation. 
    # Since we can only move whole families, we shuffle families and add them until the ratio is met.
    families = list(syn_families.keys())
    random.shuffle(families)
    
    target_syn_val = int(len(syn_records) * val_ratio)
    current_syn_val = 0
    
    for family in families:
        items = syn_families[family]
        if current_syn_val < target_syn_val:
            val_out.extend(items)
            current_syn_val += len(items)
        else:
            train_out.extend(items)
            
    # Write outputs
    def write_jsonl(path, data):
        random.shuffle(data) # Shuffle final sets
        with open(path, "w", encoding="utf-8") as f:
            f.writelines(json.dumps(row) + "\n" for row in data)
        logger.info(f"Wrote {len(data)} records to {path.name}")
        
    write_jsonl(DISTILL_DIR / "train.jsonl", train_out)
    write_jsonl(DISTILL_DIR / "val.jsonl", val_out)
    write_jsonl(DISTILL_DIR / "test.jsonl", test_out)
    
    logger.info("Split complete. Test set contains ONLY real crates.")

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    perform_split()
