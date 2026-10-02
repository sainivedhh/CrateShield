import json
from pathlib import Path
from crateshield.config import RESULTS_DIR, ROOT

def generate_report():
    ablation_file = RESULTS_DIR / "ablation.json"
    if not ablation_file.exists():
        ablation_file = RESULTS_DIR / "ablation_mini.json"
        if not ablation_file.exists():
            print("No ablation results found.")
            return

    with open(ablation_file, "r") as f:
        data = json.load(f)

    metrics = data.get("metrics", {})
    
    summary = []
    for k, v in metrics.items():
        summary.append({
            "model": k,
            "precision": v.get("precision", 0),
            "recall": v.get("recall", 0),
            "f1": v.get("f1", 0),
            "pr_auc": v.get("pr_auc", 0),
            "mcc": v.get("mcc", 0),
            "fpr": v.get("fpr", 0),
            "tp": v.get("tp", 0),
            "fp": v.get("fp", 0),
            "fn": v.get("fn", 0),
            "tn": v.get("tn", 0),
        })

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    with open(RESULTS_DIR / "summary.json", "w") as f:
        json.dump(summary, f, indent=2)

    docs_dir = ROOT / "docs"
    docs_dir.mkdir(parents=True, exist_ok=True)
    
    with open(docs_dir / "RESULTS.md", "w") as f:
        f.write("# Evaluation Results\n\n")
        f.write("| Condition | Precision | Recall | F1 | PR-AUC | MCC | FPR |\n")
        f.write("|-----------|-----------|--------|----|--------|-----|-----|\n")
        
        for item in summary:
            f.write(f"| {item['model']} | {item['precision']:.3f} | {item['recall']:.3f} | {item['f1']:.3f} | {item['pr_auc']:.3f} | {item['mcc']:.3f} | {item['fpr']:.3f} |\n")
            
        f.write("\n## Limitations\n")
        f.write("1. **Dataset Size**: The number of known malicious crates is very small. Evaluation on such limited data can result in high variance and may not generalize well to completely novel attack types.\n")
        f.write("2. **Label Noise from RustSec**: RustSec advisories sometimes conflate bugs, unmaintained crates, and outright malware. While we attempt to filter for true malware, some label noise remains.\n")
        f.write("3. **Possible Overfitting**: Despite group-based cross-validation, static signals (e.g. typosquatting score, build.rs presence) can easily overfit to the specific set of known backdoors. The dataset is too small to draw strong, definitive conclusions about production readiness without further validation on a massive unlabelled stream.\n")

if __name__ == "__main__":
    generate_report()
