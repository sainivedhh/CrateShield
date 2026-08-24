from __future__ import annotations

from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score


def _bin(label: str, positive: set[str]) -> int:
    return 1 if label in positive else 0


def compute_metrics(
    results: list[dict],
    positive: set[str] | None = None,
    precision_positive_gt: set[str] | None = None,
) -> dict:
    """
    Default: MALICIOUS+SUSPICIOUS are the positive class.
    If precision_positive_gt is set (e.g. {MALICIOUS}), SUSPICIOUS ground
    truth is dropped from the precision denominator (Section 12.3).
    """
    positive = positive or {"MALICIOUS", "SUSPICIOUS"}
    y_true, y_pred = [], []
    for r in results:
        gt = r["ground_truth"]
        if precision_positive_gt is not None and gt == "SUSPICIOUS":
            continue
        y_true.append(_bin(gt, positive if precision_positive_gt is None else precision_positive_gt))
        y_pred.append(_bin(r["prediction"], positive))

    if not y_true:
        return {"precision": 0, "recall": 0, "f1": 0, "fpr": 0, "tp": 0, "fp": 0, "fn": 0, "tn": 0}

    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    return {
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
        "fpr": float(fp / (fp + tn)) if (fp + tn) else 0.0,
        "tp": int(tp), "fp": int(fp), "fn": int(fn), "tn": int(tn),
        "n_positive": int(sum(y_true)),
        "n_negative": int(len(y_true) - sum(y_true)),
    }


def print_ablation_table(metrics: dict) -> None:
    print(f"\n{'Condition':<25} {'Precision':>10} {'Recall':>10} {'F1':>10} {'FPR':>10}")
    print("-" * 65)
    labels = {
        "condition_a": "A: Structured + LLM",
        "condition_b": "B: Raw LLM Baseline",
        "condition_c": "C: cargo-audit",
    }
    for key, label in labels.items():
        m = metrics[key]
        print(
            f"{label:<25} {m['precision']:>10.3f} {m['recall']:>10.3f} "
            f"{m['f1']:>10.3f} {m['fpr']:>10.3f}"
        )
