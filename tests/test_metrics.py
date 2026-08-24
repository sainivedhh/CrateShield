from crateshield.evaluation.metrics import compute_metrics


def test_perfect():
    rows = [
        {"ground_truth": "MALICIOUS", "prediction": "MALICIOUS"},
        {"ground_truth": "BENIGN", "prediction": "BENIGN"},
    ]
    m = compute_metrics(rows)
    assert m["precision"] == 1.0
    assert m["recall"] == 1.0
    assert m["fpr"] == 0.0
