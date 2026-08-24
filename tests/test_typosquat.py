from crateshield.signals.typosquat import analyze_typosquatting, levenshtein


def test_levenshtein_identity():
    assert levenshtein("serde", "serde") == 0


def test_flags_near_miss():
    r = analyze_typosquatting("serde-jsonn", ["serde_json", "tokio", "cc"])
    assert r["target"] == "serde_json"
    assert r["edit_distance"] <= 2
    assert r["score"] >= 0.85
