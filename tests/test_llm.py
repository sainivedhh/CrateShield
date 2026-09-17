import pytest
from crateshield.llm.client import classify_with_vote

@pytest.mark.llm
def test_llm_classification():
    # This test requires a live GEMINI_API_KEY_1 and network access.
    # It is skipped in CI by using 'pytest -m "not llm"'.
    prompt = [{"role": "user", "content": "Return a valid JSON classification. Respond with {\"classification\": \"BENIGN\"}"}]
    try:
        result = classify_with_vote(prompt, votes=1)
        assert result["classification"] in ("BENIGN", "MALICIOUS")
    except RuntimeError as e:
        if "No GEMINI_API_KEY" in str(e):
            pytest.skip("No GEMINI_API_KEY found, skipping live LLM test")
        else:
            raise
