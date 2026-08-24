from __future__ import annotations

import json
import re

ALLOWED_CLASS = {"MALICIOUS", "SUSPICIOUS", "BENIGN"}
ALLOWED_CONF = {"HIGH", "MEDIUM", "LOW"}
ALLOWED_ACTION = {"Block", "Manual review", "Pass"}


class ParseError(ValueError):
    pass


def parse_llm_response(text: str) -> dict:
    clean = text.strip()
    if clean.startswith("```"):
        parts = clean.split("```")
        clean = parts[1]
        if clean.startswith("json"):
            clean = clean[4:]
    match = re.search(r"\{.*\}", clean, re.S)
    if not match:
        raise ParseError("no JSON object in model output")
    result = json.loads(match.group(0))
    if result.get("classification") not in ALLOWED_CLASS:
        raise ParseError(f"bad classification: {result.get('classification')}")
    if result.get("confidence") not in ALLOWED_CONF:
        raise ParseError(f"bad confidence: {result.get('confidence')}")
    result.setdefault("primary_signals", [])
    result.setdefault("reasoning", "")
    if result.get("recommended_action") not in ALLOWED_ACTION:
        result["recommended_action"] = (
            "Block" if result["classification"] == "MALICIOUS" else
            "Manual review" if result["classification"] == "SUSPICIOUS" else "Pass"
        )
    return result
