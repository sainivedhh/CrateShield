from __future__ import annotations

import os
import time
import random
import threading
from collections import Counter

import google.genai as genai
from google.genai import types
from google.genai.errors import APIError

from crateshield.config import GEMINI_MODEL, LLM_VOTES, TEMPERATURE
from crateshield.llm.parser import ParseError, parse_llm_response


_keys = []
for k, v in os.environ.items():
    if k.startswith("GEMINI_API_KEY") and v.strip():
        _keys.append(v.strip())
if not _keys:
    raise RuntimeError("No GEMINI_API_KEY* found in environment")
_keys = list(set(_keys))  # Deduplicate

_key_idx = 0
_key_lock = threading.Lock()

def _client() -> genai.Client:
    global _key_idx
    with _key_lock:
        key = _keys[_key_idx % len(_keys)]
        _key_idx += 1
    return genai.Client(api_key=key)


def query_gemini(messages: list[dict], model: str | None = None) -> str:
    """Send an OpenAI-style messages list to Gemini and return the text response."""

    # Convert OpenAI-style messages to a single prompt string.
    # Gemini's generate_content accepts a plain string or a list of Parts.
    prompt_parts = []
    for msg in messages:
        role = msg.get("role", "user")
        content = msg.get("content", "")
        if role == "system":
            prompt_parts.append(f"[SYSTEM]\n{content}")
        elif role == "assistant":
            prompt_parts.append(f"[ASSISTANT]\n{content}")
        else:
            prompt_parts.append(f"[USER]\n{content}")

    prompt = "\n\n".join(prompt_parts)

    max_retries = 10
    base_delay = 2
    for attempt in range(max_retries):
        try:
            client = _client()
            response = client.models.generate_content(
                model=model or GEMINI_MODEL,
                contents=prompt,
                config=types.GenerateContentConfig(
                    temperature=TEMPERATURE,
                    response_mime_type="application/json",
                ),
            )
            return response.text or ""
        except APIError as e:
            if e.code == 429:
                delay = base_delay * (2 ** attempt) + random.uniform(0, 1)
                print(f"[429 Quota Exceeded] Retrying in {delay:.1f}s... (Attempt {attempt+1}/{max_retries})")
                time.sleep(delay)
            else:
                raise e
    
    raise RuntimeError("Max retries exceeded for Gemini API")


def classify_with_vote(messages: list[dict], votes: int = LLM_VOTES) -> dict:
    parsed = []
    raws = []
    for _ in range(votes):
        raw = query_gemini(messages)
        raws.append(raw)
        try:
            parsed.append(parse_llm_response(raw))
        except (ParseError, Exception):
            retry = messages + [
                {"role": "user", "content": "Return ONLY the JSON object. No markdown."}
            ]
            parsed.append(parse_llm_response(query_gemini(retry)))
    labels = Counter(p["classification"] for p in parsed)
    winner = labels.most_common(1)[0][0]
    chosen = next(p for p in parsed if p["classification"] == winner)
    chosen["votes"] = dict(labels)
    chosen["raw_responses"] = raws
    return chosen
