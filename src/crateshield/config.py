from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

ROOT = Path(__file__).resolve().parents[2]
WORK_DIR = Path(os.getenv("RUSTDETECT_WORK_DIR", ROOT / "data"))
RAW_DIR = WORK_DIR / "raw"
EXTRACTED_DIR = WORK_DIR / "extracted"
SIGNALS_DIR = WORK_DIR / "signals"
RESULTS_DIR = WORK_DIR / "results"

USER_AGENT = os.getenv(
    "RUSTDETECT_USER_AGENT",
    "crateshield/0.1 (academic-research; +https://github.com/rustsec/advisory-db)",
)
CRATES_STATIC = "https://static.crates.io/crates"
CRATES_API = "https://crates.io/api/v1/crates"
RUSTSEC_RAW = (
    "https://raw.githubusercontent.com/rustsec/advisory-db/main/crates"
)
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-3.6-flash")
TEMPERATURE = 0.0
LLM_VOTES = 3
RAW_LLM_TOKEN_CAP = 12_000

MALICIOUS_CATEGORIES = {"malicious-code", "backdoor"}
TYPOSQUAT_THRESHOLD = 0.85
TYPOSQUAT_MAX_DISTANCE = 2

SENSITIVE_ENV_KEYS = (
    "AWS_", "GITHUB_TOKEN", "GH_TOKEN", "SSH_", "CARGO_REGISTRY_TOKEN",
    "NPM_TOKEN", "PYPI_TOKEN", "PRIVATE_KEY", "SECRET", "PASSWORD",
    "API_KEY", "ACCESS_KEY", "TOKEN",
)
BENIGN_ENV_KEYS = {
    "OUT_DIR", "CARGO_MANIFEST_DIR", "CARGO_PKG_NAME", "CARGO_PKG_VERSION",
    "CARGO_CFG_TARGET_OS", "CARGO_CFG_TARGET_ARCH", "TARGET", "HOST",
    "OPT_LEVEL", "PROFILE", "NUM_JOBS", "CARGO_FEATURE_",
}


def ensure_dirs() -> None:
    for d in (RAW_DIR, EXTRACTED_DIR, SIGNALS_DIR, RESULTS_DIR):
        d.mkdir(parents=True, exist_ok=True)
