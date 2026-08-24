from __future__ import annotations

import json
import logging
import time
from datetime import datetime, timezone
from pathlib import Path

from tree_sitter import Language, Parser
import tree_sitter_rust as tsrust

from crateshield.config import WORK_DIR
from crateshield.ingestion.downloader import fetch_top_crates
from crateshield.ingestion.extractor import load_crate_files
from crateshield.signals.build_rs import analyze_build_rs
from crateshield.signals.dependencies import analyze_dependencies
from crateshield.signals.metadata import extract_metadata
from crateshield.signals.proc_macro import analyze_proc_macro
from crateshield.signals.typosquat import analyze_typosquatting
from crateshield.signals.unsafe_ffi import analyze_unsafe_ffi

logger = logging.getLogger(__name__)

_PARSER: Parser | None = None
_TOP_CRATES_CACHE_FILE = WORK_DIR / "top_crates_cache.json"
_TOP_CRATES_TTL_SECONDS = 24 * 60 * 60  # refresh once a day
_TOP_CRATES_N = 1000


def rust_parser() -> Parser:
    global _PARSER
    if _PARSER is None:
        _PARSER = Parser(Language(tsrust.language()))
    return _PARSER


def _load_top_crate_names() -> list[str]:
    """Popular crate names used as typosquat comparison targets. Cached to
    disk for _TOP_CRATES_TTL_SECONDS so every /api/predict call doesn't
    re-page crates.io for 1000 crates."""
    if _TOP_CRATES_CACHE_FILE.exists():
        try:
            cached = json.loads(_TOP_CRATES_CACHE_FILE.read_text(encoding="utf-8"))
            if time.time() - cached.get("fetched_at", 0) < _TOP_CRATES_TTL_SECONDS:
                return cached["names"]
        except Exception:
            pass  # fall through and refetch on any cache corruption

    try:
        crates = fetch_top_crates(_TOP_CRATES_N)
        names = [c.get("id") or c.get("name") for c in crates if c.get("id") or c.get("name")]
        WORK_DIR.mkdir(parents=True, exist_ok=True)
        _TOP_CRATES_CACHE_FILE.write_text(
            json.dumps({"fetched_at": time.time(), "names": names}), encoding="utf-8"
        )
        return names
    except Exception as exc:
        logger.warning("Could not fetch top crates for typosquat check: %s", exc)
        if _TOP_CRATES_CACHE_FILE.exists():
            try:
                return json.loads(_TOP_CRATES_CACHE_FILE.read_text(encoding="utf-8"))["names"]
            except Exception:
                pass
        return []


def extract_all_signals(
    name: str,
    version: str,
    crate_dir: Path,
    top_crates: list[str] | None = None,
) -> dict:
    files = load_crate_files(crate_dir)
    parser = rust_parser()
    if top_crates is None:
        top_crates = _load_top_crate_names()
    return {
        "crate": name,
        "version": version,
        "analysis_timestamp": datetime.now(timezone.utc).isoformat(),
        "build_rs": analyze_build_rs(files, parser),
        "unsafe_ffi": analyze_unsafe_ffi(files, parser),
        "proc_macro": analyze_proc_macro(files),
        "typosquatting": analyze_typosquatting(name, top_crates),
        "dependencies": analyze_dependencies(files),
        "metadata": extract_metadata(files, name, version),
    }
