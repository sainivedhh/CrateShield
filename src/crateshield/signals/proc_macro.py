from __future__ import annotations

import re

SUSPICIOUS_IMPORTS = ("std::process", "std::net", "std::os::raw", "reqwest", "ureq", "std::fs")


def analyze_proc_macro(files: dict) -> dict:
    toml = files.get("cargo_toml") or ""
    is_pm = bool(re.search(r"proc-macro\s*=\s*true", toml))
    suspicious: list[str] = []
    if is_pm:
        blob = "\n".join(
            p.read_text(encoding="utf-8", errors="replace")
            for p in (files.get("source_files") or [])
        )
        for s in SUSPICIOUS_IMPORTS:
            if s in blob:
                suspicious.append(s)
    return {
        "is_proc_macro": is_pm,
        "proc_macro_suspicious_imports": suspicious,
        "proc_macro_consistency_score": None if not is_pm else (0.2 if suspicious else 0.8),
    }
