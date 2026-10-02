from __future__ import annotations

import re

SUSPICIOUS_IMPORTS = (
    "std::process",
    "std::net",
    "std::os::raw",
    "reqwest",
    "ureq",
    "std::fs",
)


def analyze_proc_macro(files: dict) -> dict:
    toml = files.get("cargo_toml") or ""
    is_pm = bool(re.search(r"proc-macro\s*=\s*true", toml))
    suspicious: list[str] = []
    evidence = []
    
    if is_pm:
        for p in (files.get("source_files") or []):
            text = p.read_text(encoding="utf-8", errors="replace")
            lines = text.splitlines()
            for i, line in enumerate(lines):
                for s in SUSPICIOUS_IMPORTS:
                    if s in line:
                        if s not in suspicious:
                            suspicious.append(s)
                        if len(evidence) < 50:
                            pad = 2
                            start = max(0, i - pad)
                            end = min(len(lines), i + pad + 1)
                            snippet = "\n".join(lines[start:end])
                            evidence.append({
                                "file": str(p.name),
                                "line_start": i + 1,
                                "line_end": i + 1,
                                "snippet": snippet
                            })
                            
    return {
        "is_proc_macro": is_pm,
        "proc_macro_suspicious_imports": suspicious,
        "evidence": evidence,
        "proc_macro_consistency_score": None
        if not is_pm
        else (0.2 if suspicious else 0.8),
    }
