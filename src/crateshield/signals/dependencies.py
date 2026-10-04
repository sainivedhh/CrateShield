from __future__ import annotations

import tomllib


def analyze_dependencies(files: dict) -> dict:
    toml_text = files.get("cargo_toml") or ""
    try:
        data = tomllib.loads(toml_text)
    except tomllib.TOMLDecodeError:
        data = {}

    deps = list((data.get("dependencies") or {}).keys())
    dev = list((data.get("dev-dependencies") or {}).keys())

    # Check for exact-pinned versions (="1.2.3" style)
    pinned = any(
        isinstance(v, str) and v.startswith("=")
        for v in (data.get("dependencies") or {}).values()
    )

    suspicious = []
    evidence = []

    for dep in deps:
        if any(
            bad in dep.lower()
            for bad in ("pastebin", "discord", "ngrok", "localtunnel")
        ):
            suspicious.append(dep)
            evidence.append(
                {
                    "file": "Cargo.toml",
                    "line_start": 1,
                    "line_end": 1,
                    "snippet": f"{dep} = ...",
                }
            )

    return {
        "count": len(deps),
        "dev_dependency_count": len(dev),
        "names": deps,
        "suspicious": suspicious,
        "evidence": evidence,
        "pinned": pinned,
        "dependency_purpose_consistency": None,
    }
