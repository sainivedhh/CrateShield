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

    return {
        "count": len(deps),
        "dev_dependency_count": len(dev),
        "names": deps,
        "suspicious": [],
        "pinned": pinned,
        "dependency_purpose_consistency": None,
    }
