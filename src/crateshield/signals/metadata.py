from __future__ import annotations

import tomllib


def extract_metadata(files: dict, name: str, version: str) -> dict:
    toml_text = files.get("cargo_toml") or ""
    try:
        data = tomllib.loads(toml_text)
    except tomllib.TOMLDecodeError:
        data = {}

    pkg = data.get("package") or {}

    # authors can be a list or a string depending on the Cargo.toml style
    authors_raw = pkg.get("authors")
    if isinstance(authors_raw, list):
        authors = ", ".join(authors_raw)
    else:
        authors = authors_raw

    # keywords is always a list in valid Cargo.toml
    keywords = pkg.get("keywords") or []

    return {
        "name": name,
        "version": version,
        "description": pkg.get("description"),
        "authors": authors,
        "keywords": keywords,
        "repository": pkg.get("repository"),
        "has_build_rs": files.get("build_rs") is not None,
    }
