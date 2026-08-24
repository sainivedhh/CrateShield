from __future__ import annotations

import logging
from pathlib import Path

import requests

from crateshield.config import CRATES_API, CRATES_STATIC, RAW_DIR, USER_AGENT, ensure_dirs

logger = logging.getLogger(__name__)
_SESSION = requests.Session()
_SESSION.headers.update({"User-Agent": USER_AGENT, "Accept": "application/json"})


def crate_tarball_url(name: str, version: str) -> str:
    return f"{CRATES_STATIC}/{name}/{name}-{version}.crate"


def download_crate(name: str, version: str, dest_dir: Path | None = None) -> Path:
    """Download `{name}-{version}.crate` (a gzipped tarball)."""
    ensure_dirs()
    dest_dir = dest_dir or RAW_DIR
    dest_dir.mkdir(parents=True, exist_ok=True)
    path = dest_dir / f"{name}-{version}.crate"
    if path.exists() and path.stat().st_size > 0:
        return path

    url = crate_tarball_url(name, version)
    logger.info("Downloading %s", url)
    resp = _SESSION.get(url, timeout=60)
    resp.raise_for_status()
    path.write_bytes(resp.content)
    return path


def fetch_crate_metadata(name: str) -> dict:
    resp = _SESSION.get(f"{CRATES_API}/{name}", timeout=30)
    resp.raise_for_status()
    return resp.json()


def fetch_top_crates(n: int = 1000) -> list[dict]:
    """Page the crates.io API by downloads. Respect their User-Agent rule."""
    crates: list[dict] = []
    page = 1
    per_page = 100
    while len(crates) < n:
        resp = _SESSION.get(
            CRATES_API,
            params={"page": page, "per_page": per_page, "sort": "downloads"},
            timeout=30,
        )
        resp.raise_for_status()
        batch = resp.json().get("crates", [])
        if not batch:
            break
        crates.extend(batch)
        page += 1
    return crates[:n]
