from __future__ import annotations

import json
import logging
import re
import tomllib
from pathlib import Path

import requests

from crateshield.config import MALICIOUS_CATEGORIES, USER_AGENT

logger = logging.getLogger(__name__)

ADVISORY_API = "https://api.github.com/repos/rustsec/advisory-db/contents/crates"
ADVISORY_RAW = "https://raw.githubusercontent.com/rustsec/advisory-db/main"
CRATES_IO_API = "https://crates.io/api/v1/crates"
CRATES_IO_INDEX = "https://index.crates.io"
CRATES_IO_CDN = "https://static.crates.io/crates"


def _session() -> requests.Session:
    import os
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry

    s = requests.Session()

    retry_strategy = Retry(
        total=5,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["HEAD", "GET", "OPTIONS"]
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    s.mount("https://", adapter)
    s.mount("http://", adapter)

    s.headers.update({"User-Agent": USER_AGENT, "Accept": "application/vnd.github+json"})
    token = os.getenv("GITHUB_TOKEN")
    if token:
        s.headers["Authorization"] = f"Bearer {token}"
    return s


def _index_path(name: str) -> str:
    """Return the sparse-index subpath for a given crate name.

    Rules from the Cargo sparse-index spec:
      1-char  → 1/{name}
      2-char  → 2/{name}
      3-char  → 3/{first_char}/{name}
      4+-char → {first_two}/{next_two}/{name}
    """
    n = name.lower()
    if len(n) == 1:
        return f"1/{n}"
    if len(n) == 2:
        return f"2/{n}"
    if len(n) == 3:
        return f"3/{n[0]}/{n}"
    return f"{n[:2]}/{n[2:4]}/{n}"


def _resolve_from_sparse_index(name: str, session: requests.Session) -> str | None:
    """Look up a crate in the crates.io sparse index.

    The sparse index at index.crates.io is a separate git-backed store that
    *often still contains entries for crates that were fully deleted* from the
    registry API.  Each line in the response is a JSON object per published
    version.  We prefer the most-recent yanked version; if none is yanked we
    take the most-recent overall (this covers the case where the whole crate
    was deleted before being marked yanked).
    """
    path = _index_path(name)
    try:
        resp = session.get(
            f"{CRATES_IO_INDEX}/{path}",
            headers={"User-Agent": USER_AGENT, "Accept": "text/plain"},
            timeout=15,
        )
        if resp.status_code == 404:
            return None
        resp.raise_for_status()

        entries = []
        for line in resp.text.strip().splitlines():
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue

        # Prefer the most-recent yanked entry
        yanked = [e["vers"] for e in entries if e.get("yanked")]
        if yanked:
            logger.info("Sparse-index: found yanked version(s) %s for %s", yanked, name)
            return yanked[-1]  # last = most recently published

        # Fall back to most-recently published version (crate deleted before yank)
        if entries:
            ver = entries[-1]["vers"]
            logger.info("Sparse-index: no yanked version; using newest %s for %s", ver, name)
            return ver

    except Exception as exc:
        logger.debug("Sparse-index lookup failed for %s: %s", name, exc)
    return None


def _version_from_advisory(advisory: dict) -> str | None:
    """Derive a candidate version from the advisory [versions].patched field.

    If the advisory says patched = ['>= 1.0.1'] the malicious release is
    likely 1.0.0 (one patch below the fix).
    """
    versions_section = advisory.get("versions") or {}
    patched = versions_section.get("patched") or []
    for req in patched:
        m = re.match(r"[><=^~\s]*(\d+)\.(\d+)\.(\d+)", str(req).strip())
        if m:
            major, minor, patch = int(m.group(1)), int(m.group(2)), int(m.group(3))
            if patch > 0:
                return f"{major}.{minor}.{patch - 1}"
            if minor > 0:
                return f"{major}.{minor - 1}.0"
            if major > 0:
                return f"{major - 1}.0.0"
    return None


def _cdn_version_exists(name: str, version: str, session: requests.Session) -> bool:
    """Check if a specific version exists on the static CDN (works for deleted crates)."""
    url = f"{CRATES_IO_CDN}/{name}/{name}-{version}.crate"
    try:
        resp = session.head(url, headers={"User-Agent": USER_AGENT}, timeout=10)
        return resp.status_code == 200
    except Exception:
        return False


def resolve_malicious_version(name: str, advisory: dict, session: requests.Session) -> str | None:
    """Three-strategy version resolution for malicious crates.

    Strategy 1 – Registry API: query /api/v1/crates/{name}/versions for yanked entries.
    Strategy 2 – Sparse index: query index.crates.io (survives full deletions).
    Strategy 3 – Advisory + CDN: derive version from advisory TOML, verify via HEAD.

    Returns the version string or None if all strategies fail.
    """
    headers = {"User-Agent": USER_AGENT}

    # ── Strategy 1: registry API ──────────────────────────────────────────────
    try:
        resp = session.get(f"{CRATES_IO_API}/{name}/versions", headers=headers, timeout=30)
        if resp.status_code == 200:
            versions = resp.json().get("versions", [])
            yanked = [v["num"] for v in versions if v.get("yanked")]
            if yanked:
                logger.info("[S1] Registry API: yanked version %s for %s", yanked[0], name)
                return yanked[0]
            if versions:
                logger.info("[S1] Registry API: no yanked; using newest %s for %s",
                            versions[0]["num"], name)
                return versions[0]["num"]
    except Exception as exc:
        logger.debug("[S1] Registry API failed for %s: %s", name, exc)

    # ── Strategy 2: sparse index ──────────────────────────────────────────────
    version = _resolve_from_sparse_index(name, session)
    if version:
        logger.info("[S2] Sparse index resolved %s → %s", name, version)
        return version

    # ── Strategy 3: advisory hint + CDN HEAD check ────────────────────────────
    candidate = _version_from_advisory(advisory)
    common_fallbacks = ["1.0.0", "0.1.0", "0.0.1", "0.1.1", "0.2.0", "1.0.1", "0.0.2"]
    for ver in ([candidate] if candidate else []) + common_fallbacks:
        if ver and _cdn_version_exists(name, ver, session):
            logger.info("[S3] CDN probe: found %s@%s", name, ver)
            return ver

    logger.warning("All resolution strategies failed for malicious crate %s", name)
    return None


def fetch_malicious_advisories(session: requests.Session | None = None) -> list[dict]:
    s = session or _session()
    crates = s.get(ADVISORY_API, timeout=30)
    crates.raise_for_status()
    out: list[dict] = []

    for entry in crates.json():
        if entry.get("type") != "dir": continue
        listing = s.get(entry["url"], timeout=30)
        listing.raise_for_status()
        for f in listing.json():
            if not f["name"].endswith(".md"): continue
            raw = s.get(f"{ADVISORY_RAW}/{f['path']}", timeout=30)
            raw.raise_for_status()
            m = re.search(r"```toml\s*(.*?)```", raw.text, re.S)
            if not m: continue
            try:
                parsed = tomllib.loads(m.group(1))
            except tomllib.TOMLDecodeError as e:
                logger.debug("Failed to parse advisory TOML for %s: %s", f["path"], e)
                continue

            # RustSec advisories nest fields under [advisory].
            # Flatten that section to the top level so downstream code uses
            # adv.get("package"), adv.get("categories"), etc. directly.
            adv: dict = {}
            adv.update(parsed.get("advisory") or {})
            for section, value in parsed.items():
                if section != "advisory":
                    adv.setdefault(section, value)

            cats = set(adv.get("categories") or [])
            kwds = set(adv.get("keywords") or [])
            combined_tags = cats | kwds
            malicious_tags = {"malicious", "backdoor", "malicious-code", "malware", "typosquatting"}

            is_informational = bool(adv.get("informational"))

            if (combined_tags & malicious_tags) and not is_informational:
                adv["path"] = f["path"]
                adv["categories"] = list(combined_tags & malicious_tags)
                out.append(adv)
                logger.info("Labeled Malicious %s (%s)", adv.get("package"), adv.get("id"))
    return out


def fetch_benign_crates(session: requests.Session | None = None, count: int = 100) -> list[dict]:
    s = session or _session()
    url = "https://crates.io/api/v1/crates"
    crates = []
    page = 1
    while len(crates) < count:
        resp = s.get(url, params={"sort": "downloads", "per_page": 50, "page": page}, timeout=30)
        resp.raise_for_status()
        for c in resp.json().get("crates", []):
            crates.append({
                "package": c["id"],
                "version": c["max_version"],
                "label": "BENIGN",
                "id": "crates.io-top",
                "categories": ["none"],
                "url": f"https://crates.io/crates/{c['id']}"
            })
            logger.info("Labeled Benign %s", c["id"])
            if len(crates) >= count: break
        page += 1
    return crates


def build_full_dataset(dest: Path) -> dict:
    s = _session()
    malicious = fetch_malicious_advisories(s)
    benign = fetch_benign_crates(s, count=100)

    crates = []
    skipped_no_name = 0
    skipped_no_version = 0
    resolved_count = 0

    for a in malicious:
        name = a.get("package")
        if not name:
            logger.warning("Advisory %s has no package name, skipping", a.get("id"))
            skipped_no_name += 1
            continue

        version = resolve_malicious_version(name, a, s)
        if version is None:
            logger.warning(
                "SKIPPED malicious crate %s (%s): all version resolution strategies failed",
                name, a.get("id"),
            )
            skipped_no_version += 1
            continue

        resolved_count += 1
        crates.append({
            "name": name,
            "version": version,
            "label": "MALICIOUS",
            "label_source": a.get("id"),
            "attack_category": ",".join(a.get("categories") or []),
            "url": a.get("url"),
        })

    logger.info(
        "Malicious advisories: %d total → %d resolved, %d skipped (no name), %d skipped (no version)",
        len(malicious), resolved_count, skipped_no_name, skipped_no_version,
    )

    for b in benign:
        crates.append({
            "name": b["package"],
            "version": b["version"],
            "label": "BENIGN",
            "label_source": b["id"],
            "attack_category": "none",
            "url": b["url"],
        })

    n_malicious = sum(1 for c in crates if c["label"] == "MALICIOUS")
    n_benign = sum(1 for c in crates if c["label"] == "BENIGN")

    dataset = {
        "dataset_version": "0.4.0",
        "total_crates": len(crates),
        "label_counts": {
            "MALICIOUS": n_malicious,
            "SUSPICIOUS": 0,
            "BENIGN": n_benign
        },
        "build_stats": {
            "advisories_fetched": len(malicious),
            "resolved": resolved_count,
            "skipped_no_package_name": skipped_no_name,
            "skipped_no_version_found": skipped_no_version,
        },
        "crates": crates,
    }

    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(dataset, indent=2), encoding="utf-8")
    return dataset
