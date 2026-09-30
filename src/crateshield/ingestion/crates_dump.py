import csv
import logging
import tarfile
import urllib.request
import os
import random
from pathlib import Path

from crateshield.config import ROOT

logger = logging.getLogger(__name__)

DUMP_URL = "https://static.crates.io/db-dump.tar.gz"
DUMP_DIR = ROOT / "data" / "raw" / "db-dump"
DUMP_TAR = ROOT / "data" / "raw" / "db-dump.tar.gz"


def _download_and_extract():
    DUMP_DIR.mkdir(parents=True, exist_ok=True)

    if not DUMP_TAR.exists():
        logger.info(
            f"Downloading crates.io db dump from {DUMP_URL} (this may take a while)..."
        )
        urllib.request.urlretrieve(DUMP_URL, str(DUMP_TAR))

    crates_csv_found = False
    for path in DUMP_DIR.rglob("crates.csv"):
        crates_csv_found = True

    if not crates_csv_found:
        logger.info("Extracting db dump...")
        with tarfile.open(DUMP_TAR, "r:gz") as tar:
            tar.extractall(path=DUMP_DIR)


def sample_stratified_benign(top_n=1000, mid_n=500, tail_n=500) -> list[dict]:
    """
    Parses the crates.io db dump to sample a stratified benign set.
    """
    _download_and_extract()

    # Find the crates.csv and versions.csv in the extracted directory structure
    crates_csv = next(DUMP_DIR.rglob("crates.csv"), None)
    versions_csv = next(DUMP_DIR.rglob("versions.csv"), None)

    if not crates_csv or not versions_csv:
        logger.error("Could not find crates.csv or versions.csv after extraction.")
        return []

    # Simplified parsing logic: in a real PostgreSQL dump from crates.io,
    # crates.csv has headers like: id, name, downloads, ...
    # We will read them into memory.

    crates_by_downloads = []

    logger.info("Parsing crates.csv...")
    with open(crates_csv, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                downloads = int(row.get("downloads", 0))
            except (TypeError, ValueError):
                logger.debug("Skipping row with invalid downloads value: %r", row)
                continue

            crates_by_downloads.append(
                {
                    "id": row.get("id"),
                    "name": row.get("name"),
                    "downloads": downloads,
                }
            )

    # Sort by downloads descending
    crates_by_downloads.sort(key=lambda x: x["downloads"], reverse=True)

    # Stratified Selection
    # Top tier
    top_tier = crates_by_downloads[:top_n]

    # Mid tier (1k - 100k roughly, we'll just slice from the sorted list)
    mid_start = max(top_n, 1000)
    mid_end = min(len(crates_by_downloads), mid_start + 100000)
    mid_pool = crates_by_downloads[mid_start:mid_end]
    mid_tier = random.sample(mid_pool, min(mid_n, len(mid_pool)))

    # Long tail (bottom 50% of the registry)
    tail_start = len(crates_by_downloads) // 2
    tail_pool = crates_by_downloads[tail_start:]
    tail_tier = random.sample(tail_pool, min(tail_n, len(tail_pool)))

    selected_crates = top_tier + mid_tier + tail_tier
    selected_ids = {c["id"]: c for c in selected_crates}

    # Now find the latest version for each selected crate
    logger.info("Parsing versions.csv for selected crates...")
    out = []
    with open(versions_csv, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            crate_id = row.get("crate_id")
            if crate_id in selected_ids:
                # Store the highest version (simplification: assume last seen or just take first)
                c = selected_ids[crate_id]
                if "version" not in c or not c.get("is_highest"):
                    # versions.csv has 'num' field usually
                    c["version"] = row.get("num")

    for c in selected_crates:
        if c.get("version"):
            out.append(
                {
                    "package": c["name"],
                    "version": c["version"],
                    "label": "BENIGN",
                    "source": "crates_dump",
                    "is_synthetic": False,
                    "categories": ["none"],
                    "url": f"https://crates.io/crates/{c['name']}",
                }
            )

    logger.info(f"Sampled {len(out)} benign crates via db-dump stratification.")
    return out
