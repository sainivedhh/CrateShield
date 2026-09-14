import csv
import functools
from pathlib import Path

from crateshield.config import ROOT

CSV_PATH = ROOT / "data" / "reference" / "known_supply_chain_incidents.csv"

@functools.lru_cache(maxsize=1)
def load_incidents() -> dict[str, dict]:
    """Loads the known incidents CSV and returns a dictionary keyed by package name."""
    if not CSV_PATH.exists():
        return {}
    
    incidents = {}
    with open(CSV_PATH, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            package_raw = row.get("package", "")
            if not package_raw:
                continue
            
            # strip anything after " (" and lowercase
            package_clean = package_raw.split(" (")[0].strip().lower()
            incidents[package_clean] = row
            
    return incidents

def check_known_incident(crate_name: str) -> dict | None:
    """Checks if a crate is in the known incidents blocklist."""
    incidents = load_incidents()
    return incidents.get(crate_name.lower().strip())
