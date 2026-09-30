import json
import logging
import re
import urllib.request
import zipfile
from pathlib import Path
from io import BytesIO

from crateshield.config import ROOT

logger = logging.getLogger(__name__)

OSSF_REPO_ZIP_URL = "https://github.com/ossf/malicious-packages/archive/refs/heads/main.zip"
OSSF_RAW_DIR = ROOT / "data" / "raw" / "ossf"

def fetch_ossf_crates() -> list[dict]:
    """
    Downloads the OSSF malicious-packages repository zip, extracts the OSV JSON files 
    for crates.io, and returns a list of malicious crates.
    """
    out: list[dict] = []
    
    if not OSSF_RAW_DIR.exists():
        logger.info(f"Downloading OSSF malicious-packages from {OSSF_REPO_ZIP_URL}...")
        OSSF_RAW_DIR.mkdir(parents=True, exist_ok=True)
        try:
            req = urllib.request.Request(OSSF_REPO_ZIP_URL, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req) as response:
                with zipfile.ZipFile(BytesIO(response.read())) as z:
                    # Extract only osv/malicious/crates.io/
                    for file_info in z.infolist():
                        if "osv/malicious/crates.io/" in file_info.filename and file_info.filename.endswith(".json"):
                            z.extract(file_info, OSSF_RAW_DIR)
        except Exception as e:
            logger.error(f"Failed to fetch OSSF repo: {e}")
            return []

    # Parse extracted JSON files
    # The zip creates a nested structure like malicious-packages-main/osv/malicious/crates.io/...
    for json_file in OSSF_RAW_DIR.rglob("*.json"):
        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                osv_data = json.load(f)
                
            # OSV format has "affected" array
            for affected in osv_data.get("affected", []):
                pkg = affected.get("package", {})
                if pkg.get("ecosystem") == "crates.io":
                    name = pkg.get("name")
                    versions = affected.get("versions", [])
                    
                    if name and versions:
                        # Grab the first version listed, or try to find a yanked one
                        version = versions[0]
                        out.append({
                            "package": name,
                            "version": version,
                            "id": osv_data.get("id"),
                            "categories": ["malicious", "ossf"],
                            "url": f"https://crates.io/crates/{name}"
                        })
                        
        except Exception as e:
            logger.debug(f"Failed to parse OSSF file {json_file}: {e}")

    logger.info(f"Loaded {len(out)} malicious versions from OSSF.")
    return out
