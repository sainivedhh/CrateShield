from __future__ import annotations

import shutil
import subprocess
from pathlib import Path


def run_cargo_audit(crate_dir: Path) -> dict:
    """
    Status-quo CI baseline. cargo-audit flags *known vulnerable* crates,
    not novel malware. Expect near-zero recall on unpublished backdoors.
    """
    exe = shutil.which("cargo-audit") or shutil.which("cargo")
    if not exe:
        return {"available": False, "prediction": "BENIGN", "raw": "cargo-audit not installed"}

    cmd = ["cargo", "audit"] if Path(exe).name == "cargo" else [exe]
    try:
        proc = subprocess.run(
            cmd,
            cwd=crate_dir,
            capture_output=True,
            text=True,
            timeout=120,
        )
    except Exception as exc:
        return {"available": True, "prediction": "BENIGN", "raw": str(exc)}

    text = (proc.stdout or "") + (proc.stderr or "")
    # cargo-audit does not have a malware class; any "malicious" advisory hit counts.
    hit = "malicious" in text.lower() or "yanked" in text.lower()
    return {
        "available": True,
        "prediction": "SUSPICIOUS" if hit else "BENIGN",
        "raw": text[-4000:],
        "exit_code": proc.returncode,
    }
