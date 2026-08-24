from __future__ import annotations

import tarfile
from pathlib import Path

from crateshield.config import EXTRACTED_DIR, ensure_dirs


def extract_crate(tarball: Path, dest_root: Path | None = None) -> Path:
    """Extract a .crate tarball. Returns the crate root directory."""
    ensure_dirs()
    dest_root = dest_root or EXTRACTED_DIR
    dest_root.mkdir(parents=True, exist_ok=True)

    with tarfile.open(tarball, "r:gz") as tf:
        members = tf.getmembers()
        if not members:
            raise ValueError(f"empty tarball: {tarball}")
        # First path component is `{name}-{version}/`
        top = Path(members[0].name).parts[0]
        out = dest_root / top
        if not out.exists():
            tf.extractall(dest_root, filter="data")
    return dest_root / top


def read_text(path: Path) -> str | None:
    if not path.is_file():
        return None
    return path.read_text(encoding="utf-8", errors="replace")


def collect_rs_files(crate_dir: Path) -> list[Path]:
    return sorted(p for p in crate_dir.rglob("*.rs") if p.is_file())


def load_crate_files(crate_dir: Path) -> dict:
    return {
        "crate_dir": crate_dir,
        "cargo_toml": read_text(crate_dir / "Cargo.toml"),
        "build_rs": read_text(crate_dir / "build.rs"),
        "cargo_lock": read_text(crate_dir / "Cargo.lock"),
        "source_files": collect_rs_files(crate_dir / "src")
        if (crate_dir / "src").exists()
        else collect_rs_files(crate_dir),
    }
