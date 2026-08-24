from pathlib import Path

from crateshield.signals.build_rs import analyze_build_rs
from crateshield.signals.extractor import rust_parser

FIXTURES = Path(__file__).resolve().parents[1] / "data" / "fixtures"


def test_benign_out_dir_not_sensitive():
    text = (FIXTURES / "benign_build.rs").read_text()
    r = analyze_build_rs({"build_rs": text}, rust_parser())
    assert "sensitive_env_var_read" not in r["signals"]


def test_flags_tcp_and_token():
    text = (FIXTURES / "suspicious_build.rs").read_text()
    r = analyze_build_rs({"build_rs": text}, rust_parser())
    assert "network_call" in r["signals"]
    assert "sensitive_env_var_read" in r["signals"]
