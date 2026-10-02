# CrateShield: A Hybrid Static-Analysis and LLM-Assisted Detector for Malicious Rust Crates

## Abstract

We present **CrateShield**, a pipeline for detecting malicious packages in the Rust ecosystem (crates.io). CrateShield combines five families of Tree-sitter-based static signals with a Gemini LLM majority-vote classifier and an XGBoost risk scorer. We evaluate on a labelled dataset derived from RustSec advisories and synthetic ground-truth crates, using grouped cross-validation to prevent data leakage across crate versions. Our system provides per-signal evidence, SHAP-based feature attribution, and a transparent rule-based fallback to support human review workflows.

---

## 1. Introduction

Supply-chain attacks via malicious open-source packages have become a significant threat vector. The Rust ecosystem (crates.io) has seen incidents including typosquatting, build-script backdoors, and proc-macro trojans. Unlike npm or PyPI, Rust's strong type system deters some attack classes, but `build.rs` scripts, unsafe blocks, and proc-macros remain high-risk surfaces that are not validated by the registry.

Existing tools (e.g., `cargo-audit`) focus on known vulnerabilities via advisory databases and do not generalize to novel or unreported malware. CrateShield addresses this gap through:

1. **Static signal extraction** from five distinct attack surfaces.
2. **LLM classification** for semantic reasoning about intent.
3. **ML risk scoring** (XGBoost) for consistent, fast, re-trainable prediction.
4. **Explainability** via SHAP values and structured evidence output.

---

## 2. Threat Model

We target crates that are **intentionally malicious** with the goal of harming the developers who install them (not end users of applications). Relevant attack categories include:

| Category | Mechanism | Example |
|---|---|---|
| Credential theft | `build.rs` reads `GITHUB_TOKEN`, etc. | `rustdecimall` |
| Stage-2 download | `build.rs` opens TCP to attacker server | Various |
| Compile-time attack | Proc-macro writes/reads files at compile | Theoretical |
| Data exfiltration | Hardcoded webhook in source code | Discord token loggers |
| Typosquatting | Package name ≤ 2 edit distance from popular crate | Common |

We explicitly **exclude**:
- Maintainer negligence (unmaintained or yanked crates)
- Logic bugs or CVEs in otherwise well-intentioned crates
- Post-exploitation code in crate *dependencies*

---

## 3. Signal Families

CrateShield extracts five structured signal families using Tree-sitter (Rust grammar) for AST-level precision. Each family produces a `evidence` array with `{file, line_start, line_end, snippet}` for auditability.

| Family | File | Key Signals |
|---|---|---|
| **Build Script** | `build_rs.py` | `network_calls`, `process_spawns`, `sensitive_env_reads` |
| **Unsafe/FFI** | `unsafe_ffi.py` | `unsafe_block_count`, `unsafe_per_kloc`, `syscall_usage` |
| **Proc Macro** | `proc_macro.py` | `is_proc_macro`, `proc_macro_suspicious_imports` |
| **Obfuscation** | `obfuscation.py` | `high_entropy_strings`, `base64_blobs`, `hex_blobs` |
| **Metadata/Typosquat** | `typosquat.py`, `dependencies.py` | `typo_score`, `suspicious_deps`, `hardcoded_urls` |

### 3.1 Archive Safety

All `.crate` tarballs are extracted with Python's `tarfile` `filter="data"` mode (prevents path traversal). An additional pre-extraction check enforces:
- Max **10,000 files** per archive
- Max **500 MB** uncompressed size

---

## 4. ML Pipeline

### 4.1 Features

The ML model uses 9 numerical features derived from the signal families:

```
has_build_rs, build_network, build_env, build_spawn,
unsafe_blocks, unsafe_kloc, typo_score, dep_count, suspicious_deps
```

### 4.2 Model: XGBoost Binary Classifier

Both Random Forest and XGBoost are trained. XGBoost is used for inference because:
- `scale_pos_weight` handles class imbalance naturally.
- SHAP values are natively supported via `pred_contribs=True`.
- Saved in portable JSON format (no arbitrary code execution on load).

### 4.3 Evaluation: Grouped Cross-Validation

To prevent data leakage from multiple versions of the same crate appearing in both train and test:
- **`StratifiedGroupKFold`** groups by crate `name`.
- **Nested CV**: hyperparameter search (`GridSearchCV`) is run *inside* each outer fold on training data only.
- **Bootstrapped 95% CIs** (1000 samples) reported alongside point estimates.

---

## 5. LLM Layer

A Gemini model (majority vote of *N* samples, default N=3) provides semantic reasoning over the signal JSON. The prompt includes:

- **Injection-resistant system prompt**: explicitly instructs the model to ignore instructions embedded in crate data.
- **Signal sanitization**: strings > 400 chars are truncated before being sent to the LLM.
- **Structured JSON schema** in the prompt (RFC-style).
- **Few-shot examples** with full input/output pairs.
- **RAG-retrieved context** from the known-incidents knowledge base.

LLM output is validated against a strict allowlist (`MALICIOUS|SUSPICIOUS|BENIGN`, `HIGH|MEDIUM|LOW`, `Block|Manual review|Pass`) before being accepted.

---

## 6. Limitations

1. **Dataset Size**: The number of confirmed malicious Rust crates from RustSec is very small (~50-100 unique packages). This creates high variance in evaluation metrics. Results should be interpreted as directional, not production-ready benchmarks.

2. **Label Noise**: RustSec advisories conflate bugs, unmaintained crates, and outright malware. We filter by `[informational]` and `[unmaintained]` categories, but label noise remains.

3. **Potential Overfitting**: Despite grouped cross-validation, the feature set was partly designed while examining known malicious crates, introducing selection bias. The feature importance rankings (e.g., `build_network` consistently top-ranked) may partially reflect this.

4. **Dynamic Attacks**: CrateShield is static-only. Attacks using legitimate APIs or runtime-only C2 channels are not detected.

5. **Adversarial Robustness**: A sophisticated attacker aware of CrateShield could split network calls across multiple crates, use common crate names as build-time dependencies, or encode payloads in config files rather than source code.

---

## 7. Future Work

- **Dynamic sandbox execution**: Run `cargo build` in an isolated Docker container with syscall tracing (seccomp + eBPF) to detect runtime-only attacks.
- **Larger labelled dataset**: Partner with crates.io security team for confirmed malicious packages not in public advisories.
- **Multi-version temporal analysis**: Track crate version history to detect suspicious version bumps or dependency changes.
- **Differential privacy**: Apply DP-SGD during model training to prevent membership inference on training crates.
- **Streaming detection**: Hook into crates.io publish webhook for real-time scanning.
