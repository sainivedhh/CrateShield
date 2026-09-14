# Problem Statement

The Rust ecosystem heavily relies on standard security tooling like `cargo-audit` and crates.io metadata to prevent supply chain attacks. However, these tools primarily depend on a database of known CVEs and static vulnerability disclosures. This reactive approach systematically misses novel, zero-day supply chain attacks—such as typosquatting on popular crate names, executing malicious arbitrary code via `build.rs` and procedural macros, or employing obfuscated payloads. Because modern attackers exploit behavioral features of the build system rather than exploiting memory safety bugs, a structural and behavioral analysis engine is required to proactively detect these threats before they are flagged in community databases.

## Objectives

1. **Extract Structural Signals**: Statically analyze Rust crate contents (e.g., AST parsing of `build.rs` network calls, identifying procedural macros, inspecting un-isolated file system access) to capture behavioral signals.
2. **Detect Typosquatting & Metadata Anomalies**: Compare crate metadata and Levenshtein distances against popular crates to flag likely typosquatting attempts automatically.
3. **LLM-Assisted Classification**: Feed extracted signals into a multi-vote LLM system to accurately classify the intent behind the code (benign vs malicious), overcoming the token limits and hallucinations common when supplying raw source code directly.
4. **Algorithmic Risk Scoring**: Layer traditional Machine Learning (XGBoost) over the LLM outputs to generate a probabilistic risk score, providing a more robust fallback against LLM failure modes and edge cases.
