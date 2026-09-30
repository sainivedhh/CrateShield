# CrateShield Architecture Audit

**Date:** 2026-09-30
**Phase:** 1 (Repository Audit)

## 1. Current Pipeline
The system operates as an offline/online hybrid pipeline for analyzing Rust crates statically.
- **Online (Inference):** The FastAPI backend (`api.py`) receives a crate name + version. It fetches metadata (`downloader.py`), downloads the `.crate` tarball, extracts it safely (`extractor.py`), parses source files into an AST via Tree-sitter (`signals/extractor.py`), runs static analysis modules to extract 5 signal families, scores it against a trained XGBoost model and a rule-based fallback, and queries an exact-match known-incidents database. The results are returned to the React frontend.
- **Offline (Training/Evaluation):** `ingestion/rustsec.py` and `ingestion/synthetic.py` assemble the dataset. Features are extracted using the same Tree-sitter pipeline. Models (XGBoost & RandomForest) are trained in `evaluation/train.py`. An ablation pipeline (`evaluation/ablation.py`) tests performance across structured vs raw LLM approaches.

## 2. Signal Extractors (The "Five Families")
Static security signals are extracted via Tree-sitter AST queries and basic parsing:
1. **`build_rs.py`**: Detects network calls (TcpStream, reqwest), process spawning, file writes, and sensitive environment variable reads in `build.rs`.
2. **`unsafe_ffi.py`**: Counts `unsafe` blocks/functions, calculates unsafe density (per KLOC), and extracts FFI signatures (`extern`) and syscalls.
3. **`proc_macro.py`**: Checks if the crate is a proc-macro and flags suspicious imports (e.g., `std::net`, `std::process`, `std::fs`, `std::env`) within macro definitions.
4. **`typosquat.py`**: Computes Levenshtein distance between the target crate and a cached list of the top 1,000 crates, flagging distances <= 2.
5. **`dependencies.py`**: Parses `Cargo.toml` via `tomllib` to count dependencies, dev-dependencies, and check for exact-pinned versions.

## 3. Dataset Structure
- **Path:** `data/dataset.json` (555 crates total: 455 Malicious, 100 Benign).
- **Composition:** 
  - **Benign:** Top-downloaded crates from crates.io.
  - **Malicious (Real):** Verified malware pulled from RustSec/OSV (e.g., `append-only-vec`, `arrayref`, `bit-flags`, `proc-macro1`).
  - **Malicious (Synthetic):** 400 synthetically generated crates labeled with `label_source: "synthetic-generator"`.
- **Limitation:** The current dataset mixes real and synthetic malicious crates indiscriminately during standard cross-validation, which risks data leakage and overstating real-world accuracy.

## 4. RAG Implementation Status
- **Current State:** **Not Implemented.**
- **Details:** The current `api.py` and `prompt.py` do not perform vector retrieval (RAG). There is an exact-match dictionary lookup in `known_incidents.py` acting as a blocklist, but no sentence-transformers, cosine similarity, or RAG context injection exists. `rag_exploration.md` is merely a design document.

## 5. LLM Integration
- **Client:** `llm/client.py` uses the official `google-genai` SDK with a multi-key round-robin rotation.
- **Prompting:** `prompt.py` formats the structured JSON signals into a prompt. It uses few-shot examples and asks for a JSON response containing `classification`, `confidence`, `reasoning`, `primary_signals`, and `recommended_action`.
- **Voting:** `classify_with_vote()` queries the LLM N times (default 3) and takes a majority vote to reduce hallucination/instability.

## 6. Evaluation Code
- **`evaluation/train.py`**: Performs grid search and trains XGBoost/RandomForest models on the extracted feature vectors.
- **`evaluation/ablation.py`**: Compares `A: Structured + LLM`, `B: Raw LLM Baseline` (raw code injection), and `C: cargo-audit`. 
- **Metrics:** `metrics.py` calculates Precision, Recall, F1, and FPR.

## 7. Frontend / Dashboard
- **Stack:** React + Vite.
- **UI:** `App.jsx` handles crate searching and renders a rich dashboard displaying the RiskGauge (Critical/High/Medium/Low), metadata, the exact-match blocklist banner, detailed breakdown of the 5 signal families, extracted code snippets, and XGBoost feature importances.

## 8. Tests
- **Framework:** `pytest`
- **Coverage:** Minimal unit tests exist (`test_build_rs.py`, `test_typosquat.py`, `test_metrics.py`). The test suite passes locally but coverage is extremely low and lacks end-to-end integration tests.

## 9. Identified Dead/Obsolete/Contradictory Code
- **RAG:** Mentioned heavily in `project_workflow.md` and `rag_exploration.md`, but no actual implementation exists in the codebase.
- **Fine-Tuning:** `finetune.py` and `distill.py` exist in `evaluation/`, and `ablation.py` tries to load a local `AutoModelForCausalLM`, but this fails gracefully because PyTorch is not installed (`HAS_ML = False`).
- **Signal Coverage:** The current extractors miss huge swathes of potential attacks (e.g., dynamic loading, git dependencies, filesystem traversal, obfuscation).

## Next Steps
Proceeding to **Phase 2: RAG Implementation / Upgrade**.
