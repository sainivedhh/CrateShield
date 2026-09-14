# CrateShield Sprint Log

## Sprint 1: Core Signal Extraction
**Goals**: Build the foundational parsers (AST-based) for Rust projects to extract structural behavioral signals (build.rs, macros, typosquatting).
**Delivered**:
- Implemented AST parsers for `build.rs` network/fs access (`build_rs.py`).
- Integrated tree-sitter for macro expansion and foreign function interfaces (`macro.py`).
- Implemented typosquatting detection using Levenshtein distance on crates.io indices (`typosquat.py`).
**Retrospective**: Tree-sitter was a huge win for speed compared to running rust-analyzer, but getting the parser setup automated was a bit tricky.

## Sprint 2: LLM Integration Pipeline
**Goals**: Use Gemini LLM to classify extracted structural signals into actionable severity and risk levels.
**Delivered**:
- Created `client.py` for interacting with the `google-genai` SDK and handling retries/API rotation.
- Defined system prompts and structured JSON parsing logic (`prompt.py`, `parser.py`).
- Set up a voting mechanism to reduce hallucination.
**Retrospective**: Using raw LLM vs formatted context made a huge difference. The structured signals improved the precision significantly compared to the raw code baseline.

## Sprint 3: ML Training & Evaluation
**Goals**: Add traditional ML (RandomForest/XGBoost) as a secondary validation layer and measure LLM performance.
**Delivered**:
- Implemented XGBoost models (`train.py`) to predict probability of a crate being malicious based on LLM outputs.
- Developed an ablation study (`ablation.py`) to compare our LLM + Structural Signals approach against `cargo-audit` and Raw Code baselines.
**Retrospective**: XGBoost was excellent for catching outliers and adding a probabilistic score to the LLM's definitive answers.

## Sprint 4: FastAPI Backend Integration
**Goals**: Expose the pipeline as a REST API for consumption by external clients and dashboards.
**Delivered**:
- Built `api.py` with endpoints for metadata lookup (`/api/crate/{name}`), prediction (`/api/predict`), and manual run triggers (`/api/run`).
- Fixed critical security issues (CORS, unvalidated paths, RCE).
**Retrospective**: RCE through `subprocess` was a major risk; switching to direct function calls was a necessary pivot.

## Sprint 5: React Dashboard
**Goals**: Create an interactive visualization for analysts to review crate risks.
**Delivered**:
- Implemented a dynamic React frontend (`webapp/`) with risk score gauges, signal breakdowns, and API connections to the FastAPI backend.
**Retrospective**: Moving from a CLI-only tool to a full web dashboard made the project significantly more usable for demonstrating supply chain risks to stakeholders.

## Sprint 6: Testing & Synthetic Data
**Goals**: Harden the codebase and ensure models function against known patterns.
**Delivered**:
- Added synthetic crate generation (`synthetic.py`) to simulate various attacks.
- Implemented comprehensive unit tests (`tests/`) and established CI pipeline.
**Retrospective**: Generating synthetic crates was crucial since the real-world dataset of malicious crates is relatively small.
