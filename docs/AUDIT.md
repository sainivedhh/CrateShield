# CrateShield Security and Architecture Audit

## 1. Overview of Signals
The codebase extracts the following structured signal families:
1. **build_rs** (`src/crateshield/signals/build_rs.py`) - Network calls, env reads, process spawns in `build.rs`.
2. **unsafe_ffi** (`src/crateshield/signals/unsafe_ffi.py`) - Unsafe block counts and density.
3. **proc_macro** (`src/crateshield/signals/proc_macro.py`) - Suspicious imports in proc macros.
4. **typosquatting** (`src/crateshield/signals/typosquat.py`) - Levenshtein distance to top crates.
5. **dependencies** (`src/crateshield/signals/dependencies.py`) - Count and suspicious dependencies.

*(Note: `network.py`, `process_execution.py`, and `credentials.py` exist in `signals/` but are currently extracted independently in `extractor.py`).*

## 2. ML Model Architecture
**Which model is used?** Both are used inconsistently. 
- `risk.py` (`assess_risk`) loads `RandomForestClassifier` (`rf_model.pkl`) to compute the final `risk_score`.
- `api.py`'s `/api/predict` endpoint loads `xgb_model.json` at startup and overwrites the `risk["model"]` response block with XGBoost probabilities, leaving the `risk_score` derived from the Random Forest.

**Features:** 9 features: `has_build_rs`, `build_network`, `build_env`, `build_spawn`, `unsafe_blocks`, `unsafe_kloc`, `typo_score`, `dep_count`, `suspicious_deps`.

**Training & Evaluation:** 
- Evaluated via Stratified K-Fold or Leave-One-Out CV depending on dataset size.
- Uses `class_weight="balanced"` or `scale_pos_weight`.

## 3. Evaluation Problems
- **Data Leakage (Hyperparameters):** `GridSearchCV` is performed on the *entire* dataset (`X, y`) to find the best hyperparameters *before* the cross-validation loop. This guarantees the model has seen the entire test set distribution during parameter selection.
- **Data Leakage (Splits):** The CV split does not group by crate name. Multiple versions of the same crate (e.g., `serde 1.0.0` and `serde 1.0.1`) can appear in both training and test folds.
- **Evaluation Metrics:** Metrics are reported purely on cross-validation folds; there is no strictly held-out test set for final evaluation.

## 4. Security Assessment
- **Code Execution:** The tool uses static analysis (`tree-sitter`) and does not dynamically execute downloaded Rust code.
- **Tarball Extraction:** Extracted in `src/crateshield/ingestion/extractor.py` using `tarfile.extractall(filter="data")`. While `filter="data"` protects against path traversal (`../`) and dangerous symlinks (on supported Python versions), there are **no limits on file size or member count**, making the system vulnerable to tar bombs (resource exhaustion).
- **API Keys:** Handled in `llm/client.py` by reading `GEMINI_API_KEY*` from the environment. They are rotated round-robin using a threading lock, but there is no explicit memory clearing or log masking.
- **API Security:** The FastAPI backend (`api.py`) exposes endpoints like `/api/run` to trigger training, data ingestion, and ablation without any authentication, leading to a Denial of Service (DoS) risk.

## 5. Test Results
Running `pytest` directly results in **5 Collection Errors**:
```
=========================== short test summary info ===========================
ERROR tests/test_build_rs.py - ModuleNotFoundError: No module named 'crateshield'
ERROR tests/test_llm.py
ERROR tests/test_metrics.py
ERROR tests/test_rustsec.py
ERROR tests/test_typosquat.py
!!!!!!!!!!!!!!!!!!! Interrupted: 5 errors during collection !!!!!!!!!!!!!!!!!!!
```
**Cause:** The tests require the `crateshield` package to be installed in the environment (e.g., `pip install -e .`) or `PYTHONPATH` to be set.

## 6. Prioritized Work Plan
1. **B1: Reproducible, leak-free evaluation**
   - Fix `train.py` to group CV splits by crate name (GroupKFold).
   - Move GridSearchCV *inside* the CV loop or use a separate held-out test set to prevent hyperparameter leakage.
2. **B2: Stronger signal extraction**
   - Implement limits on tarball extraction (max file size, max files) to prevent tar bombs.
   - Expand `build_rs` and `unsafe_ffi` signal evidence extraction (file paths, line numbers).
3. **B3: Better ML layer and explainability**
   - Unify the ML model: Benchmark RF vs XGBoost properly and pick one. Update `risk.py` and `api.py` to use the chosen model exclusively.
4. **B4: Robust, injection-resistant LLM layer**
   - Implement Pydantic structured output for Gemini and add prompt injection defenses for untrusted code comments.
5. **B5: API, dashboard and developer workflow**
   - Secure the API (authentication for admin endpoints, rate limiting).
6. **B6: Engineering quality and CI**
   - Fix pytest collection issues and add CI checks for test coverage, linting, and secrets.
7. **B7: Research-style writeup**
   - Consolidate findings into `docs/PAPER.md`.
