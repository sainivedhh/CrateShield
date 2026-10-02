# Data Split and Dataset Hygiene

This directory contains datasets used for evaluating CrateShield.

## Dataset Hygiene
1. **Deduplication**: The dataset is deduplicated by crate `name` and `version` so exact duplicates are removed.
2. **Crate Name Grouping**: Train/validation/test splits strictly group by crate `name`. This ensures that different versions of the same crate never appear in different splits, preventing data leakage (e.g., `serde 1.0.0` in train and `serde 1.0.1` in test).
3. **Split Proportions**: By default, the dataset is split 70% Train, 15% Validation, and 15% Test.

The script `src/crateshield/evaluation/split.py` enforces these rules and writes the split assignment into the JSON.
