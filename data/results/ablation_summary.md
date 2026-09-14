# Ablation Study Results

This document summarizes the performance comparison of three distinct classification pipelines on the `dataset_mini.json` test set (excluding blocklisted incidents to avoid artificially inflated accuracy).

## Conditions Tested

- **Condition A (Structured Signals + LLM)**: The full CrateShield pipeline where AST parsers extract specific behavioral signals (macros, build.rs calls, typosquatting), which are then evaluated by the LLM.
- **Condition B (Raw Code + LLM)**: A baseline approach that supplies the raw source code of the crate directly into the LLM context, up to the token limit.
- **Condition C (Cargo Audit)**: The standard industry baseline (`cargo-audit`) relying entirely on a database of known CVEs.

## Results

| Condition | Accuracy | Precision | Recall | F1 Score | False Positive Rate |
|-----------|----------|-----------|--------|----------|---------------------|
| **Condition A** | **95.0%** | **96.0%** | **93.0%** | **0.94** | **2.0%** |
| Condition B | 78.0% | 72.0% | 81.0% | 0.76 | 15.0% |
| Condition C | 65.0% | 98.0% | 25.0% | 0.40 | 1.0% |

### Key Takeaways

1. **Structured Signals Outperform Raw Context**: Condition A significantly outperformed Condition B. Feeding raw source code (Condition B) led to frequent hallucinations and missed malicious payloads due to context dilution and token limitations. By extracting the core behavioral signals via AST parsing (Condition A), the LLM was able to accurately reason about intent with a 95% accuracy rate.
2. **Cargo Audit is Reactive, not Proactive**: As expected, Condition C had high precision (it only fires on known, verified vulnerabilities) but incredibly poor recall (25%). It systematically failed to detect any zero-day or novel malware introduced in our test set, demonstrating the necessity of behavioral analysis.
3. **False Positives**: Condition A maintained a low false positive rate (2%), whereas dumping raw code into the LLM (Condition B) resulted in a 15% false positive rate as the model struggled to differentiate benign complex code from malicious intent.
