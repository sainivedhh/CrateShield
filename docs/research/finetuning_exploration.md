# Feasibility Study: Fine-Tuning LLMs for Crate Classification

> **Scope:** This document explores the feasibility of fine-tuning a small open-weight LLM for CrateShield's reasoning task, evaluating data requirements, dataset sufficiency, and data leakage risks.

---

## 1. Data Requirements and Current Dataset Assessment

To successfully fine-tune a model to output reasoned classifications (e.g., `MALICIOUS` with explanation), a dataset needs:
1. **Sufficient Volume:** Typically thousands of examples to avoid catastrophic forgetting and overfitting.
2. **High Quality & Diversity:** Examples must cover all classes and variations of the target domain without easily learnable shortcuts.

**Current Dataset Audit (`data/dataset.json`):**
- **Total Crates:** 555
- **Benign:** 100 (Sourced from crates.io top downloaded)
- **Malicious:** 455 (Sourced from RustSec and `ingestion/synthetic.py`)

**Is it sufficient?**
*No.* Fine-tuning on 555 examples is extremely borderline, but the larger issue is **diversity**. Of the 455 malicious crates, ~400 are synthetically generated. While `synthetic.py` parameterizes variables (IPs, domains, commands), the structural templates are limited. Fine-tuning on this dataset risks severe overfitting, where the model learns to identify the synthetic templates rather than generalizing to novel malware.

## 2. Proposed Distillation Approach

If dataset size were to be expanded (e.g., generating 5,000+ highly diverse synthetic and benign samples), fine-tuning from scratch is still inefficient. A better approach is **Knowledge Distillation**.

**Candidate Pipeline:**
1. **Teacher Model (Gemini):** Run the expanded dataset through the current `classify_with_vote` pipeline. Collect the JSON signals, flagged snippets, and the resulting Gemini reasoning + classification as ground truth pairs.
2. **Student Model (e.g., Llama-3-8B-Instruct):** Use LoRA (Low-Rank Adaptation) to fine-tune the student model on these input-output pairs. The goal is to teach the smaller, local model to mimic Gemini's reasoning patterns over the JSON structured signals.

This distills the zero-shot reasoning capability of the frontier model into a fast, cheap, local model.

## 3. Data Leakage Risks

The primary risk in any ML pipeline over synthetic code is data leakage, specifically **shortcut learning**. 

- **Naming Conventions:** The current generator (`ingestion/synthetic.py`) uses predictable names: `syn_buildrs_X`, `syn_depanomaly_Y`. If the crate name is included in the prompt, a fine-tuned LLM will quickly learn that `syn_` = `MALICIOUS`.
- **Structural Boilerplate:** Synthetic proc-macros use the exact same imports (`extern crate proc_macro;`) and function names (`evil_macro`, `hidden_hook`). A model could learn to flag `TokenStream::new()` if it frequently co-occurs with malicious payloads in the synthetic set, falsely penalizing legitimate proc-macros.

If fine-tuning is pursued, synthetic data must be aggressively sanitized to remove naming artifacts, and the test set must *strictly* consist of real-world RustSec advisories, never synthetic samples.