# Justifying Gemini vs Smaller Models for Crate Classification

> **Scope:** This document explores why CrateShield uses a frontier LLM (Gemini) for the reasoning and classification step (`src/crateshield/llm/client.py`), comparing it honestly against smaller fine-tuned models, local LLMs, and the existing XGBoost/RandomForest feature-based models in `src/crateshield/evaluation/train.py`.

---

## 1. Why a Frontier LLM (Gemini)?

CrateShield passes structured JSON signals and flagged code snippets to Gemini (via a 3-way majority vote). The prompt (`llm/prompt.py`) asks the model to output a classification (`MALICIOUS`, `SUSPICIOUS`, `BENIGN`) alongside step-by-step reasoning citing specific signals.

**The core justification:** Supply chain attack detection requires reasoning about *intent*, not just pattern matching. 
- A `build.rs` script that spawns `cc` (the C compiler) is completely benign (e.g., the `cc` crate).
- A `build.rs` script that spawns `curl` or `powershell` is highly suspicious.
- A crate that reads `AWS_ACCESS_KEY_ID` but doesn't transmit it anywhere might be a legitimate AWS SDK, whereas reading it alongside a `TcpStream::connect` to an unknown IP is malicious.

Frontier models like Gemini excel at zero-shot chain-of-thought reasoning over these intersecting contexts. The model can read the provided flagged code snippet (`Command::new("powershell")`), see the surrounding context, and infer whether the action aligns with the crate's stated purpose (from crates.io metadata), producing a human-readable explanation of *why* the crate is dangerous.

---

## 2. Comparison with Alternatives

### A. Small Fine-tuned Code Models (e.g., CodeBERT, GraphCodeBERT)
- **Concept:** Fine-tune a 100M-300M parameter model on the raw Rust source code or the extracted AST.
- **Pros:** Extremely fast, low inference cost, entirely local, no API keys needed.
- **Cons:** These models are classifiers, not reasoners. They output a probability score without an explanation. Furthermore, supply chain attacks often involve semantic anomalies (e.g., typosquatting a name) that a code-focused model like CodeBERT is not pre-trained to recognize as a risk factor.

### B. Local Open-Weight LLMs (e.g., Llama 3 8B, Qwen 2.5 7B)
- **Concept:** Run a local 7B-8B parameter model to generate the JSON reasoning and classification.
- **Pros:** No external API dependency (solves data privacy concerns), no per-call API cost.
- **Cons:** High local compute requirements (requires a dedicated GPU for acceptable latency). In the context of CrateShield's 3-way voting mechanism (`LLM_VOTES = 3`), running three passes per crate locally would severely bottleneck the pipeline. Additionally, smaller models are more prone to strict JSON formatting errors (`ParseError` in `parser.py`).

### C. Existing Feature-based ML (XGBoost / Random Forest)
- **Concept:** The models currently implemented in `evaluation/train.py` which take a flattened, 9-dimensional numerical feature vector (e.g., `unsafe_per_kloc`, `dep_count`).
- **Pros:** Lightning-fast (sub-millisecond inference), highly interpretable (feature importance is mathematically defined), robust to noise, and cheap to run.
- **Cons:** Flattens all context. The feature vector records that `process_spawns = 1`, but loses the context of *what* process was spawned (`rustc` vs `wget`). It cannot read the flagged code snippets.

---

## 3. Explicit Trade-offs

Choosing Gemini as the reasoning engine introduces clear trade-offs against the XGBoost baseline:

| Metric | Gemini (3-way vote) | XGBoost / Random Forest |
|---|---|---|
| **Latency** | High (~3-10 seconds per crate due to API roundtrips and retries) | Low (< 10 milliseconds) |
| **Cost** | Per-token API costs | Free (local CPU inference) |
| **Explainability** | High (Outputs a natural language paragraph explaining intent) | Low (Outputs a probability score and feature weights) |
| **Context** | Full (Sees exact snippet text, env var names, network IPs) | Lossy (Only sees counts and boolean flags) |
| **Dependencies**| Requires `GEMINI_API_KEY` and internet access | Fully offline |

### The CrateShield Compromise
The current design implicitly acknowledges these trade-offs by maintaining *both*. The LLM pipeline (`pipeline.py -> classify_with_vote`) is best suited for offline analysis, auditing, and generating high-quality labeled datasets (with reasoning) that can then be used to train the much faster XGBoost model (`train.py`) for real-time, synchronous blocking at registry upload time.