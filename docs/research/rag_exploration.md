# Exploring RAG to Reduce LLM Hallucinations

> **Scope:** This document explores how Retrieval-Augmented Generation (RAG) could be integrated into CrateShield to provide the LLM with real-time ground truth, reducing hallucinations about known incidents and registry metadata.

---

## 1. Hallucination Risks in the Current Pipeline

The current LLM classification step (`src/crateshield/llm/client.py` and `prompt.py`) relies entirely on the model's pre-training and the structured JSON signals provided. It is blind to the external world at inference time.

**Specific Risks:**
1. **Known Incidents:** The LLM does not inherently know if `rustdecimall` is a confirmed typosquat in the RustSec advisory database. It has to guess based on the edit distance score.
2. **Metadata Context:** The LLM might assume a crate with high `unsafe` density is malicious because it doesn't know the crate is a well-known, widely-used FFI wrapper (e.g., `libc`).
3. **Fictitious Dependencies:** The LLM might hallucinate that a dependency is malicious when it is perfectly benign, or miss a known malicious dependency because it isn't in its training data.

## 2. Proposed RAG Design

To anchor the LLM in reality, we can retrieve relevant context and inject it into the prompt *before* calling Gemini. This mirrors approaches seen in literature (e.g., MalTracker, SocketAI).

**Data Sources for Retrieval:**
1. **`known_supply_chain_incidents.csv`:** Already parsed by `ingestion/known_incidents.py`.
2. **RustSec Advisory Database:** Raw Markdown/text of vulnerability and malware disclosures.
3. **Crates.io Registry Data:** Live download counts and repository links (already fetched by `/api/crate` but not passed to the LLM).

**The RAG Pipeline:**
1. Extract the target crate's name, description, and dependency list.
2. Query a vector database containing embeddings of all RustSec advisories and known incidents.
3. Retrieve the top-$K$ most semantically similar historical incidents.
4. Inject this context into `prompt.py`: *"Context: Similar known attacks involve..."*

## 3. Extending the Blocklist to Semantic Search

Currently, `ingestion/known_incidents.py` performs a naive, exact-match dictionary lookup (`incidents.get(crate_name)`). While effective for 1:1 blocking, it misses variations.

Instead of an exact match, embedding the incident descriptions would allow fuzzy retrieval. If a new crate spawns a hidden process downloading from a pastebin link, the semantic search could pull up a past RustSec advisory with a similar pastebin-download payload, providing the LLM with concrete precedent that this pattern is known malware, rather than leaving it to guess.