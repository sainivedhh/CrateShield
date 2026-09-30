# Threat Model (STRIDE Methodology)

## 1. Spoofing
- **Threat:** An attacker spoofs crates.io to serve a malicious crate during the download phase.
- **Mitigation:** Enforce HTTPS/TLS for all crates.io interactions. Validate crate checksums if available.

## 2. Tampering
- **Threat:** An attacker tampers with the local RAG knowledge base to poison the LLM context (Prompt Injection / Data Poisoning).
- **Mitigation:** The vector database must be read-only at runtime. Rebuilds must be strictly controlled by trusted CI pipelines.

## 3. Repudiation
- **Threat:** The system fails to log why a crate was classified as benign, preventing post-incident auditing.
- **Mitigation:** The LLM's Chain-of-Thought (CoT) and the specific extracted signals must be saved to a database for every scan.

## 4. Information Disclosure
- **Threat:** API keys (Gemini, Claude) leak via logs or error traces.
- **Mitigation:** Use `.env` files and secret managers. Scrub logs for patterns resembling API keys before outputting.

## 5. Denial of Service (DoS)
- **Threat:** A "Zip Bomb" or extremely large crate exhausts memory during AST extraction.
- **Mitigation:** Implement strict file size limits and timeouts (2 seconds maximum) for the Tree-sitter extraction phase.

## 6. Elevation of Privilege
- **Threat:** A vulnerability in the Tree-sitter parser allows arbitrary code execution.
- **Mitigation:** Run the extraction process inside a hardened, unprivileged Docker container with minimal capabilities.
