# Software Requirements Specification (SRS)

## 1. Introduction
**CrateShield** is an LLM-assisted static analysis tool designed to detect malicious Rust crates (packages) using structured signal extraction and Retrieval-Augmented Generation (RAG).

## 2. Functional Requirements
- **FR1 (Ingestion):** The system shall download and parse `.crate` tarballs from crates.io.
- **FR2 (Signal Extraction):** The system shall extract structured security signals (network, file I/O, process execution, credentials, obfuscation) using Tree-sitter AST parsing.
- **FR3 (RAG Knowledge Base):** The system shall maintain a local vector store of historical RustSec advisories and past incidents.
- **FR4 (LLM Classification):** The system shall query an LLM (e.g., Gemini/Claude) with the extracted signals and RAG context to classify the crate as Malicious or Benign.
- **FR5 (API):** The system shall expose a RESTful API (FastAPI) for external systems to query crate safety.

## 3. Non-Functional Requirements
- **NFR1 (Security):** The system must *never* execute untrusted crate code (static analysis only).
- **NFR2 (Performance):** AST parsing must complete within 2 seconds per crate.
- **NFR3 (Reliability):** LLM API failures must be handled gracefully with exponential backoff.
- **NFR4 (Portability):** The system must be deployable via Docker containers.
