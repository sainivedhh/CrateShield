# CrateShield

LLM-assisted detection of malicious Rust crates via structured static signal extraction.

Academic research pipeline (B.Tech CSE / Cybersecurity FYP):

1. Ingest crate tarballs + RustSec labels
2. Extract five structured signal families (Tree-sitter)
3. Classify with Gemini LLM chain-of-thought
4. Ablate: structured+LLM vs raw LLM vs cargo-audit

## Setup

```bash
python3.11 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
pip install -e .
cp .env.example .env             # add GEMINI_API_KEY_1, GEMINI_API_KEY_2, ...
```

## Usage

```bash
# Analyze one crate (signals only — no API cost)
python -m crateshield extract --name serde --version 1.0.219

# Full pipeline including Gemini LLM
python -m crateshield analyze --name rustdecimal --version 1.0.0

# Build labeled set from RustSec (malicious-code / backdoor)
python -m crateshield ingest-rustsec --out data/dataset.json

# Three-condition ablation
python -m crateshield ablation --dataset data/dataset.json --out data/results/ablation.json
```

## Web Dashboard

```bash
# Terminal 1: start the API backend
python -m uvicorn src.crateshield.api:app --reload --host 0.0.0.0 --port 8000

# Terminal 2: start the React frontend
cd webapp && npx vite --port 3000 --host 127.0.0.1
```

Then open **http://127.0.0.1:3000** in your browser.

## Web App

A React (Vite) UI for scanning any crates.io package by name (and optional
version). It calls the FastAPI backend, which extracts signals live and
scores risk using the trained RandomForest model when available, falling
back to a transparent rule-based score otherwise (so it works even before
you run `train`).

```bash
# Terminal 1 — backend
pip install fastapi uvicorn
uvicorn crateshield.api:app --reload --host 0.0.0.0 --port 8000

# Terminal 2 — frontend (first run only: npm install)
cd webapp
npm install
npm run dev -- --port 3000 --host 127.0.0.1
```

Open `http://127.0.0.1:3000`, type a crate name (e.g. `rand`, `tokio`, `cc`)
and hit Scan. Leave the version field blank to analyze the latest published
release.

For best accuracy, build and train first so the app blends the ML score in
alongside the rule-based one:

```bash
python -m crateshield ingest-rustsec --out data/dataset.json
python -m crateshield extract-dataset --dataset data/dataset.json   # runs signal extraction for every crate
python -m crateshield train --dataset data/dataset.json
```

## Ethics

Detection-only. Do not re-upload yanked crates. Do not commit `.env` or raw malware tarballs. Unknown high-confidence hits go to crates.io security + RustSec privately before any public writeup.

## License

Code: MIT. Dataset (when released): CC-BY-4.0.
