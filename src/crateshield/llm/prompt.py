from __future__ import annotations

import json

SYSTEM = """You are a security analyst specializing in Rust supply chain attacks and malicious package detection on crates.io.

Classify the crate as:
- MALICIOUS: high confidence the crate is intentionally harmful
- SUSPICIOUS: signals present but insufficient for a definitive call
- BENIGN: no significant malicious signals

Rules:
- Reason step by step. Cite only keys present in the JSON.
- If has_build_rs is false, do not invent build-script behavior.
- Prefer SUSPICIOUS over MALICIOUS when the only signal is typosquat or unsafe density.
- env::var("OUT_DIR") / CARGO_* reads are normal in build.rs.
- Recommended action Block only with MALICIOUS + HIGH.

Known Rust attack patterns:
- build.rs outbound network (exfiltration / stage-2)
- build.rs reading AWS_*, GITHUB_TOKEN, SSH_*, CARGO_REGISTRY_TOKEN
- typosquatting popular crates
- proc-macros importing std::net / std::process
- unsafe/FFI concentration inconsistent with stated purpose
"""

FEW_SHOT = """
Example 1 (MALICIOUS):
Signals: {"crate":"rustdecimall","build_rs":{"has_build_rs":true,"signals":["network_call","sensitive_env_var_read"]},"typosquatting":{"score":0.95,"target":"rust_decimal","edit_distance":1}}
Classification: MALICIOUS
Reasoning: Edit distance 1 from rust_decimal plus build.rs network + secret env reads matches credential-theft typosquat.

Example 2 (BENIGN):
Signals: {"crate":"cc","build_rs":{"has_build_rs":true,"signals":["process_spawn"],"process_spawns":["Command::new(cc)"]},"typosquatting":{"score":0.0}}
Classification: BENIGN
Reasoning: cc is a C compiler driver; spawning a compiler from build.rs is the crate's purpose.
"""


def build_prompt(signals: dict, snippets: list[str] | None = None, raw_source: str | None = None) -> list[dict]:
    user = "Analyze this crate and classify it. Cite specific signals.\n\n"
    if raw_source is not None:
        user += "Raw source (truncated):\n" + raw_source + "\n"
    else:
        user += "Crate signals:\n" + json.dumps(signals, indent=2) + "\n"
        if snippets:
            user += "\nFlagged snippets:\n" + "\n---\n".join(snippets)
    user += """

Respond in this exact JSON format:
{
  "classification": "MALICIOUS|SUSPICIOUS|BENIGN",
  "confidence": "HIGH|MEDIUM|LOW",
  "reasoning": "Step-by-step reasoning citing specific signals...",
  "primary_signals": ["..."],
  "recommended_action": "Block|Manual review|Pass"
}
"""
    return [
        {"role": "system", "content": SYSTEM + "\n" + FEW_SHOT},
        {"role": "user", "content": user},
    ]
