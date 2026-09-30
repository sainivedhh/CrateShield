from __future__ import annotations
from pathlib import Path

CREDENTIAL_PATHS = {
    ".ssh",
    "id_rsa",
    "id_ed25519",
    ".aws/credentials",
    ".config/gcloud",
    ".docker/config.json",
    ".kube/config",
    ".npmrc",
    "passwd",
    "shadow",
}


def _node_text(src: bytes, node) -> str:
    return src[node.start_byte : node.end_byte].decode("utf-8", errors="replace")


def _walk(node):
    yield node
    for child in node.children:
        yield from _walk(child)


def analyze_credentials(files: dict, parser) -> dict:
    paths: list[Path] = files.get("source_files") or []
    hits = []

    for path in paths:
        text = path.read_text(encoding="utf-8", errors="replace")
        src = text.encode("utf-8")
        tree = parser.parse(src)

        for node in _walk(tree.root_node):
            if node.type == "string_literal":
                val = _node_text(src, node).lower()
                for cred in CREDENTIAL_PATHS:
                    if cred in val:
                        hits.append(f"{cred} in {path.name}")
                        break

    return {
        "credential_paths_accessed": list(set(hits)),
        "has_credential_access": len(hits) > 0,
    }
