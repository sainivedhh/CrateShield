from __future__ import annotations
import math
import re
from pathlib import Path


def shannon_entropy(data: str) -> float:
    if not data:
        return 0
    entropy = 0
    for x in set(data):
        p_x = float(data.count(x)) / len(data)
        entropy += -p_x * math.log2(p_x)
    return entropy


def _node_text(src: bytes, node) -> str:
    return src[node.start_byte : node.end_byte].decode("utf-8", errors="replace")


def _walk(node):
    yield node
    for child in node.children:
        yield from _walk(child)


def _snippet(src: bytes, node, pad: int = 2) -> str:
    lines = src.decode("utf-8", errors="replace").splitlines()
    start = max(0, node.start_point[0] - pad)
    end = min(len(lines), node.end_point[0] + pad + 1)
    return "\n".join(lines[start:end])


def analyze_obfuscation(files: dict, parser) -> dict:
    paths: list[Path] = files.get("source_files") or []

    base64_regex = re.compile(
        r"^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$"
    )
    hex_regex = re.compile(r"^[0-9a-fA-F]+$")

    high_entropy_strings = []
    base64_blobs = []
    hex_blobs = []
    string_concats = 0
    evidence = []

    for path in paths:
        text = path.read_text(encoding="utf-8", errors="replace")
        src = text.encode("utf-8")
        tree = parser.parse(src)

        for node in _walk(tree.root_node):
            hit = False
            if node.type == "string_literal":
                s = _node_text(src, node).strip('"')
                if len(s) > 16:
                    ent = shannon_entropy(s)
                    if ent > 5.0:
                        high_entropy_strings.append(s[:50] + "...")
                        hit = True

                    if len(s) > 32 and hex_regex.match(s):
                        hex_blobs.append(s[:50] + "...")
                        hit = True
                    elif len(s) > 32 and base64_regex.match(s):
                        base64_blobs.append(s[:50] + "...")
                        hit = True

            # Detect string concatenation or macro building
            # e.g., format!("{}{}", a, b) with suspicious parts, or concat!
            if node.type == "macro_invocation":
                name_node = node.child_by_field_name("macro_name") or node
                name = _node_text(src, name_node)
                if name in ("concat", "format"):
                    # Check if it looks like hiding something
                    toks = _node_text(src, node)
                    if len(toks) > 50 and toks.count('"') > 4:
                        string_concats += 1
                        hit = True

            if hit and len(evidence) < 50:
                evidence.append(
                    {
                        "file": str(path.name),
                        "line_start": node.start_point[0] + 1,
                        "line_end": node.end_point[0] + 1,
                        "snippet": _snippet(src, node),
                    }
                )

    return {
        "high_entropy_strings": high_entropy_strings[:20],
        "base64_blobs": base64_blobs[:20],
        "hex_blobs": hex_blobs[:20],
        "string_concats": string_concats,
        "evidence": evidence,
    }
