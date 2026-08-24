from __future__ import annotations

from crateshield.config import BENIGN_ENV_KEYS, SENSITIVE_ENV_KEYS

NETWORK_CALLEES = {
    "TcpStream::connect",
    "UdpSocket::bind",
    "UdpSocket::connect",
    "TcpListener::bind",
}
NETWORK_IDENTIFIERS = {"reqwest", "ureq", "hyper", "curl", "attohttpc"}
FILE_WRITE_CALLEES = {"fs::write", "File::create", "OpenOptions", "BufWriter"}
PROCESS_CALLEES = {"Command::new", "process::Command"}
ENV_CALLEES = {"env::var", "env::vars", "env::var_os", "env::vars_os"}


def _node_text(src: bytes, node) -> str:
    return src[node.start_byte : node.end_byte].decode("utf-8", errors="replace")


def _walk(node):
    yield node
    for child in node.children:
        yield from _walk(child)


def _call_name(src: bytes, node) -> str:
    # call_expression → function node
    fn = node.child_by_field_name("function")
    return _node_text(src, fn) if fn else _node_text(src, node)


def _string_args(src: bytes, node) -> list[str]:
    out = []
    args = node.child_by_field_name("arguments")
    if not args:
        return out
    for child in _walk(args):
        if child.type == "string_literal":
            out.append(_node_text(src, child).strip('"'))
    return out


def _snippet(src: bytes, node, pad: int = 2) -> str:
    lines = src.decode("utf-8", errors="replace").splitlines()
    start = max(0, node.start_point[0] - pad)
    end = min(len(lines), node.end_point[0] + pad + 1)
    return "\n".join(lines[start:end])


def analyze_build_rs(files: dict, parser) -> dict:
    text = files.get("build_rs")
    empty = {
        "has_build_rs": bool(text),
        "signals": [],
        "network_calls": [],
        "env_reads": [],
        "sensitive_env_reads": [],
        "file_writes": [],
        "process_spawns": [],
        "flagged_snippets": [],
        "parse_error": False,
    }
    if not text:
        empty["has_build_rs"] = False
        return empty

    src = text.encode("utf-8")
    tree = parser.parse(src)
    result = dict(empty)
    result["has_build_rs"] = True
    result["parse_error"] = tree.root_node.has_error
    signals: set[str] = set()

    for node in _walk(tree.root_node):
        if node.type != "call_expression":
            continue
        name = _call_name(src, node)
        args = _string_args(src, node)
        hit = False

        if any(name.endswith(c.split("::")[-1]) and c.split("::")[0] in name for c in NETWORK_CALLEES) or any(
            ident in name for ident in NETWORK_IDENTIFIERS
        ):
            result["network_calls"].append(name + (f"({args[0]})" if args else ""))
            signals.add("network_call")
            hit = True

        if any(name.endswith(c.split("::")[-1]) for c in PROCESS_CALLEES) or "Command" in name:
            result["process_spawns"].append(name + (f"({args[0]})" if args else ""))
            signals.add("process_spawn")
            hit = True

        if any(k in name for k in ("fs::write", "File::create", "OpenOptions", "BufWriter")):
            result["file_writes"].append(name + (f"({args[0]})" if args else ""))
            signals.add("file_write")
            hit = True

        if any(name.endswith(c.split("::")[-1]) for c in ENV_CALLEES) or "env::var" in name:
            key = args[0] if args else ""
            result["env_reads"].append(key or name)
            if key and key not in BENIGN_ENV_KEYS and any(
                key.startswith(p) or p in key.upper() for p in SENSITIVE_ENV_KEYS
            ):
                result["sensitive_env_reads"].append(key)
                signals.add("sensitive_env_var_read")
            elif key and key not in BENIGN_ENV_KEYS and not key.startswith("CARGO_"):
                signals.add("env_var_read")
            hit = True

        if hit:
            result["flagged_snippets"].append(_snippet(src, node))

    result["signals"] = sorted(signals)
    return result
