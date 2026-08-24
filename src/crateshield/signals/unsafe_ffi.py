from __future__ import annotations

from pathlib import Path


def _node_text(src: bytes, node) -> str:
    return src[node.start_byte : node.end_byte].decode("utf-8", errors="replace")


def _walk(node):
    yield node
    for child in node.children:
        yield from _walk(child)


def analyze_unsafe_ffi(files: dict, parser) -> dict:
    paths: list[Path] = files.get("source_files") or []
    unsafe_blocks = 0
    unsafe_fns = 0
    loc = 0
    ffi = []
    syscalls = []
    parse_error = False

    for path in paths:
        text = path.read_text(encoding="utf-8", errors="replace")
        loc += text.count("\n") + 1
        src = text.encode("utf-8")
        tree = parser.parse(src)
        parse_error = parse_error or tree.root_node.has_error
        for node in _walk(tree.root_node):
            if node.type == "unsafe_block":
                unsafe_blocks += 1
            if node.type in {"function_item", "function_signature_item"}:
                # `unsafe fn`
                if any(c.type == "unsafe" for c in node.children):
                    unsafe_fns += 1
            if node.type == "extern_modifier" or node.type == "foreign_mod_item":
                ffi.append(_node_text(src, node)[:200])
            if node.type == "call_expression":
                name = _node_text(src, node.child_by_field_name("function") or node)
                if "syscall" in name or name.startswith("libc::"):
                    syscalls.append(name)

    kloc = max(loc / 1000.0, 0.001)
    return {
        "unsafe_block_count": unsafe_blocks,
        "unsafe_fn_count": unsafe_fns,
        "loc": loc,
        "unsafe_per_kloc": round((unsafe_blocks + unsafe_fns) / kloc, 2),
        "ffi_declarations": ffi[:20],
        "syscall_usage": sorted(set(syscalls))[:20],
        "parse_error": parse_error,
    }
