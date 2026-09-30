from __future__ import annotations
from pathlib import Path

PROCESS_APIS = {
    "Command::new", "process::Command", "libc::system", "libc::execve", "libc::popen"
}
SHELLS = {"sh", "bash", "cmd.exe", "powershell", "pwsh"}

def _node_text(src: bytes, node) -> str:
    return src[node.start_byte : node.end_byte].decode("utf-8", errors="replace")

def _walk(node):
    yield node
    for child in node.children:
        yield from _walk(child)

def analyze_process_execution(files: dict, parser) -> dict:
    paths: list[Path] = files.get("source_files") or []
    calls = []
    shells = []
    
    for path in paths:
        if path.name == "build.rs":
            continue
            
        text = path.read_text(encoding="utf-8", errors="replace")
        src = text.encode("utf-8")
        tree = parser.parse(src)
        
        for node in _walk(tree.root_node):
            if node.type == "call_expression":
                name = _node_text(src, node.child_by_field_name("function") or node)
                for api in PROCESS_APIS:
                    if api in name:
                        # try to get args to see if it's a shell
                        args_node = node.child_by_field_name("arguments")
                        arg_text = _node_text(src, args_node) if args_node else ""
                        calls.append(f"{api}({arg_text}) in {path.name}")
                        
                        for sh in SHELLS:
                            if sh in arg_text.lower():
                                shells.append(sh)
                        break
                        
    return {
        "process_calls": list(set(calls)),
        "uses_shell": len(shells) > 0,
        "shells_used": list(set(shells)),
        "has_process_execution": len(calls) > 0
    }
