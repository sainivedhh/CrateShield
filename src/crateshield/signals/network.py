from __future__ import annotations
from pathlib import Path

NETWORK_APIS = {
    "TcpStream::connect", "UdpSocket::bind", "reqwest::get", "reqwest::Client", 
    "hyper::Client", "ureq::get", "ureq::post", "std::net::", "attohttpc"
}

def _node_text(src: bytes, node) -> str:
    return src[node.start_byte : node.end_byte].decode("utf-8", errors="replace")

def _walk(node):
    yield node
    for child in node.children:
        yield from _walk(child)

def analyze_network(files: dict, parser) -> dict:
    paths: list[Path] = files.get("source_files") or []
    calls = []
    
    for path in paths:
        if path.name == "build.rs":
            continue # Handled by build_rs.py
            
        text = path.read_text(encoding="utf-8", errors="replace")
        src = text.encode("utf-8")
        tree = parser.parse(src)
        
        for node in _walk(tree.root_node):
            if node.type == "call_expression":
                name = _node_text(src, node.child_by_field_name("function") or node)
                for api in NETWORK_APIS:
                    if api in name:
                        calls.append(f"{api} (in {path.name})")
                        break
                        
    return {
        "network_api_calls": list(set(calls)),
        "has_network": len(calls) > 0
    }
