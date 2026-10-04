from __future__ import annotations
from pathlib import Path

import re

NETWORK_APIS = {
    "TcpStream::connect",
    "UdpSocket::bind",
    "reqwest::get",
    "reqwest::Client",
    "hyper::Client",
    "ureq::get",
    "ureq::post",
    "std::net::",
    "attohttpc",
}

PASTEBIN_DOMAINS = {
    "pastebin.com",
    "hastebin.com",
    "ghostbin.co",
    "rentry.co",
    "ngrok.io",
    "localtunnel.me",
    "discord.com/api/webhooks",
}


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


def analyze_network(files: dict, parser) -> dict:
    paths: list[Path] = files.get("source_files") or []
    calls = []
    hardcoded_urls = []
    suspicious_domains = []
    evidence = []

    url_regex = re.compile(r'https?://[^\s\'"]+')
    ip_regex = re.compile(r"(?:[0-9]{1,3}\.){3}[0-9]{1,3}")

    for path in paths:
        if path.name == "build.rs":
            continue  # Handled by build_rs.py

        text = path.read_text(encoding="utf-8", errors="replace")
        src = text.encode("utf-8")
        tree = parser.parse(src)

        for node in _walk(tree.root_node):
            hit = False

            if node.type == "string_literal":
                s = _node_text(src, node).strip('"')
                found_url = url_regex.findall(s)
                found_ip = ip_regex.findall(s)

                if found_url:
                    hardcoded_urls.extend(found_url)
                    hit = True
                    for u in found_url:
                        if any(d in u for d in PASTEBIN_DOMAINS):
                            suspicious_domains.append(u)

                if found_ip:
                    hardcoded_urls.extend(found_ip)
                    hit = True

            if node.type == "call_expression":
                name = _node_text(src, node.child_by_field_name("function") or node)
                for api in NETWORK_APIS:
                    if api in name:
                        calls.append(f"{api} (in {path.name})")
                        hit = True
                        break

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
        "network_api_calls": list(set(calls)),
        "has_network": len(calls) > 0,
        "hardcoded_urls": list(set(hardcoded_urls)),
        "suspicious_domains": list(set(suspicious_domains)),
        "evidence": evidence,
    }
