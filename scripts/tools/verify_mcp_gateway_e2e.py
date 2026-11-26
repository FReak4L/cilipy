#!/usr/bin/env python3
"""E2E verification suite for AGY Remote MCP Gateway across configured domains.
Set MCP_GW_DOMAINS="https://mcp.example.com,https://gateway.example.com" in env.
"""
import json
import os
import sys
import urllib.error
import urllib.request


def http_req(url, method="GET", headers=None, body=None, timeout=20):
    hdrs = {"User-Agent": "AGY-MCP-Client/4.0 (StreamableHTTP)"}
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(url, data=body, headers=hdrs, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, dict(resp.headers), resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode("utf-8", errors="replace")


def rpc(url, token, method, params=None, extra_headers=None, req_id=1):
    hdrs = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "Authorization": f"Bearer {token}",
    }
    if extra_headers:
        hdrs.update(extra_headers)
    payload = {"jsonrpc": "2.0", "id": req_id, "method": method}
    if params is not None:
        payload["params"] = params
    code, rhdrs, text = http_req(url, "POST", hdrs, json.dumps(payload).encode())
    data = json.loads(text) if text.strip().startswith("{") else {"raw": text}
    return code, rhdrs, data


def run_suite(token: str):
    raw_domains = os.environ.get("MCP_GW_DOMAINS", "http://127.0.0.1:8788")
    domains = [d.strip().rstrip("/") for d in raw_domains.split(",") if d.strip()]
    passed = 0
    failed = 0

    def check(name, cond, detail=""):
        nonlocal passed, failed
        if cond:
            passed += 1
            print(f"  [PASS] {name}")
        else:
            failed += 1
            print(f"  [FAIL] {name} -> {detail}")

    for base in domains:
        print(f"\n=== Testing {base} ===")
        c, _, b = http_req(f"{base}/healthz")
        check("GET /healthz 200 & ok=true", c == 200 and '"ok":true' in b.replace(" ", ""), f"{c} {b[:120]}")

        c, h, _ = http_req(
            f"{base}/mcp",
            "POST",
            {"Content-Type": "application/json"},
            b'{"jsonrpc":"2.0","id":1,"method":"ping"}',
        )
        www = {k.lower(): v for k, v in h.items()}.get("www-authenticate", "")
        check("Unauth POST /mcp -> 401 + RFC 9728 header", c == 401 and "oauth-protected-resource" in www, f"{c} {www}")

        c1, _, b1 = http_req(f"{base}/.well-known/oauth-protected-resource")
        c2, _, b2 = http_req(f"{base}/.well-known/oauth-authorization-server")
        c3, h3, _ = http_req(f"{base}/.well-known/oauth-protected-resource", "OPTIONS", {"Origin": "https://claude.ai"})
        h3l = {k.lower(): v for k, v in h3.items()}
        check(
            "RFC 9728 & RFC 8414 metadata + CORS preflight",
            c1 == 200 and "authorization_servers" in b1 and c2 == 200 and "code_challenge_methods_supported" in b2 and c3 == 204 and "access-control-allow-origin" in h3l,
            f"{c1}/{c2}/{c3}",
        )

        c, h, d = rpc(f"{base}/mcp", token, "initialize", {"protocolVersion": "2025-11-25"})
        hl = {k.lower(): v for k, v in h.items()}
        sid = hl.get("mcp-session-id", "")
        check("2025 Stateful initialize returns Mcp-Session-Id", c == 200 and bool(sid) and "result" in d, f"{c} sid={sid}")

        c, _, d = rpc(f"{base}/mcp", token, "tools/list", extra_headers={"Mcp-Session-Id": sid}, req_id=2)
        tools = d.get("result", {}).get("tools", [])
        check(f"Smart Hub compact tools/list ({len(tools)} <= 15)", c == 200 and 7 <= len(tools) <= 15, f"{c} len={len(tools)}")

        c, _, d = rpc(
            f"{base}/mcp/s/optimizer",
            token,
            "tools/call",
            {"name": "opt_classify_turn", "arguments": {"prompt": "hello"}},
            extra_headers={"MCP-Protocol-Version": "2026-07-28"},
            req_id=3,
        )
        txt = d.get("result", {}).get("content", [{}])[0].get("text", "")
        check("2026 Stateless /mcp/s/optimizer opt_classify_turn", c == 200 and '"lite"' in txt, f"{c} {txt[:120]}")

        for name, path, tool, args, expect in [
            ("hub_discover_tools", "/mcp", "hub_discover_tools", {"query": "search web dork", "limit": 5}, "search_web_v3"),
            ("skillhub_search", "/mcp/s/skillhub", "skillhub_search", {"query": "mcp-builder", "limit": 3}, "mcp-builder"),
            ("models_list", "/mcp/s/models", "models_list", {"engine": "all"}, "venice_uncensored"),
            ("models_pool_health", "/mcp/s/models", "models_pool_health", {}, "mcp_ai_slots_available"),
            ("session_list", "/mcp/s/sessions", "session_list", {"limit": 5}, "history"),
            ("oh_glob_files", "/mcp/s/openhands", "oh_glob_files", {"pattern": "*.md"}, ""),
            ("fed_list_servers", "/mcp/s/federation", "fed_list_servers", {}, "search-v3"),
            ("search_status", "/mcp/s/search", "search_status", {}, ""),
        ]:
            c, _, d = rpc(f"{base}{path}", token, "tools/call", {"name": tool, "arguments": args})
            res = d.get("result", {})
            out = res.get("content", [{}])[0].get("text", "")
            ok = c == 200 and res.get("isError") is False and (expect in out if expect else len(out) > 2)
            check(f"Tool {name}", ok, f"{c} isErr={res.get('isError')} {out[:140]}")

        c, _, d = rpc(
            f"{base}/mcp/s/openhands",
            token,
            "tools/call",
            {"name": "oh_file_editor", "arguments": {"command": "view", "path": "/etc/agy-telegram/bot.env"}},
        )
        res = d.get("result", {})
        out = res.get("content", [{}])[0].get("text", "")
        check("Security: /etc/agy-telegram/bot.env denied", c == 200 and res.get("isError") is True and "forbidden" in out.lower(), f"{out[:140]}")

        c, _, d = rpc(f"{base}/mcp/s/browser", token, "tools/call", {"name": "browser_fast_read", "arguments": {"url": "http://169.254.169.254/latest/meta-data/"}})
        out = d.get("result", {}).get("content", [{}])[0].get("text", "")
        check("Security: Browser SSRF metadata blocked", c == 200 and d.get("result", {}).get("isError") is True and "forbidden" in out.lower(), f"{out[:120]}")

        c, _, _ = http_req(f"{base}/mcp", "DELETE", {"Authorization": f"Bearer {token}", "Mcp-Session-Id": sid})
        check("DELETE /mcp session teardown -> 204", c == 204, f"got {c}")

    print(f"\nSUMMARY: {passed} passed, {failed} failed")
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: verify_mcp_gateway_e2e.py <agymcp_token>")
        sys.exit(2)
    run_suite(sys.argv[1])
