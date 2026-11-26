"""Zero-dependency async JSON-RPC 2.0 Stdio MCP server for `search-v3`."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
from typing import Any, TextIO

from mcp_server.tools import TOOL_DEFINITIONS, ToolExecutionError, dispatch_tool

SERVER_NAME = "search-v3"
SERVER_VERSION = "3.0.0"
SUPPORTED_PROTOCOL_VERSIONS = ("2025-06-18", "2025-03-26", "2024-11-05")
DEFAULT_PROTOCOL_VERSION = "2025-03-26"

SERVER_INSTRUCTIONS = (
    "Hybrid Search Pipeline v3 MCP Server: federated multi-engine search "
    "(SearXNG, Yahoo Direct, DDG HTML/Lite/DDGS, Google 4-tier) with Thompson Sampling, "
    "Dynamic Poisson pacing, Strict Boolean AST filtering, 64-bit SimHash/Jaccard dedup, "
    "SSRF-safe BoringSSL webpage reader (`fetch_url`), offline dork AST compiler (`parse_dork_ast`), "
    "Katana schema crawler (`crawl_urls`), live telemetry (`search_status`), and jq links-only exporter."
)


def _configure_stderr_only_logging() -> None:
    """Force ALL logs to stderr so stdout remains 100% pure JSON-RPC 2.0 frames."""
    debug_enabled = os.environ.get("SEARCH_V3_MCP_DEBUG", "").strip().lower() in ("1", "true", "yes")
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s"))

    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(logging.DEBUG if debug_enabled else logging.WARNING)

    v3_log = logging.getLogger("hybrid_search.v3")
    v3_log.handlers.clear()
    v3_log.propagate = False
    v3_log.addHandler(handler)
    v3_log.setLevel(logging.DEBUG if debug_enabled else logging.WARNING)


class SearchV3MCPServer:
    """Async MCP stdio JSON-RPC 2.0 protocol server with concurrent tool execution."""

    def __init__(
        self,
        *,
        stdin: TextIO | None = None,
        stdout: TextIO | None = None,
    ) -> None:
        self._stdin: TextIO = stdin if stdin is not None else sys.stdin
        self._stdout: TextIO = stdout if stdout is not None else sys.stdout
        self._write_lock = asyncio.Lock()
        self._in_flight: set[asyncio.Task[None]] = set()

    async def _send(self, payload: dict[str, Any]) -> None:
        raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n"
        async with self._write_lock:
            self._stdout.write(raw)
            self._stdout.flush()

    async def handle_message(self, message: dict[str, Any]) -> dict[str, Any] | None:
        """Process one decoded JSON-RPC 2.0 object; return response dict or None for notifications."""
        if not isinstance(message, dict):
            return {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32600, "message": "Invalid Request: expected JSON object"},
            }

        method = message.get("method")
        has_id = "id" in message and message.get("id") is not None
        req_id = message.get("id")
        params = message.get("params") or {}

        # Notifications have no id and MUST NOT produce a response
        if not has_id:
            return None

        if not isinstance(method, str):
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32600, "message": "Invalid Request: missing string method"},
            }

        if method == "initialize":
            requested_ver = str(params.get("protocolVersion") or "")
            negotiated = (
                requested_ver
                if requested_ver in SUPPORTED_PROTOCOL_VERSIONS
                else DEFAULT_PROTOCOL_VERSION
            )
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": negotiated,
                    "capabilities": {
                        "tools": {"listChanged": False},
                    },
                    "serverInfo": {
                        "name": SERVER_NAME,
                        "version": SERVER_VERSION,
                    },
                    "instructions": SERVER_INSTRUCTIONS,
                },
            }

        if method == "ping":
            return {"jsonrpc": "2.0", "id": req_id, "result": {}}

        if method == "tools/list":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"tools": TOOL_DEFINITIONS},
            }

        if method == "tools/call":
            if not isinstance(params, dict) or not isinstance(params.get("name"), str):
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32602, "message": "Invalid params: expected `name` string"},
                }
            tool_name = params["name"]
            tool_args = params.get("arguments")
            try:
                text_out = await dispatch_tool(tool_name, tool_args)
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [{"type": "text", "text": text_out}],
                        "isError": False,
                    },
                }
            except ToolExecutionError as exc:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [{"type": "text", "text": f"Error: {exc}"}],
                        "isError": True,
                    },
                }
            except Exception as exc:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [{"type": "text", "text": f"Internal error in {tool_name}: {exc}"}],
                        "isError": True,
                    },
                }

        if method == "resources/list":
            return {"jsonrpc": "2.0", "id": req_id, "result": {"resources": []}}

        if method == "resources/templates/list":
            return {"jsonrpc": "2.0", "id": req_id, "result": {"resourceTemplates": []}}

        if method == "prompts/list":
            return {"jsonrpc": "2.0", "id": req_id, "result": {"prompts": []}}

        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": -32601, "message": f"Method not found: {method}"},
        }

    async def _dispatch_line(self, raw_line: str) -> None:
        line = raw_line.strip()
        if not line:
            return
        try:
            decoded = json.loads(line)
        except json.JSONDecodeError as exc:
            await self._send(
                {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32700, "message": f"Parse error: {exc}"},
                }
            )
            return

        response = await self.handle_message(decoded)
        if response is not None:
            await self._send(response)

    async def serve_forever(self) -> None:
        """Read newline-delimited JSON-RPC 2.0 requests from stdin until EOF."""
        loop = asyncio.get_running_loop()
        while True:
            raw_line = await loop.run_in_executor(None, self._stdin.readline)
            if raw_line == "":
                break
            if not raw_line.strip():
                continue
            task = asyncio.create_task(self._dispatch_line(raw_line))
            self._in_flight.add(task)
            task.add_done_callback(self._in_flight.discard)

        if self._in_flight:
            await asyncio.gather(*list(self._in_flight), return_exceptions=True)


def main() -> None:
    """CLI entrypoint for `search-v3-mcp` stdio MCP server."""
    # Capture real stdout exclusively for JSON-RPC frames and redirect all stray prints to stderr
    rpc_stdout = sys.stdout
    sys.stdout = sys.stderr
    _configure_stderr_only_logging()

    server = SearchV3MCPServer(stdin=sys.stdin, stdout=rpc_stdout)
    try:
        asyncio.run(server.serve_forever())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
