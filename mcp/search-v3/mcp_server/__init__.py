"""Professional Model Context Protocol (MCP) stdio server for Hybrid Search Pipeline v3."""

from __future__ import annotations

from typing import Any

__all__ = ["SearchV3MCPServer", "main"]


def __getattr__(name: str) -> Any:
    if name in ("SearchV3MCPServer", "main"):
        from mcp_server.server import SearchV3MCPServer, main

        return {"SearchV3MCPServer": SearchV3MCPServer, "main": main}[name]
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
