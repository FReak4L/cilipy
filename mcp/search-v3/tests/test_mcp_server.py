"""Unit and subprocess JSON-RPC 2.0 protocol tests for the `search-v3` MCP server."""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from core.models import (
    AllEnginesMatrixOutput,
    EngineMetrics,
    EngineQueryOutcome,
    PipelineOutput,
    QueryAllEnginesRecord,
    SearchResult,
)
from mcp_server.fetcher import FetchError, html_to_markdown_and_meta, validate_public_url
from mcp_server.server import SearchV3MCPServer
from mcp_server.tools import TOOL_DEFINITIONS, ToolExecutionError, dispatch_tool


class TestFetcherAndSSRFGuard(unittest.TestCase):
    def test_ssrf_blocks_private_loopback_metadata_and_bad_schemes(self) -> None:
        forbidden = [
            "http://127.0.0.1:8888/search",
            "http://localhost/admin",
            "http://169.254.169.254/latest/meta-data/",
            "http://10.0.0.1/",
            "http://192.168.1.1/",
            "http://[::1]:8080/",
            "file:///etc/passwd",
            "ftp://example.com/file",
        ]
        for bad_url in forbidden:
            with self.assertRaises(FetchError, msg=f"Should have blocked {bad_url}"):
                asyncio.run(validate_public_url(bad_url))

    def test_html_to_markdown_headings_and_links(self) -> None:
        sample_html = """
        <html>
          <head><title>Asyncio Docs</title><script>alert(1)</script></head>
          <body>
            <nav><a href="/nav">Menu</a></nav>
            <main>
              <h1>Asyncio Guide</h1>
              <p>Read the <a href="/tasks">Tasks API</a> for coroutines.</p>
              <h2>Event Loop</h2>
              <pre><code>asyncio.run(main())</code></pre>
            </main>
          </body>
        </html>
        """
        title, md, headings, links = html_to_markdown_and_meta(
            sample_html, "https://docs.python.org/3/library/asyncio.html", include_links=True
        )
        self.assertEqual(title, "Asyncio Docs")
        self.assertNotIn("alert(1)", md)
        self.assertIn("# Asyncio Guide", md)
        self.assertIn("## Event Loop", md)
        self.assertIn("asyncio.run(main())", md)
        self.assertEqual(
            headings,
            [{"level": 1, "text": "Asyncio Guide"}, {"level": 2, "text": "Event Loop"}],
        )
        self.assertIn("https://docs.python.org/tasks", links)


class TestMCPProtocolAndTools(unittest.TestCase):
    def test_subprocess_stdio_jsonrpc_handshake_and_tools(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            env = dict(os.environ)
            env["SEARCH_V3_WORKSPACE"] = str(Path(tmpdir) / "ws")

            requests = [
                {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-03-26"}},
                {"jsonrpc": "2.0", "method": "notifications/initialized"},
                {"jsonrpc": "2.0", "id": 2, "method": "ping"},
                {"jsonrpc": "2.0", "id": 3, "method": "tools/list"},
                {
                    "jsonrpc": "2.0",
                    "id": 4,
                    "method": "tools/call",
                    "params": {
                        "name": "parse_dork_ast",
                        "arguments": {
                            "query": 'site:docs.python.org inurl:library "asyncio"',
                            "test_document": {
                                "title": "asyncio — Asynchronous I/O",
                                "url": "https://docs.python.org/3/library/asyncio.html",
                                "snippet": "High-level asyncio APIs",
                            },
                        },
                    },
                },
                {
                    "jsonrpc": "2.0",
                    "id": 5,
                    "method": "tools/call",
                    "params": {
                        "name": "fetch_url",
                        "arguments": {"url": "http://127.0.0.1:8888/"},
                    },
                },
                {"jsonrpc": "2.0", "id": 6, "method": "unknown/method"},
            ]
            stdin_payload = "\n\n" + "\n".join(json.dumps(r) for r in requests) + "\n"
            proc = subprocess.run(
                [sys.executable, "-m", "mcp_server.server"],
                input=stdin_payload,
                capture_output=True,
                text=True,
                env=env,
                timeout=15.0,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, msg=f"stderr={proc.stderr}")

            # Every single line on stdout MUST be strict JSON-RPC 2.0 (zero stray logs)
            lines = [ln for ln in proc.stdout.splitlines() if ln.strip()]
            self.assertEqual(len(lines), 6, msg=f"Expected 6 responses (notification skipped), got: {lines}")
            by_id = {json.loads(ln)["id"]: json.loads(ln) for ln in lines}

            # 1. initialize
            self.assertEqual(by_id[1]["result"]["protocolVersion"], "2025-03-26")
            self.assertEqual(by_id[1]["result"]["serverInfo"]["name"], "search-v3")
            # 2. ping
            self.assertEqual(by_id[2]["result"], {})
            # 3. tools/list
            tool_names = {t["name"] for t in by_id[3]["result"]["tools"]}
            self.assertEqual(tool_names, {t["name"] for t in TOOL_DEFINITIONS})
            self.assertGreaterEqual(len(tool_names), 8)
            # 4. parse_dork_ast
            self.assertFalse(by_id[4]["result"]["isError"])
            ast_data = json.loads(by_id[4]["result"]["content"][0]["text"])
            self.assertTrue(ast_data["valid"])
            self.assertTrue(ast_data["test_evaluation"]["admitted"])
            # 5. fetch_url SSRF blocked -> isError=True
            self.assertTrue(by_id[5]["result"]["isError"])
            self.assertIn("Blocked", by_id[5]["result"]["content"][0]["text"])
            # 6. unknown method -> -32601
            self.assertEqual(by_id[6]["error"]["code"], -32601)

    def test_search_tools_mocked_and_export_links_path_traversal_guard(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            ws_dir = Path(tmpdir) / "ws"
            with patch.dict(os.environ, {"SEARCH_V3_WORKSPACE": str(ws_dir)}):
                fake_res = SearchResult(
                    rank=1,
                    title="Asyncio Docs",
                    url="https://docs.python.org/3/library/asyncio.html",
                    snippet="Asyncio reference",
                    engine="yahoo_direct",
                    query="asyncio",
                )
                fake_out = PipelineOutput(
                    total_results=1,
                    unique_domains=1,
                    elapsed_seconds=0.42,
                    results=[fake_res],
                    engine_metrics=[
                        EngineMetrics(
                            engine="yahoo_direct",
                            requests=1,
                            successes=1,
                            total_results_yielded=1,
                        )
                    ],
                )
                with patch(
                    "mcp_server.tools.SearchOrchestrator.execute_stream",
                    new=AsyncMock(return_value=fake_out),
                ):
                    text_out = asyncio.run(
                        dispatch_tool(
                            "search_web_v3",
                            {"query": "site:docs.python.org asyncio", "save_links_txt": True},
                        )
                    )
                self.assertIn("https://docs.python.org/3/library/asyncio.html", text_out)
                self.assertIn("Exported links-only", text_out)

                fake_matrix = AllEnginesMatrixOutput(
                    total_queries=1,
                    engines=["yahoo_direct"],
                    elapsed_seconds=0.5,
                    total_verified_links=1,
                    records=[
                        QueryAllEnginesRecord(
                            query_id=1,
                            difficulty=10,
                            query="site:docs.python.org asyncio",
                            unique_verified_count=1,
                            per_engine={
                                "yahoo_direct": EngineQueryOutcome(
                                    engine="yahoo_direct",
                                    status="ok",
                                    raw_count=1,
                                    ast_admitted_count=1,
                                    links=[fake_res],
                                )
                            },
                            merged_links=[fake_res],
                        )
                    ],
                )
                with patch(
                    "mcp_server.tools.SearchOrchestrator.execute_all_engines_matrix",
                    new=AsyncMock(return_value=fake_matrix),
                ):
                    mat_json_str = asyncio.run(
                        dispatch_tool(
                            "search_all_engines",
                            {
                                "queries": ["site:docs.python.org asyncio"],
                                "profile": "direct",
                                "save_json": True,
                                "save_links_txt": True,
                                "response_format": "json",
                            },
                        )
                    )
                mat_data = json.loads(mat_json_str)
                self.assertEqual(mat_data["total_verified_links"], 1)
                saved_json_name = Path(mat_data["exports"]["json"]).name

                # Re-export links from saved JSON via export_links_txt tool
                exp_res = json.loads(
                    asyncio.run(dispatch_tool("export_links_txt", {"run_file": saved_json_name}))
                )
                self.assertEqual(exp_res["unique_links_count"], 1)
                self.assertTrue(Path(exp_res["links_txt_path"]).is_file())

                # Path traversal must be rejected
                with self.assertRaises(ToolExecutionError):
                    asyncio.run(dispatch_tool("export_links_txt", {"run_file": "../../etc/passwd"}))

                # Invalid engine name must be rejected
                with self.assertRaises(ToolExecutionError):
                    asyncio.run(
                        dispatch_tool(
                            "search_web_v3",
                            {"query": "test", "engines": ["nonexistent_engine"]},
                        )
                    )

                # search_status works cleanly
                with patch("mcp_server.tools.discover_local_searxng", new=AsyncMock(return_value=None)):
                    status_data = json.loads(asyncio.run(dispatch_tool("search_status", {})))
                self.assertEqual(status_data["server"], "search-v3")
                self.assertIn("direct", status_data["profiles"])

    def test_server_direct_handle_invalid_json_type(self) -> None:
        srv = SearchV3MCPServer()
        resp = asyncio.run(srv.handle_message("not-a-dict"))  # type: ignore[arg-type]
        assert resp is not None
        self.assertEqual(resp["error"]["code"], -32600)


if __name__ == "__main__":
    unittest.main()
