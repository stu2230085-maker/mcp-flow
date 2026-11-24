"""Read-only MCP server allowing AI agents to inspect session data flows safely (Milestone M5)."""

from __future__ import annotations

from mcp_flow.server.mcp_server import ReadOnlyFlowMcpServer, run_stdio_mcp_server

__all__ = ["ReadOnlyFlowMcpServer", "run_stdio_mcp_server"]
