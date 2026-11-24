"""
Read-only MCP Server (JSON-RPC 2.0 over stdio) exposing:
  - list_sessions
  - get_flow_graph
  - find_paths(source_label, sink_role)
  - explain_edge(edge_id)

By default (`expose_text=False`), fragment raw text is NEVER returned in responses to prevent
re-injecting sensitive payloads into the AI agent's context window.
"""

from __future__ import annotations

import json
import sys
from typing import Any, TextIO

from mcp_flow.derive.calls import derive_calls
from mcp_flow.derive.fragments import derive_fragments
from mcp_flow.graph.builder import OBSERVATION_DISCLAIMER, build_flow_graph
from mcp_flow.graph.exporters import to_json_dict
from mcp_flow.graph.paths import find_hazardous_paths
from mcp_flow.labels.rules import LabelRuleEngine
from mcp_flow.match.engine import FingerprintEngine
from mcp_flow.store.db import FlowStore


MCP_TOOLS_SPEC: list[dict[str, Any]] = [
    {
        "name": "list_sessions",
        "description": "List recorded MCP sessions with message and tool call counts.",
        "inputSchema": {
            "type": "object",
            "properties": {},
        },
    },
    {
        "name": "get_flow_graph",
        "description": (
            "Return the observed call-level data dependency graph for a session. "
            "Edges represent content similarity observations, not proof of causal reasoning. "
            "Fragment body text is omitted by default."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string", "description": "Target session ID"},
                "min_score": {"type": "number", "description": "Minimum edge score threshold", "default": 0.35},
            },
            "required": ["session_id"],
        },
    },
    {
        "name": "find_paths",
        "description": (
            "Find hazardous data-flow paths from a labeled confidential source to a sink role tool."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string", "description": "Target session ID"},
                "source_label": {
                    "type": "string",
                    "description": "Source confidentiality label pattern (e.g. 'secret:*', 'confidential:*', or '*')",
                    "default": "*",
                },
                "sink_role": {
                    "type": "string",
                    "description": "Target tool role (default 'sink')",
                    "default": "sink",
                },
                "min_score": {"type": "number", "description": "Minimum edge score threshold", "default": 0.35},
            },
            "required": ["session_id"],
        },
    },
    {
        "name": "explain_edge",
        "description": (
            "Return fragment-level match evidence (hashes, lengths, JSON paths, match spans, and scores) "
            "for a specific edge_id (e.g. 'e:1->2') or flow_id. Raw fragment text is withheld unless explicitly enabled."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string", "description": "Target session ID"},
                "edge_id": {"type": "string", "description": "Edge ID (e.g. 'e:1->2') or numeric flow_id"},
            },
            "required": ["session_id", "edge_id"],
        },
    },
]


class ReadOnlyFlowMcpServer:
    """Read-only MCP server handler enforcing non-disclosure of fragment raw text by default."""

    def __init__(
        self,
        store: FlowStore,
        expose_text: bool = False,
        auto_derive: bool = True,
    ) -> None:
        self.store = store
        self.expose_text = expose_text
        self.auto_derive = auto_derive

    def _ensure_analyzed(self, session_id: str) -> None:
        if not self.auto_derive:
            return
        calls = self.store.get_calls(session_id)
        if not calls and self.store.get_messages(session_id):
            derive_calls(self.store, session_id)
            derive_fragments(self.store, session_id)
            FingerprintEngine().run_on_session(self.store, session_id)
            LabelRuleEngine().apply_to_session(self.store, session_id)

    def call_tool(self, name: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
        """Execute one of the read-only inspection tools and return structured JSON output."""
        args = arguments or {}

        if name == "list_sessions":
            return {
                "disclaimer": OBSERVATION_DISCLAIMER,
                "expose_text": self.expose_text,
                "sessions": self.store.list_sessions(),
            }

        if name == "get_flow_graph":
            session_id = str(args.get("session_id", ""))
            min_score = float(args.get("min_score", 0.35))
            self._ensure_analyzed(session_id)
            graph = build_flow_graph(self.store, session_id, min_score=min_score)
            return to_json_dict(graph, expose_text=self.expose_text)

        if name == "find_paths":
            session_id = str(args.get("session_id", ""))
            source_label = args.get("source_label", "*")
            sink_role = str(args.get("sink_role", "sink"))
            min_score = float(args.get("min_score", 0.35))
            self._ensure_analyzed(session_id)
            graph = build_flow_graph(self.store, session_id, min_score=min_score)
            paths = find_hazardous_paths(
                graph,
                source_label=source_label,
                sink_role=sink_role,
                min_score=min_score,
            )
            return {
                "session_id": session_id,
                "disclaimer": OBSERVATION_DISCLAIMER,
                "source_label": source_label,
                "sink_role": sink_role,
                "path_count": len(paths),
                "paths": [p.to_dict(expose_text=self.expose_text) for p in paths],
            }

        if name == "explain_edge":
            session_id = str(args.get("session_id", ""))
            edge_id = str(args.get("edge_id", ""))
            self._ensure_analyzed(session_id)
            graph = build_flow_graph(self.store, session_id, min_score=0.0)
            edge = graph.get_edge(edge_id)
            if edge is None:
                return {
                    "error": f"Edge '{edge_id}' not found in session '{session_id}'",
                    "session_id": session_id,
                }
            src_node = graph.nodes[edge.src_call_id]
            dst_node = graph.nodes[edge.dst_call_id]
            return {
                "session_id": session_id,
                "disclaimer": OBSERVATION_DISCLAIMER,
                "expose_text": self.expose_text,
                "edge": edge.to_dict(expose_text=self.expose_text),
                "source_call": {
                    "call_id": src_node.call_id,
                    "display_name": src_node.display_name,
                    "req_seq": src_node.req_seq,
                    "role": src_node.role,
                    "labels": src_node.labels,
                },
                "destination_call": {
                    "call_id": dst_node.call_id,
                    "display_name": dst_node.display_name,
                    "req_seq": dst_node.req_seq,
                    "role": dst_node.role,
                    "labels": dst_node.labels,
                },
            }

        raise ValueError(f"Unknown tool: {name}")

    def handle_jsonrpc_request(self, request: dict[str, Any]) -> dict[str, Any] | None:
        """Process a single JSON-RPC 2.0 request or notification and return response dict (or None for notifications)."""
        method = request.get("method")
        rpc_id = request.get("id")
        params = request.get("params") or {}

        # Notifications have no id
        if rpc_id is None:
            return None

        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": rpc_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "mcp-flow-server", "version": "0.1.0"},
                },
            }

        if method == "ping":
            return {"jsonrpc": "2.0", "id": rpc_id, "result": {}}

        if method == "tools/list":
            return {
                "jsonrpc": "2.0",
                "id": rpc_id,
                "result": {"tools": MCP_TOOLS_SPEC},
            }

        if method == "tools/call":
            tool_name = params.get("name", "")
            tool_args = params.get("arguments") or {}
            try:
                payload = self.call_tool(tool_name, tool_args)
                return {
                    "jsonrpc": "2.0",
                    "id": rpc_id,
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": json.dumps(payload, ensure_ascii=False),
                            }
                        ],
                        "isError": False,
                    },
                }
            except Exception as exc:
                return {
                    "jsonrpc": "2.0",
                    "id": rpc_id,
                    "result": {
                        "content": [{"type": "text", "text": json.dumps({"error": str(exc)})}],
                        "isError": True,
                    },
                }

        return {
            "jsonrpc": "2.0",
            "id": rpc_id,
            "error": {"code": -32601, "message": f"Method not found: {method}"},
        }


def run_stdio_mcp_server(
    store: FlowStore,
    expose_text: bool = False,
    in_stream: TextIO | None = None,
    out_stream: TextIO | None = None,
) -> None:
    """Run the read-only MCP server over line-delimited JSON-RPC stdio."""
    server = ReadOnlyFlowMcpServer(store=store, expose_text=expose_text)
    reader = in_stream if in_stream is not None else sys.stdin
    writer = out_stream if out_stream is not None else sys.stdout

    for line in reader:
        stripped = line.strip()
        if not stripped:
            continue
        try:
            req = json.loads(stripped)
        except json.JSONDecodeError:
            continue
        if not isinstance(req, dict):
            continue
        resp = server.handle_jsonrpc_request(req)
        if resp is not None:
            writer.write(json.dumps(resp, ensure_ascii=False) + "\n")
            writer.flush()
