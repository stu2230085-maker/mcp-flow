"""Streamable HTTP reverse proxy for MCP servers (Milestone M6)."""

from __future__ import annotations

import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from mcp_flow.proxy.jsonrpc import parse_jsonrpc_line
from mcp_flow.store.db import FlowStore


def _extract_jsonrpc_lines_from_http_body(body_text: str, content_type: str) -> list[str]:
    """Extract JSON-RPC payloads from either application/json or text/event-stream (SSE) bodies."""
    if "text/event-stream" in content_type.lower():
        lines: list[str] = []
        for line in body_text.splitlines():
            stripped = line.strip()
            if stripped.startswith("data:"):
                data_part = stripped[len("data:") :].strip()
                if data_part:
                    lines.append(data_part)
        return lines
    return [line for line in body_text.splitlines() if line.strip()]


class StreamableHttpProxyServer:
    """
    Lightweight HTTP reverse proxy that forwards MCP Streamable HTTP requests
    to a target upstream URL unmodified while recording JSON-RPC messages in SQLite.
    """

    def __init__(
        self,
        target_url: str,
        store: FlowStore,
        session_id: str,
        server_name: str,
        host: str = "127.0.0.1",
        port: int = 0,
        server_id: str | None = None,
    ) -> None:
        self.target_url = target_url
        self.store = store
        self.session_id = session_id
        self.server_name = server_name
        self.server_id = server_id or f"{session_id}:{server_name}"
        self.host = host

        self.store.ensure_session(session_id=session_id, client="http-client")
        self.store.register_server(
            server_id=self.server_id,
            session_id=session_id,
            name=server_name,
            command=target_url,
            transport="streamable-http",
        )

        proxy_ref = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:  # noqa: N802
                length = int(self.headers.get("Content-Length", "0"))
                req_bytes = self.rfile.read(length) if length > 0 else b""
                t_req = time.time()

                req_text = req_bytes.decode("utf-8", errors="replace")
                for line in _extract_jsonrpc_lines_from_http_body(
                    req_text, self.headers.get("Content-Type", "application/json")
                ):
                    for msg in parse_jsonrpc_line(line):
                        proxy_ref.store.append_message(
                            session_id=proxy_ref.session_id,
                            server_id=proxy_ref.server_id,
                            direction="c2s",
                            kind=msg.kind,
                            method=msg.method,
                            rpc_id=msg.rpc_id,
                            body=msg.raw_body,
                            ts=t_req,
                        )

                forward_headers = {
                    k: v
                    for k, v in self.headers.items()
                    if k.lower() not in ("host", "content-length", "connection")
                }
                upstream_req = urllib.request.Request(
                    proxy_ref.target_url,
                    data=req_bytes,
                    headers=forward_headers,
                    method="POST",
                )
                try:
                    with urllib.request.urlopen(upstream_req, timeout=30) as resp:
                        status = resp.status
                        resp_headers = resp.headers
                        resp_bytes = resp.read()
                except urllib.error.HTTPError as exc:
                    status = exc.code
                    resp_headers = exc.headers
                    resp_bytes = exc.read()

                t_res = time.time()
                resp_ct = resp_headers.get("Content-Type", "application/json") if resp_headers else "application/json"
                resp_text = resp_bytes.decode("utf-8", errors="replace")
                for line in _extract_jsonrpc_lines_from_http_body(resp_text, resp_ct):
                    for msg in parse_jsonrpc_line(line):
                        proxy_ref.store.append_message(
                            session_id=proxy_ref.session_id,
                            server_id=proxy_ref.server_id,
                            direction="s2c",
                            kind=msg.kind,
                            method=msg.method,
                            rpc_id=msg.rpc_id,
                            body=msg.raw_body,
                            ts=t_res,
                        )

                self.send_response(status)
                if resp_headers:
                    for k, v in resp_headers.items():
                        if k.lower() not in ("transfer-encoding", "content-length", "connection"):
                            self.send_header(k, v)
                self.send_header("Content-Length", str(len(resp_bytes)))
                self.end_headers()
                self.wfile.write(resp_bytes)

            def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
                pass

        self._httpd = ThreadingHTTPServer((host, port), Handler)
        self.port = int(self._httpd.server_address[1])
        self._thread: threading.Thread | None = None

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}"

    def start_background(self) -> None:
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()

    def serve_forever(self) -> None:
        self._httpd.serve_forever()

    def stop(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
