"""Streamable HTTP reverse proxy for MCP servers (Milestone M6)."""

from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from mcp_flow.proxy.jsonrpc import parse_jsonrpc_line
from mcp_flow.store.db import FlowStore


def _extract_jsonrpc_lines_from_http_body(body_text: str, content_type: str) -> list[str]:
    """
    Extract JSON-RPC payloads from either application/json (single-line, pretty-printed,
    batch array, or NDJSON) or text/event-stream (SSE, including multi-line data events).
    """
    if "text/event-stream" in content_type.lower():
        payloads: list[str] = []
        event_data: list[str] = []

        def _flush_event() -> None:
            if not event_data:
                return
            joined = "\n".join(event_data).strip()
            event_data.clear()
            if not joined:
                return
            try:
                json.loads(joined)
                payloads.append(joined)
            except json.JSONDecodeError:
                # Fallback if multiple independent JSON lines were emitted without blank-line separators
                for part in joined.splitlines():
                    part_s = part.strip()
                    if part_s:
                        payloads.append(part_s)

        for raw_line in body_text.splitlines():
            if not raw_line.strip():
                _flush_event()
                continue
            stripped = raw_line.lstrip()
            if stripped.startswith("data:"):
                data_part = stripped[len("data:") :]
                if data_part.startswith(" "):
                    data_part = data_part[1:]
                event_data.append(data_part)
        _flush_event()
        return payloads

    stripped_body = body_text.strip()
    if not stripped_body:
        return []
    try:
        json.loads(stripped_body)
        return [stripped_body]
    except json.JSONDecodeError:
        return [line for line in body_text.splitlines() if line.strip()]


def _record_http_messages(
    store: FlowStore,
    session_id: str,
    server_id: str,
    direction: str,
    body_bytes: bytes,
    content_type: str,
    ts: float,
) -> None:
    """Best-effort passive recording of HTTP JSON-RPC payloads; never raises to disrupt relay."""
    try:
        body_text = body_bytes.decode("utf-8", errors="replace")
        records: list[tuple[str, str, str, str, str | None, str | None, str, float]] = []
        for payload in _extract_jsonrpc_lines_from_http_body(body_text, content_type):
            for msg in parse_jsonrpc_line(payload):
                records.append(
                    (
                        session_id,
                        server_id,
                        direction,
                        msg.kind,
                        msg.method,
                        msg.rpc_id,
                        msg.raw_body,
                        ts,
                    )
                )
        if records:
            store.append_messages_batch(records)
    except Exception:
        # Passive observer must never crash or block the HTTP relay
        pass


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
                raw_length = self.headers.get("Content-Length", "0")
                try:
                    length = int(raw_length)
                    if length < 0:
                        raise ValueError("Negative Content-Length")
                except ValueError:
                    err_body = b"Invalid Content-Length header"
                    self.send_response(400)
                    self.send_header("Content-Type", "text/plain; charset=utf-8")
                    self.send_header("Content-Length", str(len(err_body)))
                    self.end_headers()
                    self.wfile.write(err_body)
                    return

                req_bytes = self.rfile.read(length) if length > 0 else b""
                t_req = time.time()

                _record_http_messages(
                    store=proxy_ref.store,
                    session_id=proxy_ref.session_id,
                    server_id=proxy_ref.server_id,
                    direction="c2s",
                    body_bytes=req_bytes,
                    content_type=self.headers.get("Content-Type", "application/json"),
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
                except (urllib.error.URLError, TimeoutError, OSError) as exc:
                    err_body = f"Upstream unreachable: {exc}".encode("utf-8", errors="replace")
                    self.send_response(502)
                    self.send_header("Content-Type", "text/plain; charset=utf-8")
                    self.send_header("Content-Length", str(len(err_body)))
                    self.end_headers()
                    self.wfile.write(err_body)
                    return

                t_res = time.time()
                resp_ct = resp_headers.get("Content-Type", "application/json") if resp_headers else "application/json"
                _record_http_messages(
                    store=proxy_ref.store,
                    session_id=proxy_ref.session_id,
                    server_id=proxy_ref.server_id,
                    direction="s2c",
                    body_bytes=resp_bytes,
                    content_type=resp_ct,
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
