"""Regression and hardening tests for FlowStore concurrency/scaling, HTTP proxy, UTF-8 unescape, FIFO pairing, and MCP server."""

from __future__ import annotations

import http.server
import json
import socket
import stat
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from mcp_flow.derive.calls import derive_calls
from mcp_flow.derive.fragments import normalize_basic, sha256_hex
from mcp_flow.graph.builder import OBSERVATION_DISCLAIMER
from mcp_flow.match.base import MatchFragment
from mcp_flow.match.normalized import NormalizedMatcher, decode_and_normalize_variants
from mcp_flow.proxy.http_proxy import (
    StreamableHttpProxyServer,
    _extract_jsonrpc_lines_from_http_body,
)
from mcp_flow.server.mcp_server import ReadOnlyFlowMcpServer
from mcp_flow.store.db import FlowStore


def _get_unused_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class TestStoreHardening(unittest.TestCase):
    def test_concurrent_multithreaded_writes_and_reads(self) -> None:
        """FlowStore must safely serialize concurrent multi-threaded SQLite access without transaction errors."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "concurrent.db"
            store = FlowStore(db_path=db_path)
            try:
                store.ensure_session("s_conc", client="test")
                store.register_server("s_conc:srv", "s_conc", "srv", transport="streamable-http")
                errors: list[Exception] = []

                def worker(tid: int) -> None:
                    try:
                        for i in range(25):
                            body = json.dumps(
                                {"jsonrpc": "2.0", "id": f"{tid}-{i}", "method": "tools/call", "params": {"name": "t"}}
                            )
                            store.append_message(
                                session_id="s_conc",
                                server_id="s_conc:srv",
                                direction="c2s",
                                kind="request",
                                method="tools/call",
                                rpc_id=f"{tid}-{i}",
                                body=body,
                            )
                            if i % 5 == 0:
                                _ = store.get_messages("s_conc")
                    except Exception as exc:
                        errors.append(exc)

                threads = [threading.Thread(target=worker, args=(t,)) for t in range(6)]
                for th in threads:
                    th.start()
                for th in threads:
                    th.join()

                self.assertEqual(errors, [])
                self.assertEqual(len(store.get_messages("s_conc")), 150)

                # Verify 0600 permissions on DB and any WAL/SHM sidecars
                store._enforce_permissions()
                for suffix in ("", "-wal", "-shm"):
                    p = Path(f"{db_path}{suffix}")
                    if p.exists():
                        mode = stat.S_IMODE(p.stat().st_mode)
                        self.assertEqual(mode, 0o600, f"Expected 0600 on {p.name}, got {oct(mode)}")
            finally:
                store.close()

    def test_clear_flows_and_derived_data_exceeds_sqlite_param_limit(self) -> None:
        """clear_flows and clear_derived_data must use SQL subqueries and handle >1000 fragments cleanly."""
        store = FlowStore(":memory:")
        try:
            store.ensure_session("s_big", client="test")
            store.register_server("s_big:srv", "s_big", "srv")
            call_id = store.insert_call("s_big", "s_big:srv", "read_doc", 1, 2, 1.0, 2.0, 0)

            frag_ids: list[int] = []
            with store._lock, store.conn:
                for i in range(1100):
                    cur = store.conn.execute(
                        """
                        INSERT INTO fragments(call_id, side, json_path, text, norm, len, hash)
                        VALUES (?, 'out', ?, ?, ?, ?, ?)
                        """,
                        (call_id, f"$.items[{i}]", f"payload_value_{i}", f"payload_value_{i}", 16, f"h{i}"),
                    )
                    frag_ids.append(int(cur.lastrowid or 0))
                store.conn.execute(
                    """
                    INSERT INTO flows(src_frag, dst_frag, kind, score, src_span, dst_span)
                    VALUES (?, ?, 'exact', 1.0, '0:16', '0:16')
                    """,
                    (frag_ids[0], frag_ids[-1]),
                )

            store.insert_label("call", call_id, "confidential:manual", source="manual")
            store.insert_label("fragment", frag_ids[0], "secret:api_key", source="regex:test")

            store.clear_flows("s_big")
            self.assertEqual(store.get_flows("s_big"), [])

            store.clear_derived_data("s_big")
            self.assertEqual(store.get_calls("s_big"), [])
            self.assertEqual(store.get_fragments("s_big"), [])

            # Manual label must survive clear_derived_data (recomputability invariant)
            remaining = store.conn.execute("SELECT source, label FROM labels").fetchall()
            self.assertEqual([(r["source"], r["label"]) for r in remaining], [("manual", "confidential:manual")])
        finally:
            store.close()

    def test_purge_older_than_removes_manual_labels(self) -> None:
        """purge_older_than must delete all labels (including manual) for purged sessions so no orphans remain."""
        store = FlowStore(":memory:")
        try:
            old_ts = time.time() - 3600
            store.ensure_session("s_old", client="test", started_at=old_ts)
            store.register_server("s_old:srv", "s_old", "srv")
            cid = store.insert_call("s_old", "s_old:srv", "read", 1, 2, old_ts, old_ts + 1, 0)
            fid = store.insert_fragment(cid, "out", "$.text", "secret_data_1234", "secret_data_1234", 16, "h1")
            store.insert_label("call", cid, "confidential:manual", source="manual")
            store.insert_label("fragment", fid, "secret:manual_frag", source="manual")

            purged = store.purge_older_than(max_age_seconds=60)
            self.assertEqual(purged, 1)
            label_count = store.conn.execute("SELECT COUNT(*) FROM labels").fetchone()[0]
            self.assertEqual(label_count, 0)
        finally:
            store.close()


class TestHttpProxyHardening(unittest.TestCase):
    def test_extract_pretty_printed_json_and_multiline_sse(self) -> None:
        pretty_json = json.dumps(
            {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "docs.read"}},
            indent=2,
        )
        extracted = _extract_jsonrpc_lines_from_http_body(pretty_json, "application/json")
        self.assertEqual(len(extracted), 1)
        self.assertEqual(json.loads(extracted[0])["id"], 1)

        sse_body = (
            "event: message\n"
            "data: {\n"
            'data:   "jsonrpc": "2.0",\n'
            'data:   "id": 2,\n'
            'data:   "result": {"ok": true}\n'
            "data: }\n"
            "\n"
            'data: {"jsonrpc":"2.0","id":3,"result":{"ok":true}}\n\n'
        )
        sse_extracted = _extract_jsonrpc_lines_from_http_body(sse_body, "text/event-stream; charset=utf-8")
        self.assertEqual(len(sse_extracted), 2)
        self.assertEqual(json.loads(sse_extracted[0])["id"], 2)
        self.assertEqual(json.loads(sse_extracted[1])["id"], 3)

    def test_http_proxy_pretty_json_logging_failure_isolation_and_502(self) -> None:
        """HTTP proxy must record pretty-printed JSON, survive DB write errors without dropping relay, and return 502 on upstream failure."""

        class UpstreamHandler(http.server.BaseHTTPRequestHandler):
            def do_POST(self) -> None:  # noqa: N802
                length = int(self.headers.get("Content-Length", "0"))
                raw = self.rfile.read(length)
                req = json.loads(raw.decode("utf-8"))
                resp = json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": req["id"],
                        "result": {"content": [{"type": "text", "text": "secret-token-998877"}]},
                    },
                    indent=2,
                ).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(resp)))
                self.end_headers()
                self.wfile.write(resp)

            def log_message(self, format: str, *args: object) -> None:  # noqa: A002
                pass

        upstream = http.server.ThreadingHTTPServer(("127.0.0.1", 0), UpstreamHandler)
        upstream_port = int(upstream.server_address[1])
        upstream_thread = threading.Thread(target=upstream.serve_forever, daemon=True)
        upstream_thread.start()

        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "http_hardening.db"
            store = FlowStore(db_path=db_path)
            proxy = StreamableHttpProxyServer(
                target_url=f"http://127.0.0.1:{upstream_port}/mcp",
                store=store,
                session_id="s_http_pretty",
                server_name="docs",
            )
            proxy.start_background()
            try:
                pretty_req = json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": 10,
                        "method": "tools/call",
                        "params": {"name": "read_secret", "arguments": {"path": "/a"}},
                    },
                    indent=2,
                ).encode("utf-8")
                req = urllib.request.Request(
                    proxy.url,
                    data=pretty_req,
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=5) as resp:
                    self.assertEqual(resp.status, 200)
                    body = json.loads(resp.read().decode("utf-8"))
                    self.assertEqual(body["id"], 10)

                msgs = store.get_messages("s_http_pretty")
                self.assertEqual(len(msgs), 2)
                self.assertEqual(msgs[0].dir, "c2s")
                self.assertEqual(msgs[1].dir, "s2c")

                # Force DB max_size_bytes failure; relay must still succeed unmodified
                store.max_size_bytes = 1
                req2 = urllib.request.Request(
                    proxy.url,
                    data=pretty_req,
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with urllib.request.urlopen(req2, timeout=5) as resp2:
                    self.assertEqual(resp2.status, 200)
                    body2 = json.loads(resp2.read().decode("utf-8"))
                    self.assertEqual(body2["id"], 10)
            finally:
                proxy.stop()
                store.close()
                upstream.shutdown()
                upstream.server_close()

        # Verify 502 Bad Gateway when upstream is unreachable
        dead_port = _get_unused_port()
        store2 = FlowStore(":memory:")
        bad_proxy = StreamableHttpProxyServer(
            target_url=f"http://127.0.0.1:{dead_port}/mcp",
            store=store2,
            session_id="s_http_502",
            server_name="dead",
        )
        bad_proxy.start_background()
        try:
            req = urllib.request.Request(
                bad_proxy.url,
                data=b'{"jsonrpc":"2.0","id":1,"method":"ping"}',
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with self.assertRaises(urllib.error.HTTPError) as ctx:
                urllib.request.urlopen(req, timeout=5)
            self.assertEqual(ctx.exception.code, 502)
        finally:
            bad_proxy.stop()
            store2.close()


class TestNormalizedUnicodeAndFifoPairingAndMcpServer(unittest.TestCase):
    def test_utf8_safe_json_unescape_in_normalized_matcher(self) -> None:
        """NormalizedMatcher must decode JSON escapes without corrupting Japanese/non-ASCII UTF-8 characters."""
        src_text = "社外秘\nプロジェクトαの財務予測データ"
        dst_text = r"社外秘\nプロジェクト\u03b1の財務予測データ"

        variants = dict(decode_and_normalize_variants(dst_text))
        self.assertIn("json_unescape", variants)
        self.assertIn("社外秘", variants["json_unescape"])
        self.assertIn("プロジェクトα", variants["json_unescape"])

        src_frag = MatchFragment(
            id=1,
            call_id=1,
            side="out",
            json_path="$.text",
            text=src_text,
            norm=normalize_basic(src_text),
            len=len(src_text),
            hash=sha256_hex(src_text),
            req_seq=1,
            res_seq=2,
        )
        dst_frag = MatchFragment(
            id=2,
            call_id=2,
            side="in",
            json_path="$.body",
            text=dst_text,
            norm=normalize_basic(dst_text),
            len=len(dst_text),
            hash=sha256_hex(dst_text),
            req_seq=3,
            res_seq=4,
        )
        edges = NormalizedMatcher().match([src_frag], [dst_frag])
        self.assertEqual(len(edges), 1)
        self.assertEqual(edges[0].kind, "normalized")
        self.assertGreaterEqual(edges[0].score, 0.85)

    def test_derive_calls_fifo_pairing_for_duplicate_rpc_id(self) -> None:
        """Duplicate pending rpc_ids on the same server must pair with responses in FIFO order."""
        store = FlowStore(":memory:")
        try:
            store.ensure_session("s_fifo", client="test")
            store.register_server("s_fifo:srv", "s_fifo", "srv")
            store.append_message(
                "s_fifo", "s_fifo:srv", "c2s", "request", "tools/call", "1",
                json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "first_tool"}}),
                ts=1.0,
            )
            store.append_message(
                "s_fifo", "s_fifo:srv", "c2s", "request", "tools/call", "1",
                json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "second_tool"}}),
                ts=2.0,
            )
            store.append_message(
                "s_fifo", "s_fifo:srv", "s2c", "response", None, "1",
                json.dumps({"jsonrpc": "2.0", "id": 1, "result": {"content": [{"type": "text", "text": "r1"}]}}),
                ts=3.0,
            )
            store.append_message(
                "s_fifo", "s_fifo:srv", "s2c", "response", None, "1",
                json.dumps({"jsonrpc": "2.0", "id": 1, "result": {"content": [{"type": "text", "text": "r2"}]}}),
                ts=4.0,
            )

            calls = derive_calls(store, "s_fifo")
            self.assertEqual(len(calls), 2)
            self.assertEqual(calls[0].tool, "first_tool")
            self.assertEqual(calls[0].res_seq, 3)
            self.assertEqual(calls[1].tool, "second_tool")
            self.assertEqual(calls[1].res_seq, 4)
        finally:
            store.close()

    def test_mcp_server_disclaimer_on_error_and_not_found_and_invalid_args(self) -> None:
        """All MCP server tool responses (including errors and not-found) must preserve OBSERVATION_DISCLAIMER."""
        store = FlowStore(":memory:")
        try:
            server = ReadOnlyFlowMcpServer(store=store, expose_text=False)

            not_found = server.call_tool("explain_edge", {"session_id": "missing", "edge_id": "e:1->2"})
            self.assertEqual(not_found["disclaimer"], OBSERVATION_DISCLAIMER)
            self.assertIn("error", not_found)

            bad_args_resp = server.handle_jsonrpc_request(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {"name": "list_sessions", "arguments": ["not-a-dict"]},
                }
            )
            assert bad_args_resp is not None
            self.assertTrue(bad_args_resp["result"]["isError"])
            bad_payload = json.loads(bad_args_resp["result"]["content"][0]["text"])
            self.assertEqual(bad_payload["disclaimer"], OBSERVATION_DISCLAIMER)

            unknown_tool_resp = server.handle_jsonrpc_request(
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {"name": "no_such_tool", "arguments": {}},
                }
            )
            assert unknown_tool_resp is not None
            self.assertTrue(unknown_tool_resp["result"]["isError"])
            err_payload = json.loads(unknown_tool_resp["result"]["content"][0]["text"])
            self.assertEqual(err_payload["disclaimer"], OBSERVATION_DISCLAIMER)
        finally:
            store.close()


if __name__ == "__main__":
    unittest.main()
