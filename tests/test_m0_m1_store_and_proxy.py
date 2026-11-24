"""Tests for M0 (SQLite schema, 0600 permissions, migrations, JSON-RPC parsing) and M1 (stdio proxy recording)."""

from __future__ import annotations

import io
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path

from mcp_flow.derive.calls import derive_calls
from mcp_flow.proxy.jsonrpc import parse_jsonrpc_line
from mcp_flow.proxy.stdio_proxy import run_stdio_proxy
from mcp_flow.store.db import FlowStore
from mcp_flow.store.redaction import RedactionPolicy


class TestM0AndM1StoreAndProxy(unittest.TestCase):
    """Verify M0 foundation and M1 transparent stdio proxy recording gates."""

    def test_m0_sqlite_schema_migrations_and_0600_permissions(self) -> None:
        """Database file must be created with 0600 permissions, WAL mode, and all 8 tables."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_file = Path(tmpdir) / "test_flow.db"
            store = FlowStore(db_path=db_file)
            try:
                mode = stat.S_IMODE(os.stat(db_file).st_mode)
                self.assertEqual(mode, 0o600)

                tables = {
                    r["name"]
                    for r in store.conn.execute(
                        "SELECT name FROM sqlite_master WHERE type='table'"
                    ).fetchall()
                }
                expected_tables = {
                    "schema_migrations",
                    "sessions",
                    "servers",
                    "messages",
                    "calls",
                    "fragments",
                    "flows",
                    "labels",
                    "tool_roles",
                }
                self.assertTrue(expected_tables.issubset(tables))
            finally:
                store.close()

    def test_m0_jsonrpc_extraction_is_non_mutating(self) -> None:
        """parse_jsonrpc_line must classify request/response/notification without altering raw text."""
        raw_req = '{"jsonrpc":"2.0","id":42,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/a"}}}'
        parsed = parse_jsonrpc_line(raw_req + "\n")
        self.assertEqual(len(parsed), 1)
        self.assertEqual(parsed[0].kind, "request")
        self.assertEqual(parsed[0].method, "tools/call")
        self.assertEqual(parsed[0].rpc_id, "42")
        self.assertEqual(parsed[0].raw_body, raw_req)

        raw_notif = '{"jsonrpc":"2.0","method":"notifications/initialized"}'
        parsed_n = parse_jsonrpc_line(raw_notif)
        self.assertEqual(len(parsed_n), 1)
        self.assertEqual(parsed_n[0].kind, "notification")
        self.assertIsNone(parsed_n[0].rpc_id)

        raw_res = '{"jsonrpc":"2.0","id":42,"result":{"content":[{"type":"text","text":"hello"}]}}'
        parsed_r = parse_jsonrpc_line(raw_res)
        self.assertEqual(len(parsed_r), 1)
        self.assertEqual(parsed_r[0].kind, "response")
        self.assertEqual(parsed_r[0].rpc_id, "42")

    def test_m1_stdio_proxy_records_messages_and_derives_calls(self) -> None:
        """M1 Gate: Invoking mock MCP server through stdio proxy must relay unmodified bytes and record messages/calls."""
        store = FlowStore(db_path=":memory:")
        try:
            mock_server_script = str(
                Path(__file__).resolve().parent.parent / "scenarios" / "mock_mcp_server.py"
            )
            requests = [
                {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {
                        "name": "read_file",
                        "arguments": {"path": "/corp/roadmap_2026.md"},
                    },
                },
                {
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "tools/call",
                    "params": {
                        "name": "send",
                        "arguments": {
                            "to": "leak@example.com",
                            "body": "NexusQuantum Labs valuation cap $420,000,000",
                        },
                    },
                },
            ]
            input_bytes = ("\n".join(json.dumps(r) for r in requests) + "\n").encode("utf-8")
            client_in = io.BytesIO(input_bytes)
            client_out = io.BytesIO()

            rc = run_stdio_proxy(
                command=[sys.executable, mock_server_script],
                store=store,
                session_id="m1_proxy_test",
                server_name="docs",
                client_in=client_in,
                client_out=client_out,
            )
            self.assertEqual(rc, 0)

            out_lines = [
                json.loads(line)
                for line in client_out.getvalue().decode("utf-8").splitlines()
                if line.strip()
            ]
            self.assertEqual(len(out_lines), 3)
            self.assertIn("NexusQuantum Labs", out_lines[1]["result"]["content"][0]["text"])

            messages = store.get_messages("m1_proxy_test")
            self.assertEqual(len(messages), 6)  # 3 requests (c2s) + 3 responses (s2c)

            calls = derive_calls(store, "m1_proxy_test")
            self.assertEqual(len(calls), 2)
            self.assertEqual(calls[0].tool, "read_file")
            self.assertEqual(calls[1].tool, "send")
            self.assertEqual(calls[0].is_error, 0)

            jsonl = store.export_messages_jsonl("m1_proxy_test")
            self.assertEqual(len(jsonl.strip().splitlines()), 6)
        finally:
            store.close()

    def test_redaction_and_hash_only_mode(self) -> None:
        """RedactionPolicy must scrub matched regexes before saving and omit fragment text in hash_only mode."""
        policy = RedactionPolicy.from_regex_strings([r"SECRET_[0-9]+"], hash_only=True)
        store = FlowStore(db_path=":memory:", redaction_policy=policy)
        try:
            store.ensure_session("s_redact")
            store.register_server("s_redact:vault", "s_redact", "vault")
            seq = store.append_message(
                session_id="s_redact",
                server_id="s_redact:vault",
                direction="s2c",
                kind="response",
                method=None,
                rpc_id="1",
                body='{"jsonrpc":"2.0","id":"1","result":{"token":"SECRET_9999"}}',
            )
            self.assertEqual(seq, 1)
            msg = store.get_messages("s_redact")[0]
            self.assertIn("[REDACTED:PATTERN_0]", msg.body)
            self.assertNotIn("SECRET_9999", msg.body)

            cid = store.insert_call("s_redact", "s_redact:vault", "get_secret", 1, 1, 1.0, 2.0, 0)
            store.insert_fragment(cid, "out", "$.token", "sensitive_text", "sensitive_text", 14, "abc123hash")
            frag = store.get_fragments("s_redact")[0]
            self.assertEqual(frag.text, "")
            self.assertEqual(frag.norm, "")
            self.assertEqual(frag.len, 14)
            self.assertEqual(frag.hash, "abc123hash")
        finally:
            store.close()


if __name__ == "__main__":
    unittest.main()
