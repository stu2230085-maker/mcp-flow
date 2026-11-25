import json
import tempfile
import unittest
from pathlib import Path

from mcp_flow.cli import main
from mcp_flow.graph.builder import OBSERVATION_DISCLAIMER, build_flow_graph
from mcp_flow.interop.trace_io import export_otel_spans, import_trace_jsonl
from mcp_flow.store.db import FlowStore


def _seed_two_step_session(store: FlowStore, session_id: str) -> None:
    store.ensure_session(session_id, client="test-client")
    docs_id = f"{session_id}:docs"
    mail_id = f"{session_id}:mail"
    store.register_server(docs_id, session_id, "docs", command="docs-srv")
    store.register_server(mail_id, session_id, "mail", command="mail-srv")

    secret = "sk-proj-secret-token-value-998877"
    req1 = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "read_secret", "arguments": {"path": "/etc/secret"}},
    }
    res1 = {
        "jsonrpc": "2.0",
        "id": 1,
        "result": {"content": [{"type": "text", "text": f"token={secret}"}]},
    }
    req2 = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "send_mail",
            "arguments": {"to": "ops@example.com", "body": f"Sending {secret}"},
        },
    }
    res2 = {
        "jsonrpc": "2.0",
        "id": 2,
        "result": {"content": [{"type": "text", "text": "sent"}]},
    }

    store.append_message(session_id, docs_id, "c2s", "request", "tools/call", "1", json.dumps(req1), ts=1000.0)
    store.append_message(session_id, docs_id, "s2c", "response", None, "1", json.dumps(res1), ts=1000.5)
    store.append_message(session_id, mail_id, "c2s", "request", "tools/call", "2", json.dumps(req2), ts=1001.0)
    store.append_message(session_id, mail_id, "s2c", "response", None, "2", json.dumps(res2), ts=1001.5)


class InteropOtelTests(unittest.TestCase):
    def test_round_trip_export_import_analyze_produces_identical_flow_graph(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "flow.db"
            jsonl_path = Path(tmp) / "trace.jsonl"

            store = FlowStore(db_path=db_path)
            try:
                _seed_two_step_session(store, "orig-session")
            finally:
                store.close()

            self.assertEqual(main(["--db", str(db_path), "analyze", "orig-session"]), 0)
            self.assertEqual(
                main(["--db", str(db_path), "export", "orig-session", "--out", str(jsonl_path)]),
                0,
            )
            self.assertEqual(
                main(["--db", str(db_path), "import", str(jsonl_path), "--session", "reimported-session"]),
                0,
            )
            self.assertEqual(main(["--db", str(db_path), "analyze", "reimported-session"]), 0)

            store = FlowStore(db_path=db_path)
            try:
                orig_graph = build_flow_graph(store, "orig-session")
                re_graph = build_flow_graph(store, "reimported-session")
                orig_server_map = store.get_server_map("orig-session")
                re_server_map = store.get_server_map("reimported-session")
            finally:
                store.close()

            self.assertEqual(
                orig_server_map,
                {"orig-session:docs": "docs", "orig-session:mail": "mail"},
            )
            self.assertEqual(
                re_server_map,
                {"reimported-session:docs": "docs", "reimported-session:mail": "mail"},
            )

            self.assertEqual(len(orig_graph.nodes), 2)
            self.assertEqual(len(re_graph.nodes), 2)

            re_nodes = sorted(re_graph.nodes.values(), key=lambda n: n.req_seq)
            self.assertEqual([n.server_name for n in re_nodes], ["docs", "mail"])
            self.assertEqual([n.role for n in re_nodes], ["source", "sink"])
            self.assertIn("confidential:internal_doc", re_nodes[0].labels)

            self.assertEqual(
                [n.display_name for n in orig_graph.nodes.values()],
                [n.display_name for n in re_graph.nodes.values()],
            )
            self.assertEqual(len(orig_graph.edges), len(re_graph.edges))
            self.assertEqual(len(re_graph.edges), 1)
            self.assertEqual(orig_graph.edges[0].primary_kind, re_graph.edges[0].primary_kind)
            self.assertAlmostEqual(orig_graph.edges[0].max_score, re_graph.edges[0].max_score)
            self.assertEqual(orig_graph.edges[0].match_count, re_graph.edges[0].match_count)

    def test_mcptape_compatible_import(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "tape.db"
            tape_path = Path(tmp) / "mcptape.jsonl"
            token = "ghp_ExampleSecretTokenForMcptape12345"
            lines = [
                {
                    "ts": "2026-11-25T00:00:00Z",
                    "direction": "client_to_server",
                    "server": "vault",
                    "message": {
                        "jsonrpc": "2.0",
                        "id": 10,
                        "method": "tools/call",
                        "params": {"name": "get_secret", "arguments": {"key": "api"}},
                    },
                },
                {
                    "ts": "2026-11-25T00:00:01Z",
                    "direction": "server_to_client",
                    "server": "vault",
                    "message": {
                        "jsonrpc": "2.0",
                        "id": 10,
                        "result": {"content": [{"type": "text", "text": token}]},
                    },
                },
                {
                    "ts": "2026-11-25T00:00:02Z",
                    "direction": "client_to_server",
                    "server": "webhook",
                    "message": {
                        "jsonrpc": "2.0",
                        "id": 11,
                        "method": "tools/call",
                        "params": {"name": "post", "arguments": {"auth": token}},
                    },
                },
                {
                    "ts": "2026-11-25T00:00:03Z",
                    "direction": "server_to_client",
                    "server": "webhook",
                    "message": {
                        "jsonrpc": "2.0",
                        "id": 11,
                        "result": {"content": [{"type": "text", "text": "200 OK"}]},
                    },
                },
            ]
            tape_path.write_text(
                "\n".join(json.dumps(item) for item in lines) + "\n",
                encoding="utf-8",
            )

            store = FlowStore(db_path=db_path)
            try:
                res = import_trace_jsonl(store, tape_path, session_id="tape-sess")
                self.assertEqual(res.imported_messages, 4)
                self.assertEqual(res.servers, ["vault", "webhook"])
                self.assertEqual(
                    store.get_server_map("tape-sess"),
                    {"tape-sess:vault": "vault", "tape-sess:webhook": "webhook"},
                )
            finally:
                store.close()

            self.assertEqual(main(["--db", str(db_path), "analyze", "tape-sess"]), 0)
            store = FlowStore(db_path=db_path)
            try:
                graph = build_flow_graph(store, "tape-sess")
            finally:
                store.close()

            self.assertEqual(len(graph.nodes), 2)
            self.assertEqual(len(graph.edges), 1)
            self.assertEqual(graph.edges[0].primary_kind, "exact")

    def test_import_same_mcptape_into_multiple_sessions_without_server_collision(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "multi.db"
            tape_path = Path(tmp) / "mcptape.jsonl"
            token = "ghp_MultiSessionIsolationToken99999"
            lines = [
                {
                    "ts": "2026-11-25T00:00:00Z",
                    "direction": "outbound",
                    "server": "vault",
                    "message": {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "tools/call",
                        "params": {"name": "get_secret", "arguments": {"key": "k"}},
                    },
                },
                {
                    "ts": "2026-11-25T00:00:01Z",
                    "direction": "inbound",
                    "server": "vault",
                    "message": {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "result": {"content": [{"type": "text", "text": token}]},
                    },
                },
                {
                    "ts": "2026-11-25T00:00:02Z",
                    "direction": "outbound",
                    "server": "webhook",
                    "message": {
                        "jsonrpc": "2.0",
                        "id": 2,
                        "method": "tools/call",
                        "params": {"name": "post", "arguments": {"auth": token}},
                    },
                },
                {
                    "ts": "2026-11-25T00:00:03Z",
                    "direction": "inbound",
                    "server": "webhook",
                    "message": {
                        "jsonrpc": "2.0",
                        "id": 2,
                        "result": {"content": [{"type": "text", "text": "ok"}]},
                    },
                },
            ]
            tape_path.write_text(
                "\n".join(json.dumps(item) for item in lines) + "\n",
                encoding="utf-8",
            )

            store = FlowStore(db_path=db_path)
            try:
                res1 = import_trace_jsonl(store, tape_path, session_id="tape-sess-1")
                res2 = import_trace_jsonl(store, tape_path, session_id="tape-sess-2")
                self.assertEqual(res1.servers, ["vault", "webhook"])
                self.assertEqual(res2.servers, ["vault", "webhook"])
                self.assertEqual(
                    store.get_server_map("tape-sess-1"),
                    {"tape-sess-1:vault": "vault", "tape-sess-1:webhook": "webhook"},
                )
                self.assertEqual(
                    store.get_server_map("tape-sess-2"),
                    {"tape-sess-2:vault": "vault", "tape-sess-2:webhook": "webhook"},
                )
            finally:
                store.close()

            self.assertEqual(main(["--db", str(db_path), "analyze", "tape-sess-1"]), 0)
            self.assertEqual(main(["--db", str(db_path), "analyze", "tape-sess-2"]), 0)

            store = FlowStore(db_path=db_path)
            try:
                g1 = build_flow_graph(store, "tape-sess-1")
                g2 = build_flow_graph(store, "tape-sess-2")
            finally:
                store.close()

            self.assertEqual(len(g1.nodes), 2)
            self.assertEqual(len(g1.edges), 1)
            self.assertEqual(len(g2.nodes), 2)
            self.assertEqual(len(g2.edges), 1)
            self.assertEqual(
                [n.server_name for n in sorted(g1.nodes.values(), key=lambda n: n.req_seq)],
                ["vault", "webhook"],
            )
            self.assertEqual(
                [n.server_name for n in sorted(g2.nodes.values(), key=lambda n: n.req_seq)],
                ["vault", "webhook"],
            )

    def test_import_aborts_atomically_on_malformed_mid_file_line(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "atomic.db"
            bad_jsonl = Path(tmp) / "bad_mid.jsonl"
            valid_line = json.dumps(
                {
                    "ts": 1000.0,
                    "direction": "outbound",
                    "server": "vault",
                    "message": {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "tools/call",
                        "params": {"name": "get_secret", "arguments": {}},
                    },
                }
            )
            # Second line lacks 'body'/'message' -> must fail before any DB writes occur
            missing_body_line = json.dumps(
                {
                    "ts": 1001.0,
                    "direction": "inbound",
                    "server": "vault",
                }
            )
            bad_jsonl.write_text(f"{valid_line}\n{missing_body_line}\n", encoding="utf-8")

            store = FlowStore(db_path=db_path)
            try:
                with self.assertRaises(ValueError):
                    import_trace_jsonl(store, bad_jsonl, session_id="atomic-fail-sess")
                self.assertEqual(store.get_messages("atomic-fail-sess"), [])
                self.assertEqual(store.get_server_map("atomic-fail-sess"), {})
                self.assertEqual(store.list_sessions(), [])
            finally:
                store.close()

            # Ambiguous 'in'/'out' direction strings must be rejected without partial writes
            bad_dir_jsonl = Path(tmp) / "bad_dir.jsonl"
            ambiguous_dir_line = json.dumps(
                {
                    "ts": 1001.0,
                    "direction": "in",
                    "server": "vault",
                    "message": {"jsonrpc": "2.0", "id": 1, "result": {}},
                }
            )
            bad_dir_jsonl.write_text(f"{valid_line}\n{ambiguous_dir_line}\n", encoding="utf-8")
            store = FlowStore(db_path=db_path)
            try:
                with self.assertRaises(ValueError):
                    import_trace_jsonl(store, bad_dir_jsonl, session_id="bad-dir-sess")
                self.assertEqual(store.get_messages("bad-dir-sess"), [])
            finally:
                store.close()

    def test_otel_export_structure_links_and_disclaimer(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "otel.db"
            otel_path = Path(tmp) / "spans.json"

            store = FlowStore(db_path=db_path)
            try:
                _seed_two_step_session(store, "otel-sess")
                store.set_tool_role("docs", "read_secret", "source")
                store.set_tool_role("mail", "send_mail", "sink")
            finally:
                store.close()

            self.assertEqual(main(["--db", str(db_path), "analyze", "otel-sess"]), 0)
            self.assertEqual(
                main(["--db", str(db_path), "export", "otel-sess", "--format", "otel", "--out", str(otel_path)]),
                0,
            )

            raw_text = otel_path.read_text(encoding="utf-8")
            self.assertNotIn("sk-proj-secret-token-value-998877", raw_text)

            payload = json.loads(raw_text)
            self.assertEqual(
                payload["resource"]["attributes"]["mcp.observation.disclaimer"],
                OBSERVATION_DISCLAIMER,
            )
            spans = payload["spans"]
            self.assertEqual(len(spans), 2)

            src_span, dst_span = spans[0], spans[1]
            self.assertEqual(len(src_span["trace_id"]), 32)
            self.assertEqual(len(src_span["span_id"]), 16)
            self.assertEqual(src_span["trace_id"], dst_span["trace_id"])
            self.assertEqual(src_span["start_time_unix_nano"], 1000_000_000_000)
            self.assertEqual(src_span["end_time_unix_nano"], 1000_500_000_000)
            self.assertEqual(src_span["attributes"]["mcp.server"], "docs")
            self.assertEqual(src_span["attributes"]["mcp.tool"], "read_secret")
            self.assertEqual(src_span["attributes"]["mcp.role"], "source")
            self.assertIsInstance(src_span["attributes"]["mcp.labels"], list)
            self.assertIn("mcp.res_seq", src_span["attributes"])

            self.assertEqual(dst_span["attributes"]["mcp.server"], "mail")
            self.assertEqual(dst_span["attributes"]["mcp.role"], "sink")
            self.assertEqual(len(dst_span["links"]), 1)
            link = dst_span["links"][0]
            self.assertEqual(link["span_id"], src_span["span_id"])
            self.assertIn("mcp.flow.kind", link["attributes"])
            self.assertIn("mcp.flow.score", link["attributes"])

    def test_otel_export_omits_res_seq_when_response_missing(self):
        store = FlowStore(db_path=":memory:")
        try:
            store.ensure_session("orphan-sess")
            store.register_server("orphan-sess:docs", "orphan-sess", "docs")
            req = {
                "jsonrpc": "2.0",
                "id": 99,
                "method": "tools/call",
                "params": {"name": "read_secret", "arguments": {"path": "/a"}},
            }
            store.append_message(
                "orphan-sess", "orphan-sess:docs", "c2s", "request", "tools/call", "99", json.dumps(req), ts=500.0
            )
            from mcp_flow.derive.calls import derive_calls

            derive_calls(store, "orphan-sess")
            otel_payload = export_otel_spans(store, "orphan-sess")
            self.assertEqual(len(otel_payload["spans"]), 1)
            attrs = otel_payload["spans"][0]["attributes"]
            self.assertNotIn("mcp.res_seq", attrs)
        finally:
            store.close()


if __name__ == "__main__":
    unittest.main()
