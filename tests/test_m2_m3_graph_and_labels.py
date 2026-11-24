"""Tests for M2 (fragmentation, exact/substring matching, Mermaid/DOT output) and M3 (labels, hazardous paths, negative scenarios)."""

from __future__ import annotations

import unittest

from mcp_flow.derive.calls import derive_calls
from mcp_flow.derive.fragments import derive_fragments
from mcp_flow.graph.builder import OBSERVATION_DISCLAIMER, build_flow_graph
from mcp_flow.graph.exporters import format_cli_report, to_dot, to_json_dict, to_mermaid
from mcp_flow.graph.paths import find_hazardous_paths
from mcp_flow.labels.rules import LabelRuleEngine
from mcp_flow.match.engine import FingerprintEngine
from mcp_flow.store.db import FlowStore
from scenarios.synthetic_suite import build_synthetic_scenarios, record_synthetic_scenario


class TestM2AndM3GraphAndLabels(unittest.TestCase):
    """Verify M2 graph construction/exporters and M3 confidentiality labels/hazardous path reporting."""

    def test_m2_synthetic_scenarios_produce_expected_mermaid_graph(self) -> None:
        """M2 Gate: First 3 synthetic scenarios must produce expected dependency flows and valid Mermaid output."""
        store = FlowStore(db_path=":memory:")
        try:
            scenarios = {s.name: s for s in build_synthetic_scenarios()}
            for name in ("s1_exact_token_exfil", "s2_substring_embed", "s3_encoded_base64_and_url"):
                sc = scenarios[name]
                sid = record_synthetic_scenario(store, sc)
                derive_calls(store, sid)
                derive_fragments(store, sid)
                FingerprintEngine(max_stage=3).run_on_session(store, sid)
                LabelRuleEngine().apply_to_session(store, sid)

                graph = build_flow_graph(store, sid, min_score=0.35)
                sorted_cids = sorted(graph.nodes.keys())
                cid_to_idx = {cid: idx for idx, cid in enumerate(sorted_cids, start=1)}
                actual_pairs = {
                    (cid_to_idx[e.src_call_id], cid_to_idx[e.dst_call_id])
                    for e in graph.edges
                }
                self.assertEqual(actual_pairs, sc.expected_edges, f"Mismatch in scenario {name}")

                mermaid = to_mermaid(graph)
                self.assertIn("graph LR", mermaid)
                self.assertIn("-->|", mermaid)
                self.assertIn(OBSERVATION_DISCLAIMER, mermaid)

                dot = to_dot(graph)
                self.assertIn("digraph mcp_flow {", dot)
        finally:
            store.close()

    def test_m3_labels_hazardous_paths_and_negative_scenario_zero_false_positives(self) -> None:
        """M3 Gate: Regex detectors and rules must find hazardous paths and produce 0 false positives on negative scenarios."""
        store = FlowStore(db_path=":memory:")
        try:
            scenarios = {s.name: s for s in build_synthetic_scenarios()}

            # Positive multi-hop path: docs.read_file -> summarize.run -> mail.send
            s2 = scenarios["s2_substring_embed"]
            sid2 = record_synthetic_scenario(store, s2)
            derive_calls(store, sid2)
            derive_fragments(store, sid2)
            FingerprintEngine(max_stage=4).run_on_session(store, sid2)
            LabelRuleEngine().apply_to_session(store, sid2)

            graph2 = build_flow_graph(store, sid2)
            paths2 = find_hazardous_paths(graph2, source_label="*", sink_role="sink")
            self.assertGreaterEqual(len(paths2), 2)  # Direct (1->3) and 2-hop (1->2->3)

            report_text = format_cli_report(graph2, paths2, expose_text=False)
            self.assertIn("Hazardous Paths:", report_text)
            self.assertIn(OBSERVATION_DISCLAIMER, report_text)
            self.assertIn("docs.read_file", report_text)
            self.assertIn("mail.send", report_text)

            # Negative scenario: must produce 0 edges and 0 hazardous paths
            s_neg = scenarios["s6_negative_unrelated"]
            sid_neg = record_synthetic_scenario(store, s_neg)
            derive_calls(store, sid_neg)
            derive_fragments(store, sid_neg)
            FingerprintEngine(max_stage=5, enable_semantic=True).run_on_session(store, sid_neg)
            LabelRuleEngine().apply_to_session(store, sid_neg)

            graph_neg = build_flow_graph(store, sid_neg)
            self.assertEqual(len(graph_neg.edges), 0)
            paths_neg = find_hazardous_paths(graph_neg)
            self.assertEqual(len(paths_neg), 0)

            json_out = to_json_dict(graph_neg, paths=paths_neg)
            self.assertEqual(len(json_out["edges"]), 0)
        finally:
            store.close()


if __name__ == "__main__":
    unittest.main()
