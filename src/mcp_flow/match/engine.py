"""Cascading multi-stage fingerprint engine (Stages 1 -> 5)."""

from __future__ import annotations

from mcp_flow.match.base import CandidateEdge, MatchContext, Matcher, MatchFragment
from mcp_flow.match.exact import ExactMatcher
from mcp_flow.match.minhash import MinHashMatcher
from mcp_flow.match.normalized import NormalizedMatcher
from mcp_flow.match.semantic import EmbeddingFn, SemanticMatcher
from mcp_flow.match.substring import SubstringMatcher
from mcp_flow.store.db import FlowRow, FlowStore


class FingerprintEngine:
    """
    Runs fingerprint matchers in ascending order of cost:
      1. ExactMatcher
      2. SubstringMatcher
      3. NormalizedMatcher
      4. MinHashMatcher
      5. SemanticMatcher (opt-in)
    If an earlier stage finds a high-confidence match for a `(src_frag, dst_frag)` pair,
    later stages do not overwrite it.
    """

    def __init__(
        self,
        max_stage: int = 4,
        enable_semantic: bool = False,
        min_score: float = 0.35,
        short_circuit_score: float = 0.82,
        embedding_fn: EmbeddingFn | None = None,
        custom_matchers: list[Matcher] | None = None,
    ) -> None:
        self.min_score = min_score
        self.short_circuit_score = short_circuit_score

        if custom_matchers is not None:
            self.matchers = custom_matchers
        else:
            stages: list[tuple[int, Matcher]] = [
                (1, ExactMatcher()),
                (2, SubstringMatcher()),
                (3, NormalizedMatcher()),
                (4, MinHashMatcher()),
            ]
            if enable_semantic or max_stage >= 5:
                stages.append((5, SemanticMatcher(embedding_fn=embedding_fn)))
            self.matchers = [m for stage_num, m in stages if stage_num <= max(max_stage, 5 if enable_semantic else max_stage)]

    def build_match_fragments(self, store: FlowStore, session_id: str) -> tuple[list[MatchFragment], list[MatchFragment]]:
        """Load session fragments enriched with call sequence numbers and split into (out, in)."""
        calls_by_id = {c.id: c for c in store.get_calls(session_id)}
        fragments = store.get_fragments(session_id)

        src_frags: list[MatchFragment] = []
        dst_frags: list[MatchFragment] = []
        for f in fragments:
            call = calls_by_id.get(f.call_id)
            if call is None:
                continue
            mf = MatchFragment(
                id=f.id,
                call_id=f.call_id,
                side=f.side,
                json_path=f.json_path,
                text=f.text,
                norm=f.norm,
                len=f.len,
                hash=f.hash,
                req_seq=call.req_seq,
                res_seq=call.res_seq,
            )
            if f.side == "out":
                src_frags.append(mf)
            elif f.side == "in":
                dst_frags.append(mf)

        return src_frags, dst_frags

    def match_fragments(
        self,
        src_fragments: list[MatchFragment],
        dst_fragments: list[MatchFragment],
    ) -> list[CandidateEdge]:
        """Run configured stages in cascade order and deduplicate by `(src_frag, dst_frag)`."""
        ctx = MatchContext.from_fragments(src_fragments + dst_fragments, min_score=self.min_score)
        best_edges: dict[tuple[int, int], CandidateEdge] = {}

        for matcher in self.matchers:
            stage_edges = matcher.match(src_fragments, dst_fragments, ctx=ctx)
            for edge in stage_edges:
                pair = (edge.src_frag, edge.dst_frag)
                existing = best_edges.get(pair)
                if existing is not None and existing.score >= self.short_circuit_score:
                    # High-confidence match from an earlier stage short-circuits later stages
                    continue
                if existing is None or edge.score > existing.score:
                    best_edges[pair] = edge
                    if edge.score >= self.short_circuit_score:
                        ctx.skip_pairs.add(pair)

        return sorted(best_edges.values(), key=lambda e: (-e.score, e.src_frag, e.dst_frag))

    def run_on_session(self, store: FlowStore, session_id: str) -> list[FlowRow]:
        """Clear previous flows for `session_id`, run the engine, and persist detected flows."""
        store.clear_flows(session_id)
        src_frags, dst_frags = self.build_match_fragments(store, session_id)
        edges = self.match_fragments(src_frags, dst_frags)
        for edge in edges:
            store.insert_flow(
                src_frag=edge.src_frag,
                dst_frag=edge.dst_frag,
                kind=edge.kind,
                score=edge.score,
                src_span=edge.src_span,
                dst_span=edge.dst_span,
            )
        return store.get_flows(session_id)
