"""Stage 2: Substring containment and longest common substring matching."""

from __future__ import annotations

from difflib import SequenceMatcher

from mcp_flow.match.base import (
    CandidateEdge,
    MatchContext,
    Matcher,
    MatchFragment,
    is_informative_text,
    is_temporally_valid,
    shannon_entropy,
)


class SubstringMatcher(Matcher):
    """Detects when a significant substring of an output fragment is embedded in a later input fragment."""

    stage_name = "substring"

    def __init__(self, min_match_len: int = 12) -> None:
        self.min_match_len = min_match_len

    def match(
        self,
        src_fragments: list[MatchFragment],
        dst_fragments: list[MatchFragment],
        ctx: MatchContext | None = None,
    ) -> list[CandidateEdge]:
        context = ctx or MatchContext.from_fragments(src_fragments + dst_fragments)
        edges: list[CandidateEdge] = []

        valid_srcs = [
            s
            for s in src_fragments
            if s.text and is_informative_text(s.text, s.norm, min_len=self.min_match_len)
        ]
        valid_dsts = [
            d
            for d in dst_fragments
            if d.text and is_informative_text(d.text, d.norm, min_len=self.min_match_len)
        ]

        for src in valid_srcs:
            for dst in valid_dsts:
                if not is_temporally_valid(src, dst):
                    continue
                if src.hash == dst.hash or (src.norm and src.norm == dst.norm):
                    # Exact matches are handled by Stage 1
                    continue

                # Case 1: full source text is contained in destination text
                idx = dst.text.find(src.text)
                if idx != -1:
                    match_len = len(src.text)
                    src_span = f"0:{match_len}"
                    dst_span = f"{idx}:{idx + match_len}"
                    matched_str = src.text
                else:
                    # Case 2: full destination text is extracted from source text
                    r_idx = src.text.find(dst.text)
                    if r_idx != -1:
                        match_len = len(dst.text)
                        src_span = f"{r_idx}:{r_idx + match_len}"
                        dst_span = f"0:{match_len}"
                        matched_str = dst.text
                    else:
                        # Case 3: longest contiguous common substring
                        sm = SequenceMatcher(None, src.text, dst.text, autojunk=False)
                        block = sm.find_longest_match(0, len(src.text), 0, len(dst.text))
                        if block.size < self.min_match_len:
                            continue
                        match_len = block.size
                        src_span = f"{block.a}:{block.a + block.size}"
                        dst_span = f"{block.b}:{block.b + block.size}"
                        matched_str = src.text[block.a : block.a + block.size]

                if not is_informative_text(
                    matched_str,
                    matched_str.strip().casefold(),
                    min_len=self.min_match_len,
                    min_entropy=2.2,
                ):
                    continue

                smaller_len = max(min(len(src.text), len(dst.text)), 1)
                coverage = match_len / smaller_len
                len_bonus = min(1.0, match_len / 32.0)
                entropy_bonus = min(1.0, shannon_entropy(matched_str) / 3.5)
                rarity = context.rarity_weight(src.norm or src.hash)

                raw_score = (0.45 + 0.35 * coverage + 0.20 * len_bonus) * entropy_bonus * rarity
                score = round(min(0.95, raw_score), 4)
                if score >= context.min_score:
                    edges.append(
                        CandidateEdge(
                            src_frag=src.id,
                            dst_frag=dst.id,
                            kind="substring",
                            score=score,
                            src_span=src_span,
                            dst_span=dst_span,
                        )
                    )

        return edges
