"""Stage 1: Exact hash and basic-normalized hash matching."""

from __future__ import annotations

from mcp_flow.derive.fragments import sha256_hex
from mcp_flow.match.base import (
    CandidateEdge,
    MatchContext,
    Matcher,
    MatchFragment,
    is_informative_text,
    is_temporally_valid,
)


class ExactMatcher(Matcher):
    """Matches fragments whose raw hash or basic-normalized hash are identical."""

    stage_name = "exact"

    def __init__(self, min_len: int = 6) -> None:
        self.min_len = min_len

    def match(
        self,
        src_fragments: list[MatchFragment],
        dst_fragments: list[MatchFragment],
        ctx: MatchContext | None = None,
    ) -> list[CandidateEdge]:
        context = ctx or MatchContext.from_fragments(src_fragments + dst_fragments)
        edges: list[CandidateEdge] = []

        # Index informative source fragments by raw hash and norm hash
        by_raw_hash: dict[str, list[MatchFragment]] = {}
        by_norm_hash: dict[str, list[MatchFragment]] = {}

        for src in src_fragments:
            # Support hash-only mode where text/norm are empty but src.len and src.hash are populated
            if src.text or src.norm:
                if not is_informative_text(src.text, src.norm, min_len=self.min_len):
                    continue
            elif src.len < self.min_len:
                continue

            by_raw_hash.setdefault(src.hash, []).append(src)
            if src.norm:
                nh = sha256_hex(src.norm)
                by_norm_hash.setdefault(nh, []).append(src)

        for dst in dst_fragments:
            if dst.text or dst.norm:
                if not is_informative_text(dst.text, dst.norm, min_len=self.min_len):
                    continue
            elif dst.len < self.min_len:
                continue

            matched_srcs: dict[int, tuple[MatchFragment, float]] = {}

            for src in by_raw_hash.get(dst.hash, []):
                if is_temporally_valid(src, dst):
                    matched_srcs[src.id] = (src, 1.0)

            if dst.norm:
                nh = sha256_hex(dst.norm)
                for src in by_norm_hash.get(nh, []):
                    if is_temporally_valid(src, dst) and src.id not in matched_srcs:
                        matched_srcs[src.id] = (src, 0.98)

            for src, base_score in matched_srcs.values():
                rarity = context.rarity_weight(src.norm or src.hash)
                length_factor = min(1.0, 0.8 + 0.2 * (min(src.len, 32) / 32.0))
                score = round(base_score * rarity * length_factor, 4)
                if score >= context.min_score:
                    edges.append(
                        CandidateEdge(
                            src_frag=src.id,
                            dst_frag=dst.id,
                            kind="exact",
                            score=min(1.0, score),
                            src_span=f"0:{src.len}",
                            dst_span=f"0:{dst.len}",
                        )
                    )

        return edges
