"""Stage 4: Character/word n-gram shingling and MinHash Jaccard similarity."""

from __future__ import annotations

import hashlib
import re

from mcp_flow.match.base import (
    CandidateEdge,
    MatchContext,
    Matcher,
    MatchFragment,
    is_informative_text,
    is_temporally_valid,
)

_SPACE_RE = re.compile(r"\s+")


def extract_shingles(text: str, k: int = 4) -> set[str]:
    """Generate character k-gram shingles and word tokens from normalized text."""
    cleaned = _SPACE_RE.sub(" ", text.strip().casefold())
    if not cleaned:
        return set()
    shingles: set[str] = set()
    if len(cleaned) <= k:
        shingles.add(cleaned)
    else:
        for i in range(len(cleaned) - k + 1):
            shingles.add(cleaned[i : i + k])
    for word in re.findall(r"\w{3,}", cleaned):
        shingles.add(f"w:{word}")
    return shingles


def compute_minhash_signature(shingles: set[str], num_perm: int = 64) -> tuple[int, ...]:
    """Compute a deterministic MinHash signature of length `num_perm` using Universal Hashing."""
    if not shingles:
        return ()
    base_hashes = [
        int.from_bytes(hashlib.blake2b(s.encode("utf-8"), digest_size=8).digest(), "big")
        for s in shingles
    ]
    prime = (1 << 61) - 1
    sig: list[int] = []
    for i in range(num_perm):
        a = (i * 2654435761 + 17) | 1
        b = i * 11400714819323198485 + 31
        min_h = min(((a * h + b) % prime) for h in base_hashes)
        sig.append(min_h)
    return tuple(sig)


def estimate_minhash_similarity(sig_a: tuple[int, ...], sig_b: tuple[int, ...]) -> float:
    """Estimate Jaccard similarity from two MinHash signatures."""
    if not sig_a or not sig_b or len(sig_a) != len(sig_b):
        return 0.0
    matches = sum(1 for x, y in zip(sig_a, sig_b) if x == y)
    return matches / len(sig_a)


def exact_jaccard_and_containment(set_a: set[str], set_b: set[str]) -> tuple[float, float]:
    """Return (Jaccard similarity, containment ratio relative to smaller shingle set)."""
    if not set_a or not set_b:
        return 0.0, 0.0
    inter = len(set_a & set_b)
    union = len(set_a | set_b)
    smaller = min(len(set_a), len(set_b))
    return inter / union, inter / smaller


class MinHashMatcher(Matcher):
    """Detects partially edited, reordered, or summarized text via n-gram shingling and MinHash."""

    stage_name = "minhash"

    def __init__(
        self,
        shingle_k: int = 4,
        num_perm: int = 64,
        min_len: int = 20,
        min_similarity: float = 0.28,
    ) -> None:
        self.shingle_k = shingle_k
        self.num_perm = num_perm
        self.min_len = min_len
        self.min_similarity = min_similarity

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
            if s.text and is_informative_text(s.text, s.norm, min_len=self.min_len, min_entropy=2.4)
        ]
        valid_dsts = [
            d
            for d in dst_fragments
            if d.text and is_informative_text(d.text, d.norm, min_len=self.min_len, min_entropy=2.4)
        ]

        candidate_pairs: list[tuple[MatchFragment, MatchFragment]] = []
        needed_srcs: dict[int, MatchFragment] = {}
        needed_dsts: dict[int, MatchFragment] = {}
        for src in valid_srcs:
            for dst in valid_dsts:
                if (src.id, dst.id) in context.skip_pairs:
                    continue
                if not is_temporally_valid(src, dst):
                    continue
                candidate_pairs.append((src, dst))
                needed_srcs[src.id] = src
                needed_dsts[dst.id] = dst

        if not candidate_pairs:
            return []

        src_data: dict[int, tuple[set[str], tuple[int, ...]]] = {}
        for src_id, src in needed_srcs.items():
            sh = extract_shingles(src.norm or src.text, k=self.shingle_k)
            if len(sh) >= 5:
                src_data[src_id] = (sh, compute_minhash_signature(sh, self.num_perm))

        dst_data: dict[int, tuple[set[str], tuple[int, ...]]] = {}
        for dst_id, dst in needed_dsts.items():
            sh = extract_shingles(dst.norm or dst.text, k=self.shingle_k)
            if len(sh) >= 5:
                dst_data[dst_id] = (sh, compute_minhash_signature(sh, self.num_perm))

        for src, dst in candidate_pairs:
            s_entry = src_data.get(src.id)
            d_entry = dst_data.get(dst.id)
            if not s_entry or not d_entry:
                continue
            s_shingles, s_sig = s_entry
            d_shingles, d_sig = d_entry

            if s_shingles.isdisjoint(d_shingles):
                continue

            mh_sim = estimate_minhash_similarity(s_sig, d_sig)
            jaccard, containment = exact_jaccard_and_containment(s_shingles, d_shingles)
            effective_sim = max(mh_sim, 0.6 * jaccard + 0.4 * containment)

            if effective_sim < self.min_similarity:
                continue

            rarity = context.rarity_weight(src.norm or src.hash)
            score = round(min(0.85, (0.25 + 0.70 * effective_sim) * rarity), 4)
            if score >= context.min_score:
                edges.append(
                    CandidateEdge(
                        src_frag=src.id,
                        dst_frag=dst.id,
                        kind="minhash",
                        score=score,
                        src_span=f"0:{src.len}(shingles={len(s_shingles)})",
                        dst_span=f"0:{dst.len}(jaccard={jaccard:.2f},contain={containment:.2f})",
                    )
                )

        return edges
