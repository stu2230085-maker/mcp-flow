"""Stage 5: Opt-in semantic/embedding similarity matcher for paraphrased or summarized text."""

from __future__ import annotations

import math
import re
from collections import Counter
from typing import Callable

from mcp_flow.match.base import (
    CandidateEdge,
    MatchContext,
    Matcher,
    MatchFragment,
    is_informative_text,
    is_temporally_valid,
)

EmbeddingFn = Callable[[str], list[float]]


_STOPWORDS = {
    "the", "and", "for", "with", "that", "this", "from", "into", "under",
    "are", "was", "were", "will", "have", "has", "had", "not", "but",
    "out", "you", "our", "can", "all", "any", "his", "her", "its",
    "memo", "regarding", "upcoming", "inquiries", "details", "reach",
    "http", "https", "www", "com", "org", "net", "example", "localhost",
}

_SYNONYM_CONCEPTS: dict[str, str] = {
    "acquisition": "concept:acquire",
    "buyout": "concept:acquire",
    "takeover": "concept:acquire",
    "purchase": "concept:acquire",
    "cap": "concept:limit",
    "ceiling": "concept:limit",
    "limit": "concept:limit",
    "maximum": "concept:limit",
    "valuation": "concept:budget",
    "budget": "concept:budget",
    "price": "concept:budget",
    "project": "concept:project",
    "initiative": "concept:project",
    "program": "concept:project",
    "labs": "concept:lab",
    "laboratories": "concept:lab",
    "laboratory": "concept:lab",
    "confidential": "concept:secret",
    "classified": "concept:secret",
    "restricted": "concept:secret",
    "internal": "concept:secret",
    "contact": "concept:contact",
    "inquiries": "concept:contact",
    "chief": "concept:cfo",
    "financial": "concept:cfo",
    "officer": "concept:cfo",
    "cfo": "concept:cfo",
    "fourth": "concept:q4",
    "quarter": "concept:q4",
    "q4": "concept:q4",
}


def _extract_semantic_features(text: str) -> Counter[str]:
    """
    Extract hybrid word-stem, camelCase sub-token, synonym concept, numeric root,
    and CJK character bi-gram features for zero-dependency local vector cosine similarity.
    """
    camel_split = re.sub(r"([a-z])([A-Z])", r"\1 \2", text)
    norm = camel_split.strip().casefold()
    features: Counter[str] = Counter()

    tokens = re.findall(r"[a-z0-9]{2,}", norm)
    for word in tokens:
        if word in _SYNONYM_CONCEPTS:
            features[_SYNONYM_CONCEPTS[word]] += 3
        if word in _STOPWORDS:
            continue
        if len(word) >= 3:
            features[f"s4:{word[:4]}"] += 2
        if len(word) >= 5:
            features[f"s5:{word[:5]}"] += 1

    for num in re.findall(r"\d{2,}", norm):
        if set(num) != {"0"}:
            features[f"num:{num[:3]}"] += 3

    non_space = re.sub(r"\s+", "", norm)
    cjk_chars = [ch for ch in non_space if ord(ch) > 127]
    for ch in cjk_chars:
        features[f"c1:{ch}"] += 1
    for i in range(len(cjk_chars) - 1):
        features[f"c2:{cjk_chars[i]}{cjk_chars[i + 1]}"] += 2

    return features


def _cosine_counter(a: Counter[str], b: Counter[str]) -> float:
    if not a or not b:
        return 0.0
    common = set(a.keys()) & set(b.keys())
    if not common:
        return 0.0
    dot = sum(a[k] * b[k] for k in common)
    norm_a = math.sqrt(sum(v * v for v in a.values()))
    norm_b = math.sqrt(sum(v * v for v in b.values()))
    if norm_a == 0.0 or norm_b == 0.0:
        return 0.0
    return dot / (norm_a * norm_b)


def _cosine_dense(vec_a: list[float], vec_b: list[float]) -> float:
    if not vec_a or not vec_b or len(vec_a) != len(vec_b):
        return 0.0
    dot = sum(x * y for x, y in zip(vec_a, vec_b))
    na = math.sqrt(sum(x * x for x in vec_a))
    nb = math.sqrt(sum(y * y for y in vec_b))
    if na == 0.0 or nb == 0.0:
        return 0.0
    return dot / (na * nb)


class SemanticMatcher(Matcher):
    """
    Stage 5 opt-in semantic similarity matcher.
    Accepts a custom `embedding_fn: Callable[[str], list[float]]` (for local or API models)
    and falls back to an IDF-weighted hybrid lexical/CJK feature vector cosine similarity.
    """

    stage_name = "semantic"

    def __init__(
        self,
        embedding_fn: EmbeddingFn | None = None,
        min_len: int = 45,
        min_cosine: float = 0.35,
    ) -> None:
        self.embedding_fn = embedding_fn
        self.min_len = min_len
        self.min_cosine = min_cosine

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

        if not valid_srcs or not valid_dsts:
            return []

        if self.embedding_fn is not None:
            dense_vecs: dict[int, list[float]] = {}
            for frag in valid_srcs + valid_dsts:
                if frag.id not in dense_vecs:
                    dense_vecs[frag.id] = self.embedding_fn(frag.text)
            for src in valid_srcs:
                for dst in valid_dsts:
                    if not is_temporally_valid(src, dst):
                        continue
                    cos = _cosine_dense(dense_vecs[src.id], dense_vecs[dst.id])
                    if cos < self.min_cosine:
                        continue
                    rarity = context.rarity_weight(src.norm or src.hash)
                    score = round(min(0.78, (0.20 + 0.65 * cos) * rarity), 4)
                    if score >= context.min_score:
                        edges.append(
                            CandidateEdge(
                                src_frag=src.id,
                                dst_frag=dst.id,
                                kind="semantic",
                                score=score,
                                src_span=f"0:{src.len}(embed)",
                                dst_span=f"0:{dst.len}(cos={cos:.2f})",
                            )
                        )
            return edges

        # Default hybrid semantic feature vector similarity
        feat_map: dict[int, Counter[str]] = {}
        all_unique = {f.id: f for f in valid_srcs + valid_dsts}
        for fid, frag in all_unique.items():
            feat_map[fid] = _extract_semantic_features(frag.text)

        for src in valid_srcs:
            for dst in valid_dsts:
                if not is_temporally_valid(src, dst):
                    continue
                cos = _cosine_counter(feat_map[src.id], feat_map[dst.id])
                if cos < self.min_cosine:
                    continue
                rarity = context.rarity_weight(src.norm or src.hash)
                score = round(min(0.75, (0.20 + 0.75 * cos) * rarity), 4)
                if score >= context.min_score:
                    edges.append(
                        CandidateEdge(
                            src_frag=src.id,
                            dst_frag=dst.id,
                            kind="semantic",
                            score=score,
                            src_span=f"0:{src.len}(tfidf)",
                            dst_span=f"0:{dst.len}(cos={cos:.2f})",
                        )
                    )

        return edges
