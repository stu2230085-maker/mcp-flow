"""Common matcher interface, information-content filters, entropy, and rarity weighting."""

from __future__ import annotations

import math
from abc import ABC, abstractmethod
from collections import Counter
from dataclasses import dataclass, field


LOW_VALUE_LITERALS: set[str] = {
    "true",
    "false",
    "null",
    "none",
    "nil",
    "ok",
    "error",
    "success",
    "failed",
    "text",
    "json",
    "utf-8",
    "utf8",
    "application/json",
    "text/plain",
    "localhost",
    "127.0.0.1",
}


@dataclass(frozen=True)
class MatchFragment:
    """Enriched fragment representation passed to matchers."""

    id: int
    call_id: int
    side: str
    json_path: str
    text: str
    norm: str
    len: int
    hash: str
    req_seq: int
    res_seq: int | None


@dataclass(frozen=True)
class CandidateEdge:
    """A detected content correlation edge from an output fragment to a subsequent input fragment."""

    src_frag: int
    dst_frag: int
    kind: str  # 'exact' | 'substring' | 'normalized' | 'minhash' | 'semantic'
    score: float
    src_span: str
    dst_span: str


def shannon_entropy(text: str) -> float:
    """Calculate character-level Shannon entropy in bits per character."""
    if not text:
        return 0.0
    n = len(text)
    counts = Counter(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def is_informative_text(
    text: str,
    norm: str,
    min_len: int = 6,
    min_entropy: float = 1.5,
) -> bool:
    """
    Return True if a fragment carries enough information to be eligible for matching.
    Filters out booleans, short strings, low-entropy repetitions, and small numbers.
    """
    check_str = norm if norm else text.strip().casefold()
    if len(check_str) < min_len:
        return False
    if check_str in LOW_VALUE_LITERALS:
        return False
    # Reject pure integers with < 8 digits
    if check_str.isdigit() and len(check_str) < 8:
        return False
    if shannon_entropy(check_str) < min_entropy:
        return False
    return True


def is_temporally_valid(src: MatchFragment, dst: MatchFragment) -> bool:
    """
    Output must have occurred strictly before the destination call request.
    """
    if src.call_id == dst.call_id:
        return False
    src_seq = src.res_seq if src.res_seq is not None else src.req_seq
    return src_seq < dst.req_seq


@dataclass
class MatchContext:
    """Session-level rarity statistics and thresholds shared across matchers."""

    total_calls: int = 1
    norm_call_freq: dict[str, int] = field(default_factory=dict)
    min_score: float = 0.35

    @classmethod
    def from_fragments(
        cls,
        fragments: list[MatchFragment],
        min_score: float = 0.35,
    ) -> MatchContext:
        call_ids = {f.call_id for f in fragments}
        norm_to_calls: dict[str, set[int]] = {}
        for f in fragments:
            key = f.norm or f.hash
            if key:
                norm_to_calls.setdefault(key, set()).add(f.call_id)
        freq = {k: len(v) for k, v in norm_to_calls.items()}
        return cls(
            total_calls=max(len(call_ids), 1),
            norm_call_freq=freq,
            min_score=min_score,
        )

    def rarity_weight(self, norm_or_hash: str) -> float:
        """
        Down-weight values that appear repeatedly across many calls in the same session.
        Values appearing in <= 2 calls receive weight 1.0; ubiquitous boilerplate is penalized.
        """
        df = self.norm_call_freq.get(norm_or_hash, 1)
        if df <= 2 or self.total_calls <= 3:
            return 1.0
        # Smooth IDF penalty when a value appears in >= 3 calls
        ratio = df / self.total_calls
        if ratio >= 0.75 and df >= 4:
            return 0.25
        return max(0.35, 1.0 - 0.5 * (df - 2) / max(self.total_calls - 2, 1))


class Matcher(ABC):
    """Common interface for all fingerprint matching stages."""

    stage_name: str = "base"

    @abstractmethod
    def match(
        self,
        src_fragments: list[MatchFragment],
        dst_fragments: list[MatchFragment],
        ctx: MatchContext | None = None,
    ) -> list[CandidateEdge]:
        """Match output fragments against subsequent input fragments and return candidate flow edges."""
        raise NotImplementedError
