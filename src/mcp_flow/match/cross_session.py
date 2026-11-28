"""Opt-in cross-session persistent taint registry and matcher (hash-only, no plaintext storage)."""

from __future__ import annotations

from dataclasses import dataclass

from mcp_flow.derive.fragments import normalize_basic, sha256_hex
from mcp_flow.labels.detectors import detect_all_secrets_in_text
from mcp_flow.match.base import is_informative_text, shannon_entropy
from mcp_flow.store.db import FlowStore, FragmentRow, PersistentFingerprintRow

PERSISTENT_LABEL_PREFIXES: tuple[str, ...] = ("secret:", "confidential:")
CROSS_SESSION_LABEL_PREFIX = "cross_session:"
CROSS_SESSION_LABEL_SOURCE = "cross_session"

# Detector labels whose matched span is a self-contained high-entropy secret value
# (excludes header-only patterns like `secret:private_key` or marker words like `confidential:doc`).
_SPAN_HASHABLE_SECRET_LABELS: frozenset[str] = frozenset(
    {
        "secret:api_key",
        "secret:github_token",
        "secret:aws_key",
        "secret:jwt",
        "secret:bearer_token",
        "secret:slack_token",
        "secret:google_api_key",
        "secret:stripe_key",
    }
)


@dataclass(frozen=True)
class CrossSessionMatch:
    """Observed hash correlation between an earlier session's sensitive output and a current input fragment."""

    fingerprint_id: int
    origin_session_id: str
    origin_call_id: int
    origin_frag_id: int
    origin_label: str
    dst_session_id: str
    dst_call_id: int
    dst_frag_id: int
    match_kind: str  # 'raw_hash' | 'norm_hash'
    score: float
    provenance_label: str


def is_persistable_label(label: str) -> bool:
    """Return True if `label` is a sensitive label eligible for persistent cross-session tracking."""
    return label.startswith(PERSISTENT_LABEL_PREFIXES)


def format_provenance_label(origin_session_id: str, label: str) -> str:
    """Format the cross-session provenance label attached to matched input fragments and calls."""
    return f"{CROSS_SESSION_LABEL_PREFIX}{origin_session_id}:{label}"


def _fragment_hashes(frag: FragmentRow) -> tuple[str, str]:
    """Compute `(raw_hash, norm_hash)` for a fragment, supporting hash-only storage mode."""
    raw_hash = frag.hash or (sha256_hex(frag.text) if frag.text else "")
    if frag.norm:
        norm_hash = sha256_hex(frag.norm)
    elif frag.text:
        norm_hash = sha256_hex(normalize_basic(frag.text))
    else:
        norm_hash = raw_hash
    return raw_hash, norm_hash


def _is_fragment_informative(frag: FragmentRow, min_len: int = 6) -> bool:
    """Return True if a fragment carries enough information to be registered or matched across sessions."""
    if frag.text or frag.norm:
        return is_informative_text(frag.text, frag.norm, min_len=min_len)
    # Hash-only mode: no plaintext available, rely on length and presence of hash
    return frag.len >= min_len and bool(frag.hash)


def _is_fragment_eligible_for_inherited_label(
    frag: FragmentRow,
    min_len: int = 16,
    min_entropy: float = 2.5,
) -> bool:
    """
    Stricter information threshold for labels inherited from the parent call (e.g. `confidential:*`),
    preventing short generic JSON field values like `"completed"` or `"production"` from being persisted.
    """
    if frag.text or frag.norm:
        check_str = frag.norm if frag.norm else frag.text.strip().casefold()
        if len(check_str) < min_len:
            return False
        return shannon_entropy(check_str) >= min_entropy
    # Hash-only mode: no plaintext/norm available, rely on length and presence of hash
    return frag.len >= min_len and bool(frag.hash)


def _extract_secret_span_hashes(text: str) -> list[tuple[str, str, str, int]]:
    """
    Extract `(label, raw_hash, norm_hash, length)` for all self-contained secret spans embedded inside `text`.
    Never returns plaintext — only hashes and lengths.
    """
    if not text:
        return []
    results: list[tuple[str, str, str, int]] = []
    seen: set[tuple[str, str]] = set()
    for det in detect_all_secrets_in_text(text):
        if det.label not in _SPAN_HASHABLE_SECRET_LABELS:
            continue
        try:
            start_s, end_s = det.span.split(":", 1)
            start, end = int(start_s), int(end_s)
        except ValueError:
            continue
        if start < 0 or end <= start or end > len(text):
            continue
        if start == 0 and end == len(text):
            # Full fragment is already hashed at the fragment level
            continue
        span_text = text[start:end]
        span_norm = normalize_basic(span_text)
        if not is_informative_text(span_text, span_norm):
            continue
        raw_h = sha256_hex(span_text)
        key = (det.label, raw_h)
        if key in seen:
            continue
        seen.add(key)
        results.append(
            (
                det.label,
                raw_h,
                sha256_hex(span_norm),
                len(span_text),
            )
        )
    return results


def register_persistent_fingerprints(
    store: FlowStore,
    session_id: str,
    min_len: int = 6,
) -> list[PersistentFingerprintRow]:
    """
    Record hash-only fingerprints (`raw_hash`, `norm_hash`, `length`, `label`) for all informative
    `out` fragments in `session_id` carrying a `secret:*` or `confidential:*` label (directly on
    the fragment or inherited from its call).

    Plaintext is never stored in `persistent_fingerprints`.
    """
    fragments = store.get_fragments(session_id)
    labels = store.get_labels(session_id)

    call_labels: dict[int, list[str]] = {}
    frag_labels: dict[int, list[str]] = {}
    for lbl in labels:
        if not is_persistable_label(lbl.label):
            continue
        if lbl.target_kind == "call":
            bucket = call_labels.setdefault(lbl.target_id, [])
            if lbl.label not in bucket:
                bucket.append(lbl.label)
        elif lbl.target_kind == "fragment":
            bucket = frag_labels.setdefault(lbl.target_id, [])
            if lbl.label not in bucket:
                bucket.append(lbl.label)

    # Replace any stale records from a prior analysis of the same session
    store.clear_persistent_fingerprints(session_id)

    for frag in fragments:
        if frag.side != "out":
            continue
        if not _is_fragment_informative(frag, min_len=min_len):
            continue

        direct_labels = frag_labels.get(frag.id, [])
        inherited_labels = call_labels.get(frag.call_id, [])
        allow_inherited = _is_fragment_eligible_for_inherited_label(frag)

        combined_labels: list[str] = []
        for lbl_str in direct_labels:
            if lbl_str not in combined_labels:
                combined_labels.append(lbl_str)
        if allow_inherited:
            for lbl_str in inherited_labels:
                if lbl_str not in combined_labels:
                    combined_labels.append(lbl_str)
        if not combined_labels:
            continue

        raw_hash, norm_hash = _fragment_hashes(frag)
        if not raw_hash and not norm_hash:
            continue

        for lbl_str in combined_labels:
            store.insert_persistent_fingerprint(
                origin_session_id=session_id,
                origin_call_id=frag.call_id,
                origin_frag_id=frag.id,
                label=lbl_str,
                norm_hash=norm_hash,
                raw_hash=raw_hash,
                length=frag.len,
            )

        # Also index hashes of self-contained secret spans embedded in larger output text
        for span_label, span_raw_hash, span_norm_hash, span_len in _extract_secret_span_hashes(frag.text):
            store.insert_persistent_fingerprint(
                origin_session_id=session_id,
                origin_call_id=frag.call_id,
                origin_frag_id=frag.id,
                label=span_label,
                norm_hash=span_norm_hash,
                raw_hash=span_raw_hash,
                length=span_len,
            )

    return store.get_persistent_fingerprints(origin_session_id=session_id)


def match_cross_session_taint(
    store: FlowStore,
    session_id: str,
    min_len: int = 6,
) -> list[CrossSessionMatch]:
    """
    Check `in` fragments of `session_id` against `persistent_fingerprints` from earlier sessions.
    For each hash match, attach `cross_session:<origin_session_id>:<label>` to both the input
    fragment and its parent call so `mcp-flow report` flags cross-session exfiltration to sinks.
    """
    in_fragments = [
        f
        for f in store.get_fragments(session_id)
        if f.side == "in" and _is_fragment_informative(f, min_len=min_len)
    ]
    if not in_fragments:
        return []

    frag_candidates: dict[int, tuple[FragmentRow, list[tuple[str, str]]]] = {}
    all_raw_hashes: set[str] = set()
    all_norm_hashes: set[str] = set()

    for frag in in_fragments:
        raw_hash, norm_hash = _fragment_hashes(frag)
        pairs: list[tuple[str, str]] = []
        if raw_hash or norm_hash:
            pairs.append((raw_hash, norm_hash))
            if raw_hash:
                all_raw_hashes.add(raw_hash)
            if norm_hash:
                all_norm_hashes.add(norm_hash)
        for _lbl, s_raw, s_norm, _slen in _extract_secret_span_hashes(frag.text):
            pairs.append((s_raw, s_norm))
            all_raw_hashes.add(s_raw)
            all_norm_hashes.add(s_norm)
        if pairs:
            frag_candidates[frag.id] = (frag, pairs)

    if not all_raw_hashes and not all_norm_hashes:
        return []

    current_started_at = store.get_session_started_at(session_id)
    persisted = store.find_persistent_fingerprints_by_hashes(
        raw_hashes=all_raw_hashes,
        norm_hashes=all_norm_hashes,
        exclude_session_id=session_id,
        max_origin_started_at=current_started_at,
    )
    if not persisted:
        return []

    by_raw: dict[str, list[PersistentFingerprintRow]] = {}
    by_norm: dict[str, list[PersistentFingerprintRow]] = {}
    for fp in persisted:
        if fp.raw_hash:
            by_raw.setdefault(fp.raw_hash, []).append(fp)
        if fp.norm_hash:
            by_norm.setdefault(fp.norm_hash, []).append(fp)

    best_matches: dict[tuple[int, str, str], CrossSessionMatch] = {}

    for frag, pairs in frag_candidates.values():
        for raw_h, norm_h in pairs:
            for fp in by_raw.get(raw_h, []):
                key = (frag.id, fp.origin_session_id, fp.label)
                prov_label = format_provenance_label(fp.origin_session_id, fp.label)
                candidate = CrossSessionMatch(
                    fingerprint_id=fp.id,
                    origin_session_id=fp.origin_session_id,
                    origin_call_id=fp.origin_call_id,
                    origin_frag_id=fp.origin_frag_id,
                    origin_label=fp.label,
                    dst_session_id=session_id,
                    dst_call_id=frag.call_id,
                    dst_frag_id=frag.id,
                    match_kind="raw_hash",
                    score=1.0,
                    provenance_label=prov_label,
                )
                existing = best_matches.get(key)
                if existing is None or candidate.score > existing.score:
                    best_matches[key] = candidate

            for fp in by_norm.get(norm_h, []):
                key = (frag.id, fp.origin_session_id, fp.label)
                prov_label = format_provenance_label(fp.origin_session_id, fp.label)
                candidate = CrossSessionMatch(
                    fingerprint_id=fp.id,
                    origin_session_id=fp.origin_session_id,
                    origin_call_id=fp.origin_call_id,
                    origin_frag_id=fp.origin_frag_id,
                    origin_label=fp.label,
                    dst_session_id=session_id,
                    dst_call_id=frag.call_id,
                    dst_frag_id=frag.id,
                    match_kind="norm_hash",
                    score=0.95,
                    provenance_label=prov_label,
                )
                existing = best_matches.get(key)
                if existing is None or candidate.score > existing.score:
                    best_matches[key] = candidate

    matches = sorted(
        best_matches.values(),
        key=lambda m: (-m.score, m.dst_call_id, m.dst_frag_id, m.origin_session_id, m.origin_label),
    )

    for m in matches:
        store.insert_label("fragment", m.dst_frag_id, m.provenance_label, source=CROSS_SESSION_LABEL_SOURCE)
        store.insert_label("call", m.dst_call_id, m.provenance_label, source=CROSS_SESSION_LABEL_SOURCE)

    return matches


class CrossSessionMatcher:
    """Facade for registering persistent fingerprints and matching cross-session taint."""

    def __init__(self, min_len: int = 6) -> None:
        self.min_len = min_len

    def register_session(self, store: FlowStore, session_id: str) -> list[PersistentFingerprintRow]:
        """Persist sensitive `out` fragment hashes from `session_id` into `persistent_fingerprints`."""
        return register_persistent_fingerprints(store, session_id, min_len=self.min_len)

    def match_session(self, store: FlowStore, session_id: str) -> list[CrossSessionMatch]:
        """Match `in` fragments of `session_id` against earlier sessions' persistent fingerprints."""
        return match_cross_session_taint(store, session_id, min_len=self.min_len)
