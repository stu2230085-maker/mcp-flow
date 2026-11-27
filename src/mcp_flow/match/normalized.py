"""Stage 3: Normalized matching across URL encoding, Base64 encoding, JSON escaping, and Unicode/whitespace."""

from __future__ import annotations

import base64
import json
import re
import unicodedata
import urllib.parse

from mcp_flow.match.base import (
    CandidateEdge,
    MatchContext,
    Matcher,
    MatchFragment,
    is_informative_text,
    is_temporally_valid,
)

_ALNUM_COMPACT_RE = re.compile(r"\s+")
_BASE64_TOKEN_RE = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}|[A-Za-z0-9_-]{16,}={0,2}")
_JSON_ESCAPE_RE = re.compile(r'\\(?:["\\/bfnrt]|u[0-9a-fA-F]{4}(?:\\u[0-9a-fA-F]{4})?)')


def _safe_json_unescape(text: str) -> str:
    """Decode JSON escape sequences without corrupting existing non-ASCII Unicode characters."""

    def _replace(match: re.Match[str]) -> str:
        seq = match.group(0)
        try:
            return str(json.loads(f'"{seq}"'))
        except json.JSONDecodeError:
            return seq

    return _JSON_ESCAPE_RE.sub(_replace, text)


def _try_b64_decode(candidate: str) -> str | None:
    padded = candidate + "=" * ((4 - len(candidate) % 4) % 4)
    for alt in (None, b"-_"):
        try:
            raw = base64.b64decode(padded, altchars=alt, validate=True)
            decoded = raw.decode("utf-8")
            # Ensure decoded string is printable text
            printable_ratio = sum(1 for ch in decoded if ch.isprintable() or ch.isspace()) / max(
                len(decoded), 1
            )
            if len(decoded) >= 8 and printable_ratio >= 0.9:
                return decoded
        except Exception:
            continue
    return None


def decode_and_normalize_variants(text: str) -> list[tuple[str, str]]:
    """
    Produce normalized text representations by stripping URL encoding, Base64 encoding,
    JSON escapes, Unicode width differences, and whitespace.
    Returns list of `(variant_label, normalized_string)`.
    """
    variants: list[tuple[str, str]] = []
    seen: set[str] = set()

    def _add(label: str, s: str) -> None:
        nfkc = unicodedata.normalize("NFKC", s)
        compact = _ALNUM_COMPACT_RE.sub(" ", nfkc).strip().casefold()
        if len(compact) >= 8 and compact not in seen:
            seen.add(compact)
            variants.append((label, compact))
        no_space = re.sub(r"\s+", "", compact)
        if len(no_space) >= 8 and no_space not in seen:
            seen.add(no_space)
            variants.append((f"{label}:nospace", no_space))

    _add("raw", text)

    # 1. URL decode (up to 2 passes)
    unquoted = urllib.parse.unquote_plus(text)
    if unquoted != text:
        _add("url", unquoted)
        unquoted2 = urllib.parse.unquote_plus(unquoted)
        if unquoted2 != unquoted:
            _add("url2", unquoted2)

    # 2. JSON string unescape (UTF-8 safe)
    if "\\" in text:
        unescaped = _safe_json_unescape(text)
        if unescaped != text:
            _add("json_unescape", unescaped)

    # 3. Full or embedded Base64 decode on raw and URL-decoded strings
    for source_str in (text.strip(), unquoted.strip()):
        full_dec = _try_b64_decode(source_str)
        if full_dec:
            _add("base64", full_dec)
        for m in _BASE64_TOKEN_RE.finditer(source_str):
            tok = m.group(0)
            tok_dec = _try_b64_decode(tok)
            if tok_dec:
                _add(f"base64@{m.start()}:{m.end()}", tok_dec)

    return variants


class NormalizedMatcher(Matcher):
    """Detects flows across format transformations (Base64, URL-encoding, JSON escaping, whitespace)."""

    stage_name = "normalized"

    def __init__(self, min_len: int = 10) -> None:
        self.min_len = min_len

    def match(
        self,
        src_fragments: list[MatchFragment],
        dst_fragments: list[MatchFragment],
        ctx: MatchContext | None = None,
    ) -> list[CandidateEdge]:
        context = ctx or MatchContext.from_fragments(src_fragments + dst_fragments)
        edges: list[CandidateEdge] = []

        src_variants_map: dict[int, list[tuple[str, str]]] = {}
        for src in src_fragments:
            if src.text and is_informative_text(src.text, src.norm, min_len=self.min_len):
                src_variants_map[src.id] = decode_and_normalize_variants(src.text)

        dst_variants_map: dict[int, list[tuple[str, str]]] = {}
        for dst in dst_fragments:
            if dst.text and is_informative_text(dst.text, dst.norm, min_len=self.min_len):
                dst_variants_map[dst.id] = decode_and_normalize_variants(dst.text)

        for src in src_fragments:
            s_vars = src_variants_map.get(src.id)
            if not s_vars:
                continue
            for dst in dst_fragments:
                if not is_temporally_valid(src, dst):
                    continue
                d_vars = dst_variants_map.get(dst.id)
                if not d_vars:
                    continue

                best_score = 0.0
                best_src_span = f"0:{src.len}"
                best_dst_span = f"0:{dst.len}"

                for s_label, s_val in s_vars:
                    if len(s_val) < self.min_len:
                        continue
                    for d_label, d_val in d_vars:
                        if len(d_val) < self.min_len:
                            continue
                        if s_val == d_val:
                            cand_score = 0.90
                        elif len(s_val) >= 12 and s_val in d_val:
                            cand_score = 0.84
                        elif len(d_val) >= 12 and d_val in s_val:
                            cand_score = 0.80
                        else:
                            continue

                        if cand_score > best_score:
                            best_score = cand_score
                            best_src_span = f"0:{src.len}({s_label})"
                            best_dst_span = f"0:{dst.len}({d_label})"

                if best_score > 0.0:
                    rarity = context.rarity_weight(src.norm or src.hash)
                    score = round(best_score * rarity, 4)
                    if score >= context.min_score:
                        edges.append(
                            CandidateEdge(
                                src_frag=src.id,
                                dst_frag=dst.id,
                                kind="normalized",
                                score=score,
                                src_span=best_src_span,
                                dst_span=best_dst_span,
                            )
                        )

        return edges
