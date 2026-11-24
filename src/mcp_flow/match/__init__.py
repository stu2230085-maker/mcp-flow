"""Multi-stage fingerprint matching engine for data dependency detection."""

from __future__ import annotations

from mcp_flow.match.base import CandidateEdge, MatchContext, MatchFragment, Matcher
from mcp_flow.match.engine import FingerprintEngine
from mcp_flow.match.exact import ExactMatcher
from mcp_flow.match.minhash import MinHashMatcher
from mcp_flow.match.normalized import NormalizedMatcher
from mcp_flow.match.semantic import SemanticMatcher
from mcp_flow.match.substring import SubstringMatcher

__all__ = [
    "CandidateEdge",
    "ExactMatcher",
    "FingerprintEngine",
    "MatchContext",
    "MatchFragment",
    "Matcher",
    "MinHashMatcher",
    "NormalizedMatcher",
    "SemanticMatcher",
    "SubstringMatcher",
]
