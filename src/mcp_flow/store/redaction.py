"""Pre-storage redaction and hash-only policies for sensitive trace protection."""

from __future__ import annotations

import re
from dataclasses import dataclass, field


DEFAULT_REDACT_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("PRIVATE_KEY", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]+?-----END [A-Z ]*PRIVATE KEY-----")),
]


@dataclass
class RedactionPolicy:
    """Controls how raw messages and derived fragments are sanitized before persistence."""

    redact_patterns: list[tuple[str, re.Pattern[str]]] = field(default_factory=list)
    hash_only: bool = False

    def redact_text(self, text: str) -> str:
        """Apply configured redaction regex patterns to raw text."""
        if not self.redact_patterns:
            return text
        result = text
        for label, pattern in self.redact_patterns:
            result = pattern.sub(f"[REDACTED:{label}]", result)
        return result

    @classmethod
    def from_regex_strings(cls, patterns: list[str], hash_only: bool = False) -> RedactionPolicy:
        """Create a RedactionPolicy from user-supplied regex strings."""
        compiled = [(f"PATTERN_{ idx }", re.compile(p)) for idx, p in enumerate(patterns)]
        return cls(redact_patterns=compiled, hash_only=hash_only)
