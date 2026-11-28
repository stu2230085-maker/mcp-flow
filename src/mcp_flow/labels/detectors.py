"""Content-based regex detectors for API keys, tokens, emails, private keys, and confidential markers."""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class SecretDetection:
    label: str
    detector: str
    span: str


SECRET_PATTERNS: list[tuple[str, str, re.Pattern[str]]] = [
    (
        "secret:api_key",
        "regex:openai_or_sk_key",
        re.compile(r"(?<![A-Za-z0-9_-])sk-[A-Za-z0-9_-]{16,}(?![A-Za-z0-9_-])"),
    ),
    (
        "secret:github_token",
        "regex:github_pat",
        re.compile(
            r"(?<![A-Za-z0-9_])(?:(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{25,})(?![A-Za-z0-9_])"
        ),
    ),
    (
        "secret:aws_key",
        "regex:aws_access_key",
        re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    ),
    (
        "secret:jwt",
        "regex:jwt_token",
        re.compile(
            r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}(?![A-Za-z0-9_-])"
        ),
    ),
    (
        "secret:bearer_token",
        "regex:bearer_token",
        re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/-]{16,}=*(?![A-Za-z0-9._~+/=-])"),
    ),
    (
        "secret:slack_token",
        "regex:slack_token",
        re.compile(r"(?<![A-Za-z0-9_-])xox[baprs]-[0-9A-Za-z-]{16,}(?![A-Za-z0-9_-])"),
    ),
    (
        "secret:google_api_key",
        "regex:google_api_key",
        re.compile(r"(?<![A-Za-z0-9_-])AIza[0-9A-Za-z_-]{35}(?![A-Za-z0-9_-])"),
    ),
    (
        "secret:stripe_key",
        "regex:stripe_key",
        re.compile(r"(?<![A-Za-z0-9_])(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,}(?![A-Za-z0-9_])"),
    ),
    (
        "secret:private_key",
        "regex:pem_private_key",
        re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    ),
    (
        "pii:email",
        "regex:email_address",
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    ),
    (
        "confidential:doc",
        "regex:confidential_marker",
        re.compile(r"(?i)\b(?:CONFIDENTIAL|INTERNAL_ONLY|SECRET_TOKEN)\b|社外秘|機密文書|極秘"),
    ),
]


def detect_all_secrets_in_text(text: str) -> list[SecretDetection]:
    """Scan a fragment text and return every matched sensitive data span (including multiple per label)."""
    if not text:
        return []
    detections: list[SecretDetection] = []
    for label, detector_name, pattern in SECRET_PATTERNS:
        for m in pattern.finditer(text):
            detections.append(
                SecretDetection(
                    label=label,
                    detector=detector_name,
                    span=f"{m.start()}:{m.end()}",
                )
            )
    return detections


def detect_secrets_in_text(text: str) -> list[SecretDetection]:
    """Scan a fragment text and return one detection per matched sensitive data label."""
    if not text:
        return []
    detections: list[SecretDetection] = []
    seen_labels: set[str] = set()
    for det in detect_all_secrets_in_text(text):
        if det.label not in seen_labels:
            seen_labels.add(det.label)
            detections.append(det)
    return detections
