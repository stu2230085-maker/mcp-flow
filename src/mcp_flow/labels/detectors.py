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
        re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b"),
    ),
    (
        "secret:github_token",
        "regex:github_pat",
        re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b|\bgithub_pat_[A-Za-z0-9_]{25,}\b"),
    ),
    (
        "secret:aws_key",
        "regex:aws_access_key",
        re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    ),
    (
        "secret:jwt",
        "regex:jwt_token",
        re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    ),
    (
        "secret:bearer_token",
        "regex:bearer_token",
        re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/-]{16,}=*\b"),
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


def detect_secrets_in_text(text: str) -> list[SecretDetection]:
    """Scan a fragment text and return all matched sensitive data labels."""
    if not text:
        return []
    detections: list[SecretDetection] = []
    seen_labels: set[str] = set()
    for label, detector_name, pattern in SECRET_PATTERNS:
        m = pattern.search(text)
        if m and label not in seen_labels:
            seen_labels.add(label)
            detections.append(
                SecretDetection(
                    label=label,
                    detector=detector_name,
                    span=f"{m.start()}:{m.end()}",
                )
            )
    return detections
