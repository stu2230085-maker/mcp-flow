"""Zero-mutation JSON-RPC 2.0 message parser and classifier."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ParsedRpcMessage:
    """Extracted metadata from a JSON-RPC 2.0 frame alongside the unmodified raw body."""

    kind: str  # 'request' | 'response' | 'notification'
    method: str | None
    rpc_id: str | None
    raw_body: str
    payload: dict[str, Any]


def classify_rpc_dict(obj: dict[str, Any], raw_body: str) -> ParsedRpcMessage:
    """Classify a single JSON-RPC 2.0 dictionary into request, response, or notification."""
    has_method = "method" in obj and isinstance(obj["method"], str)
    has_id = "id" in obj and obj["id"] is not None
    rpc_id = str(obj["id"]) if has_id else None
    method = str(obj["method"]) if has_method else None

    if has_method and has_id:
        kind = "request"
    elif has_method and not has_id:
        kind = "notification"
    elif "result" in obj or "error" in obj or has_id:
        kind = "response"
    else:
        kind = "notification"

    return ParsedRpcMessage(
        kind=kind,
        method=method,
        rpc_id=rpc_id,
        raw_body=raw_body,
        payload=obj,
    )


def parse_jsonrpc_line(raw_line: str) -> list[ParsedRpcMessage]:
    """
    Parse a single line (or body) of JSON-RPC 2.0 without modifying the original raw text.
    Supports both single JSON objects and JSON-RPC batch arrays.
    Returns an empty list if the line is empty or not valid JSON-RPC.
    """
    stripped = raw_line.strip()
    if not stripped:
        return []
    try:
        parsed = json.loads(stripped)
    except json.JSONDecodeError:
        return []

    if isinstance(parsed, dict):
        return [classify_rpc_dict(parsed, stripped)]
    if isinstance(parsed, list):
        results: list[ParsedRpcMessage] = []
        for item in parsed:
            if isinstance(item, dict):
                item_raw = json.dumps(item, ensure_ascii=False)
                results.append(classify_rpc_dict(item, item_raw))
        return results
    return []
