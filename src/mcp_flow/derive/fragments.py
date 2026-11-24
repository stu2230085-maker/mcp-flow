"""Decompose tool call request arguments and response results into leaf fragments."""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from typing import Any

from mcp_flow.store.db import FlowStore, FragmentRow

_WHITESPACE_RE = re.compile(r"\s+")

# Boilerplate MCP protocol fields that carry structural types rather than user/tool payload
_IGNORED_LEAF_PATHS = {
    "$.content[*].type",
    "$.isError",
    "$._meta",
}


def normalize_basic(text: str) -> str:
    """Normalize Unicode NFKC, collapse whitespace, strip, and case-fold."""
    nfkc = unicodedata.normalize("NFKC", text)
    collapsed = _WHITESPACE_RE.sub(" ", nfkc).strip()
    return collapsed.casefold()


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def _should_ignore_path(json_path: str) -> bool:
    normalized_path = re.sub(r"\[\d+\]", "[*]", json_path)
    return normalized_path in _IGNORED_LEAF_PATHS


def _iter_json_leaves(
    node: Any,
    path: str = "$",
    parse_embedded_json: bool = True,
) -> list[tuple[str, str]]:
    """
    Recursively walk a JSON structure down to leaf strings/scalars.
    If a leaf string is itself a JSON object or array (common in MCP `content[0].text`),
    emit both the outer string leaf and its inner JSON leaves.
    """
    leaves: list[tuple[str, str]] = []
    if isinstance(node, dict):
        for k, v in node.items():
            child_path = f"{path}.{k}"
            leaves.extend(_iter_json_leaves(v, child_path, parse_embedded_json=parse_embedded_json))
    elif isinstance(node, list):
        for idx, item in enumerate(node):
            child_path = f"{path}[{idx}]"
            leaves.extend(_iter_json_leaves(item, child_path, parse_embedded_json=parse_embedded_json))
    elif isinstance(node, str):
        if not _should_ignore_path(path) and node != "":
            leaves.append((path, node))
            if parse_embedded_json:
                stripped = node.strip()
                if (stripped.startswith("{") and stripped.endswith("}")) or (
                    stripped.startswith("[") and stripped.endswith("]")
                ):
                    try:
                        inner = json.loads(stripped)
                        if isinstance(inner, (dict, list)):
                            leaves.extend(
                                _iter_json_leaves(
                                    inner,
                                    f"{path}$json",
                                    parse_embedded_json=False,
                                )
                            )
                    except json.JSONDecodeError:
                        pass
    elif isinstance(node, (int, float)) and not isinstance(node, bool):
        if not _should_ignore_path(path):
            leaves.append((path, str(node)))
    return leaves


def derive_fragments(store: FlowStore, session_id: str) -> list[FragmentRow]:
    """
    Decompose every call's arguments (`side='in'`) and result (`side='out'`)
    in `session_id` into leaf fragments and persist them to `fragments`.
    """
    calls = store.get_calls(session_id)
    messages_by_seq = {m.seq: m for m in store.get_messages(session_id)}

    for call in calls:
        req_msg = messages_by_seq.get(call.req_seq)
        if req_msg is not None:
            try:
                req_obj = json.loads(req_msg.body)
                params = req_obj.get("params", {}) if isinstance(req_obj, dict) else {}
                args = params.get("arguments", {}) if isinstance(params, dict) else {}
                for jpath, text in _iter_json_leaves(args, "$"):
                    norm = normalize_basic(text)
                    store.insert_fragment(
                        call_id=call.id,
                        side="in",
                        json_path=jpath,
                        text=text,
                        norm=norm,
                        length=len(text),
                        frag_hash=sha256_hex(text),
                    )
            except json.JSONDecodeError:
                pass

        if call.res_seq is not None:
            res_msg = messages_by_seq.get(call.res_seq)
            if res_msg is not None:
                try:
                    res_obj = json.loads(res_msg.body)
                    if isinstance(res_obj, dict):
                        result_node = res_obj.get("result")
                        if result_node is not None:
                            for jpath, text in _iter_json_leaves(result_node, "$"):
                                norm = normalize_basic(text)
                                store.insert_fragment(
                                    call_id=call.id,
                                    side="out",
                                    json_path=jpath,
                                    text=text,
                                    norm=norm,
                                    length=len(text),
                                    frag_hash=sha256_hex(text),
                                )
                except json.JSONDecodeError:
                    pass

    return store.get_fragments(session_id)
