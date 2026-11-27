"""Reconstruct `calls` table rows by pairing `tools/call` JSON-RPC requests and responses."""

from __future__ import annotations

from collections import deque
import json
from typing import Any

from mcp_flow.store.db import CallRow, FlowStore, MessageRow


def _extract_tool_name(payload: dict[str, Any]) -> str:
    params = payload.get("params")
    if isinstance(params, dict):
        name = params.get("name")
        if isinstance(name, str) and name:
            return name
    return "unknown_tool"


def _is_error_response(payload: dict[str, Any]) -> int:
    if "error" in payload and payload["error"] is not None:
        return 1
    result = payload.get("result")
    if isinstance(result, dict) and bool(result.get("isError")):
        return 1
    return 0


def derive_calls(store: FlowStore, session_id: str) -> list[CallRow]:
    """
    Scan all raw messages in `session_id`, pair `tools/call` requests with their responses
    by `(server_id, rpc_id)` in FIFO order, and populate the `calls` table.
    """
    messages: list[MessageRow] = store.get_messages(session_id)
    pending_requests: dict[tuple[str, str], deque[tuple[MessageRow, str]]] = {}
    paired: dict[int, tuple[MessageRow, str, MessageRow | None]] = {}

    for msg in messages:
        try:
            payload = json.loads(msg.body)
        except json.JSONDecodeError:
            continue
        if not isinstance(payload, dict):
            continue

        if msg.dir == "c2s" and msg.kind == "request" and msg.method == "tools/call":
            tool_name = _extract_tool_name(payload)
            rpc_id = msg.rpc_id or f"seq:{msg.seq}"
            key = (msg.server_id, rpc_id)
            pending_requests.setdefault(key, deque()).append((msg, tool_name))
            paired[msg.seq] = (msg, tool_name, None)
        elif msg.dir == "s2c" and msg.kind == "response" and msg.rpc_id is not None:
            key = (msg.server_id, msg.rpc_id)
            queue = pending_requests.get(key)
            if queue:
                req_msg, tool_name = queue.popleft()
                if not queue:
                    pending_requests.pop(key, None)
                paired[req_msg.seq] = (req_msg, tool_name, msg)

    for req_seq in sorted(paired.keys()):
        req_msg, tool_name, res_msg = paired[req_seq]
        res_seq = res_msg.seq if res_msg is not None else None
        t_end = res_msg.ts if res_msg is not None else None
        is_error = 0
        if res_msg is not None:
            try:
                res_payload = json.loads(res_msg.body)
                if isinstance(res_payload, dict):
                    is_error = _is_error_response(res_payload)
            except json.JSONDecodeError:
                is_error = 1

        store.insert_call(
            session_id=session_id,
            server_id=req_msg.server_id,
            tool=tool_name,
            req_seq=req_msg.seq,
            res_seq=res_seq,
            t_start=req_msg.ts,
            t_end=t_end,
            is_error=is_error,
        )

    return store.get_calls(session_id)
