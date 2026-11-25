"""Trace import (mcp-flow JSONL / mcptape) and OpenTelemetry Span JSON export."""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from mcp_flow.graph.builder import OBSERVATION_DISCLAIMER, CallEdge, build_flow_graph
from mcp_flow.proxy.jsonrpc import parse_jsonrpc_line
from mcp_flow.store.db import FlowStore

_DIRECTION_ALIASES: dict[str, str] = {
    "c2s": "c2s",
    "client_to_server": "c2s",
    "client-to-server": "c2s",
    "client->server": "c2s",
    "request": "c2s",
    "outbound": "c2s",
    "in": "c2s",
    "->": "c2s",
    "s2c": "s2c",
    "server_to_client": "s2c",
    "server-to-client": "s2c",
    "server->client": "s2c",
    "response": "s2c",
    "inbound": "s2c",
    "out": "s2c",
    "<-": "s2c",
}


@dataclass(frozen=True)
class ImportResult:
    """Summary of an imported JSONL trace session."""

    session_id: str
    imported_messages: int
    servers: list[str]


def _normalize_timestamp(raw_ts: Any, fallback_base: float, index: int) -> float:
    if isinstance(raw_ts, (int, float)) and not isinstance(raw_ts, bool):
        return float(raw_ts)
    if isinstance(raw_ts, str):
        text = raw_ts.strip()
        if text:
            try:
                return float(text)
            except ValueError:
                pass
            iso = text[:-1] + "+00:00" if text.endswith("Z") else text
            dt = datetime.fromisoformat(iso)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.timestamp()
    return fallback_base + (index * 0.001)


def _normalize_body(record: dict[str, Any], line_no: int) -> str:
    if "body" in record and record["body"] is not None:
        raw_body = record["body"]
    elif "message" in record and record["message"] is not None:
        raw_body = record["message"]
    else:
        raise ValueError(f"Line {line_no}: missing 'body' or 'message' field")

    if isinstance(raw_body, dict):
        return json.dumps(raw_body, ensure_ascii=False)
    if isinstance(raw_body, str):
        return raw_body
    raise ValueError(f"Line {line_no}: 'body'/'message' must be a JSON object or string")


def _normalize_direction(record: dict[str, Any], inferred_kind: str, line_no: int) -> str:
    raw_dir = record.get("dir") if "dir" in record else record.get("direction")
    if raw_dir is None:
        return "s2c" if inferred_kind == "response" else "c2s"
    if not isinstance(raw_dir, str):
        raise ValueError(f"Line {line_no}: direction must be a string")
    normalized = _DIRECTION_ALIASES.get(raw_dir.strip().lower())
    if normalized is None:
        raise ValueError(f"Line {line_no}: unsupported direction {raw_dir!r}")
    return normalized


def _extract_rpc_metadata(
    record: dict[str, Any], body_str: str
) -> tuple[str, str | None, str | None]:
    raw_kind = record.get("kind")
    raw_method = record.get("method")
    raw_rpc_id = record.get("rpc_id")

    parsed = parse_jsonrpc_line(body_str)
    first = parsed[0] if parsed else None

    if isinstance(raw_kind, str) and raw_kind in ("request", "response", "notification"):
        kind = raw_kind
    elif first is not None:
        kind = first.kind
    else:
        kind = "notification"

    method = str(raw_method) if isinstance(raw_method, str) else (first.method if first else None)
    if raw_rpc_id is not None:
        rpc_id: str | None = str(raw_rpc_id)
    elif first is not None:
        rpc_id = first.rpc_id
    else:
        rpc_id = None

    return kind, method, rpc_id


def import_trace_jsonl(
    store: FlowStore,
    jsonl_path: str | Path,
    session_id: str | None = None,
) -> ImportResult:
    """
    Ingest JSONL lines produced by `mcp-flow export` or `mcptape`-compatible recordings
    into `sessions`, `servers`, and `messages`.
    """
    path = Path(jsonl_path)
    raw_lines = path.read_text(encoding="utf-8").splitlines()
    records: list[tuple[int, dict[str, Any]]] = []
    for line_no, raw_line in enumerate(raw_lines, start=1):
        stripped = raw_line.strip()
        if not stripped:
            continue
        parsed = json.loads(stripped)
        if not isinstance(parsed, dict):
            raise ValueError(f"Line {line_no}: JSONL record must be a JSON object")
        records.append((line_no, parsed))

    resolved_session = session_id
    if not resolved_session:
        for _, rec in records:
            cand = rec.get("session_id")
            if isinstance(cand, str) and cand.strip():
                resolved_session = cand.strip()
                break
    if not resolved_session:
        stem = path.stem.strip()
        resolved_session = stem or f"import-{uuid.uuid4().hex[:8]}"

    fallback_base = time.time()
    first_ts = (
        _normalize_timestamp(
            records[0][1].get("ts") if "ts" in records[0][1] else records[0][1].get("timestamp"),
            fallback_base,
            0,
        )
        if records
        else fallback_base
    )
    store.ensure_session(
        resolved_session,
        client="import",
        note=f"Imported from {path.name}",
        started_at=first_ts,
    )

    registered_servers: dict[str, str] = {}
    for idx, (line_no, rec) in enumerate(records):
        body_str = _normalize_body(rec, line_no)
        kind, method, rpc_id = _extract_rpc_metadata(rec, body_str)
        direction = _normalize_direction(rec, kind, line_no)

        raw_ts = rec.get("ts") if "ts" in rec else rec.get("timestamp")
        ts = _normalize_timestamp(raw_ts, fallback_base, idx)

        raw_server_name = rec.get("server") or rec.get("server_name") or rec.get("server_id") or "default"
        raw_server_id = rec.get("server_id") or raw_server_name
        server_id = str(raw_server_id)
        server_name = str(raw_server_name)

        if server_id not in registered_servers:
            store.register_server(
                server_id=server_id,
                session_id=resolved_session,
                name=server_name,
                transport="import",
            )
            registered_servers[server_id] = server_name

        store.append_message(
            session_id=resolved_session,
            server_id=server_id,
            direction=direction,
            kind=kind,
            method=method,
            rpc_id=rpc_id,
            body=body_str,
            ts=ts,
        )

    return ImportResult(
        session_id=resolved_session,
        imported_messages=len(records),
        servers=list(registered_servers.keys()),
    )


def _otel_trace_id(session_id: str) -> str:
    return hashlib.sha256(f"mcp-flow:trace:{session_id}".encode("utf-8")).hexdigest()[:32]


def _otel_span_id(session_id: str, call_id: int) -> str:
    return hashlib.sha256(f"mcp-flow:span:{session_id}:{call_id}".encode("utf-8")).hexdigest()[:16]


def export_otel_spans(
    store: FlowStore,
    session_id: str,
    min_score: float = 0.0,
) -> dict[str, Any]:
    """
    Export derived `CallNode`s and `CallEdge`s as an OpenTelemetry-compatible Span JSON payload.
    Never includes raw fragment text; preserves `OBSERVATION_DISCLAIMER` in resource attributes.
    """
    graph = build_flow_graph(store, session_id, min_score=min_score)
    trace_id = _otel_trace_id(session_id)

    incoming_edges: dict[int, list[CallEdge]] = {}
    for edge in graph.edges:
        incoming_edges.setdefault(edge.dst_call_id, []).append(edge)

    spans: list[dict[str, Any]] = []
    for node in sorted(graph.nodes.values(), key=lambda n: (n.req_seq, n.call_id)):
        end_ts = node.t_end if node.t_end is not None else node.t_start
        links = [
            {
                "trace_id": trace_id,
                "span_id": _otel_span_id(session_id, edge.src_call_id),
                "attributes": {
                    "mcp.flow.edge_id": edge.edge_id,
                    "mcp.flow.kind": edge.primary_kind,
                    "mcp.flow.score": edge.max_score,
                    "mcp.flow.match_count": edge.match_count,
                },
            }
            for edge in incoming_edges.get(node.call_id, [])
        ]
        spans.append(
            {
                "trace_id": trace_id,
                "span_id": _otel_span_id(session_id, node.call_id),
                "name": node.display_name,
                "kind": "SPAN_KIND_CLIENT",
                "start_time_unix_nano": int(node.t_start * 1_000_000_000),
                "end_time_unix_nano": int(end_ts * 1_000_000_000),
                "status": {
                    "code": "STATUS_CODE_ERROR" if node.is_error else "STATUS_CODE_OK"
                },
                "attributes": {
                    "mcp.call_id": node.call_id,
                    "mcp.server": node.server_name,
                    "mcp.tool": node.tool,
                    "mcp.role": node.role,
                    "mcp.labels": list(node.labels),
                    "mcp.req_seq": node.req_seq,
                    "mcp.res_seq": node.res_seq,
                },
                "links": links,
            }
        )

    return {
        "resource": {
            "attributes": {
                "service.name": "mcp-flow",
                "mcp.session.id": session_id,
                "mcp.observation.disclaimer": OBSERVATION_DISCLAIMER,
            }
        },
        "spans": spans,
    }
