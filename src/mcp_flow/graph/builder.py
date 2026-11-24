"""Build call-level dependency graphs by aggregating fragment-level flow edges."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from mcp_flow.store.db import FlowStore

OBSERVATION_DISCLAIMER = (
    "注記: 辺はプロトコル入出力間の「内容一致の観測」を表すものであり、LLM内部推論の因果関係の証明ではありません。"
)


@dataclass
class EdgeEvidence:
    """Fragment-level evidence supporting a call-to-call dependency edge."""

    flow_id: int
    src_frag_id: int
    dst_frag_id: int
    src_json_path: str
    dst_json_path: str
    kind: str
    score: float
    src_span: str
    dst_span: str
    src_hash: str
    dst_hash: str
    src_len: int
    dst_len: int
    src_text: str = ""
    dst_text: str = ""
    labels: list[str] = field(default_factory=list)

    def to_dict(self, expose_text: bool = False) -> dict[str, Any]:
        data: dict[str, Any] = {
            "flow_id": self.flow_id,
            "src_frag_id": self.src_frag_id,
            "dst_frag_id": self.dst_frag_id,
            "src_json_path": self.src_json_path,
            "dst_json_path": self.dst_json_path,
            "kind": self.kind,
            "score": self.score,
            "src_span": self.src_span,
            "dst_span": self.dst_span,
            "src_hash": self.src_hash,
            "dst_hash": self.dst_hash,
            "src_len": self.src_len,
            "dst_len": self.dst_len,
            "labels": list(self.labels),
        }
        if expose_text:
            data["src_text"] = self.src_text
            data["dst_text"] = self.dst_text
        return data


@dataclass
class CallNode:
    """A single MCP tool invocation node in the session flow graph."""

    call_id: int
    session_id: str
    server_id: str
    server_name: str
    tool: str
    req_seq: int
    res_seq: int | None
    t_start: float
    t_end: float | None
    is_error: int
    role: str = "neutral"
    labels: list[str] = field(default_factory=list)

    @property
    def display_name(self) -> str:
        if self.server_name and not self.tool.startswith(f"{self.server_name}."):
            return f"{self.server_name}.{self.tool}"
        return self.tool


@dataclass
class CallEdge:
    """Aggregated directed edge between two tool calls."""

    edge_id: str
    src_call_id: int
    dst_call_id: int
    max_score: float
    match_count: int
    primary_kind: str
    evidences: list[EdgeEvidence] = field(default_factory=list)

    def to_dict(self, expose_text: bool = False) -> dict[str, Any]:
        return {
            "edge_id": self.edge_id,
            "src_call_id": self.src_call_id,
            "dst_call_id": self.dst_call_id,
            "max_score": self.max_score,
            "match_count": self.match_count,
            "primary_kind": self.primary_kind,
            "evidences": [ev.to_dict(expose_text=expose_text) for ev in self.evidences],
        }


@dataclass
class FlowGraph:
    """Adjacency-list representation of a session's tool-call data flow graph."""

    session_id: str
    nodes: dict[int, CallNode] = field(default_factory=dict)
    edges: list[CallEdge] = field(default_factory=list)
    adjacency: dict[int, list[CallEdge]] = field(default_factory=dict)
    disclaimer: str = OBSERVATION_DISCLAIMER

    def get_edge(self, edge_identifier: str) -> CallEdge | None:
        """Find a CallEdge by its `edge_id` (e.g. 'e:1->2') or by a constituent `flow_id`."""
        for edge in self.edges:
            if edge.edge_id == edge_identifier:
                return edge
        if edge_identifier.isdigit():
            fid = int(edge_identifier)
            for edge in self.edges:
                if any(ev.flow_id == fid for ev in edge.evidences):
                    return edge
        return None


def build_flow_graph(
    store: FlowStore,
    session_id: str,
    min_score: float = 0.0,
) -> FlowGraph:
    """
    Construct a `FlowGraph` from derived `calls`, `fragments`, `flows`, `labels`, and `tool_roles`.
    Multiple fragment matches between the same `(src_call, dst_call)` pair are aggregated into one edge.
    """
    calls = store.get_calls(session_id)
    fragments = {f.id: f for f in store.get_fragments(session_id)}
    flows = store.get_flows(session_id)
    labels = store.get_labels(session_id)
    tool_roles = store.get_tool_roles()

    call_labels: dict[int, list[str]] = {}
    frag_labels: dict[int, list[str]] = {}
    for lbl in labels:
        if lbl.target_kind == "call":
            bucket = call_labels.setdefault(lbl.target_id, [])
            if lbl.label not in bucket:
                bucket.append(lbl.label)
        elif lbl.target_kind == "fragment":
            bucket = frag_labels.setdefault(lbl.target_id, [])
            if lbl.label not in bucket:
                bucket.append(lbl.label)

    nodes: dict[int, CallNode] = {}
    for c in calls:
        role = (
            tool_roles.get((c.server_name, c.tool))
            or tool_roles.get(("*", c.tool))
            or "neutral"
        )
        c_lbls = list(call_labels.get(c.id, []))
        nodes[c.id] = CallNode(
            call_id=c.id,
            session_id=c.session_id,
            server_id=c.server_id,
            server_name=c.server_name,
            tool=c.tool,
            req_seq=c.req_seq,
            res_seq=c.res_seq,
            t_start=c.t_start,
            t_end=c.t_end,
            is_error=c.is_error,
            role=role,
            labels=c_lbls,
        )

    grouped_evidences: dict[tuple[int, int], list[EdgeEvidence]] = {}
    for fl in flows:
        if fl.score < min_score:
            continue
        src_f = fragments.get(fl.src_frag)
        dst_f = fragments.get(fl.dst_frag)
        if src_f is None or dst_f is None:
            continue
        if src_f.call_id not in nodes or dst_f.call_id not in nodes:
            continue

        ev_labels = list(frag_labels.get(src_f.id, []))
        for dl in frag_labels.get(dst_f.id, []):
            if dl not in ev_labels:
                ev_labels.append(dl)

        ev = EdgeEvidence(
            flow_id=fl.id,
            src_frag_id=src_f.id,
            dst_frag_id=dst_f.id,
            src_json_path=src_f.json_path,
            dst_json_path=dst_f.json_path,
            kind=fl.kind,
            score=fl.score,
            src_span=fl.src_span,
            dst_span=fl.dst_span,
            src_hash=src_f.hash,
            dst_hash=dst_f.hash,
            src_len=src_f.len,
            dst_len=dst_f.len,
            src_text=src_f.text,
            dst_text=dst_f.text,
            labels=ev_labels,
        )
        grouped_evidences.setdefault((src_f.call_id, dst_f.call_id), []).append(ev)

    edges: list[CallEdge] = []
    adjacency: dict[int, list[CallEdge]] = {cid: [] for cid in nodes}

    for (src_cid, dst_cid), ev_list in sorted(grouped_evidences.items()):
        ev_sorted = sorted(ev_list, key=lambda e: (-e.score, e.flow_id))
        top = ev_sorted[0]
        edge = CallEdge(
            edge_id=f"e:{src_cid}->{dst_cid}",
            src_call_id=src_cid,
            dst_call_id=dst_cid,
            max_score=top.score,
            match_count=len(ev_sorted),
            primary_kind=top.kind,
            evidences=ev_sorted,
        )
        edges.append(edge)
        adjacency.setdefault(src_cid, []).append(edge)

    return FlowGraph(
        session_id=session_id,
        nodes=nodes,
        edges=edges,
        adjacency=adjacency,
    )
