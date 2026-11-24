"""Graph traversal for detecting hazardous data flow paths from labeled sources to external sinks."""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass
from typing import Any

from mcp_flow.graph.builder import CallEdge, CallNode, FlowGraph


@dataclass
class HazardousPath:
    """A directed path from a confidential/source tool call to an external sink tool call."""

    nodes: list[CallNode]
    edges: list[CallEdge]
    bottleneck_score: float
    weakest_edge_id: str
    source_labels: list[str]

    def to_dict(self, expose_text: bool = False) -> dict[str, Any]:
        return {
            "call_ids": [n.call_id for n in self.nodes],
            "calls": [f"{n.display_name} #{n.req_seq}" for n in self.nodes],
            "bottleneck_score": self.bottleneck_score,
            "weakest_edge_id": self.weakest_edge_id,
            "source_labels": list(self.source_labels),
            "edges": [e.to_dict(expose_text=expose_text) for e in self.edges],
        }


def _matches_source_criteria(node: CallNode, source_label: str | None) -> bool:
    if source_label and source_label != "*":
        return any(
            fnmatch.fnmatchcase(lbl.casefold(), source_label.casefold())
            or source_label.casefold() in lbl.casefold()
            for lbl in node.labels
        )
    return node.role == "source" or len(node.labels) > 0


def find_hazardous_paths(
    graph: FlowGraph,
    source_label: str | None = None,
    sink_role: str = "sink",
    min_score: float = 0.35,
    max_depth: int = 8,
) -> list[HazardousPath]:
    """
    Enumerate all simple directed paths from labeled/source nodes to nodes with `role == sink_role`.
    Each path is scored by the minimum edge score along the path (the weakest link).
    """
    results: list[HazardousPath] = []
    source_nodes = [
        node
        for node in graph.nodes.values()
        if _matches_source_criteria(node, source_label)
    ]

    for start_node in source_nodes:
        stack: list[tuple[int, list[CallNode], list[CallEdge]]] = [
            (start_node.call_id, [start_node], [])
        ]
        while stack:
            curr_id, path_nodes, path_edges = stack.pop()
            curr_node = graph.nodes[curr_id]

            if path_edges and curr_node.role == sink_role:
                weakest = min(path_edges, key=lambda e: e.max_score)
                src_labels = list(start_node.labels)
                for edge in path_edges:
                    for ev in edge.evidences:
                        for lbl in ev.labels:
                            if lbl not in src_labels:
                                src_labels.append(lbl)
                results.append(
                    HazardousPath(
                        nodes=list(path_nodes),
                        edges=list(path_edges),
                        bottleneck_score=weakest.max_score,
                        weakest_edge_id=weakest.edge_id,
                        source_labels=src_labels or [f"role:{start_node.role}"],
                    )
                )

            if len(path_edges) >= max_depth:
                continue

            visited_ids = {n.call_id for n in path_nodes}
            for out_edge in graph.adjacency.get(curr_id, []):
                if out_edge.max_score < min_score:
                    continue
                if out_edge.dst_call_id in visited_ids:
                    continue
                next_node = graph.nodes.get(out_edge.dst_call_id)
                if next_node is None:
                    continue
                stack.append(
                    (
                        next_node.call_id,
                        path_nodes + [next_node],
                        path_edges + [out_edge],
                    )
                )

    results.sort(key=lambda p: (-p.bottleneck_score, len(p.edges), p.nodes[0].call_id))
    return results
