"""Graph traversal for detecting hazardous data flow paths from labeled sources to external sinks."""

from __future__ import annotations

import fnmatch
import heapq
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


def _label_matches_pattern(lbl: str, pattern: str) -> bool:
    pat = pattern.casefold()
    lbl_cf = lbl.casefold()
    if fnmatch.fnmatchcase(lbl_cf, pat) or pat in lbl_cf:
        return True
    if lbl.startswith("cross_session:"):
        parts = lbl.split(":", 2)
        if len(parts) == 3:
            orig_cf = parts[2].casefold()
            if fnmatch.fnmatchcase(orig_cf, pat) or pat in orig_cf:
                return True
    return False


def _matches_source_criteria(node: CallNode, source_label: str | None) -> bool:
    if source_label and source_label != "*":
        return any(_label_matches_pattern(lbl, source_label) for lbl in node.labels)
    return node.role == "source" or len(node.labels) > 0


def find_hazardous_paths(
    graph: FlowGraph,
    source_label: str | None = None,
    sink_role: str = "sink",
    min_score: float = 0.35,
    max_depth: int = 8,
    max_paths: int = 500,
) -> list[HazardousPath]:
    """
    Enumerate simple directed paths from labeled/source nodes to nodes with `role == sink_role`.
    Each path is scored by the minimum edge score along the path (the weakest link).
    Uses best-first search ordered by bottleneck score and caps output at `max_paths`
    (pass `max_paths <= 0` for unlimited) to stay resilient on dense graphs.
    """
    results: list[HazardousPath] = []
    source_nodes = sorted(
        (
            node
            for node in graph.nodes.values()
            if _matches_source_criteria(node, source_label)
        ),
        key=lambda n: n.call_id,
    )

    heap: list[tuple[float, int, int, int, list[CallNode], list[CallEdge]]] = []
    counter = 0

    for start_node in source_nodes:
        cross_session_labels = [
            lbl
            for lbl in start_node.labels
            if lbl.startswith("cross_session:")
            and (not source_label or source_label == "*" or _label_matches_pattern(lbl, source_label))
        ]
        if start_node.role == sink_role and cross_session_labels and 1.0 >= min_score:
            results.append(
                HazardousPath(
                    nodes=[start_node],
                    edges=[],
                    bottleneck_score=1.0,
                    weakest_edge_id="cross_session",
                    source_labels=cross_session_labels,
                )
            )
            if max_paths > 0 and len(results) >= max_paths:
                break

        counter += 1
        heapq.heappush(heap, (-1.0, 0, start_node.call_id, counter, [start_node], []))

    max_expansions = max(max_paths * 20, 10_000) if max_paths > 0 else 0
    expansions = 0

    while heap:
        if max_paths > 0 and len(results) >= max_paths:
            break
        if max_expansions > 0 and expansions >= max_expansions:
            break

        neg_bottleneck, depth, start_cid, _, path_nodes, path_edges = heapq.heappop(heap)
        expansions += 1
        start_node = path_nodes[0]
        curr_node = path_nodes[-1]

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
            if max_paths > 0 and len(results) >= max_paths:
                break

        if depth >= max_depth:
            continue

        visited_ids = {n.call_id for n in path_nodes}
        for out_edge in graph.adjacency.get(curr_node.call_id, []):
            if out_edge.max_score < min_score:
                continue
            if out_edge.dst_call_id in visited_ids:
                continue
            next_node = graph.nodes.get(out_edge.dst_call_id)
            if next_node is None:
                continue
            next_bottleneck = out_edge.max_score if not path_edges else min(-neg_bottleneck, out_edge.max_score)
            counter += 1
            heapq.heappush(
                heap,
                (
                    -next_bottleneck,
                    depth + 1,
                    start_cid,
                    counter,
                    path_nodes + [next_node],
                    path_edges + [out_edge],
                ),
            )

    results.sort(key=lambda p: (-p.bottleneck_score, len(p.edges), p.nodes[0].call_id))
    return results
