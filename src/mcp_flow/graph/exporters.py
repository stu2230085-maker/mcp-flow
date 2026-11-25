"""Exporters for Mermaid, Graphviz DOT, JSON, and human-readable CLI reports."""

from __future__ import annotations

from typing import Any

from mcp_flow.graph.builder import OBSERVATION_DISCLAIMER, FlowGraph
from mcp_flow.graph.paths import HazardousPath


def to_mermaid(graph: FlowGraph, min_score: float = 0.0) -> str:
    """
    Render the call flow graph in Mermaid `graph LR` syntax.
    Matches the design document format:
      graph LR
        c1["docs.read_file #12"] -->|substring 0.92| c2["summarize.run #14"]
    """
    lines: list[str] = [
        f"%% {OBSERVATION_DISCLAIMER}",
        "graph LR",
    ]
    for cid in sorted(graph.nodes.keys()):
        node = graph.nodes[cid]
        label_suffix = f" [{','.join(node.labels)}]" if node.labels else ""
        safe_title = f"{node.display_name} #{node.req_seq}{label_suffix}".replace('"', "'")
        lines.append(f'  c{cid}["{safe_title}"]')

    for edge in graph.edges:
        if edge.max_score < min_score:
            continue
        extra = f" x{edge.match_count}" if edge.match_count > 1 else ""
        edge_label = f"{edge.primary_kind} {edge.max_score:.2f}{extra}"
        lines.append(f"  c{edge.src_call_id} -->|{edge_label}| c{edge.dst_call_id}")

    return "\n".join(lines) + "\n"


def to_dot(graph: FlowGraph, min_score: float = 0.0) -> str:
    """Render the call flow graph in Graphviz DOT syntax."""
    lines: list[str] = [
        f"// {OBSERVATION_DISCLAIMER}",
        "digraph mcp_flow {",
        "  rankdir=LR;",
        '  node [shape=box, style="rounded"];',
    ]
    for cid in sorted(graph.nodes.keys()):
        node = graph.nodes[cid]
        role_color = {
            "source": "#ffe0b2",
            "sink": "#ffcdd2",
            "neutral": "#e3f2fd",
        }.get(node.role, "#ffffff")
        safe_title = f"{node.display_name} #{node.req_seq}".replace('"', '\\"')
        lines.append(
            f'  c{cid} [label="{safe_title}\\nrole={node.role}", style="rounded,filled", fillcolor="{role_color}"];'
        )
    for edge in graph.edges:
        if edge.max_score < min_score:
            continue
        label = f"{edge.primary_kind} ({edge.max_score:.2f}, n={edge.match_count})"
        lines.append(f'  c{edge.src_call_id} -> c{edge.dst_call_id} [label="{label}"];')
    lines.append("}")
    return "\n".join(lines) + "\n"


def to_json_dict(
    graph: FlowGraph,
    paths: list[HazardousPath] | None = None,
    expose_text: bool = False,
) -> dict[str, Any]:
    """Serialize the flow graph and optional hazardous paths into a JSON-compatible dictionary."""
    return {
        "session_id": graph.session_id,
        "disclaimer": graph.disclaimer,
        "nodes": [
            {
                "call_id": n.call_id,
                "server_id": n.server_id,
                "server_name": n.server_name,
                "tool": n.tool,
                "display_name": n.display_name,
                "req_seq": n.req_seq,
                "res_seq": n.res_seq,
                "role": n.role,
                "labels": list(n.labels),
                "is_error": n.is_error,
            }
            for n in sorted(graph.nodes.values(), key=lambda x: x.call_id)
        ],
        "edges": [e.to_dict(expose_text=expose_text) for e in graph.edges],
        "hazardous_paths": [p.to_dict(expose_text=expose_text) for p in (paths or [])],
    }


def format_cli_report(
    graph: FlowGraph,
    paths: list[HazardousPath],
    expose_text: bool = False,
) -> str:
    """Format a human-readable CLI report listing hazardous paths and supporting evidence."""
    lines: list[str] = [
        f"=== MCP Data Flow Report (session: {graph.session_id}) ===",
        OBSERVATION_DISCLAIMER,
        f"Calls: {len(graph.nodes)} | Observed Flow Edges: {len(graph.edges)} | Hazardous Paths: {len(paths)}",
        "",
    ]

    if not paths:
        lines.append("No hazardous paths from labeled sources to external sinks were detected.")
        return "\n".join(lines) + "\n"

    for idx, hp in enumerate(paths, start=1):
        chain = " -> ".join(f"{n.display_name} #{n.req_seq}" for n in hp.nodes)
        lines.append(
            f"[Path #{idx}] bottleneck_score={hp.bottleneck_score:.2f} "
            f"(weakest={hp.weakest_edge_id}) labels={','.join(hp.source_labels)}"
        )
        lines.append(f"  Route: {chain}")
        if not hp.edges and any(lbl.startswith("cross_session:") for lbl in hp.source_labels):
            lines.append(
                "  Provenance: cross-session taint matched input fragment(s) from earlier session(s)"
            )
        for edge in hp.edges:
            src_node = graph.nodes[edge.src_call_id]
            dst_node = graph.nodes[edge.dst_call_id]
            lines.append(
                f"  Edge {edge.edge_id}: {src_node.display_name} #{src_node.req_seq} "
                f"--> {dst_node.display_name} #{dst_node.req_seq} "
                f"[{edge.primary_kind}, max_score={edge.max_score:.2f}, matches={edge.match_count}]"
            )
            for ev in edge.evidences[:3]:
                base_ev = (
                    f"    Evidence flow#{ev.flow_id}: out({ev.src_json_path} span={ev.src_span} len={ev.src_len} "
                    f"sha256={ev.src_hash[:12]}...) -> in({ev.dst_json_path} span={ev.dst_span} len={ev.dst_len} "
                    f"sha256={ev.dst_hash[:12]}...) [{ev.kind} score={ev.score:.2f}]"
                )
                lines.append(base_ev)
                if expose_text and (ev.src_text or ev.dst_text):
                    lines.append(f"      src_text: {ev.src_text[:80]!r}")
                    lines.append(f"      dst_text: {ev.dst_text[:80]!r}")
        lines.append("")

    return "\n".join(lines) + "\n"
