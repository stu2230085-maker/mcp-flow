"""Command-line interface (`mcp-flow`) implemented with standard library `argparse`."""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import sys
import tempfile
import uuid
from pathlib import Path

from mcp_flow.derive.calls import derive_calls
from mcp_flow.config_wrapper import unwrap_mcp_config, wrap_mcp_config
from mcp_flow.derive.fragments import derive_fragments
from mcp_flow.graph.builder import build_flow_graph
from mcp_flow.graph.exporters import format_cli_report, to_dot, to_json_dict, to_mermaid
from mcp_flow.graph.paths import find_hazardous_paths
from mcp_flow.interop.trace_io import export_otel_spans, import_trace_jsonl
from mcp_flow.labels.rules import LabelRuleEngine
from mcp_flow.match.cross_session import match_cross_session_taint
from mcp_flow.match.engine import FingerprintEngine
from mcp_flow.proxy.http_proxy import StreamableHttpProxyServer
from mcp_flow.proxy.stdio_proxy import run_stdio_proxy
from mcp_flow.server.mcp_server import run_stdio_mcp_server
from mcp_flow.store.db import FlowStore
from mcp_flow.store.redaction import RedactionPolicy


def _atomic_write_bytes(target: Path, data: bytes, mode: int) -> None:
    """Write *data* to a temp file in *target.parent* with *mode* and replace *target*."""
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{target.name}.", dir=target.parent)
    tmp_path = Path(tmp_name)
    try:
        os.chmod(fd, mode)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp_path, target)
    except BaseException:
        tmp_path.unlink(missing_ok=True)
        raise


def analyze_session(
    store: FlowStore,
    session_id: str,
    max_stage: int = 4,
    enable_semantic: bool = False,
    min_score: float = 0.35,
    rules_path: str | None = None,
    persist_labels: bool = False,
    cross_session: bool = False,
) -> None:
    """Recompute all derived data (`calls`, `fragments`, `flows`, `labels`) from immutable `messages`."""
    store.clear_derived_data(session_id)
    derive_calls(store, session_id)
    derive_fragments(store, session_id)
    engine = FingerprintEngine(
        max_stage=max_stage,
        enable_semantic=enable_semantic,
        min_score=min_score,
    )
    engine.run_on_session(store, session_id)
    rule_engine = (
        LabelRuleEngine.from_json_file(rules_path)
        if rules_path
        else LabelRuleEngine()
    )
    rule_engine.apply_to_session(
        store,
        session_id,
        persist_labels=persist_labels,
        prefer_rules=bool(rules_path),
    )
    if cross_session:
        match_cross_session_taint(store, session_id)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcp-flow",
        description="Passive data-flow tracer and dependency graph analyzer across multiple MCP servers.",
    )
    parser.add_argument(
        "--db",
        default="mcp_flow.db",
        help="Path to local SQLite database file (default: mcp_flow.db)",
    )

    sub = parser.add_subparsers(dest="subcommand", required=True)

    # 1. proxy
    p_proxy = sub.add_parser("proxy", help="Run transparent MCP stdio or Streamable HTTP proxy")
    p_proxy.add_argument("--session", required=True, help="Session ID to record under")
    p_proxy.add_argument("--server", required=True, help="Logical MCP server name (e.g. docs, mail, http)")
    p_proxy.add_argument("--transport", choices=["stdio", "http"], default="stdio")
    p_proxy.add_argument("--target-url", help="Upstream URL when --transport=http")
    p_proxy.add_argument("--port", type=int, default=8765, help="Listen port when --transport=http")
    p_proxy.add_argument("--hash-only", action="store_true", help="Store only fragment hashes/lengths on derivation")
    p_proxy.add_argument("--redact-pattern", action="append", default=[], help="Regex pattern to redact before storing")
    p_proxy.add_argument("command", nargs=argparse.REMAINDER, help="Target MCP server command (after --)")

    # 2. analyze
    p_analyze = sub.add_parser("analyze", help="Recompute calls, fragments, flows, and labels from raw messages")
    p_analyze.add_argument("session", help="Session ID to analyze")
    p_analyze.add_argument("--max-stage", type=int, default=4, choices=[1, 2, 3, 4, 5])
    p_analyze.add_argument("--enable-semantic", action="store_true", help="Enable Stage 5 semantic similarity")
    p_analyze.add_argument("--min-score", type=float, default=0.35)
    p_analyze.add_argument("--rules", help="Optional JSON rules file for tool roles and labels")
    p_analyze.add_argument(
        "--persist-labels",
        action="store_true",
        help="Record hash-only fingerprints of sensitive output fragments for cross-session tracking",
    )
    p_analyze.add_argument(
        "--cross-session",
        action="store_true",
        help="Match input fragments against persistent fingerprints from earlier sessions",
    )
    p_analyze.add_argument(
        "--hash-only",
        action="store_true",
        help="Store only fragment hashes and lengths during derivation (omitting plaintext text)",
    )

    # 3. report
    p_report = sub.add_parser("report", help="Detect and report hazardous paths from confidential sources to sinks")
    p_report.add_argument("session", help="Session ID to report on")
    p_report.add_argument("--source-label", default="*", help="Filter by source label pattern (default: *)")
    p_report.add_argument("--sink-role", default="sink", help="Target sink role (default: sink)")
    p_report.add_argument("--min-score", type=float, default=0.35)
    p_report.add_argument("--format", choices=["text", "json"], default="text")
    p_report.add_argument("--expose-text", action="store_true", help="Include raw fragment text snippets in output")
    p_report.add_argument("--recompute", action="store_true", help="Force recomputation before reporting")
    p_report.add_argument(
        "--cross-session",
        action="store_true",
        help="Enable cross-session taint matching when recomputing",
    )

    # 4. graph
    p_graph = sub.add_parser("graph", help="Export call-level data dependency graph as Mermaid, DOT, or JSON")
    p_graph.add_argument("session", help="Session ID")
    p_graph.add_argument("--format", choices=["mermaid", "dot", "json"], default="mermaid")
    p_graph.add_argument("--min-score", type=float, default=0.35)
    p_graph.add_argument("--expose-text", action="store_true")
    p_graph.add_argument("--out", help="Write output to file instead of stdout")

    # 5. label
    p_label = sub.add_parser("label", help="Manually attach a confidentiality label or tool role")
    p_label.add_argument("--target-kind", choices=["call", "fragment"], default="call")
    p_label.add_argument("--target-id", type=int, required=True)
    p_label.add_argument("--label", required=True, help="Label string (e.g. confidential:manual)")

    # 6. export
    p_export = sub.add_parser("export", help="Export session messages as JSONL or derived spans as OpenTelemetry JSON")
    p_export.add_argument("session", help="Session ID")
    p_export.add_argument("--format", choices=["jsonl", "otel"], default="jsonl")
    p_export.add_argument("--out", help="Output file path")

    # 6b. import
    p_import = sub.add_parser("import", help="Import JSONL or mcptape-compatible trace recordings into raw messages")
    p_import.add_argument("jsonl_file", help="Path to JSONL trace file")
    p_import.add_argument("--session", help="Override session ID for imported messages")

    # 7. serve-mcp
    p_serve = sub.add_parser("serve-mcp", help="Run read-only MCP inspection server over stdio")
    p_serve.add_argument(
        "--expose-text",
        action="store_true",
        help="Explicitly allow returning fragment text in MCP tool responses (disabled by default)",
    )

    # 8. evaluate
    p_eval = sub.add_parser("evaluate", help="Run synthetic scenarios and report stage-by-stage Precision/Recall/FPR")
    p_eval.add_argument("--format", choices=["text", "json"], default="text")

    # 9. wrap-config
    p_wrap = sub.add_parser(
        "wrap-config", help="Wrap MCP client server commands with the recording proxy"
    )
    p_wrap.add_argument("config_json_path", help="MCP client JSON configuration file")
    p_wrap.add_argument("--session", help="Session ID (generated when omitted)")
    p_wrap.add_argument("--db", dest="config_db", default=None, help="Local SQLite database path")
    p_wrap.add_argument("--servers", help="Comma-separated MCP server names to target")
    p_wrap.add_argument("--unwrap", action="store_true", help="Restore original commands")
    p_wrap.add_argument("--dry-run", action="store_true", help="Print transformed JSON without writing")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.subcommand == "evaluate":
        from scenarios.synthetic_suite import format_evaluation_report, run_full_evaluation

        metrics = run_full_evaluation()
        if args.format == "json":
            print(json.dumps(metrics, indent=2, ensure_ascii=False))
        else:
            print(format_evaluation_report(metrics), end="")
        return 0

    if args.subcommand == "wrap-config":
        path = Path(args.config_json_path)
        try:
            original_bytes = path.read_bytes()
            config = json.loads(original_bytes.decode("utf-8"))
            if not isinstance(config, dict):
                raise ValueError("Configuration root must be a JSON object")
            selected = (
                [name.strip() for name in args.servers.split(",") if name.strip()]
                if args.servers is not None
                else None
            )
            db_path = args.config_db if args.config_db is not None else args.db
            if args.unwrap:
                transformed = unwrap_mcp_config(config, servers=selected)
            else:
                transformed = wrap_mcp_config(
                    config,
                    session_id=args.session or uuid.uuid4().hex,
                    db_path=db_path,
                    servers=selected,
                )
            rendered = json.dumps(transformed, indent=2, ensure_ascii=False) + "\n"
            if args.dry_run:
                sys.stdout.write(rendered)
                return 0
            if transformed == config:
                print("Configuration unchanged.")
                return 0
            backup = Path(str(path) + ".bak")
            _atomic_write_bytes(backup, original_bytes, 0o600)
            target_mode = stat.S_IMODE(path.stat().st_mode) or 0o600
            _atomic_write_bytes(path, rendered.encode("utf-8"), target_mode)
            print(f"Updated {path}; backup: {backup}")
            return 0
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
            print(f"mcp-flow wrap-config: {exc}", file=sys.stderr)
            return 2

    try:
        redaction = RedactionPolicy.from_regex_strings(
            getattr(args, "redact_pattern", []),
            hash_only=getattr(args, "hash_only", False),
        )
    except re.error as exc:
        print(f"mcp-flow: invalid --redact-pattern regex: {exc}", file=sys.stderr)
        return 2
    store = FlowStore(db_path=args.db, redaction_policy=redaction)
    try:
        if args.subcommand == "proxy":
            if args.transport == "http":
                if not args.target_url:
                    parser.error("--target-url is required when --transport=http")
                srv = StreamableHttpProxyServer(
                    target_url=args.target_url,
                    store=store,
                    session_id=args.session,
                    server_name=args.server,
                    port=args.port,
                )
                srv.serve_forever()
                return 0

            cmd = list(args.command)
            if cmd and cmd[0] == "--":
                cmd = cmd[1:]
            if not cmd:
                parser.error("Proxy target command is required after '--'")
            return run_stdio_proxy(
                command=cmd,
                store=store,
                session_id=args.session,
                server_name=args.server,
            )

        if args.subcommand == "analyze":
            try:
                analyze_session(
                    store=store,
                    session_id=args.session,
                    max_stage=args.max_stage,
                    enable_semantic=args.enable_semantic,
                    min_score=args.min_score,
                    rules_path=args.rules,
                    persist_labels=args.persist_labels,
                    cross_session=args.cross_session,
                )
            except (OSError, ValueError, json.JSONDecodeError) as exc:
                print(f"mcp-flow analyze: {exc}", file=sys.stderr)
                return 2
            calls = store.get_calls(args.session)
            frags = store.get_fragments(args.session)
            flows = store.get_flows(args.session)
            print(
                f"Analyzed session '{args.session}': {len(calls)} calls, "
                f"{len(frags)} fragments, {len(flows)} flow edges."
            )
            return 0

        if args.subcommand == "report":
            if args.recompute or not store.get_calls(args.session):
                analyze_session(
                    store,
                    args.session,
                    min_score=args.min_score,
                    cross_session=args.cross_session,
                )
            elif args.cross_session:
                match_cross_session_taint(store, args.session)
            graph = build_flow_graph(store, args.session, min_score=args.min_score)
            paths = find_hazardous_paths(
                graph,
                source_label=args.source_label,
                sink_role=args.sink_role,
                min_score=args.min_score,
            )
            if args.format == "json":
                print(
                    json.dumps(
                        to_json_dict(graph, paths=paths, expose_text=args.expose_text),
                        indent=2,
                        ensure_ascii=False,
                    )
                )
            else:
                print(format_cli_report(graph, paths, expose_text=args.expose_text), end="")
            return 0

        if args.subcommand == "graph":
            if not store.get_calls(args.session):
                analyze_session(store, args.session, min_score=args.min_score)
            graph = build_flow_graph(store, args.session, min_score=args.min_score)
            if args.format == "mermaid":
                rendered = to_mermaid(graph, min_score=args.min_score)
            elif args.format == "dot":
                rendered = to_dot(graph, min_score=args.min_score)
            else:
                paths = find_hazardous_paths(graph, min_score=args.min_score)
                rendered = (
                    json.dumps(
                        to_json_dict(graph, paths=paths, expose_text=args.expose_text),
                        indent=2,
                        ensure_ascii=False,
                    )
                    + "\n"
                )
            if args.out:
                _atomic_write_bytes(Path(args.out), rendered.encode("utf-8"), 0o600)
            else:
                sys.stdout.write(rendered)
            return 0

        if args.subcommand == "label":
            lid = store.insert_label(
                target_kind=args.target_kind,
                target_id=args.target_id,
                label=args.label,
                source="manual",
            )
            print(f"Added manual label #{lid}: {args.target_kind}:{args.target_id} -> {args.label}")
            return 0

        if args.subcommand == "export":
            if args.format == "otel":
                if not store.get_calls(args.session):
                    analyze_session(store, args.session)
                rendered = (
                    json.dumps(
                        export_otel_spans(store, args.session),
                        indent=2,
                        ensure_ascii=False,
                    )
                    + "\n"
                )
            else:
                rendered = store.export_messages_jsonl(args.session)
            if args.out:
                _atomic_write_bytes(Path(args.out), rendered.encode("utf-8"), 0o600)
            else:
                sys.stdout.write(rendered)
            return 0

        if args.subcommand == "import":
            try:
                result = import_trace_jsonl(
                    store,
                    args.jsonl_file,
                    session_id=args.session,
                )
            except (OSError, ValueError, json.JSONDecodeError) as exc:
                print(f"mcp-flow import: {exc}", file=sys.stderr)
                return 2
            print(
                f"Imported {result.imported_messages} messages into session '{result.session_id}' "
                f"(servers: {', '.join(result.servers) or 'none'})."
            )
            return 0

        if args.subcommand == "serve-mcp":
            run_stdio_mcp_server(store=store, expose_text=args.expose_text)
            return 0

        return 1
    finally:
        store.close()
