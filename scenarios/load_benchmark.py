"""
High-throughput & large-payload (1MB+ JSON-RPC frame) latency benchmark for mcp-flow stdio proxy.

Measures:
1. Large-payload relay fidelity and latency (1MB+ single-line JSON-RPC frames).
2. High-frequency burst throughput (200+ rapid back-to-back tool calls) comparing
   direct subprocess execution, single-row SQLite commits (batch_size=1), and
   batched SQLite transactions (batch_size=64).

Run standalone:
    PYTHONPATH=src:. python3 scenarios/load_benchmark.py
"""

from __future__ import annotations

import io
import json
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

from mcp_flow.proxy.stdio_proxy import DEFAULT_BATCH_SIZE, run_stdio_proxy
from mcp_flow.store.db import FlowStore


@dataclass(frozen=True)
class LargePayloadBenchmarkResult:
    """Measured metrics for multi-megabyte JSON-RPC frame relay."""

    payload_bytes: int
    num_frames: int
    direct_ms: float
    proxied_ms: float
    overhead_ms: float
    total_relayed_bytes: int
    throughput_mb_s: float
    recorded_messages: int
    expected_messages: int
    byte_exact: bool


@dataclass(frozen=True)
class BurstBenchmarkResult:
    """Measured metrics for rapid back-to-back tool call bursts."""

    num_calls: int
    batch_size: int
    direct_ms: float
    proxied_single_ms: float
    proxied_batched_ms: float
    batch_speedup: float
    calls_per_sec: float
    recorded_messages: int
    expected_messages: int
    byte_exact: bool


def serve_echo_mcp() -> None:
    """Minimal deterministic stdio MCP server for load and large-payload benchmarks."""
    reader = sys.stdin.buffer
    writer = sys.stdout.buffer

    while True:
        raw_line = reader.readline()
        if not raw_line:
            break
        stripped = raw_line.strip()
        if not stripped:
            continue
        try:
            msg = json.loads(stripped.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            continue
        if not isinstance(msg, dict):
            continue

        rpc_id = msg.get("id")
        method = msg.get("method")
        if rpc_id is None:
            continue

        if method == "initialize":
            resp = {
                "jsonrpc": "2.0",
                "id": rpc_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "load-bench-echo", "version": "0.1.0"},
                },
            }
        elif method == "tools/call":
            params = msg.get("params") or {}
            tool_name = str(params.get("name", ""))
            args = params.get("arguments") or {}
            if tool_name == "echo_blob":
                text = str(args.get("payload", ""))
            elif tool_name == "generate_blob":
                size = int(args.get("size_bytes", 1048576))
                marker = str(args.get("marker", "M"))
                text = f"{marker}:" + ("A" * max(0, size - len(marker) - 1))
            else:
                text = f"ok:{rpc_id}:{tool_name}"
            resp = {
                "jsonrpc": "2.0",
                "id": rpc_id,
                "result": {
                    "content": [{"type": "text", "text": text}],
                    "isError": False,
                },
            }
        else:
            resp = {"jsonrpc": "2.0", "id": rpc_id, "result": {}}

        out_bytes = (json.dumps(resp, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
        writer.write(out_bytes)
        writer.flush()


def _echo_server_command() -> list[str]:
    return [sys.executable, str(Path(__file__).resolve()), "--echo-server"]


def _run_direct(command: list[str], input_bytes: bytes) -> tuple[bytes, float]:
    """Run the server subprocess directly without the proxy and return (stdout_bytes, elapsed_ms)."""
    t0 = time.perf_counter()
    proc = subprocess.run(
        command,
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    )
    elapsed_ms = (time.perf_counter() - t0) * 1000.0
    return proc.stdout, elapsed_ms


def build_large_payload_requests(payload_bytes: int = 1_048_576, num_frames: int = 3) -> bytes:
    """Build newline-delimited JSON-RPC requests each carrying a `payload_bytes` string."""
    lines: list[str] = []
    # Deterministic non-trivial repeating pattern with unique per-frame boundary markers
    base_chunk = "0123456789abcdef-mcp-flow-payload-" * 32
    for idx in range(1, num_frames + 1):
        prefix = f"FRAME_{idx}_START|"
        suffix = f"|FRAME_{idx}_END"
        fill_len = max(0, payload_bytes - len(prefix) - len(suffix))
        repeats = (fill_len // len(base_chunk)) + 1
        blob = prefix + (base_chunk * repeats)[:fill_len] + suffix
        req = {
            "jsonrpc": "2.0",
            "id": idx,
            "method": "tools/call",
            "params": {
                "name": "echo_blob",
                "arguments": {"payload": blob},
            },
        }
        lines.append(json.dumps(req, ensure_ascii=False, separators=(",", ":")))
    return ("\n".join(lines) + "\n").encode("utf-8")


def build_burst_requests(num_calls: int = 250) -> bytes:
    """Build `num_calls` rapid back-to-back JSON-RPC `tools/call` lines."""
    lines: list[str] = []
    for idx in range(1, num_calls + 1):
        req = {
            "jsonrpc": "2.0",
            "id": idx,
            "method": "tools/call",
            "params": {
                "name": "ping_burst",
                "arguments": {"seq": idx, "tag": f"burst_item_{idx:04d}"},
            },
        }
        lines.append(json.dumps(req, ensure_ascii=False, separators=(",", ":")))
    return ("\n".join(lines) + "\n").encode("utf-8")


def run_large_payload_benchmark(
    payload_bytes: int = 1_048_576,
    num_frames: int = 3,
    batch_size: int = DEFAULT_BATCH_SIZE,
) -> LargePayloadBenchmarkResult:
    """Benchmark relaying `num_frames` 1MB+ JSON-RPC frames through `run_stdio_proxy`."""
    cmd = _echo_server_command()
    input_bytes = build_large_payload_requests(payload_bytes=payload_bytes, num_frames=num_frames)
    direct_out, direct_ms = _run_direct(cmd, input_bytes)

    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "large_payload.db"
        store = FlowStore(db_path=db_path)
        try:
            client_in = io.BytesIO(input_bytes)
            client_out = io.BytesIO()
            t0 = time.perf_counter()
            rc = run_stdio_proxy(
                command=cmd,
                store=store,
                session_id="bench_large_payload",
                server_name="echo",
                client_in=client_in,
                client_out=client_out,
                batch_size=batch_size,
            )
            proxied_ms = (time.perf_counter() - t0) * 1000.0
            if rc != 0:
                raise RuntimeError(f"Proxy exited with non-zero code {rc}")
            proxied_out = client_out.getvalue()
            recorded = len(store.get_messages("bench_large_payload"))
        finally:
            store.close()

    total_bytes = len(input_bytes) + len(proxied_out)
    throughput_mb_s = (total_bytes / (1024 * 1024)) / max(proxied_ms / 1000.0, 1e-9)
    return LargePayloadBenchmarkResult(
        payload_bytes=payload_bytes,
        num_frames=num_frames,
        direct_ms=direct_ms,
        proxied_ms=proxied_ms,
        overhead_ms=proxied_ms - direct_ms,
        total_relayed_bytes=total_bytes,
        throughput_mb_s=throughput_mb_s,
        recorded_messages=recorded,
        expected_messages=num_frames * 2,
        byte_exact=(proxied_out == direct_out),
    )


def run_burst_throughput_benchmark(
    num_calls: int = 250,
    batch_size: int = DEFAULT_BATCH_SIZE,
) -> BurstBenchmarkResult:
    """Benchmark `num_calls` rapid back-to-back calls comparing single-row vs batched SQLite writes."""
    cmd = _echo_server_command()
    input_bytes = build_burst_requests(num_calls=num_calls)
    direct_out, direct_ms = _run_direct(cmd, input_bytes)

    with tempfile.TemporaryDirectory() as tmpdir:
        # 1. Single-row commits (batch_size=1)
        db_single = Path(tmpdir) / "burst_single.db"
        store_single = FlowStore(db_path=db_single)
        try:
            out_single = io.BytesIO()
            t0 = time.perf_counter()
            rc_s = run_stdio_proxy(
                command=cmd,
                store=store_single,
                session_id="bench_burst_single",
                server_name="echo",
                client_in=io.BytesIO(input_bytes),
                client_out=out_single,
                batch_size=1,
            )
            proxied_single_ms = (time.perf_counter() - t0) * 1000.0
            if rc_s != 0:
                raise RuntimeError(f"Single-row proxy exited with code {rc_s}")
        finally:
            store_single.close()

        # 2. Batched commits (batch_size=64 by default)
        db_batched = Path(tmpdir) / "burst_batched.db"
        store_batched = FlowStore(db_path=db_batched)
        try:
            out_batched = io.BytesIO()
            t0 = time.perf_counter()
            rc_b = run_stdio_proxy(
                command=cmd,
                store=store_batched,
                session_id="bench_burst_batched",
                server_name="echo",
                client_in=io.BytesIO(input_bytes),
                client_out=out_batched,
                batch_size=batch_size,
            )
            proxied_batched_ms = (time.perf_counter() - t0) * 1000.0
            if rc_b != 0:
                raise RuntimeError(f"Batched proxy exited with code {rc_b}")
            recorded = len(store_batched.get_messages("bench_burst_batched"))
            batched_bytes = out_batched.getvalue()
        finally:
            store_batched.close()

    speedup = proxied_single_ms / max(proxied_batched_ms, 1e-9)
    calls_per_sec = num_calls / max(proxied_batched_ms / 1000.0, 1e-9)
    return BurstBenchmarkResult(
        num_calls=num_calls,
        batch_size=batch_size,
        direct_ms=direct_ms,
        proxied_single_ms=proxied_single_ms,
        proxied_batched_ms=proxied_batched_ms,
        batch_speedup=speedup,
        calls_per_sec=calls_per_sec,
        recorded_messages=recorded,
        expected_messages=num_calls * 2,
        byte_exact=(batched_bytes == direct_out),
    )


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    if "--echo-server" in args:
        serve_echo_mcp()
        return 0

    large = run_large_payload_benchmark()
    burst = run_burst_throughput_benchmark()

    print("=== mcp-flow Stdio Proxy Load & Large-Payload Benchmark ===")
    print(
        f"[Large Payload] {large.num_frames} x {large.payload_bytes / (1024 * 1024):.2f} MiB frames | "
        f"direct={large.direct_ms:.1f}ms | proxied={large.proxied_ms:.1f}ms | "
        f"overhead={large.overhead_ms:+.1f}ms | throughput={large.throughput_mb_s:.1f} MiB/s | "
        f"recorded={large.recorded_messages}/{large.expected_messages} | byte_exact={large.byte_exact}"
    )
    print(
        f"[Burst Calls]   {burst.num_calls} rapid calls (batch_size={burst.batch_size}) | "
        f"direct={burst.direct_ms:.1f}ms | single_tx={burst.proxied_single_ms:.1f}ms | "
        f"batched_tx={burst.proxied_batched_ms:.1f}ms | speedup={burst.batch_speedup:.2f}x | "
        f"rate={burst.calls_per_sec:.0f} calls/s | "
        f"recorded={burst.recorded_messages}/{burst.expected_messages} | byte_exact={burst.byte_exact}"
    )
    return 0 if (large.byte_exact and burst.byte_exact) else 1


if __name__ == "__main__":
    raise SystemExit(main())
