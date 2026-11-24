"""Transparent stdio pipe proxy that relays bytes unmodified while logging JSON-RPC frames asynchronously."""

from __future__ import annotations

import queue
import subprocess
import sys
import threading
import time
from typing import BinaryIO

from mcp_flow.proxy.jsonrpc import parse_jsonrpc_line
from mcp_flow.store.db import FlowStore


def _writer_worker(
    store: FlowStore,
    session_id: str,
    server_id: str,
    log_queue: queue.Queue[tuple[str, float, bytes] | None],
) -> None:
    """Background worker that persists captured JSON-RPC lines to SQLite without blocking I/O relay."""
    while True:
        item = log_queue.get()
        if item is None:
            log_queue.task_done()
            break
        direction, ts, raw_bytes = item
        try:
            text = raw_bytes.decode("utf-8", errors="replace")
            for msg in parse_jsonrpc_line(text):
                store.append_message(
                    session_id=session_id,
                    server_id=server_id,
                    direction=direction,
                    kind=msg.kind,
                    method=msg.method,
                    rpc_id=msg.rpc_id,
                    body=msg.raw_body,
                    ts=ts,
                )
        except Exception:
            # Passive observer must never crash the relay if logging fails
            pass
        finally:
            log_queue.task_done()


def _relay_stream(
    src: BinaryIO,
    dst: BinaryIO,
    direction: str,
    log_queue: queue.Queue[tuple[str, float, bytes] | None],
    close_dst_on_eof: bool = False,
) -> None:
    """Read lines from src, immediately write raw bytes to dst unmodified, and enqueue for logging."""
    try:
        while True:
            chunk = src.readline()
            if not chunk:
                break
            ts = time.time()
            dst.write(chunk)
            dst.flush()
            log_queue.put((direction, ts, chunk))
    except (BrokenPipeError, ValueError, OSError):
        pass
    finally:
        if close_dst_on_eof:
            try:
                dst.close()
            except Exception:
                pass


def run_stdio_proxy(
    command: list[str],
    store: FlowStore,
    session_id: str,
    server_name: str,
    server_id: str | None = None,
    client_in: BinaryIO | None = None,
    client_out: BinaryIO | None = None,
    client_name: str = "stdio-client",
) -> int:
    """
    Launch an MCP server command as a subprocess and relay stdin/stdout transparently.
    Every JSON-RPC message is recorded asynchronously into `store`.
    """
    if not command:
        raise ValueError("Server command cannot be empty")

    actual_server_id = server_id or f"{session_id}:{server_name}"
    store.ensure_session(session_id=session_id, client=client_name)
    store.register_server(
        server_id=actual_server_id,
        session_id=session_id,
        name=server_name,
        command=" ".join(command),
        transport="stdio",
    )

    in_stream = client_in if client_in is not None else sys.stdin.buffer
    out_stream = client_out if client_out is not None else sys.stdout.buffer

    proc = subprocess.Popen(
        command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=sys.stderr,
        bufsize=0,
    )
    assert proc.stdin is not None
    assert proc.stdout is not None

    log_queue: queue.Queue[tuple[str, float, bytes] | None] = queue.Queue()
    db_thread = threading.Thread(
        target=_writer_worker,
        args=(store, session_id, actual_server_id, log_queue),
        daemon=True,
    )
    db_thread.start()

    c2s_thread = threading.Thread(
        target=_relay_stream,
        args=(in_stream, proc.stdin, "c2s", log_queue, True),
        daemon=True,
    )
    s2c_thread = threading.Thread(
        target=_relay_stream,
        args=(proc.stdout, out_stream, "s2c", log_queue, False),
        daemon=True,
    )

    c2s_thread.start()
    s2c_thread.start()

    s2c_thread.join()
    proc.wait()
    c2s_thread.join(timeout=1.0)
    try:
        proc.stdout.close()
    except Exception:
        pass

    log_queue.put(None)
    log_queue.join()
    db_thread.join(timeout=2.0)

    return int(proc.returncode or 0)
