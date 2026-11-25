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


DEFAULT_BATCH_SIZE = 64


def _write_all(dst: BinaryIO, data: bytes) -> None:
    """Write all bytes in `data` to `dst`, handling partial writes on unbuffered streams."""
    view = memoryview(data)
    written = 0
    total = len(view)
    while written < total:
        n = dst.write(view[written:])
        if n is None or n == 0:
            break
        written += n
    dst.flush()


def _writer_worker(
    store: FlowStore,
    session_id: str,
    server_id: str,
    log_queue: queue.Queue[tuple[str, float, bytes] | None],
    batch_size: int = DEFAULT_BATCH_SIZE,
) -> None:
    """Background worker that persists captured JSON-RPC lines in batches without blocking I/O relay."""
    effective_batch_size = max(1, batch_size)
    while True:
        first_item = log_queue.get()
        if first_item is None:
            log_queue.task_done()
            break

        raw_batch: list[tuple[str, float, bytes]] = [first_item]
        stop_after_batch = False

        while len(raw_batch) < effective_batch_size:
            try:
                next_item = log_queue.get_nowait()
            except queue.Empty:
                break
            if next_item is None:
                stop_after_batch = True
                break
            raw_batch.append(next_item)

        try:
            records: list[tuple[str, str, str, str, str | None, str | None, str, float]] = []
            for direction, ts, raw_bytes in raw_batch:
                try:
                    text = raw_bytes.decode("utf-8", errors="replace")
                    for msg in parse_jsonrpc_line(text):
                        records.append(
                            (
                                session_id,
                                server_id,
                                direction,
                                msg.kind,
                                msg.method,
                                msg.rpc_id,
                                msg.raw_body,
                                ts,
                            )
                        )
                except Exception:
                    # Passive observer must never crash the relay if a single frame fails to parse
                    continue

            if records:
                store.append_messages_batch(records)
        except Exception:
            # Passive observer must never crash the relay if logging fails
            pass
        finally:
            for _ in raw_batch:
                log_queue.task_done()
            if stop_after_batch:
                log_queue.task_done()

        if stop_after_batch:
            break


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
            _write_all(dst, chunk)
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
    batch_size: int = DEFAULT_BATCH_SIZE,
) -> int:
    """
    Launch an MCP server command as a subprocess and relay stdin/stdout transparently.
    Every JSON-RPC message is recorded asynchronously into `store` in batched SQLite transactions.
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
        bufsize=-1,
    )
    assert proc.stdin is not None
    assert proc.stdout is not None

    log_queue: queue.Queue[tuple[str, float, bytes] | None] = queue.Queue()
    db_thread = threading.Thread(
        target=_writer_worker,
        args=(store, session_id, actual_server_id, log_queue, batch_size),
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
