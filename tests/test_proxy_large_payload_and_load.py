"""Stress and unit tests for batched SQLite writes, 1MB+ JSON-RPC frames, and high-frequency bursts."""

from __future__ import annotations

import io
import json
import os
import queue
import stat
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from mcp_flow.derive.calls import derive_calls
from mcp_flow.proxy.stdio_proxy import _writer_worker, run_stdio_proxy
from mcp_flow.store.db import FlowStore
from mcp_flow.store.redaction import RedactionPolicy
from scenarios.load_benchmark import (
    _echo_server_command,
    _run_direct,
    build_burst_requests,
    build_large_payload_requests,
    run_burst_throughput_benchmark,
    run_large_payload_benchmark,
)


class TestProxyLargePayloadAndLoad(unittest.TestCase):
    """Verify batched SQLite logging, 1MB+ payload integrity, and high-throughput burst handling."""

    def test_append_messages_batch_single_transaction_and_redaction(self) -> None:
        """append_messages_batch must support dicts/tuples, redact bodies, validate atomically, and handle empty input."""
        policy = RedactionPolicy.from_regex_strings([r"SECRET_[0-9]+"])
        store = FlowStore(db_path=":memory:", redaction_policy=policy)
        try:
            store.ensure_session("s_batch")
            store.register_server("s_batch:echo", "s_batch", "echo")

            self.assertEqual(store.append_messages_batch([]), 0)

            inserted = store.append_messages_batch(
                [
                    (
                        "s_batch",
                        "s_batch:echo",
                        "c2s",
                        "request",
                        "tools/call",
                        "1",
                        '{"jsonrpc":"2.0","id":"1","method":"tools/call","params":{"name":"a","arguments":{"k":"SECRET_111"}}}',
                        100.0,
                    ),
                    {
                        "session_id": "s_batch",
                        "server_id": "s_batch:echo",
                        "direction": "s2c",
                        "kind": "response",
                        "method": None,
                        "rpc_id": "1",
                        "body": '{"jsonrpc":"2.0","id":"1","result":{"v":"SECRET_222"}}',
                        "ts": 100.5,
                    },
                ]
            )
            self.assertEqual(inserted, 2)

            msgs = store.get_messages("s_batch")
            self.assertEqual(len(msgs), 2)
            self.assertIn("[REDACTED:PATTERN_0]", msgs[0].body)
            self.assertNotIn("SECRET_111", msgs[0].body)
            self.assertIn("[REDACTED:PATTERN_0]", msgs[1].body)
            self.assertNotIn("SECRET_222", msgs[1].body)

            # Invalid row in a batch must fail validation before inserting any rows from that batch
            with self.assertRaises(ValueError):
                store.append_messages_batch(
                    [
                        ("s_batch", "s_batch:echo", "c2s", "request", "ping", "2", "{}", 101.0),
                        ("s_batch", "s_batch:echo", "invalid_dir", "request", "ping", "3", "{}", 101.1),
                    ]
                )
            self.assertEqual(len(store.get_messages("s_batch")), 2)
        finally:
            store.close()

    def test_writer_worker_drains_queue_in_batches(self) -> None:
        """_writer_worker must drain up to batch_size items non-blockingly and commit each batch in one call."""
        store = FlowStore(db_path=":memory:")
        try:
            store.ensure_session("s_drain")
            store.register_server("s_drain:echo", "s_drain", "echo")

            log_q: queue.Queue[tuple[str, float, bytes] | None] = queue.Queue()
            total_frames = 150
            for idx in range(1, total_frames + 1):
                raw = json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": idx,
                        "method": "tools/call",
                        "params": {"name": "ping", "arguments": {"i": idx}},
                    }
                ).encode("utf-8") + b"\n"
                log_q.put(("c2s", float(idx), raw))
            # Include a non-JSON noise line to confirm it does not drop valid siblings in the batch
            log_q.put(("c2s", 999.0, b"not-json-noise\n"))
            log_q.put(None)

            batch_sizes_seen: list[int] = []
            orig_batch = store.append_messages_batch

            def spy_batch(records):
                batch_sizes_seen.append(len(records))
                return orig_batch(records)

            with patch.object(store, "append_messages_batch", side_effect=spy_batch):
                worker = threading.Thread(
                    target=_writer_worker,
                    args=(store, "s_drain", "s_drain:echo", log_q, 64),
                    daemon=True,
                )
                worker.start()
                log_q.join()
                worker.join(timeout=2.0)

            self.assertFalse(worker.is_alive())
            # 150 valid frames + 1 noise line = 151 items -> drained in ceil(151 / 64) == 3 batches
            self.assertLessEqual(len(batch_sizes_seen), 3)
            self.assertEqual(sum(batch_sizes_seen), total_frames)
            self.assertEqual(len(store.get_messages("s_drain")), total_frames)
        finally:
            store.close()

    def test_large_payload_1mb_plus_byte_for_byte_fidelity(self) -> None:
        """1MB+ single-line JSON-RPC frames must relay byte-for-byte identically with zero dropped messages."""
        cmd = _echo_server_command()
        payload_bytes = 1_100_000  # > 1 MiB
        num_frames = 2
        input_bytes = build_large_payload_requests(payload_bytes=payload_bytes, num_frames=num_frames)
        direct_out, _ = _run_direct(cmd, input_bytes)

        with tempfile.TemporaryDirectory() as tmpdir:
            db_file = Path(tmpdir) / "large_stress.db"
            store = FlowStore(db_path=db_file)
            try:
                client_out = io.BytesIO()
                t0 = time.perf_counter()
                rc = run_stdio_proxy(
                    command=cmd,
                    store=store,
                    session_id="stress_large_1mb",
                    server_name="echo",
                    client_in=io.BytesIO(input_bytes),
                    client_out=client_out,
                    batch_size=64,
                )
                elapsed = time.perf_counter() - t0
                self.assertEqual(rc, 0)
                self.assertLess(elapsed, 3.0)

                proxied_out = client_out.getvalue()
                self.assertEqual(proxied_out, direct_out)
                self.assertGreater(len(proxied_out), payload_bytes * num_frames)

                # Verify 0600 permissions preserved on disk DB
                mode = stat.S_IMODE(os.stat(db_file).st_mode)
                self.assertEqual(mode, 0o600)

                messages = store.get_messages("stress_large_1mb")
                self.assertEqual(len(messages), num_frames * 2)
                calls = derive_calls(store, "stress_large_1mb")
                self.assertEqual(len(calls), num_frames)
                for c in calls:
                    self.assertEqual(c.tool, "echo_blob")
                    self.assertEqual(c.is_error, 0)
            finally:
                store.close()

    def test_burst_250_rapid_calls_zero_drops_and_low_overhead(self) -> None:
        """250 rapid back-to-back tool calls must relay with 100% fidelity and zero dropped messages."""
        cmd = _echo_server_command()
        num_calls = 250
        input_bytes = build_burst_requests(num_calls=num_calls)
        direct_out, _ = _run_direct(cmd, input_bytes)

        with tempfile.TemporaryDirectory() as tmpdir:
            db_file = Path(tmpdir) / "burst_stress.db"
            store = FlowStore(db_path=db_file)
            try:
                client_out = io.BytesIO()
                t0 = time.perf_counter()
                rc = run_stdio_proxy(
                    command=cmd,
                    store=store,
                    session_id="stress_burst_250",
                    server_name="echo",
                    client_in=io.BytesIO(input_bytes),
                    client_out=client_out,
                    batch_size=64,
                )
                elapsed = time.perf_counter() - t0
                self.assertEqual(rc, 0)
                self.assertLess(elapsed, 3.0)

                self.assertEqual(client_out.getvalue(), direct_out)

                messages = store.get_messages("stress_burst_250")
                self.assertEqual(len(messages), num_calls * 2)

                calls = derive_calls(store, "stress_burst_250")
                self.assertEqual(len(calls), num_calls)
                self.assertTrue(all(c.res_seq is not None for c in calls))
            finally:
                store.close()

    def test_load_benchmark_runners(self) -> None:
        """Benchmark helper functions in scenarios/load_benchmark.py must pass integrity checks quickly."""
        t0 = time.perf_counter()
        large = run_large_payload_benchmark(payload_bytes=1_048_576, num_frames=1)
        burst = run_burst_throughput_benchmark(num_calls=200, batch_size=64)
        elapsed = time.perf_counter() - t0

        self.assertTrue(large.byte_exact)
        self.assertEqual(large.recorded_messages, large.expected_messages)
        self.assertTrue(burst.byte_exact)
        self.assertEqual(burst.recorded_messages, burst.expected_messages)
        self.assertLess(elapsed, 3.0)


if __name__ == "__main__":
    unittest.main()
