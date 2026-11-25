"""SQLite store with WAL mode, 0600 permissions, migrations, and append-only raw message log."""

from __future__ import annotations

import json
import os
import sqlite3
import stat
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from mcp_flow.store.redaction import RedactionPolicy


SCHEMA_V1_SQL = """
CREATE TABLE IF NOT EXISTS schema_migrations(
    version INTEGER PRIMARY KEY,
    applied_at REAL NOT NULL,
    description TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions(
    id TEXT PRIMARY KEY,
    started_at REAL,
    client TEXT,
    note TEXT
);

CREATE TABLE IF NOT EXISTS servers(
    id TEXT PRIMARY KEY,
    session_id TEXT,
    name TEXT,
    command TEXT,
    transport TEXT
);

CREATE TABLE IF NOT EXISTS messages(
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT,
    server_id TEXT,
    ts REAL,
    dir TEXT,
    kind TEXT,
    method TEXT,
    rpc_id TEXT,
    body TEXT
);

CREATE TABLE IF NOT EXISTS calls(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT,
    server_id TEXT,
    tool TEXT,
    req_seq INTEGER,
    res_seq INTEGER,
    t_start REAL,
    t_end REAL,
    is_error INTEGER
);

CREATE TABLE IF NOT EXISTS fragments(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    call_id INTEGER,
    side TEXT,
    json_path TEXT,
    text TEXT,
    norm TEXT,
    len INTEGER,
    hash TEXT
);

CREATE TABLE IF NOT EXISTS flows(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    src_frag INTEGER,
    dst_frag INTEGER,
    kind TEXT,
    score REAL,
    src_span TEXT,
    dst_span TEXT
);

CREATE TABLE IF NOT EXISTS labels(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_kind TEXT,
    target_id INTEGER,
    label TEXT,
    source TEXT
);

CREATE TABLE IF NOT EXISTS tool_roles(
    server TEXT,
    tool TEXT,
    role TEXT,
    PRIMARY KEY(server, tool)
);

CREATE INDEX IF NOT EXISTS idx_messages_session ON messages(session_id, seq);
CREATE INDEX IF NOT EXISTS idx_calls_session ON calls(session_id, req_seq);
CREATE INDEX IF NOT EXISTS idx_fragments_call ON fragments(call_id, side);
CREATE INDEX IF NOT EXISTS idx_flows_src ON flows(src_frag);
CREATE INDEX IF NOT EXISTS idx_flows_dst ON flows(dst_frag);
CREATE INDEX IF NOT EXISTS idx_labels_target ON labels(target_kind, target_id);
"""

SCHEMA_V2_SQL = """
CREATE TABLE IF NOT EXISTS persistent_fingerprints(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    origin_session_id TEXT NOT NULL,
    origin_call_id INTEGER NOT NULL,
    origin_frag_id INTEGER NOT NULL,
    label TEXT NOT NULL,
    norm_hash TEXT NOT NULL,
    raw_hash TEXT NOT NULL,
    length INTEGER NOT NULL,
    created_at REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_persistent_fp_raw_hash ON persistent_fingerprints(raw_hash);
CREATE INDEX IF NOT EXISTS idx_persistent_fp_norm_hash ON persistent_fingerprints(norm_hash);
CREATE INDEX IF NOT EXISTS idx_persistent_fp_session ON persistent_fingerprints(origin_session_id);
"""

MIGRATIONS: list[tuple[int, str, str]] = [
    (1, "Initial M0 schema for mcp-flow", SCHEMA_V1_SQL),
    (2, "Add persistent_fingerprints table for cross-session taint tracking", SCHEMA_V2_SQL),
]


@dataclass
class MessageRow:
    seq: int
    session_id: str
    server_id: str
    ts: float
    dir: str
    kind: str
    method: str | None
    rpc_id: str | None
    body: str


@dataclass
class CallRow:
    id: int
    session_id: str
    server_id: str
    tool: str
    req_seq: int
    res_seq: int | None
    t_start: float
    t_end: float | None
    is_error: int
    server_name: str = ""


@dataclass
class FragmentRow:
    id: int
    call_id: int
    side: str
    json_path: str
    text: str
    norm: str
    len: int
    hash: str


@dataclass
class FlowRow:
    id: int
    src_frag: int
    dst_frag: int
    kind: str
    score: float
    src_span: str
    dst_span: str


@dataclass
class LabelRow:
    id: int
    target_kind: str
    target_id: int
    label: str
    source: str


@dataclass
class PersistentFingerprintRow:
    id: int
    origin_session_id: str
    origin_call_id: int
    origin_frag_id: int
    label: str
    norm_hash: str
    raw_hash: str
    length: int
    created_at: float


class FlowStore:
    """SQLite database layer for raw message logging and derived flow graph tables."""

    def __init__(
        self,
        db_path: str | Path = "mcp_flow.db",
        redaction_policy: RedactionPolicy | None = None,
        max_size_bytes: int | None = None,
    ) -> None:
        self.db_path = str(db_path)
        self.redaction_policy = redaction_policy or RedactionPolicy()
        self.max_size_bytes = max_size_bytes
        self._is_memory = self.db_path == ":memory:"

        if not self._is_memory:
            path_obj = Path(self.db_path)
            path_obj.parent.mkdir(parents=True, exist_ok=True)
            if not path_obj.exists():
                path_obj.touch(mode=0o600)
            os.chmod(path_obj, stat.S_IRUSR | stat.S_IWUSR)

        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._configure_pragmas()
        self.apply_migrations()

        if not self._is_memory and Path(self.db_path).exists():
            os.chmod(self.db_path, stat.S_IRUSR | stat.S_IWUSR)

    def _configure_pragmas(self) -> None:
        cur = self.conn.cursor()
        if not self._is_memory:
            cur.execute("PRAGMA journal_mode=WAL;")
        cur.execute("PRAGMA synchronous=NORMAL;")
        cur.execute("PRAGMA foreign_keys=ON;")
        cur.close()

    def apply_migrations(self) -> None:
        """Apply any unapplied database migrations in order."""
        with self.conn:
            self.conn.execute(
                """
                CREATE TABLE IF NOT EXISTS schema_migrations(
                    version INTEGER PRIMARY KEY,
                    applied_at REAL NOT NULL,
                    description TEXT NOT NULL
                );
                """
            )
            applied = {
                row["version"]
                for row in self.conn.execute("SELECT version FROM schema_migrations").fetchall()
            }
            for version, description, sql in MIGRATIONS:
                if version not in applied:
                    self.conn.executescript(sql)
                    self.conn.execute(
                        "INSERT INTO schema_migrations(version, applied_at, description) VALUES (?, ?, ?)",
                        (version, time.time(), description),
                    )

    def close(self) -> None:
        """Close the SQLite connection."""
        self.conn.close()

    def ensure_session(
        self,
        session_id: str,
        client: str = "unknown",
        note: str = "",
        started_at: float | None = None,
    ) -> str:
        """Create or update a session entry."""
        ts = started_at if started_at is not None else time.time()
        with self.conn:
            self.conn.execute(
                """
                INSERT INTO sessions(id, started_at, client, note)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    client = COALESCE(excluded.client, sessions.client),
                    note = CASE WHEN excluded.note != '' THEN excluded.note ELSE sessions.note END
                """,
                (session_id, ts, client, note),
            )
        return session_id

    def register_server(
        self,
        server_id: str,
        session_id: str,
        name: str,
        command: str = "",
        transport: str = "stdio",
    ) -> str:
        """Register an MCP server instance within a session."""
        with self.conn:
            self.conn.execute(
                """
                INSERT INTO servers(id, session_id, name, command, transport)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    name = excluded.name,
                    command = excluded.command,
                    transport = excluded.transport
                """,
                (server_id, session_id, name, command, transport),
            )
        return server_id

    def append_message(
        self,
        session_id: str,
        server_id: str,
        direction: str,
        kind: str,
        method: str | None,
        rpc_id: str | None,
        body: str,
        ts: float | None = None,
    ) -> int:
        """Append a raw JSON-RPC message to the immutable messages log."""
        if direction not in ("c2s", "s2c"):
            raise ValueError(f"Invalid direction: {direction}")
        if kind not in ("request", "response", "notification"):
            raise ValueError(f"Invalid message kind: {kind}")

        if (
            self.max_size_bytes is not None
            and not self._is_memory
            and Path(self.db_path).exists()
            and Path(self.db_path).stat().st_size >= self.max_size_bytes
        ):
            raise RuntimeError(f"Database file exceeded max_size_bytes ({self.max_size_bytes})")

        stored_body = self.redaction_policy.redact_text(body)
        msg_ts = ts if ts is not None else time.time()
        with self.conn:
            cur = self.conn.execute(
                """
                INSERT INTO messages(session_id, server_id, ts, dir, kind, method, rpc_id, body)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (session_id, server_id, msg_ts, direction, kind, method, rpc_id, stored_body),
            )
            return int(cur.lastrowid or 0)

    def list_sessions(self) -> list[dict[str, Any]]:
        """List all recorded sessions with message and call counts."""
        rows = self.conn.execute(
            """
            SELECT
                s.id,
                s.started_at,
                s.client,
                s.note,
                (SELECT COUNT(*) FROM messages m WHERE m.session_id = s.id) AS message_count,
                (SELECT COUNT(*) FROM calls c WHERE c.session_id = s.id) AS call_count
            FROM sessions s
            ORDER BY s.started_at DESC, s.id ASC
            """
        ).fetchall()
        return [dict(r) for r in rows]

    def get_messages(self, session_id: str) -> list[MessageRow]:
        """Return all messages for a session ordered by sequence number."""
        rows = self.conn.execute(
            """
            SELECT seq, session_id, server_id, ts, dir, kind, method, rpc_id, body
            FROM messages
            WHERE session_id = ?
            ORDER BY seq ASC
            """,
            (session_id,),
        ).fetchall()
        return [
            MessageRow(
                seq=r["seq"],
                session_id=r["session_id"],
                server_id=r["server_id"],
                ts=r["ts"],
                dir=r["dir"],
                kind=r["kind"],
                method=r["method"],
                rpc_id=r["rpc_id"],
                body=r["body"],
            )
            for r in rows
        ]

    def get_server_map(self, session_id: str) -> dict[str, str]:
        """Return a mapping of server_id -> server_name for a session."""
        rows = self.conn.execute(
            "SELECT id, name FROM servers WHERE session_id = ?",
            (session_id,),
        ).fetchall()
        mapping = {r["id"]: r["name"] for r in rows}
        return mapping

    def clear_derived_data(self, session_id: str) -> None:
        """Delete derived calls, fragments, flows, and auto-generated labels for a session so they can be recomputed."""
        with self.conn:
            call_ids = [
                r["id"]
                for r in self.conn.execute(
                    "SELECT id FROM calls WHERE session_id = ?", (session_id,)
                ).fetchall()
            ]
            if call_ids:
                placeholders = ",".join("?" for _ in call_ids)
                frag_ids = [
                    r["id"]
                    for r in self.conn.execute(
                        f"SELECT id FROM fragments WHERE call_id IN ({placeholders})",
                        call_ids,
                    ).fetchall()
                ]
                if frag_ids:
                    f_ph = ",".join("?" for _ in frag_ids)
                    self.conn.execute(
                        f"DELETE FROM flows WHERE src_frag IN ({f_ph}) OR dst_frag IN ({f_ph})",
                        frag_ids + frag_ids,
                    )
                    self.conn.execute(
                        f"DELETE FROM labels WHERE target_kind = 'fragment' AND target_id IN ({f_ph}) AND source != 'manual'",
                        frag_ids,
                    )
                self.conn.execute(
                    f"DELETE FROM labels WHERE target_kind = 'call' AND target_id IN ({placeholders}) AND source != 'manual'",
                    call_ids,
                )
                self.conn.execute(
                    f"DELETE FROM fragments WHERE call_id IN ({placeholders})",
                    call_ids,
                )
                self.conn.execute(
                    "DELETE FROM calls WHERE session_id = ?",
                    (session_id,),
                )

    def clear_flows(self, session_id: str) -> None:
        """Clear only the flows table for a session without deleting calls or fragments."""
        with self.conn:
            frag_ids = [
                r["id"]
                for r in self.conn.execute(
                    """
                    SELECT f.id
                    FROM fragments f
                    JOIN calls c ON c.id = f.call_id
                    WHERE c.session_id = ?
                    """,
                    (session_id,),
                ).fetchall()
            ]
            if frag_ids:
                f_ph = ",".join("?" for _ in frag_ids)
                self.conn.execute(
                    f"DELETE FROM flows WHERE src_frag IN ({f_ph}) OR dst_frag IN ({f_ph})",
                    frag_ids + frag_ids,
                )

    def insert_call(
        self,
        session_id: str,
        server_id: str,
        tool: str,
        req_seq: int,
        res_seq: int | None,
        t_start: float,
        t_end: float | None,
        is_error: int,
    ) -> int:
        with self.conn:
            cur = self.conn.execute(
                """
                INSERT INTO calls(session_id, server_id, tool, req_seq, res_seq, t_start, t_end, is_error)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (session_id, server_id, tool, req_seq, res_seq, t_start, t_end, is_error),
            )
            return int(cur.lastrowid or 0)

    def get_calls(self, session_id: str) -> list[CallRow]:
        server_map = self.get_server_map(session_id)
        rows = self.conn.execute(
            """
            SELECT id, session_id, server_id, tool, req_seq, res_seq, t_start, t_end, is_error
            FROM calls
            WHERE session_id = ?
            ORDER BY req_seq ASC, id ASC
            """,
            (session_id,),
        ).fetchall()
        return [
            CallRow(
                id=r["id"],
                session_id=r["session_id"],
                server_id=r["server_id"],
                tool=r["tool"],
                req_seq=r["req_seq"],
                res_seq=r["res_seq"],
                t_start=r["t_start"],
                t_end=r["t_end"],
                is_error=r["is_error"],
                server_name=server_map.get(r["server_id"], r["server_id"]),
            )
            for r in rows
        ]

    def insert_fragment(
        self,
        call_id: int,
        side: str,
        json_path: str,
        text: str,
        norm: str,
        length: int,
        frag_hash: str,
    ) -> int:
        stored_text = "" if self.redaction_policy.hash_only else text
        stored_norm = "" if self.redaction_policy.hash_only else norm
        with self.conn:
            cur = self.conn.execute(
                """
                INSERT INTO fragments(call_id, side, json_path, text, norm, len, hash)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (call_id, side, json_path, stored_text, stored_norm, length, frag_hash),
            )
            return int(cur.lastrowid or 0)

    def get_fragments(self, session_id: str) -> list[FragmentRow]:
        rows = self.conn.execute(
            """
            SELECT f.id, f.call_id, f.side, f.json_path, f.text, f.norm, f.len, f.hash
            FROM fragments f
            JOIN calls c ON c.id = f.call_id
            WHERE c.session_id = ?
            ORDER BY c.req_seq ASC, f.id ASC
            """,
            (session_id,),
        ).fetchall()
        return [
            FragmentRow(
                id=r["id"],
                call_id=r["call_id"],
                side=r["side"],
                json_path=r["json_path"],
                text=r["text"],
                norm=r["norm"],
                len=r["len"],
                hash=r["hash"],
            )
            for r in rows
        ]

    def insert_flow(
        self,
        src_frag: int,
        dst_frag: int,
        kind: str,
        score: float,
        src_span: str,
        dst_span: str,
    ) -> int:
        with self.conn:
            cur = self.conn.execute(
                """
                INSERT INTO flows(src_frag, dst_frag, kind, score, src_span, dst_span)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (src_frag, dst_frag, kind, score, src_span, dst_span),
            )
            return int(cur.lastrowid or 0)

    def get_flows(self, session_id: str) -> list[FlowRow]:
        rows = self.conn.execute(
            """
            SELECT fl.id, fl.src_frag, fl.dst_frag, fl.kind, fl.score, fl.src_span, fl.dst_span
            FROM flows fl
            JOIN fragments fs ON fs.id = fl.src_frag
            JOIN calls cs ON cs.id = fs.call_id
            WHERE cs.session_id = ?
            ORDER BY fl.score DESC, fl.id ASC
            """,
            (session_id,),
        ).fetchall()
        return [
            FlowRow(
                id=r["id"],
                src_frag=r["src_frag"],
                dst_frag=r["dst_frag"],
                kind=r["kind"],
                score=r["score"],
                src_span=r["src_span"],
                dst_span=r["dst_span"],
            )
            for r in rows
        ]

    def insert_label(
        self,
        target_kind: str,
        target_id: int,
        label: str,
        source: str,
    ) -> int:
        with self.conn:
            existing = self.conn.execute(
                """
                SELECT id FROM labels
                WHERE target_kind = ? AND target_id = ? AND label = ? AND source = ?
                """,
                (target_kind, target_id, label, source),
            ).fetchone()
            if existing:
                return int(existing["id"])
            cur = self.conn.execute(
                """
                INSERT INTO labels(target_kind, target_id, label, source)
                VALUES (?, ?, ?, ?)
                """,
                (target_kind, target_id, label, source),
            )
            return int(cur.lastrowid or 0)

    def get_labels(self, session_id: str) -> list[LabelRow]:
        rows = self.conn.execute(
            """
            SELECT l.id, l.target_kind, l.target_id, l.label, l.source
            FROM labels l
            WHERE (l.target_kind = 'call' AND l.target_id IN (SELECT id FROM calls WHERE session_id = ?))
               OR (l.target_kind = 'fragment' AND l.target_id IN (
                    SELECT f.id FROM fragments f JOIN calls c ON c.id = f.call_id WHERE c.session_id = ?
               ))
            ORDER BY l.id ASC
            """,
            (session_id, session_id),
        ).fetchall()
        return [
            LabelRow(
                id=r["id"],
                target_kind=r["target_kind"],
                target_id=r["target_id"],
                label=r["label"],
                source=r["source"],
            )
            for r in rows
        ]

    def set_tool_role(self, server: str, tool: str, role: str) -> None:
        if role not in ("source", "sink", "neutral"):
            raise ValueError(f"Invalid role: {role}")
        with self.conn:
            self.conn.execute(
                """
                INSERT INTO tool_roles(server, tool, role)
                VALUES (?, ?, ?)
                ON CONFLICT(server, tool) DO UPDATE SET role = excluded.role
                """,
                (server, tool, role),
            )

    def get_tool_roles(self) -> dict[tuple[str, str], str]:
        rows = self.conn.execute("SELECT server, tool, role FROM tool_roles").fetchall()
        return {(r["server"], r["tool"]): r["role"] for r in rows}

    def get_session_started_at(self, session_id: str) -> float | None:
        """Return the recorded `started_at` timestamp for `session_id`, if present."""
        row = self.conn.execute(
            "SELECT started_at FROM sessions WHERE id = ?",
            (session_id,),
        ).fetchone()
        if row is None or row["started_at"] is None:
            return None
        return float(row["started_at"])

    def insert_persistent_fingerprint(
        self,
        origin_session_id: str,
        origin_call_id: int,
        origin_frag_id: int,
        label: str,
        norm_hash: str,
        raw_hash: str,
        length: int,
        created_at: float | None = None,
    ) -> int:
        """Insert a hash-only sensitive output fingerprint for cross-session taint tracking."""
        ts = created_at if created_at is not None else time.time()
        with self.conn:
            existing = self.conn.execute(
                """
                SELECT id FROM persistent_fingerprints
                WHERE origin_session_id = ?
                  AND origin_frag_id = ?
                  AND label = ?
                  AND raw_hash = ?
                  AND norm_hash = ?
                """,
                (origin_session_id, origin_frag_id, label, raw_hash, norm_hash),
            ).fetchone()
            if existing:
                return int(existing["id"])
            cur = self.conn.execute(
                """
                INSERT INTO persistent_fingerprints(
                    origin_session_id, origin_call_id, origin_frag_id,
                    label, norm_hash, raw_hash, length, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    origin_session_id,
                    origin_call_id,
                    origin_frag_id,
                    label,
                    norm_hash,
                    raw_hash,
                    length,
                    ts,
                ),
            )
            return int(cur.lastrowid or 0)

    def clear_persistent_fingerprints(self, session_id: str) -> None:
        """Delete persistent fingerprints originating from `session_id`."""
        with self.conn:
            self.conn.execute(
                "DELETE FROM persistent_fingerprints WHERE origin_session_id = ?",
                (session_id,),
            )

    def get_persistent_fingerprints(
        self,
        origin_session_id: str | None = None,
        exclude_session_id: str | None = None,
    ) -> list[PersistentFingerprintRow]:
        """Return persistent fingerprint records, optionally filtered by origin session."""
        clauses: list[str] = []
        params: list[Any] = []
        if origin_session_id is not None:
            clauses.append("origin_session_id = ?")
            params.append(origin_session_id)
        if exclude_session_id is not None:
            clauses.append("origin_session_id != ?")
            params.append(exclude_session_id)
        where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        rows = self.conn.execute(
            f"""
            SELECT id, origin_session_id, origin_call_id, origin_frag_id,
                   label, norm_hash, raw_hash, length, created_at
            FROM persistent_fingerprints
            {where_sql}
            ORDER BY id ASC
            """,
            params,
        ).fetchall()
        return [
            PersistentFingerprintRow(
                id=r["id"],
                origin_session_id=r["origin_session_id"],
                origin_call_id=r["origin_call_id"],
                origin_frag_id=r["origin_frag_id"],
                label=r["label"],
                norm_hash=r["norm_hash"],
                raw_hash=r["raw_hash"],
                length=r["length"],
                created_at=r["created_at"],
            )
            for r in rows
        ]

    def find_persistent_fingerprints_by_hashes(
        self,
        raw_hashes: set[str],
        norm_hashes: set[str],
        exclude_session_id: str | None = None,
        max_origin_started_at: float | None = None,
    ) -> list[PersistentFingerprintRow]:
        """
        Look up persistent fingerprints matching any hash in `raw_hashes` or `norm_hashes`
        from earlier sessions (excluding `exclude_session_id`).
        """
        if not raw_hashes and not norm_hashes:
            return []

        results_by_id: dict[int, PersistentFingerprintRow] = {}
        chunk_size = 400

        def _query_column(column: str, hashes: list[str]) -> None:
            for i in range(0, len(hashes), chunk_size):
                batch = hashes[i : i + chunk_size]
                placeholders = ",".join("?" for _ in batch)
                clauses = [f"pf.{column} IN ({placeholders})"]
                params: list[Any] = list(batch)
                if exclude_session_id is not None:
                    clauses.append("pf.origin_session_id != ?")
                    params.append(exclude_session_id)
                if max_origin_started_at is not None:
                    clauses.append("(s.started_at IS NULL OR s.started_at <= ?)")
                    params.append(max_origin_started_at)
                where_sql = " AND ".join(clauses)
                rows = self.conn.execute(
                    f"""
                    SELECT pf.id, pf.origin_session_id, pf.origin_call_id, pf.origin_frag_id,
                           pf.label, pf.norm_hash, pf.raw_hash, pf.length, pf.created_at
                    FROM persistent_fingerprints pf
                    LEFT JOIN sessions s ON s.id = pf.origin_session_id
                    WHERE {where_sql}
                    ORDER BY pf.id ASC
                    """,
                    params,
                ).fetchall()
                for r in rows:
                    fp_id = int(r["id"])
                    if fp_id not in results_by_id:
                        results_by_id[fp_id] = PersistentFingerprintRow(
                            id=fp_id,
                            origin_session_id=r["origin_session_id"],
                            origin_call_id=r["origin_call_id"],
                            origin_frag_id=r["origin_frag_id"],
                            label=r["label"],
                            norm_hash=r["norm_hash"],
                            raw_hash=r["raw_hash"],
                            length=r["length"],
                            created_at=r["created_at"],
                        )

        if raw_hashes:
            _query_column("raw_hash", sorted(raw_hashes))
        if norm_hashes:
            _query_column("norm_hash", sorted(norm_hashes))

        return [results_by_id[k] for k in sorted(results_by_id.keys())]

    def export_messages_jsonl(self, session_id: str) -> str:
        """Export raw messages for a session as JSONL for interoperability with other trace tools."""
        messages = self.get_messages(session_id)
        lines: list[str] = []
        for m in messages:
            lines.append(
                json.dumps(
                    {
                        "seq": m.seq,
                        "session_id": m.session_id,
                        "server_id": m.server_id,
                        "ts": m.ts,
                        "dir": m.dir,
                        "kind": m.kind,
                        "method": m.method,
                        "rpc_id": m.rpc_id,
                        "body": m.body,
                    },
                    ensure_ascii=False,
                )
            )
        return "\n".join(lines) + ("\n" if lines else "")

    def purge_older_than(self, max_age_seconds: float) -> int:
        """Purge sessions and their messages/calls older than max_age_seconds."""
        cutoff = time.time() - max_age_seconds
        old_sessions = [
            r["id"]
            for r in self.conn.execute(
                "SELECT id FROM sessions WHERE started_at < ?", (cutoff,)
            ).fetchall()
        ]
        for sid in old_sessions:
            self.clear_derived_data(sid)
            self.clear_persistent_fingerprints(sid)
            with self.conn:
                self.conn.execute("DELETE FROM messages WHERE session_id = ?", (sid,))
                self.conn.execute("DELETE FROM servers WHERE session_id = ?", (sid,))
                self.conn.execute("DELETE FROM sessions WHERE id = ?", (sid,))
        return len(old_sessions)
