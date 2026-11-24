"""Persistent cache so TMLL does not redo the same Trace Server work per question.

Everything a question needs from the Trace Server is a deterministic function
of the trace files, so it can be kept across questions and service restarts:

- *Table scans*: the syscall-latency and futex tables are scanned once per
  trace, keeping every thread's rows (indexed by TID), instead of rescanning
  the whole table on every question just to keep one thread's rows.
- *Derived results*: finished per-thread analyses and periodic-jitter results,
  keyed by their parameters.

Keys use a fingerprint of the trace files (path, size, mtime of every file),
not the Trace Server experiment UUID, so the cache survives Trace Server and
service restarts and is invalidated automatically if a trace is re-captured
in place. Derived results also include a hash of the analysis source code, so
changing the analysis never serves a result computed by the old code.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
import tempfile
import threading
import time
import zlib
from pathlib import Path
from typing import Any, Callable, Iterable

import requests

_SCHEMA = """
CREATE TABLE IF NOT EXISTS results (
    fingerprint TEXT NOT NULL,
    namespace   TEXT NOT NULL,
    key         TEXT NOT NULL,
    value       BLOB NOT NULL,
    created_at  REAL NOT NULL,
    PRIMARY KEY (fingerprint, namespace, key)
);
CREATE TABLE IF NOT EXISTS table_scans (
    fingerprint  TEXT NOT NULL,
    kind         TEXT NOT NULL,
    version      TEXT NOT NULL,
    columns      TEXT NOT NULL,
    scanned_rows INTEGER NOT NULL,
    row_count    INTEGER NOT NULL,
    complete     INTEGER NOT NULL,
    max_rows     INTEGER NOT NULL,
    created_at   REAL NOT NULL,
    PRIMARY KEY (fingerprint, kind)
);
CREATE TABLE IF NOT EXISTS tid_rows (
    fingerprint TEXT NOT NULL,
    kind        TEXT NOT NULL,
    tid         INTEGER NOT NULL,
    blob        BLOB NOT NULL,
    PRIMARY KEY (fingerprint, kind, tid)
);
"""

# Rebuilt on read instead of stored: both follow from start and duration.
_DERIVED_FIELDS = ("end_timestamp_exclusive_ns", "duration_ms")
_SPILL_BUCKETS = 64


def _source_hash(paths: Iterable[Path]) -> str:
    digest = hashlib.sha1()
    for path in paths:
        digest.update(path.read_bytes())
    return digest.hexdigest()[:12]


_HERE = Path(__file__).resolve().parent

# Raw table rows only depend on how the probe normalizes them; derived results
# depend on all the analysis code.
RAW_VERSION = _source_hash([_HERE / "tmll_control_flow_probe_syscall_v1.py"])
DERIVED_VERSION = _source_hash(
    [
        _HERE / "tmll_control_flow_probe_syscall_v1.py",
        _HERE / "tmll_assistant_service_syscall_v1.py",
        _HERE / "periodic_jitter_probe.py",
    ]
)


class TraceCache:
    """SQLite-backed cache. ``path=None`` disables it (every call is a miss)."""

    def __init__(self, path: Path | None) -> None:
        self.path = path
        self._lock = threading.Lock()
        self._fingerprints: dict[tuple[str, int, str], tuple[float, str]] = {}
        if path is not None:
            path.parent.mkdir(parents=True, exist_ok=True)
            with self._connect() as db:
                db.executescript(_SCHEMA)

    @property
    def enabled(self) -> bool:
        return self.path is not None

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, timeout=30)
        db.execute("PRAGMA journal_mode=WAL")
        return db

    # ------------------------------------------------------------------
    # Trace identity
    # ------------------------------------------------------------------

    def fingerprint(self, host: str, port: int, experiment_id: str) -> str:
        """Fingerprint of the files behind an experiment.

        Recomputed at most every few seconds per experiment (a stat of each
        trace file), so a trace re-captured in place is picked up quickly.
        """
        key = (host, port, experiment_id)
        cached = self._fingerprints.get(key)
        if cached is not None and time.monotonic() - cached[0] < 5:
            return cached[1]

        response = requests.get(
            f"http://{host}:{port}/tsp/api/experiments/{experiment_id}",
            timeout=10,
        )
        response.raise_for_status()
        experiment = response.json()

        digest = hashlib.sha1()
        paths = sorted(trace.get("path", "") for trace in experiment.get("traces", []))
        local_files = 0
        for trace_path in paths:
            digest.update(trace_path.encode())
            root = Path(trace_path)
            if not root.exists():
                continue
            files = [root] if root.is_file() else sorted(
                p for p in root.rglob("*") if p.is_file()
            )
            for file in files:
                stat = file.stat()
                digest.update(
                    f"{file.relative_to(root.parent)}:{stat.st_size}:"
                    f"{stat.st_mtime_ns}".encode()
                )
                local_files += 1

        if local_files == 0:
            # Trace files not visible from here (remote Trace Server): fall
            # back to what the server reports about the experiment.
            digest.update(
                f"{experiment_id}:{experiment.get('start')}:"
                f"{experiment.get('end')}:{experiment.get('nbEvents')}".encode()
            )

        fingerprint = digest.hexdigest()[:20]
        self._fingerprints[key] = (time.monotonic(), fingerprint)
        return fingerprint

    # ------------------------------------------------------------------
    # Derived results
    # ------------------------------------------------------------------

    def get_or_compute(
        self,
        fingerprint: str,
        namespace: str,
        params: dict[str, Any],
        compute: Callable[[], Any],
    ) -> tuple[Any, bool]:
        """Return (value, was_cached)."""
        if not self.enabled:
            return compute(), False

        key = json.dumps({"v": DERIVED_VERSION, **params}, sort_keys=True)
        with self._connect() as db:
            row = db.execute(
                "SELECT value FROM results WHERE fingerprint=? AND namespace=? AND key=?",
                (fingerprint, namespace, key),
            ).fetchone()
        if row is not None:
            return json.loads(zlib.decompress(row[0])), True

        value = compute()
        blob = zlib.compress(json.dumps(value).encode())
        with self._lock, self._connect() as db:
            db.execute(
                "INSERT OR REPLACE INTO results VALUES (?, ?, ?, ?, ?)",
                (fingerprint, namespace, key, blob, time.time()),
            )
        return value, False

    # ------------------------------------------------------------------
    # Table scans
    # ------------------------------------------------------------------

    def table_rows_for_tid(
        self, fingerprint: str, kind: str, tid: int, max_rows: int
    ) -> dict[str, Any] | None:
        """Rows for one TID from an earlier full scan, if that scan covers
        ``max_rows`` (it finished the table, or scanned at least as far)."""
        if not self.enabled:
            return None
        with self._connect() as db:
            scan = db.execute(
                "SELECT scanned_rows, complete, max_rows, version, columns "
                "FROM table_scans WHERE fingerprint=? AND kind=?",
                (fingerprint, kind),
            ).fetchone()
            if scan is None or scan[3] != RAW_VERSION:
                return None
            scanned_rows, complete, scan_max_rows, _, columns_json = scan
            if not complete and scan_max_rows < max_rows:
                return None
            blob = db.execute(
                "SELECT blob FROM tid_rows WHERE fingerprint=? AND kind=? AND tid=?",
                (fingerprint, kind, tid),
            ).fetchone()
        columns = json.loads(columns_json)
        rows = []
        for values in json.loads(zlib.decompress(blob[0])) if blob else []:
            row = dict(zip(columns, values))
            if "start_timestamp_ns" in row and "duration_ns" in row:
                row["end_timestamp_exclusive_ns"] = (
                    row["start_timestamp_ns"] + row["duration_ns"]
                )
                row["duration_ms"] = round(row["duration_ns"] / 1_000_000.0, 3)
            rows.append(row)
        return {
            "scanned_rows": scanned_rows,
            "scan_complete": bool(complete),
            "rows": rows,
        }

    def begin_table_scan(self, fingerprint: str, kind: str) -> "TableScanWriter":
        return TableScanWriter(self, fingerprint, kind)

    # ------------------------------------------------------------------
    # Maintenance
    # ------------------------------------------------------------------

    def stats(self) -> dict[str, Any]:
        if not self.enabled:
            return {"enabled": False}
        with self._connect() as db:
            results = db.execute(
                "SELECT namespace, COUNT(*) FROM results GROUP BY namespace"
            ).fetchall()
            scans = db.execute(
                "SELECT fingerprint, kind, scanned_rows, row_count, complete "
                "FROM table_scans"
            ).fetchall()
        return {
            "enabled": True,
            "path": str(self.path),
            "size_bytes": os.path.getsize(self.path) if self.path.exists() else 0,
            "derived_version": DERIVED_VERSION,
            "raw_version": RAW_VERSION,
            "results_by_namespace": dict(results),
            "table_scans": [
                {
                    "fingerprint": fp,
                    "kind": kind,
                    "scanned_rows": scanned,
                    "stored_rows": stored,
                    "complete": bool(complete),
                }
                for fp, kind, scanned, stored, complete in scans
            ],
        }

    def clear(self, fingerprint: str | None = None) -> None:
        if not self.enabled:
            return
        with self._lock, self._connect() as db:
            for table in ("results", "table_scans", "tid_rows"):
                if fingerprint is None:
                    db.execute(f"DELETE FROM {table}")
                else:
                    db.execute(f"DELETE FROM {table} WHERE fingerprint=?", (fingerprint,))
        if fingerprint is None:
            with self._connect() as db:
                db.execute("VACUUM")


class TableScanWriter:
    """Streams one full table scan into the cache.

    Rows arrive interleaved across threads, but are stored as one compressed
    blob per thread (compact value lists, derivable fields dropped): about
    30x smaller than one JSON row each, which on a 924 MB trace was 2.15 GB.
    To avoid holding a multi-million-row table in memory, rows are first
    spilled to per-TID-bucket temp files, then grouped and compressed one
    bucket at a time in finish(). Nothing is visible to readers until then.
    """

    def __init__(self, cache: TraceCache, fingerprint: str, kind: str) -> None:
        self.cache = cache
        self.fingerprint = fingerprint
        self.kind = kind
        self.columns: list[str] | None = None
        self.row_count = 0
        self._dir = (
            tempfile.mkdtemp(prefix="scan-", dir=cache.path.parent)
            if cache.enabled
            else None
        )
        self._files: dict[int, Any] = {}

    def add(self, rows: list[tuple[int, dict[str, Any]]]) -> None:
        if self._dir is None or not rows:
            return
        if self.columns is None:
            self.columns = [k for k in rows[0][1] if k not in _DERIVED_FIELDS]
        for tid, row in rows:
            bucket = tid % _SPILL_BUCKETS
            spill = self._files.get(bucket)
            if spill is None:
                spill = open(os.path.join(self._dir, f"{bucket}.jsonl"), "w")
                self._files[bucket] = spill
            spill.write(json.dumps([tid, [row[c] for c in self.columns]]))
            spill.write("\n")
        self.row_count += len(rows)

    def finish(self, scanned_rows: int, complete: bool, max_rows: int) -> None:
        if self._dir is None:
            return
        try:
            for spill in self._files.values():
                spill.close()
            with self.cache._lock, self.cache._connect() as db:
                db.execute(
                    "DELETE FROM table_scans WHERE fingerprint=? AND kind=?",
                    (self.fingerprint, self.kind),
                )
                db.execute(
                    "DELETE FROM tid_rows WHERE fingerprint=? AND kind=?",
                    (self.fingerprint, self.kind),
                )
                for bucket in self._files:
                    by_tid: dict[int, list[Any]] = {}
                    with open(os.path.join(self._dir, f"{bucket}.jsonl")) as spill:
                        for line in spill:
                            tid, values = json.loads(line)
                            by_tid.setdefault(tid, []).append(values)
                    db.executemany(
                        "INSERT INTO tid_rows VALUES (?, ?, ?, ?)",
                        [
                            (
                                self.fingerprint,
                                self.kind,
                                tid,
                                zlib.compress(json.dumps(values).encode(), 6),
                            )
                            for tid, values in by_tid.items()
                        ],
                    )
                db.execute(
                    "INSERT INTO table_scans VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        self.fingerprint,
                        self.kind,
                        RAW_VERSION,
                        json.dumps(self.columns or []),
                        scanned_rows,
                        self.row_count,
                        int(complete),
                        max_rows,
                        time.time(),
                    ),
                )
        finally:
            self._cleanup()

    def abort(self) -> None:
        if self._dir is not None:
            for spill in self._files.values():
                spill.close()
            self._cleanup()

    def _cleanup(self) -> None:
        shutil.rmtree(self._dir, ignore_errors=True)
        self._dir = None
