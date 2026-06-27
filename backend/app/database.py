"""SQLite database setup and access."""

from __future__ import annotations

import os
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Generator

def _default_db_path() -> str:
    return os.environ.get("MASREK_DB", str(
        Path(__file__).resolve().parent.parent / "masrek.db"
    ))

SCHEMA = """\
CREATE TABLE IF NOT EXISTS runs (
    id              TEXT PRIMARY KEY,
    target_url      TEXT NOT NULL,
    target_host     TEXT NOT NULL,
    mode            TEXT NOT NULL CHECK (mode IN ('passive', 'active', 'sast')),
    status          TEXT NOT NULL DEFAULT 'queued'
                        CHECK (status IN ('queued', 'running', 'done', 'failed', 'timeout')),
    created_at      TEXT NOT NULL,
    completed_at    TEXT,
    results_dir     TEXT,
    summary_json    TEXT,
    error_message   TEXT,
    selected_checks TEXT,
    scan_type       TEXT,
    target_type     TEXT DEFAULT 'url',
    source_path     TEXT
);

CREATE INDEX IF NOT EXISTS idx_runs_target_host ON runs(target_host);
CREATE INDEX IF NOT EXISTS idx_runs_created_at  ON runs(created_at);

CREATE TABLE IF NOT EXISTS findings (
    id              TEXT PRIMARY KEY,
    run_id          TEXT NOT NULL REFERENCES runs(id),
    severity        TEXT NOT NULL CHECK (severity IN ('critical','high','medium','low','info')),
    title           TEXT NOT NULL,
    category        TEXT NOT NULL,
    category_name   TEXT NOT NULL,
    location        TEXT NOT NULL,
    evidence        TEXT,
    verified        TEXT NOT NULL DEFAULT 'no'
                        CHECK (verified IN ('yes', 'no', 'needs-manual')),
    fix             TEXT,
    source_tool     TEXT NOT NULL,
    raw_id          TEXT,
    dedupe_hash     TEXT NOT NULL,
    mapping         TEXT NOT NULL DEFAULT 'exact'
                        CHECK (mapping IN ('exact', 'tag', 'fallback'))
);

CREATE INDEX IF NOT EXISTS idx_findings_run_id   ON findings(run_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_category ON findings(category);
CREATE UNIQUE INDEX IF NOT EXISTS idx_findings_dedupe ON findings(run_id, dedupe_hash);
"""


def init_db(db_path: str | None = None) -> None:
    path = db_path or _default_db_path()
    conn = sqlite3.connect(path)
    conn.executescript(SCHEMA)
    # Migration: add mapping column if missing (pre-existing DB)
    cols = {row[1] for row in conn.execute("PRAGMA table_info(findings)").fetchall()}
    if "mapping" not in cols:
        conn.execute("ALTER TABLE findings ADD COLUMN mapping TEXT NOT NULL DEFAULT 'exact'")
        conn.commit()
    run_cols = {row[1] for row in conn.execute("PRAGMA table_info(runs)").fetchall()}
    if "selected_checks" not in run_cols:
        conn.execute("ALTER TABLE runs ADD COLUMN selected_checks TEXT")
        conn.execute("ALTER TABLE runs ADD COLUMN scan_type TEXT")
        conn.commit()
    if "target_type" not in run_cols:
        conn.execute("ALTER TABLE runs ADD COLUMN target_type TEXT DEFAULT 'url'")
        conn.execute("ALTER TABLE runs ADD COLUMN source_path TEXT")
        conn.commit()

    # Migration: widen mode CHECK constraint to include 'sast'.
    # SQLite can't ALTER a CHECK — rebuild the table if the constraint is stale.
    # Uses a dedicated autocommit connection to avoid executescript() transaction bugs.
    conn.commit()
    conn.close()

    mig = sqlite3.connect(path, isolation_level=None)
    try:
        old_sql = mig.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='runs'"
        ).fetchone()[0]

        # Clean up partial migration from a previous failed attempt
        has_old = mig.execute(
            "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='_runs_old'"
        ).fetchone()[0]
        if has_old:
            has_new = mig.execute(
                "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='runs'"
            ).fetchone()[0]
            if has_new:
                mig.execute("DROP TABLE _runs_old")
            else:
                mig.execute("ALTER TABLE _runs_old RENAME TO runs")

        if "'sast'" not in old_sql:
            mig.execute("PRAGMA foreign_keys=OFF")
            mig.execute("BEGIN")
            mig.execute("ALTER TABLE runs RENAME TO _runs_old")
            mig.execute("""CREATE TABLE runs (
                id              TEXT PRIMARY KEY,
                target_url      TEXT NOT NULL,
                target_host     TEXT NOT NULL,
                mode            TEXT NOT NULL CHECK (mode IN ('passive', 'active', 'sast')),
                status          TEXT NOT NULL DEFAULT 'queued'
                                    CHECK (status IN ('queued', 'running', 'done', 'failed', 'timeout')),
                created_at      TEXT NOT NULL,
                completed_at    TEXT,
                results_dir     TEXT,
                summary_json    TEXT,
                error_message   TEXT,
                selected_checks TEXT,
                scan_type       TEXT,
                target_type     TEXT DEFAULT 'url',
                source_path     TEXT
            )""")
            mig.execute(
                "INSERT INTO runs SELECT id, target_url, target_host, mode, status, "
                "created_at, completed_at, results_dir, summary_json, error_message, "
                "selected_checks, scan_type, target_type, source_path FROM _runs_old"
            )
            mig.execute("DROP TABLE _runs_old")
            mig.execute("CREATE INDEX IF NOT EXISTS idx_runs_target_host ON runs(target_host)")
            mig.execute("CREATE INDEX IF NOT EXISTS idx_runs_created_at ON runs(created_at)")
            mig.execute("COMMIT")
            mig.execute("PRAGMA foreign_keys=ON")
    finally:
        mig.close()


@contextmanager
def get_db(db_path: str | None = None) -> Generator[sqlite3.Connection, None, None]:
    path = db_path or _default_db_path()
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
