from __future__ import annotations

import sqlite3

from cairn.server import db


def test_configure_adds_bootstrap_enabled_to_legacy_projects_table(tmp_path, monkeypatch) -> None:
    path = tmp_path / "legacy.db"
    with sqlite3.connect(path) as conn:
        conn.execute(
            """
            CREATE TABLE projects (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'active',
                created_at TEXT NOT NULL,
                reason_worker TEXT,
                reason_trigger TEXT,
                reason_started_at TEXT,
                reason_last_heartbeat_at TEXT
            )
            """
        )
        conn.execute(
            "INSERT INTO projects (id, title, created_at) VALUES ('proj_001', 'legacy', '2026-01-01T00:00:00Z')"
        )

    monkeypatch.setattr(db, "_db_path", None)
    db.configure(path)

    with db.get_conn() as conn:
        row = conn.execute("SELECT bootstrap_enabled FROM projects WHERE id = 'proj_001'").fetchone()
    assert row["bootstrap_enabled"] == 1


def test_configure_maps_disabled_bootstrap_mode_to_false(tmp_path, monkeypatch) -> None:
    path = tmp_path / "intermediate.db"
    with sqlite3.connect(path) as conn:
        conn.execute(
            """
            CREATE TABLE projects (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'active',
                bootstrap_mode TEXT NOT NULL DEFAULT 'auto',
                created_at TEXT NOT NULL,
                reason_worker TEXT,
                reason_trigger TEXT,
                reason_started_at TEXT,
                reason_last_heartbeat_at TEXT
            )
            """
        )
        conn.execute(
            "INSERT INTO projects (id, title, bootstrap_mode, created_at) VALUES ('proj_001', 'disabled', 'disabled', '2026-01-01T00:00:00Z')"
        )
        conn.execute(
            "INSERT INTO projects (id, title, bootstrap_mode, created_at) VALUES ('proj_002', 'enabled', 'enabled', '2026-01-01T00:00:00Z')"
        )

    monkeypatch.setattr(db, "_db_path", None)
    db.configure(path)

    with db.get_conn() as conn:
        rows = conn.execute("SELECT id, bootstrap_enabled FROM projects ORDER BY id").fetchall()
    assert [(row["id"], row["bootstrap_enabled"]) for row in rows] == [
        ("proj_001", 0),
        ("proj_002", 1),
    ]


def test_migration_15_adds_validation_linkage_and_disabled_passive_sources(
    tmp_path, monkeypatch
) -> None:
    path = tmp_path / "current.db"
    monkeypatch.setattr(db, "_db_path", None)
    db.configure(path)

    with db.get_conn() as conn:
        versions = {
            row["version"] for row in conn.execute("SELECT version FROM schema_migrations")
        }
        task_columns = {
            row["name"]
            for row in conn.execute("PRAGMA table_info(vuln_collection_tasks)")
        }
    assert 15 in versions
    assert {"finding_id", "validation_kind"} <= task_columns


def test_migration_16_adds_campaign_retest_limit_and_queue_indexes(
    tmp_path, monkeypatch
) -> None:
    path = tmp_path / "retest.db"
    monkeypatch.setattr(db, "_db_path", None)
    db.configure(path)

    with db.get_conn() as conn:
        versions = {
            row["version"] for row in conn.execute("SELECT version FROM schema_migrations")
        }
        campaign_columns = {
            row["name"] for row in conn.execute("PRAGMA table_info(vuln_campaigns)")
        }
        indexes = {
            row["name"]
            for row in conn.execute("PRAGMA index_list(vuln_collection_tasks)")
        }
    assert 16 in versions
    assert "auto_retest_daily_limit" in campaign_columns
    assert {
        "idx_vuln_collection_tasks_auto_retest_daily",
        "idx_vuln_collection_tasks_pending_retest",
    } <= indexes


def test_migration_17_adds_queue_governance_columns_and_indexes(
    tmp_path, monkeypatch
) -> None:
    path = tmp_path / "queue-governance.db"
    monkeypatch.setattr(db, "_db_path", None)
    db.configure(path)

    with db.get_conn() as conn:
        versions = {
            row["version"] for row in conn.execute("SELECT version FROM schema_migrations")
        }
        source_columns = {
            row["name"] for row in conn.execute("PRAGMA table_info(vuln_sources)")
        }
        task_columns = {
            row["name"]
            for row in conn.execute("PRAGMA table_info(vuln_collection_tasks)")
        }
        job_columns = {
            row["name"] for row in conn.execute("PRAGMA table_info(vuln_jobs)")
        }
        run_columns = {
            row["name"] for row in conn.execute("PRAGMA table_info(vuln_job_runs)")
        }
        indexes = {
            row["name"]
            for row in conn.execute("PRAGMA index_list(vuln_collection_tasks)")
        }
    assert 17 in versions
    assert "schedule_offset" in source_columns
    assert "archived_at" in task_columns
    assert "archived_at" in job_columns
    assert "archived_at" in run_columns
    assert {
        "idx_vuln_collection_tasks_source_status",
        "idx_vuln_collection_tasks_archive",
    } <= indexes
