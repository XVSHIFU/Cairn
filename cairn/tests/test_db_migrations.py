from __future__ import annotations

import json
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


def test_migration_22_adds_disabled_fofa_source_without_credentials(
    tmp_path, monkeypatch
) -> None:
    path = tmp_path / "fofa-source.db"
    monkeypatch.setattr(db, "_db_path", None)
    db.configure(path)

    with db.get_conn() as conn:
        assert conn.execute(
            "SELECT 1 FROM schema_migrations WHERE version = 22"
        ).fetchone()
        # Migration 22 seeds existing Campaigns. A directly-created fixture
        # proves the INSERT remains idempotent when configure is called again.
        conn.execute(
            """
            INSERT INTO projects
                (id, title, status, bootstrap_enabled, project_kind, created_at)
            VALUES ('proj-fofa', 'FOFA migration', 'active', 0,
                    'vulnerability', '2026-09-02T00:00:00Z')
            """
        )
        conn.execute(
            """
            INSERT INTO vuln_campaigns
                (id, project_id, objective, status, authorization_confirmed,
                 authorization_expires_at, created_at, updated_at)
            VALUES ('vuln-fofa', 'proj-fofa', 'migration test', 'running', 1,
                    '2099-01-01', '2026-09-02T00:00:00Z',
                    '2026-09-02T00:00:00Z')
            """
        )

    # Re-run only the migration block against a database that advertises 21 as
    # its latest version, matching a real upgrade without deleting any state.
    with db.get_conn() as conn:
        conn.execute("DELETE FROM schema_migrations WHERE version = 22")
    monkeypatch.setattr(db, "_db_path", None)
    db.configure(path)
    with db.get_conn() as conn:
        rows = conn.execute(
            "SELECT enabled, config_json FROM vuln_sources "
            "WHERE campaign_id = 'vuln-fofa' AND source_type = 'fofa_asset_search'"
        ).fetchall()
        config = json.loads(rows[0]["config_json"])
    assert len(rows) == 1
    assert rows[0]["enabled"] == 0
    assert config == {
        "adapter": "fofa.asset-search.v1",
        "credential_ref": "",
        "page_size": 100,
        "default_disabled": True,
    }


def test_migration_23_adds_disabled_browser_sources_and_capture_vault(
    tmp_path, monkeypatch
) -> None:
    path = tmp_path / "browser-sources.db"
    monkeypatch.setattr(db, "_db_path", None)
    db.configure(path)
    with db.get_conn() as conn:
        assert conn.execute(
            "SELECT 1 FROM schema_migrations WHERE version = 23"
        ).fetchone()
        assert conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' "
            "AND name = 'vuln_collection_evidence_vault'"
        ).fetchone()
        conn.execute(
            """
            INSERT INTO projects
                (id, title, status, bootstrap_enabled, project_kind, created_at)
            VALUES ('proj-browser', 'Browser migration', 'active', 0,
                    'vulnerability', '2026-09-02T00:00:00Z')
            """
        )
        conn.execute(
            """
            INSERT INTO vuln_campaigns
                (id, project_id, objective, status, authorization_confirmed,
                 authorization_expires_at, created_at, updated_at)
            VALUES ('vuln-browser', 'proj-browser', 'migration test', 'running', 1,
                    '2099-01-01', '2026-09-02T00:00:00Z',
                    '2026-09-02T00:00:00Z')
            """
        )
        conn.execute("DELETE FROM schema_migrations WHERE version = 23")

    monkeypatch.setattr(db, "_db_path", None)
    db.configure(path)
    with db.get_conn() as conn:
        rows = conn.execute(
            "SELECT source_type, enabled, config_json FROM vuln_sources "
            "WHERE campaign_id = 'vuln-browser' "
            "AND source_type IN ('browser_archive_analysis', 'browser_evidence_session') "
            "ORDER BY source_type"
        ).fetchall()
    assert [row["source_type"] for row in rows] == [
        "browser_archive_analysis",
        "browser_evidence_session",
    ]
    assert all(row["enabled"] == 0 for row in rows)
    assert [json.loads(row["config_json"])["adapter"] for row in rows] == [
        "browser.archive-analyze.v1",
        "browser.evidence-session.v1",
    ]


def test_migration_24_adds_collection_evidence_access_audit_tables(
    tmp_path, monkeypatch
) -> None:
    path = tmp_path / "collection-evidence-access.db"
    monkeypatch.setattr(db, "_db_path", None)
    db.configure(path)
    with db.get_conn() as conn:
        tables = {
            row["name"]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }
        assert {
            "vuln_collection_evidence_access_grants",
            "vuln_collection_evidence_access_events",
        } <= tables
        migration = conn.execute(
            "SELECT name FROM schema_migrations WHERE version = 24"
        ).fetchone()
    assert migration["name"] == "vulnerability_collection_evidence_access"


def test_migration_25_adds_scope_lineage_and_aggregate_exception_tables(
    tmp_path, monkeypatch
) -> None:
    path = tmp_path / "scope-lineage.db"
    monkeypatch.setattr(db, "_db_path", None)
    db.configure(path)
    with db.get_conn() as conn:
        tables = {
            row["name"]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }
        assert {
            "vuln_scope_lineage",
            "vuln_scope_exception_groups",
        } <= tables
        migration = conn.execute(
            "SELECT name FROM schema_migrations WHERE version = 25"
        ).fetchone()
    assert migration["name"] == "vulnerability_scope_lineage_and_exceptions"


def test_migration_26_adds_task_workspace_lifecycle_tables(
    tmp_path, monkeypatch
) -> None:
    path = tmp_path / "task-workspaces.db"
    monkeypatch.setattr(db, "_db_path", None)
    db.configure(path)
    with db.get_conn() as conn:
        tables = {
            row["name"]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }
        assert {
            "vuln_task_workspaces",
            "vuln_task_workspace_artifacts",
        } <= tables
        migration = conn.execute(
            "SELECT name FROM schema_migrations WHERE version = 26"
        ).fetchone()
    assert migration["name"] == "vulnerability_task_workspace_lifecycle"


def test_migration_27_adds_report_profile_snapshot_columns(
    tmp_path, monkeypatch
) -> None:
    path = tmp_path / "report-profiles.db"
    monkeypatch.setattr(db, "_db_path", None)
    db.configure(path)
    with db.get_conn() as conn:
        columns = {
            row["name"] for row in conn.execute("PRAGMA table_info(vuln_reports)")
        }
        migration = conn.execute(
            "SELECT name FROM schema_migrations WHERE version = 27"
        ).fetchone()
    assert {"profile", "profile_version", "evidence_mode", "context_json"} <= columns
    assert migration["name"] == "vulnerability_report_profiles"


def test_migration_28_adds_local_sbom_inventory_tables(
    tmp_path, monkeypatch
) -> None:
    path = tmp_path / "local-sbom.db"
    monkeypatch.setattr(db, "_db_path", None)
    db.configure(path)
    with db.get_conn() as conn:
        tables = {
            row["name"]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }
        migration = conn.execute(
            "SELECT name FROM schema_migrations WHERE version = 28"
        ).fetchone()
    assert {"vuln_sboms", "vuln_sbom_components"} <= tables
    assert migration["name"] == "vulnerability_local_sbom_inventory"


def test_migration_28_seeds_disabled_syft_source_for_existing_campaign(
    tmp_path, monkeypatch
) -> None:
    path = tmp_path / "existing-campaign-sbom.db"
    monkeypatch.setattr(db, "_db_path", None)
    db.configure(path)
    with db.get_conn() as conn:
        conn.execute(
            """
            INSERT INTO projects (id, title, status, created_at)
            VALUES ('project-existing', 'Existing', 'active', '2026-09-03T00:00:00Z')
            """
        )
        conn.execute(
            """
            INSERT INTO vuln_campaigns
                (id, project_id, objective, authorization_expires_at,
                 created_at, updated_at)
            VALUES ('vuln-existing', 'project-existing', 'Existing campaign',
                    '2026-12-31', '2026-09-03T00:00:00Z',
                    '2026-09-03T00:00:00Z')
            """
        )
        conn.execute("DROP TABLE vuln_sbom_components")
        conn.execute("DROP TABLE vuln_sboms")
        conn.execute("DELETE FROM schema_migrations WHERE version = 28")
        db._apply_migrations(conn)
        source = conn.execute(
            """
            SELECT * FROM vuln_sources
            WHERE campaign_id = 'vuln-existing'
              AND source_type = 'syft_local_sbom'
            """
        ).fetchone()
    assert source is not None
    assert source["enabled"] == 0
    assert json.loads(source["config_json"]) == {
        "adapter": "syft.local-sbom.v1",
        "default_disabled": True,
    }


def test_migration_29_seeds_disabled_offline_trivy_source_for_existing_campaign(
    tmp_path, monkeypatch
) -> None:
    path = tmp_path / "existing-campaign-trivy.db"
    monkeypatch.setattr(db, "_db_path", None)
    db.configure(path)
    with db.get_conn() as conn:
        conn.execute(
            """
            INSERT INTO projects (id, title, status, created_at)
            VALUES ('project-existing-trivy', 'Existing', 'active', '2026-09-03T00:00:00Z')
            """
        )
        conn.execute(
            """
            INSERT INTO vuln_campaigns
                (id, project_id, objective, authorization_expires_at,
                 created_at, updated_at)
            VALUES ('vuln-existing-trivy', 'project-existing-trivy', 'Existing campaign',
                    '2026-12-31', '2026-09-03T00:00:00Z',
                    '2026-09-03T00:00:00Z')
            """
        )
        conn.execute(
            "DELETE FROM vuln_sources WHERE campaign_id = 'vuln-existing-trivy' "
            "AND source_type = 'trivy_sbom_vulnerability'"
        )
        conn.execute("DELETE FROM schema_migrations WHERE version = 29")
        db._apply_migrations(conn)
        source = conn.execute(
            """
            SELECT * FROM vuln_sources
            WHERE campaign_id = 'vuln-existing-trivy'
              AND source_type = 'trivy_sbom_vulnerability'
            """
        ).fetchone()
        migration = conn.execute(
            "SELECT name FROM schema_migrations WHERE version = 29"
        ).fetchone()
    assert source is not None
    assert source["enabled"] == 0
    config = json.loads(source["config_json"])
    assert config["adapter"] == "trivy.sbom-vuln.v1"
    assert config["default_disabled"] is True
    assert config["offline_only"] is True
    assert migration["name"] == "vulnerability_offline_sbom_vulnerability_analysis"


def test_migration_30_adds_container_sbom_subject_and_disabled_sources(
    tmp_path, monkeypatch
) -> None:
    path = tmp_path / "container-sbom.db"
    monkeypatch.setattr(db, "_db_path", None)
    db.configure(path)
    with db.get_conn() as conn:
        columns = {
            row["name"] for row in conn.execute("PRAGMA table_info(vuln_sboms)")
        }
        project_id = "project-container-existing"
        campaign_id = "vuln-container-existing"
        conn.execute(
            """
            INSERT INTO projects (id, title, status, created_at)
            VALUES (?, 'Existing', 'active', '2026-09-03T00:00:00Z')
            """,
            (project_id,),
        )
        conn.execute(
            """
            INSERT INTO vuln_campaigns
                (id, project_id, objective, authorization_expires_at,
                 created_at, updated_at)
            VALUES (?, ?, 'Existing campaign', '2026-12-31',
                    '2026-09-03T00:00:00Z', '2026-09-03T00:00:00Z')
            """,
            (campaign_id, project_id),
        )
        conn.execute(
            "DELETE FROM vuln_sources WHERE campaign_id = ? AND source_type IN "
            "('syft_container_archive_sbom', 'trivy_container_sbom_vulnerability')",
            (campaign_id,),
        )
        conn.execute("DELETE FROM schema_migrations WHERE version = 30")
        db._apply_migrations(conn)
        sources = conn.execute(
            """
            SELECT source_type, enabled, config_json FROM vuln_sources
            WHERE campaign_id = ? AND source_type IN
                  ('syft_container_archive_sbom',
                   'trivy_container_sbom_vulnerability')
            ORDER BY source_type
            """,
            (campaign_id,),
        ).fetchall()
        migration = conn.execute(
            "SELECT name FROM schema_migrations WHERE version = 30"
        ).fetchone()
    assert {"subject_asset_id", "subject_type"} <= columns
    assert len(sources) == 2
    assert all(row["enabled"] == 0 for row in sources)
    configs = {row["source_type"]: json.loads(row["config_json"]) for row in sources}
    assert configs["syft_container_archive_sbom"] == {
        "adapter": "syft.container-archive-sbom.v1",
        "default_disabled": True,
        "offline_only": True,
    }
    assert configs["trivy_container_sbom_vulnerability"]["adapter"] == (
        "trivy.container-sbom-vuln.v1"
    )
    assert configs["trivy_container_sbom_vulnerability"]["offline_only"] is True
    assert migration["name"] == "vulnerability_container_archive_sbom"
