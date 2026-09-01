from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Generator

DEFAULT_DB = Path.home() / ".local" / "share" / "cairn" / "cairn.db"

_db_path: Path | None = None

SCHEMA = """\
CREATE TABLE IF NOT EXISTS settings (
    intent_timeout INTEGER NOT NULL DEFAULT 15,
    reason_timeout INTEGER NOT NULL DEFAULT 15
);

INSERT OR IGNORE INTO settings (rowid, intent_timeout, reason_timeout) VALUES (1, 15, 15);

CREATE TABLE IF NOT EXISTS projects (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    bootstrap_enabled INTEGER NOT NULL DEFAULT 1,
    project_kind TEXT NOT NULL DEFAULT 'general',
    created_at TEXT NOT NULL,
    reason_worker TEXT,
    reason_trigger TEXT,
    reason_started_at TEXT,
    reason_last_heartbeat_at TEXT
);

CREATE TABLE IF NOT EXISTS facts (
    id TEXT NOT NULL,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    description TEXT NOT NULL,
    PRIMARY KEY (id, project_id)
);

CREATE TABLE IF NOT EXISTS intents (
    id TEXT NOT NULL,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    to_fact_id TEXT,
    description TEXT NOT NULL,
    creator TEXT NOT NULL,
    worker TEXT,
    last_heartbeat_at TEXT,
    created_at TEXT NOT NULL,
    concluded_at TEXT,
    PRIMARY KEY (id, project_id)
);

CREATE TABLE IF NOT EXISTS intent_sources (
    intent_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    fact_id TEXT NOT NULL,
    PRIMARY KEY (intent_id, project_id, fact_id),
    FOREIGN KEY (intent_id, project_id) REFERENCES intents(id, project_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS hints (
    id TEXT NOT NULL,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    content TEXT NOT NULL,
    creator TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (id, project_id)
);

CREATE TABLE IF NOT EXISTS counters (
    name TEXT PRIMARY KEY,
    value INTEGER NOT NULL DEFAULT 0
);

INSERT OR IGNORE INTO counters (name, value) VALUES ('project', 0);

CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    applied_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scoped_counters (
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    value INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (project_id, kind)
);

CREATE TABLE IF NOT EXISTS ctf_config (
    mode TEXT NOT NULL DEFAULT 'manual',
    adapter TEXT NOT NULL DEFAULT 'ctfd',
    base_url TEXT NOT NULL DEFAULT '',
    token TEXT NOT NULL DEFAULT '',
    team_name TEXT NOT NULL DEFAULT '',
    flag_regex TEXT NOT NULL DEFAULT '(?:DASCTF|flag)\\{[^}]+\\}',
    auto_submit INTEGER NOT NULL DEFAULT 1,
    max_concurrent INTEGER NOT NULL DEFAULT 2,
    poll_interval INTEGER NOT NULL DEFAULT 10,
    env_poll_interval INTEGER NOT NULL DEFAULT 5,
    env_timeout INTEGER NOT NULL DEFAULT 180,
    submission_max_retries INTEGER NOT NULL DEFAULT 5,
    rate_limit_backoff INTEGER NOT NULL DEFAULT 30,
    model_base_url TEXT NOT NULL DEFAULT '',
    model_name TEXT NOT NULL DEFAULT '',
    model_api_key TEXT NOT NULL DEFAULT '',
    last_model_error TEXT,
    model_health_at TEXT,
    last_sync_at TEXT,
    bridge_heartbeat_at TEXT,
    bridge_error TEXT,
    sync_requested INTEGER NOT NULL DEFAULT 0,
    budget_easy INTEGER NOT NULL DEFAULT 12,
    budget_medium INTEGER NOT NULL DEFAULT 25,
    budget_hard INTEGER NOT NULL DEFAULT 40
);

INSERT OR IGNORE INTO ctf_config (rowid) VALUES (1);

CREATE TABLE IF NOT EXISTS ctf_challenges (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    external_id TEXT NOT NULL UNIQUE,
    title TEXT NOT NULL,
    category TEXT NOT NULL DEFAULT '',
    points INTEGER NOT NULL DEFAULT 0,
    description TEXT NOT NULL DEFAULT '',
    target TEXT NOT NULL DEFAULT '',
    attachments TEXT NOT NULL DEFAULT '[]',
    hints TEXT NOT NULL DEFAULT '[]',
    status TEXT NOT NULL DEFAULT 'queued',
    project_id TEXT,
    last_flag TEXT,
    attempt_count INTEGER NOT NULL DEFAULT 0,
    needs_refresh INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
"""

VULNERABILITY_SCHEMA = """\
CREATE TABLE IF NOT EXISTS vuln_campaigns (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL UNIQUE REFERENCES projects(id) ON DELETE CASCADE,
    objective TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'draft',
    authorization_confirmed INTEGER NOT NULL DEFAULT 0,
    authorization_expires_at TEXT NOT NULL,
    active_testing_enabled INTEGER NOT NULL DEFAULT 0,
    r2_enabled INTEGER NOT NULL DEFAULT 0,
    r2_auto_approve INTEGER NOT NULL DEFAULT 0,
    r2_proxy_url TEXT,
    auto_analysis_enabled INTEGER NOT NULL DEFAULT 0,
    auto_analysis_budget_units INTEGER NOT NULL DEFAULT 8,
    auto_analysis_daily_budget_units INTEGER NOT NULL DEFAULT 20,
    auto_analysis_min_observations INTEGER NOT NULL DEFAULT 5,
    ai_max_cost_usd REAL NOT NULL DEFAULT 0.50,
    ai_daily_cost_limit_usd REAL NOT NULL DEFAULT 2.00,
    ai_max_input_tokens INTEGER NOT NULL DEFAULT 12000,
    ai_max_output_tokens INTEGER NOT NULL DEFAULT 4096,
    ai_daily_token_limit INTEGER NOT NULL DEFAULT 50000,
    ai_require_hard_cost_limit INTEGER NOT NULL DEFAULT 1,
    ai_require_hard_token_limit INTEGER NOT NULL DEFAULT 0,
    ai_circuit_failure_threshold INTEGER NOT NULL DEFAULT 3,
    ai_circuit_cooldown_seconds INTEGER NOT NULL DEFAULT 3600,
    ai_relation_confidence_threshold REAL NOT NULL DEFAULT 0.60,
    ai_hypothesis_confidence_threshold REAL NOT NULL DEFAULT 0.60,
    ai_review_sample_rate REAL NOT NULL DEFAULT 0.10,
    max_requests_per_second INTEGER NOT NULL DEFAULT 30,
    max_concurrency INTEGER NOT NULL DEFAULT 3,
    request_header TEXT NOT NULL DEFAULT 'X-Cairn-Research',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS vuln_scopes (
    id TEXT PRIMARY KEY,
    campaign_id TEXT NOT NULL REFERENCES vuln_campaigns(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    value TEXT NOT NULL,
    normalized_value TEXT NOT NULL,
    include INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    UNIQUE(campaign_id, normalized_value, include)
);

CREATE TABLE IF NOT EXISTS vuln_assets (
    id TEXT PRIMARY KEY,
    campaign_id TEXT NOT NULL REFERENCES vuln_campaigns(id) ON DELETE CASCADE,
    asset_type TEXT NOT NULL,
    identifier TEXT NOT NULL,
    normalized_identifier TEXT NOT NULL,
    scope_state TEXT NOT NULL DEFAULT 'pending',
    importance TEXT NOT NULL DEFAULT 'normal',
    technology_json TEXT NOT NULL DEFAULT '[]',
    risk TEXT NOT NULL DEFAULT 'unknown',
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    stale_after TEXT,
    source_count INTEGER NOT NULL DEFAULT 0,
    importance_score REAL NOT NULL DEFAULT 50,
    risk_score REAL NOT NULL DEFAULT 0,
    scoring_factors_json TEXT NOT NULL DEFAULT '{}',
    scored_at TEXT,
    UNIQUE(campaign_id, asset_type, normalized_identifier)
);

CREATE TABLE IF NOT EXISTS vuln_asset_relations (
    id TEXT PRIMARY KEY,
    campaign_id TEXT NOT NULL REFERENCES vuln_campaigns(id) ON DELETE CASCADE,
    source_asset_id TEXT NOT NULL REFERENCES vuln_assets(id) ON DELETE CASCADE,
    target_asset_id TEXT NOT NULL REFERENCES vuln_assets(id) ON DELETE CASCADE,
    relation_type TEXT NOT NULL,
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    visible INTEGER NOT NULL DEFAULT 1,
    review_state TEXT NOT NULL DEFAULT 'auto_visible',
    UNIQUE(campaign_id, source_asset_id, target_asset_id, relation_type)
);

CREATE TABLE IF NOT EXISTS vuln_sources (
    id TEXT PRIMARY KEY,
    campaign_id TEXT NOT NULL REFERENCES vuln_campaigns(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    source_type TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'idle',
    enabled INTEGER NOT NULL DEFAULT 1,
    freshness_seconds INTEGER NOT NULL DEFAULT 3600,
    last_success_at TEXT,
    next_run_at TEXT,
    last_error TEXT,
    cursor TEXT,
    config_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(campaign_id, name)
);

CREATE TABLE IF NOT EXISTS vuln_observations (
    id TEXT PRIMARY KEY,
    campaign_id TEXT NOT NULL REFERENCES vuln_campaigns(id) ON DELETE CASCADE,
    asset_id TEXT REFERENCES vuln_assets(id) ON DELETE SET NULL,
    source_id TEXT REFERENCES vuln_sources(id) ON DELETE SET NULL,
    dimension TEXT NOT NULL,
    data_json TEXT NOT NULL,
    evidence_hash TEXT NOT NULL,
    confidence REAL NOT NULL DEFAULT 1.0,
    status TEXT NOT NULL DEFAULT 'current',
    raw_reference TEXT,
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    UNIQUE(campaign_id, evidence_hash)
);

CREATE TABLE IF NOT EXISTS vuln_coverage (
    campaign_id TEXT NOT NULL REFERENCES vuln_campaigns(id) ON DELETE CASCADE,
    dimension TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    discovered_count INTEGER NOT NULL DEFAULT 0,
    expected_count INTEGER,
    last_success_at TEXT,
    next_run_at TEXT,
    error TEXT,
    PRIMARY KEY(campaign_id, dimension)
);

CREATE TABLE IF NOT EXISTS vuln_snapshots (
    id TEXT PRIMARY KEY,
    campaign_id TEXT NOT NULL REFERENCES vuln_campaigns(id) ON DELETE CASCADE,
    summary_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS vuln_changes (
    id TEXT PRIMARY KEY,
    campaign_id TEXT NOT NULL REFERENCES vuln_campaigns(id) ON DELETE CASCADE,
    asset_id TEXT REFERENCES vuln_assets(id) ON DELETE SET NULL,
    change_type TEXT NOT NULL,
    title TEXT NOT NULL,
    detail_json TEXT NOT NULL DEFAULT '{}',
    detected_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS vuln_jobs (
    id TEXT PRIMARY KEY,
    campaign_id TEXT NOT NULL REFERENCES vuln_campaigns(id) ON DELETE CASCADE,
    job_type TEXT NOT NULL,
    mode TEXT NOT NULL DEFAULT 'passive',
    status TEXT NOT NULL DEFAULT 'queued',
    target TEXT,
    dimensions_json TEXT NOT NULL DEFAULT '[]',
    progress INTEGER NOT NULL DEFAULT 0,
    requested_by TEXT NOT NULL DEFAULT 'human',
    created_at TEXT NOT NULL,
    started_at TEXT,
    finished_at TEXT,
    error TEXT
);

CREATE TABLE IF NOT EXISTS vuln_job_runs (
    id TEXT PRIMARY KEY,
    job_id TEXT NOT NULL REFERENCES vuln_jobs(id) ON DELETE CASCADE,
    worker TEXT,
    status TEXT NOT NULL DEFAULT 'queued',
    log_json TEXT NOT NULL DEFAULT '[]',
    exit_code INTEGER,
    started_at TEXT,
    finished_at TEXT
);

CREATE TABLE IF NOT EXISTS vuln_findings (
    id TEXT PRIMARY KEY,
    campaign_id TEXT NOT NULL REFERENCES vuln_campaigns(id) ON DELETE CASCADE,
    asset_id TEXT REFERENCES vuln_assets(id) ON DELETE SET NULL,
    fact_id TEXT,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    finding_type TEXT NOT NULL,
    cwe TEXT,
    severity TEXT NOT NULL DEFAULT 'info',
    status TEXT NOT NULL DEFAULT 'candidate',
    confidence REAL NOT NULL DEFAULT 0.5,
    cvss_score REAL,
    epss_score REAL,
    kev INTEGER NOT NULL DEFAULT 0,
    fingerprint TEXT NOT NULL,
    remediation TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(campaign_id, fingerprint)
);

CREATE TABLE IF NOT EXISTS vuln_evidence (
    id TEXT PRIMARY KEY,
    finding_id TEXT NOT NULL REFERENCES vuln_findings(id) ON DELETE CASCADE,
    evidence_type TEXT NOT NULL,
    title TEXT NOT NULL,
    content TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    redacted INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS vuln_reports (
    id TEXT PRIMARY KEY,
    campaign_id TEXT NOT NULL REFERENCES vuln_campaigns(id) ON DELETE CASCADE,
    finding_id TEXT REFERENCES vuln_findings(id) ON DELETE SET NULL,
    title TEXT NOT NULL,
    report_type TEXT NOT NULL,
    format TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'ready',
    content TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_vuln_assets_campaign ON vuln_assets(campaign_id);
CREATE INDEX IF NOT EXISTS idx_vuln_observations_asset ON vuln_observations(asset_id);
CREATE INDEX IF NOT EXISTS idx_vuln_jobs_campaign ON vuln_jobs(campaign_id, created_at);
CREATE INDEX IF NOT EXISTS idx_vuln_findings_campaign ON vuln_findings(campaign_id, status, severity);
CREATE INDEX IF NOT EXISTS idx_vuln_changes_campaign ON vuln_changes(campaign_id, detected_at);
"""

VULNERABILITY_AUDIT_SCHEMA = """\
CREATE TABLE IF NOT EXISTS vuln_audit_events (
    id TEXT PRIMARY KEY,
    campaign_id TEXT NOT NULL REFERENCES vuln_campaigns(id) ON DELETE CASCADE,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT,
    detail_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_vuln_audit_campaign
ON vuln_audit_events(campaign_id, created_at);
"""

VULNERABILITY_LINKAGE_SCHEMA = """\
CREATE TABLE IF NOT EXISTS vuln_asset_coverage (
    campaign_id TEXT NOT NULL REFERENCES vuln_campaigns(id) ON DELETE CASCADE,
    asset_id TEXT NOT NULL REFERENCES vuln_assets(id) ON DELETE CASCADE,
    dimension TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    last_success_at TEXT,
    error TEXT,
    PRIMARY KEY(campaign_id, asset_id, dimension)
);

CREATE INDEX IF NOT EXISTS idx_vuln_asset_coverage_campaign
ON vuln_asset_coverage(campaign_id, dimension, status);
"""

VULNERABILITY_COLLECTION_TASK_SCHEMA = """\
CREATE TABLE IF NOT EXISTS vuln_collection_tasks (
    id TEXT PRIMARY KEY,
    campaign_id TEXT NOT NULL REFERENCES vuln_campaigns(id) ON DELETE CASCADE,
    job_id TEXT NOT NULL REFERENCES vuln_jobs(id) ON DELETE CASCADE,
    source_id TEXT NOT NULL REFERENCES vuln_sources(id) ON DELETE CASCADE,
    adapter TEXT NOT NULL,
    risk_tier TEXT NOT NULL DEFAULT 'R1',
    approval_state TEXT NOT NULL DEFAULT 'pending',
    status TEXT NOT NULL DEFAULT 'pending_approval',
    target TEXT,
    params_json TEXT NOT NULL DEFAULT '{}',
    dry_run INTEGER NOT NULL DEFAULT 0,
    lease_owner TEXT,
    lease_expires_at TEXT,
    attempt_count INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL DEFAULT 3,
    idempotency_key TEXT NOT NULL,
    approved_by TEXT,
    approval_reason TEXT,
    approved_at TEXT,
    result_json TEXT NOT NULL DEFAULT '{}',
    last_error TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    started_at TEXT,
    finished_at TEXT,
    UNIQUE(campaign_id, idempotency_key)
);

CREATE INDEX IF NOT EXISTS idx_vuln_collection_tasks_job
ON vuln_collection_tasks(job_id, status);

CREATE INDEX IF NOT EXISTS idx_vuln_collection_tasks_claim
ON vuln_collection_tasks(status, approval_state, lease_expires_at, created_at);

CREATE INDEX IF NOT EXISTS idx_vuln_collection_tasks_source
ON vuln_collection_tasks(source_id, created_at);
"""

VULNERABILITY_AI_SCHEMA = """\
CREATE TABLE IF NOT EXISTS vuln_ai_analyses (
    id TEXT PRIMARY KEY,
    campaign_id TEXT NOT NULL REFERENCES vuln_campaigns(id) ON DELETE CASCADE,
    project_id TEXT NOT NULL,
    intent_id TEXT NOT NULL,
    analysis_type TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'queued',
    observation_ids_json TEXT NOT NULL DEFAULT '[]',
    input_summary_json TEXT NOT NULL DEFAULT '{}',
    output_json TEXT NOT NULL DEFAULT '{}',
    worker TEXT,
    model TEXT,
    budget_units INTEGER NOT NULL,
    trigger_kind TEXT NOT NULL DEFAULT 'manual',
    started_at TEXT,
    finished_at TEXT,
    error TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(project_id, intent_id),
    FOREIGN KEY(intent_id, project_id) REFERENCES intents(id, project_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS vuln_hypotheses (
    id TEXT PRIMARY KEY,
    campaign_id TEXT NOT NULL REFERENCES vuln_campaigns(id) ON DELETE CASCADE,
    analysis_id TEXT NOT NULL REFERENCES vuln_ai_analyses(id) ON DELETE CASCADE,
    asset_id TEXT REFERENCES vuln_assets(id) ON DELETE SET NULL,
    vuln_id TEXT,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    confidence REAL NOT NULL DEFAULT 0.5,
    evidence_refs_json TEXT NOT NULL DEFAULT '[]',
    status TEXT NOT NULL DEFAULT 'proposed',
    visible INTEGER NOT NULL DEFAULT 1,
    review_state TEXT NOT NULL DEFAULT 'auto_visible',
    fingerprint TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(campaign_id, fingerprint)
);

CREATE INDEX IF NOT EXISTS idx_vuln_ai_analyses_campaign
ON vuln_ai_analyses(campaign_id, created_at);

CREATE INDEX IF NOT EXISTS idx_vuln_hypotheses_campaign
ON vuln_hypotheses(campaign_id, status, created_at);
"""

VULNERABILITY_CONTINUOUS_COLLECTION_SCHEMA = """\
CREATE TABLE IF NOT EXISTS vuln_task_assets (
    task_id TEXT NOT NULL REFERENCES vuln_collection_tasks(id) ON DELETE CASCADE,
    source_id TEXT NOT NULL REFERENCES vuln_sources(id) ON DELETE CASCADE,
    asset_id TEXT NOT NULL REFERENCES vuln_assets(id) ON DELETE CASCADE,
    observed_at TEXT NOT NULL,
    PRIMARY KEY(task_id, asset_id)
);

CREATE TABLE IF NOT EXISTS vuln_snapshot_assets (
    snapshot_id TEXT NOT NULL REFERENCES vuln_snapshots(id) ON DELETE CASCADE,
    asset_id TEXT NOT NULL REFERENCES vuln_assets(id) ON DELETE CASCADE,
    asset_type TEXT NOT NULL,
    normalized_identifier TEXT NOT NULL,
    state_hash TEXT NOT NULL,
    freshness_state TEXT NOT NULL DEFAULT 'fresh',
    data_json TEXT NOT NULL DEFAULT '{}',
    PRIMARY KEY(snapshot_id, asset_id)
);

CREATE INDEX IF NOT EXISTS idx_vuln_task_assets_source
ON vuln_task_assets(source_id, observed_at);

CREATE INDEX IF NOT EXISTS idx_vuln_snapshot_assets_asset
ON vuln_snapshot_assets(asset_id, snapshot_id);

CREATE INDEX IF NOT EXISTS idx_vuln_collection_tasks_ready
ON vuln_collection_tasks(status, approval_state, not_before, lease_expires_at, created_at);

CREATE UNIQUE INDEX IF NOT EXISTS idx_vuln_changes_event_key
ON vuln_changes(campaign_id, event_key) WHERE event_key IS NOT NULL;
"""

VULNERABILITY_PRODUCTION_SAFETY_SCHEMA = """\
CREATE TABLE IF NOT EXISTS vuln_http_rate_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    campaign_id TEXT NOT NULL REFERENCES vuln_campaigns(id) ON DELETE CASCADE,
    task_id TEXT NOT NULL REFERENCES vuln_collection_tasks(id) ON DELETE CASCADE,
    observed_at REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_vuln_http_rate_events_window
ON vuln_http_rate_events(campaign_id, observed_at);
"""

VULNERABILITY_PASSIVE_FINDINGS_AND_APPROVERS_SCHEMA = """\
CREATE TABLE IF NOT EXISTS vuln_http_responses (
    id TEXT PRIMARY KEY,
    campaign_id TEXT NOT NULL REFERENCES vuln_campaigns(id) ON DELETE CASCADE,
    task_id TEXT NOT NULL REFERENCES vuln_collection_tasks(id) ON DELETE CASCADE,
    source_id TEXT NOT NULL REFERENCES vuln_sources(id) ON DELETE CASCADE,
    asset_id TEXT NOT NULL REFERENCES vuln_assets(id) ON DELETE CASCADE,
    observation_id TEXT REFERENCES vuln_observations(id) ON DELETE SET NULL,
    url TEXT NOT NULL,
    method TEXT NOT NULL DEFAULT 'GET',
    status_code INTEGER,
    request_text TEXT NOT NULL,
    response_text TEXT NOT NULL,
    response_hash TEXT NOT NULL,
    response_bytes INTEGER NOT NULL DEFAULT 0,
    content_truncated INTEGER NOT NULL DEFAULT 0,
    redacted INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    UNIQUE(task_id, url)
);

CREATE INDEX IF NOT EXISTS idx_vuln_http_responses_asset
ON vuln_http_responses(campaign_id, asset_id, created_at);

CREATE TABLE IF NOT EXISTS vuln_finding_import_runs (
    id TEXT PRIMARY KEY,
    campaign_id TEXT NOT NULL REFERENCES vuln_campaigns(id) ON DELETE CASCADE,
    task_id TEXT NOT NULL REFERENCES vuln_collection_tasks(id) ON DELETE CASCADE,
    adapter TEXT NOT NULL,
    target TEXT NOT NULL,
    coverage_complete INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL,
    seen_fingerprints_json TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL,
    finished_at TEXT,
    UNIQUE(task_id, target)
);

CREATE INDEX IF NOT EXISTS idx_vuln_finding_import_runs_target
ON vuln_finding_import_runs(campaign_id, adapter, target, created_at);

CREATE TABLE IF NOT EXISTS vuln_approvers (
    id TEXT PRIMARY KEY,
    identity TEXT NOT NULL UNIQUE,
    role TEXT NOT NULL DEFAULT 'approver',
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS vuln_approver_credentials (
    id TEXT PRIMARY KEY,
    approver_id TEXT NOT NULL REFERENCES vuln_approvers(id) ON DELETE CASCADE,
    key_hash TEXT NOT NULL UNIQUE,
    key_prefix TEXT NOT NULL,
    issued_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    revoked_at TEXT,
    last_used_at TEXT,
    issued_by TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_vuln_approver_credentials_active
ON vuln_approver_credentials(key_hash, expires_at, revoked_at);

CREATE TABLE IF NOT EXISTS vuln_approver_audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT NOT NULL,
    detail_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);
"""

VULNERABILITY_AI_GOVERNANCE_SCHEMA = """\
CREATE TABLE IF NOT EXISTS vuln_ai_budget_events (
    analysis_id TEXT PRIMARY KEY REFERENCES vuln_ai_analyses(id) ON DELETE CASCADE,
    campaign_id TEXT NOT NULL REFERENCES vuln_campaigns(id) ON DELETE CASCADE,
    provider TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'reserved',
    reserved_cost_usd REAL NOT NULL,
    reserved_tokens INTEGER NOT NULL,
    actual_cost_usd REAL,
    actual_input_tokens INTEGER,
    actual_output_tokens INTEGER,
    created_at TEXT NOT NULL,
    finalized_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_vuln_ai_budget_campaign_day
ON vuln_ai_budget_events(campaign_id, created_at, status);

CREATE TABLE IF NOT EXISTS vuln_ai_circuit_breakers (
    campaign_id TEXT NOT NULL REFERENCES vuln_campaigns(id) ON DELETE CASCADE,
    provider TEXT NOT NULL,
    consecutive_failures INTEGER NOT NULL DEFAULT 0,
    opened_until TEXT,
    reason TEXT,
    updated_at TEXT NOT NULL,
    PRIMARY KEY(campaign_id, provider)
);

CREATE TABLE IF NOT EXISTS vuln_ai_reviews (
    id TEXT PRIMARY KEY,
    campaign_id TEXT NOT NULL REFERENCES vuln_campaigns(id) ON DELETE CASCADE,
    analysis_id TEXT NOT NULL UNIQUE REFERENCES vuln_ai_analyses(id) ON DELETE CASCADE,
    reasons_json TEXT NOT NULL DEFAULT '[]',
    status TEXT NOT NULL DEFAULT 'pending',
    reviewer TEXT,
    review_reason TEXT,
    reviewed_at TEXT,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_vuln_ai_reviews_campaign
ON vuln_ai_reviews(campaign_id, status, created_at);
"""


def configure(path: Path) -> None:
    global _db_path
    if _db_path is not None:
        return
    _db_path = path
    _db_path.parent.mkdir(parents=True, exist_ok=True)
    with get_conn() as conn:
        conn.executescript(SCHEMA)
        _ensure_project_columns(conn)
        _ensure_ctf_columns(conn)
        _apply_migrations(conn)


def _ensure_project_columns(conn: sqlite3.Connection) -> None:
    columns = {row["name"] for row in conn.execute("PRAGMA table_info(projects)")}
    if "bootstrap_enabled" not in columns:
        conn.execute("ALTER TABLE projects ADD COLUMN bootstrap_enabled INTEGER NOT NULL DEFAULT 1")
        if "bootstrap_mode" in columns:
            conn.execute(
                "UPDATE projects SET bootstrap_enabled = CASE WHEN bootstrap_mode = 'disabled' THEN 0 ELSE 1 END"
            )
    if "project_kind" not in columns:
        conn.execute("ALTER TABLE projects ADD COLUMN project_kind TEXT NOT NULL DEFAULT 'general'")


def _apply_migrations(conn: sqlite3.Connection) -> None:
    applied = {
        row["version"] for row in conn.execute("SELECT version FROM schema_migrations")
    }
    if 1 not in applied:
        conn.executescript(VULNERABILITY_SCHEMA)
        conn.execute(
            "INSERT INTO schema_migrations (version, name, applied_at) VALUES (1, 'vulnerability_foundation', strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))"
        )
    if 2 not in applied:
        conn.executescript(VULNERABILITY_AUDIT_SCHEMA)
        conn.execute(
            "INSERT INTO schema_migrations (version, name, applied_at) VALUES (2, 'vulnerability_audit', strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))"
        )
    if 3 not in applied:
        conn.executescript(VULNERABILITY_LINKAGE_SCHEMA)
        finding_columns = {
            row["name"] for row in conn.execute("PRAGMA table_info(vuln_findings)")
        }
        if "job_id" not in finding_columns:
            conn.execute("ALTER TABLE vuln_findings ADD COLUMN job_id TEXT")
        if "intent_id" not in finding_columns:
            conn.execute("ALTER TABLE vuln_findings ADD COLUMN intent_id TEXT")
        conn.execute(
            "INSERT INTO schema_migrations (version, name, applied_at) VALUES (3, 'vulnerability_asset_coverage_and_linkage', strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))"
        )
    if 4 not in applied:
        job_columns = {
            row["name"] for row in conn.execute("PRAGMA table_info(vuln_jobs)")
        }
        if "approval_required" not in job_columns:
            conn.execute(
                "ALTER TABLE vuln_jobs ADD COLUMN approval_required INTEGER NOT NULL DEFAULT 0"
            )
        if "idempotency_key" not in job_columns:
            conn.execute("ALTER TABLE vuln_jobs ADD COLUMN idempotency_key TEXT")
        conn.executescript(VULNERABILITY_COLLECTION_TASK_SCHEMA)
        conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_vuln_jobs_idempotency ON vuln_jobs(campaign_id, idempotency_key) WHERE idempotency_key IS NOT NULL"
        )
        conn.execute(
            "INSERT INTO schema_migrations (version, name, applied_at) VALUES (4, 'vulnerability_collection_tasks', strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))"
        )
    if 5 not in applied:
        task_columns = {
            row["name"] for row in conn.execute("PRAGMA table_info(vuln_collection_tasks)")
        }
        for column, ddl in (
            ("adapter_version", "ALTER TABLE vuln_collection_tasks ADD COLUMN adapter_version TEXT"),
            ("tool_version", "ALTER TABLE vuln_collection_tasks ADD COLUMN tool_version TEXT"),
            ("output_hash", "ALTER TABLE vuln_collection_tasks ADD COLUMN output_hash TEXT"),
            ("output_size", "ALTER TABLE vuln_collection_tasks ADD COLUMN output_size INTEGER NOT NULL DEFAULT 0"),
            (
                "execution_metadata_json",
                "ALTER TABLE vuln_collection_tasks ADD COLUMN execution_metadata_json TEXT NOT NULL DEFAULT '{}'",
            ),
        ):
            if column not in task_columns:
                conn.execute(ddl)
        for id_prefix, name, source_type, freshness_seconds, adapter in (
            (
                "source-r1-subfinder-",
                "Subfinder passive DNS",
                "subfinder_passive",
                3600,
                "subfinder.passive-dns.v1",
            ),
            (
                "source-r1-amass-",
                "Amass passive enumeration",
                "amass_passive",
                3600,
                "amass.passive-enum.v1",
            ),
            (
                "source-r1-rdap-",
                "RDAP domain registration",
                "rdap_domain",
                21600,
                "rdap.domain.v1",
            ),
            (
                "source-r1-whois-",
                "WHOIS domain registration",
                "whois_domain",
                21600,
                "whois.domain.v1",
            ),
        ):
            conn.execute(
                """
                INSERT INTO vuln_sources
                    (id, campaign_id, name, source_type, status, enabled,
                     freshness_seconds, config_json, created_at, updated_at)
                SELECT ? || campaign.id, campaign.id, ?, ?, 'idle', 1, ?, ?,
                       strftime('%Y-%m-%dT%H:%M:%SZ', 'now'),
                       strftime('%Y-%m-%dT%H:%M:%SZ', 'now')
                FROM vuln_campaigns AS campaign
                WHERE NOT EXISTS (
                    SELECT 1 FROM vuln_sources AS source
                    WHERE source.campaign_id = campaign.id AND source.source_type = ?
                )
                """,
                (
                    id_prefix,
                    name,
                    source_type,
                    freshness_seconds,
                    json.dumps({"adapter": adapter}),
                    source_type,
                ),
            )
        conn.execute(
            "INSERT INTO schema_migrations (version, name, applied_at) VALUES (5, 'vulnerability_adapter_execution_metadata', strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))"
        )
    if 6 not in applied:
        relation_columns = {
            row["name"] for row in conn.execute("PRAGMA table_info(vuln_asset_relations)")
        }
        if "analysis_id" not in relation_columns:
            conn.execute("ALTER TABLE vuln_asset_relations ADD COLUMN analysis_id TEXT")
        if "confidence" not in relation_columns:
            conn.execute(
                "ALTER TABLE vuln_asset_relations ADD COLUMN confidence REAL NOT NULL DEFAULT 1.0"
            )
        conn.executescript(VULNERABILITY_AI_SCHEMA)
        conn.execute(
            "INSERT INTO schema_migrations (version, name, applied_at) VALUES (6, 'vulnerability_ai_analysis', strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))"
        )
    if 7 not in applied:
        task_columns = {
            row["name"] for row in conn.execute("PRAGMA table_info(vuln_collection_tasks)")
        }
        for column, ddl in (
            (
                "approval_kind",
                "ALTER TABLE vuln_collection_tasks ADD COLUMN approval_kind TEXT NOT NULL DEFAULT 'manual'",
            ),
            ("not_before", "ALTER TABLE vuln_collection_tasks ADD COLUMN not_before TEXT"),
            (
                "retry_base_seconds",
                "ALTER TABLE vuln_collection_tasks ADD COLUMN retry_base_seconds INTEGER NOT NULL DEFAULT 30",
            ),
        ):
            if column not in task_columns:
                conn.execute(ddl)

        asset_columns = {
            row["name"] for row in conn.execute("PRAGMA table_info(vuln_assets)")
        }
        if "freshness_state" not in asset_columns:
            conn.execute(
                "ALTER TABLE vuln_assets ADD COLUMN freshness_state TEXT NOT NULL DEFAULT 'fresh'"
            )

        snapshot_columns = {
            row["name"] for row in conn.execute("PRAGMA table_info(vuln_snapshots)")
        }
        for column, ddl in (
            ("source_id", "ALTER TABLE vuln_snapshots ADD COLUMN source_id TEXT"),
            ("task_id", "ALTER TABLE vuln_snapshots ADD COLUMN task_id TEXT"),
            (
                "previous_snapshot_id",
                "ALTER TABLE vuln_snapshots ADD COLUMN previous_snapshot_id TEXT",
            ),
            (
                "coverage_complete",
                "ALTER TABLE vuln_snapshots ADD COLUMN coverage_complete INTEGER NOT NULL DEFAULT 0",
            ),
        ):
            if column not in snapshot_columns:
                conn.execute(ddl)

        change_columns = {
            row["name"] for row in conn.execute("PRAGMA table_info(vuln_changes)")
        }
        for column, ddl in (
            ("snapshot_id", "ALTER TABLE vuln_changes ADD COLUMN snapshot_id TEXT"),
            ("event_key", "ALTER TABLE vuln_changes ADD COLUMN event_key TEXT"),
        ):
            if column not in change_columns:
                conn.execute(ddl)

        conn.executescript(VULNERABILITY_CONTINUOUS_COLLECTION_SCHEMA)
        conn.execute(
            "INSERT INTO schema_migrations (version, name, applied_at) VALUES (7, 'vulnerability_continuous_snapshots', strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))"
        )
    if 8 not in applied:
        task_columns = {
            row["name"] for row in conn.execute("PRAGMA table_info(vuln_collection_tasks)")
        }
        if "trigger_kind" not in task_columns:
            conn.execute(
                "ALTER TABLE vuln_collection_tasks ADD COLUMN trigger_kind TEXT NOT NULL DEFAULT 'manual'"
            )
        conn.executescript(VULNERABILITY_PRODUCTION_SAFETY_SCHEMA)
        conn.execute(
            "INSERT INTO schema_migrations (version, name, applied_at) VALUES (8, 'vulnerability_production_safety', strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))"
        )
    if 9 not in applied:
        analysis_columns = {
            row["name"] for row in conn.execute("PRAGMA table_info(vuln_ai_analyses)")
        }
        if "execution_metadata_json" not in analysis_columns:
            conn.execute(
                "ALTER TABLE vuln_ai_analyses ADD COLUMN execution_metadata_json TEXT NOT NULL DEFAULT '{}'"
            )
        conn.execute(
            "INSERT INTO schema_migrations (version, name, applied_at) VALUES (9, 'vulnerability_ai_execution_metadata', strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))"
        )
    if 10 not in applied:
        campaign_columns = {
            row["name"] for row in conn.execute("PRAGMA table_info(vuln_campaigns)")
        }
        for column, ddl in (
            ("r2_enabled", "ALTER TABLE vuln_campaigns ADD COLUMN r2_enabled INTEGER NOT NULL DEFAULT 0"),
            ("r2_auto_approve", "ALTER TABLE vuln_campaigns ADD COLUMN r2_auto_approve INTEGER NOT NULL DEFAULT 0"),
            ("r2_proxy_url", "ALTER TABLE vuln_campaigns ADD COLUMN r2_proxy_url TEXT"),
            ("auto_analysis_enabled", "ALTER TABLE vuln_campaigns ADD COLUMN auto_analysis_enabled INTEGER NOT NULL DEFAULT 0"),
            ("auto_analysis_budget_units", "ALTER TABLE vuln_campaigns ADD COLUMN auto_analysis_budget_units INTEGER NOT NULL DEFAULT 8"),
            ("auto_analysis_daily_budget_units", "ALTER TABLE vuln_campaigns ADD COLUMN auto_analysis_daily_budget_units INTEGER NOT NULL DEFAULT 20"),
            ("auto_analysis_min_observations", "ALTER TABLE vuln_campaigns ADD COLUMN auto_analysis_min_observations INTEGER NOT NULL DEFAULT 5"),
        ):
            if column not in campaign_columns:
                conn.execute(ddl)
        analysis_columns = {
            row["name"] for row in conn.execute("PRAGMA table_info(vuln_ai_analyses)")
        }
        if "trigger_kind" not in analysis_columns:
            conn.execute(
                "ALTER TABLE vuln_ai_analyses ADD COLUMN trigger_kind TEXT NOT NULL DEFAULT 'manual'"
            )
        for source_type, adapter in (
            ("dns", "dnsx.resolve.v1"),
            ("http", "httpx.http-meta.v1"),
        ):
            for source in conn.execute(
                "SELECT id, config_json FROM vuln_sources WHERE source_type = ?",
                (source_type,),
            ).fetchall():
                try:
                    config = json.loads(source["config_json"] or "{}")
                except (TypeError, json.JSONDecodeError):
                    config = {}
                if not isinstance(config, dict):
                    config = {}
                config["adapter"] = adapter
                conn.execute(
                    "UPDATE vuln_sources SET config_json = ? WHERE id = ?",
                    (json.dumps(config), source["id"]),
                )
        conn.execute(
            """
            INSERT INTO vuln_sources
                (id, campaign_id, name, source_type, status, enabled,
                 freshness_seconds, config_json, created_at, updated_at)
            SELECT 'source-r2-tls-' || campaign.id, campaign.id, 'TLS metadata', 'tls',
                   'idle', 1, 21600, '{"adapter":"tlsx.tls-meta.v1"}',
                   strftime('%Y-%m-%dT%H:%M:%SZ', 'now'),
                   strftime('%Y-%m-%dT%H:%M:%SZ', 'now')
            FROM vuln_campaigns AS campaign
            WHERE NOT EXISTS (
                SELECT 1 FROM vuln_sources AS source
                WHERE source.campaign_id = campaign.id AND source.source_type = 'tls'
            )
            """
        )
        conn.execute(
            "INSERT INTO schema_migrations (version, name, applied_at) VALUES (10, 'vulnerability_r2_and_auto_analysis', strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))"
        )
    if 11 not in applied:
        finding_columns = {
            row["name"] for row in conn.execute("PRAGMA table_info(vuln_findings)")
        }
        for column, ddl in (
            ("source_adapter", "ALTER TABLE vuln_findings ADD COLUMN source_adapter TEXT"),
            ("template_id", "ALTER TABLE vuln_findings ADD COLUMN template_id TEXT"),
            ("target", "ALTER TABLE vuln_findings ADD COLUMN target TEXT"),
            (
                "evidence_fingerprint",
                "ALTER TABLE vuln_findings ADD COLUMN evidence_fingerprint TEXT",
            ),
            (
                "reimport_state",
                "ALTER TABLE vuln_findings ADD COLUMN reimport_state TEXT NOT NULL DEFAULT 'NEW'",
            ),
            ("first_seen_at", "ALTER TABLE vuln_findings ADD COLUMN first_seen_at TEXT"),
            ("last_seen_at", "ALTER TABLE vuln_findings ADD COLUMN last_seen_at TEXT"),
            (
                "candidate_resolved_at",
                "ALTER TABLE vuln_findings ADD COLUMN candidate_resolved_at TEXT",
            ),
            ("last_task_id", "ALTER TABLE vuln_findings ADD COLUMN last_task_id TEXT"),
        ):
            if column not in finding_columns:
                conn.execute(ddl)
        conn.execute(
            "UPDATE vuln_findings SET first_seen_at = COALESCE(first_seen_at, created_at), last_seen_at = COALESCE(last_seen_at, updated_at)"
        )
        conn.executescript(VULNERABILITY_PASSIVE_FINDINGS_AND_APPROVERS_SCHEMA)
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_vuln_findings_reimport ON vuln_findings(campaign_id, source_adapter, target, reimport_state)"
        )
        conn.execute(
            """
            INSERT INTO vuln_sources
                (id, campaign_id, name, source_type, status, enabled,
                 freshness_seconds, config_json, created_at, updated_at)
            SELECT 'source-r2-nuclei-passive-' || campaign.id,
                   campaign.id, 'Nuclei passive HTTP response', 'nuclei_passive',
                   'idle', 0, 21600,
                   '{"adapter":"nuclei.passive-response.v1"}',
                   strftime('%Y-%m-%dT%H:%M:%SZ', 'now'),
                   strftime('%Y-%m-%dT%H:%M:%SZ', 'now')
            FROM vuln_campaigns AS campaign
            WHERE NOT EXISTS (
                SELECT 1 FROM vuln_sources AS source
                WHERE source.campaign_id = campaign.id
                  AND source.source_type = 'nuclei_passive'
            )
            """
        )
        conn.execute(
            "INSERT INTO schema_migrations (version, name, applied_at) VALUES (11, 'vulnerability_passive_findings_and_approvers', strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))"
        )
    if 12 not in applied:
        campaign_columns = {
            row["name"] for row in conn.execute("PRAGMA table_info(vuln_campaigns)")
        }
        for column, ddl in (
            ("ai_max_cost_usd", "ALTER TABLE vuln_campaigns ADD COLUMN ai_max_cost_usd REAL NOT NULL DEFAULT 0.50"),
            ("ai_daily_cost_limit_usd", "ALTER TABLE vuln_campaigns ADD COLUMN ai_daily_cost_limit_usd REAL NOT NULL DEFAULT 2.00"),
            ("ai_max_input_tokens", "ALTER TABLE vuln_campaigns ADD COLUMN ai_max_input_tokens INTEGER NOT NULL DEFAULT 12000"),
            ("ai_max_output_tokens", "ALTER TABLE vuln_campaigns ADD COLUMN ai_max_output_tokens INTEGER NOT NULL DEFAULT 4096"),
            ("ai_daily_token_limit", "ALTER TABLE vuln_campaigns ADD COLUMN ai_daily_token_limit INTEGER NOT NULL DEFAULT 50000"),
            ("ai_require_hard_cost_limit", "ALTER TABLE vuln_campaigns ADD COLUMN ai_require_hard_cost_limit INTEGER NOT NULL DEFAULT 1"),
            ("ai_require_hard_token_limit", "ALTER TABLE vuln_campaigns ADD COLUMN ai_require_hard_token_limit INTEGER NOT NULL DEFAULT 0"),
            ("ai_circuit_failure_threshold", "ALTER TABLE vuln_campaigns ADD COLUMN ai_circuit_failure_threshold INTEGER NOT NULL DEFAULT 3"),
            ("ai_circuit_cooldown_seconds", "ALTER TABLE vuln_campaigns ADD COLUMN ai_circuit_cooldown_seconds INTEGER NOT NULL DEFAULT 3600"),
            ("ai_relation_confidence_threshold", "ALTER TABLE vuln_campaigns ADD COLUMN ai_relation_confidence_threshold REAL NOT NULL DEFAULT 0.60"),
            ("ai_hypothesis_confidence_threshold", "ALTER TABLE vuln_campaigns ADD COLUMN ai_hypothesis_confidence_threshold REAL NOT NULL DEFAULT 0.60"),
            ("ai_review_sample_rate", "ALTER TABLE vuln_campaigns ADD COLUMN ai_review_sample_rate REAL NOT NULL DEFAULT 0.10"),
        ):
            if column not in campaign_columns:
                conn.execute(ddl)
        asset_columns = {
            row["name"] for row in conn.execute("PRAGMA table_info(vuln_assets)")
        }
        for column, ddl in (
            ("importance_score", "ALTER TABLE vuln_assets ADD COLUMN importance_score REAL NOT NULL DEFAULT 50"),
            ("risk_score", "ALTER TABLE vuln_assets ADD COLUMN risk_score REAL NOT NULL DEFAULT 0"),
            ("scoring_factors_json", "ALTER TABLE vuln_assets ADD COLUMN scoring_factors_json TEXT NOT NULL DEFAULT '{}'"),
            ("scored_at", "ALTER TABLE vuln_assets ADD COLUMN scored_at TEXT"),
        ):
            if column not in asset_columns:
                conn.execute(ddl)
        relation_columns = {
            row["name"] for row in conn.execute("PRAGMA table_info(vuln_asset_relations)")
        }
        for column, ddl in (
            ("visible", "ALTER TABLE vuln_asset_relations ADD COLUMN visible INTEGER NOT NULL DEFAULT 1"),
            ("review_state", "ALTER TABLE vuln_asset_relations ADD COLUMN review_state TEXT NOT NULL DEFAULT 'auto_visible'"),
        ):
            if column not in relation_columns:
                conn.execute(ddl)
        hypothesis_columns = {
            row["name"] for row in conn.execute("PRAGMA table_info(vuln_hypotheses)")
        }
        for column, ddl in (
            ("visible", "ALTER TABLE vuln_hypotheses ADD COLUMN visible INTEGER NOT NULL DEFAULT 1"),
            ("review_state", "ALTER TABLE vuln_hypotheses ADD COLUMN review_state TEXT NOT NULL DEFAULT 'auto_visible'"),
        ):
            if column not in hypothesis_columns:
                conn.execute(ddl)
        conn.executescript(VULNERABILITY_AI_GOVERNANCE_SCHEMA)
        conn.execute(
            "INSERT INTO schema_migrations (version, name, applied_at) VALUES (12, 'vulnerability_ai_governance_and_asset_scoring', strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))"
        )


def _ensure_ctf_columns(conn: sqlite3.Connection) -> None:
    # ctf_config may not exist yet on databases created before the CTF feature.
    rows = conn.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'ctf_config'"
    ).fetchall()
    if rows:
        columns = {row["name"] for row in conn.execute("PRAGMA table_info(ctf_config)")}
        for column, ddl in (
            ("sync_requested", "ALTER TABLE ctf_config ADD COLUMN sync_requested INTEGER NOT NULL DEFAULT 0"),
            ("bridge_heartbeat_at", "ALTER TABLE ctf_config ADD COLUMN bridge_heartbeat_at TEXT"),
            ("bridge_error", "ALTER TABLE ctf_config ADD COLUMN bridge_error TEXT"),
            ("env_poll_interval", "ALTER TABLE ctf_config ADD COLUMN env_poll_interval INTEGER NOT NULL DEFAULT 5"),
            ("env_timeout", "ALTER TABLE ctf_config ADD COLUMN env_timeout INTEGER NOT NULL DEFAULT 180"),
            ("submission_max_retries", "ALTER TABLE ctf_config ADD COLUMN submission_max_retries INTEGER NOT NULL DEFAULT 5"),
            ("rate_limit_backoff", "ALTER TABLE ctf_config ADD COLUMN rate_limit_backoff INTEGER NOT NULL DEFAULT 30"),
            ("model_base_url", "ALTER TABLE ctf_config ADD COLUMN model_base_url TEXT NOT NULL DEFAULT ''"),
            ("model_name", "ALTER TABLE ctf_config ADD COLUMN model_name TEXT NOT NULL DEFAULT ''"),
            ("model_api_key", "ALTER TABLE ctf_config ADD COLUMN model_api_key TEXT NOT NULL DEFAULT ''"),
            ("last_model_error", "ALTER TABLE ctf_config ADD COLUMN last_model_error TEXT"),
            ("model_health_at", "ALTER TABLE ctf_config ADD COLUMN model_health_at TEXT"),
            ("budget_easy", "ALTER TABLE ctf_config ADD COLUMN budget_easy INTEGER NOT NULL DEFAULT 12"),
            ("budget_medium", "ALTER TABLE ctf_config ADD COLUMN budget_medium INTEGER NOT NULL DEFAULT 25"),
            ("budget_hard", "ALTER TABLE ctf_config ADD COLUMN budget_hard INTEGER NOT NULL DEFAULT 40"),
        ):
            if column not in columns:
                conn.execute(ddl)

    rows = conn.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'ctf_challenges'"
    ).fetchall()
    if rows:
        columns = {row["name"] for row in conn.execute("PRAGMA table_info(ctf_challenges)")}
        if "needs_refresh" not in columns:
            conn.execute("ALTER TABLE ctf_challenges ADD COLUMN needs_refresh INTEGER NOT NULL DEFAULT 0")


@contextmanager
def get_conn() -> Generator[sqlite3.Connection, None, None]:
    assert _db_path is not None
    conn = sqlite3.connect(str(_db_path))
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
