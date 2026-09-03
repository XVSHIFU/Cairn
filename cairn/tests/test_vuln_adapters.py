from __future__ import annotations

import base64
import hashlib
import io
import json
import sqlite3
import subprocess
import sys
import tarfile
import time
from pathlib import Path

import pytest

from cairn.server import vuln_adapters as vuln_adapters_module
from cairn.server.vuln_adapters import (
    ADAPTER_REGISTRY,
    AdapterContext,
    AdapterCancellationError,
    AdapterExecution,
    AdapterExecutionError,
    AdapterInvocation,
    AdapterUnavailableError,
    AdapterValidationError,
    AmassPassiveEnumAdapter,
    BrowserArchiveAnalyzeAdapter,
    BrowserEvidenceSessionAdapter,
    CertificateTransparencyAdapter,
    CommandResult,
    DnsxResolveAdapter,
    FofaAssetSearchAdapter,
    GitleaksLocalRepositoryAdapter,
    HttpxHttpMetadataAdapter,
    KatanaCrawlerAdapter,
    NaabuPortScanAdapter,
    NucleiPassiveResponseAdapter,
    NvdKevVulnerabilityIntelligenceAdapter,
    OsvVulnerabilityIntelligenceAdapter,
    RATE_LIMIT_RESERVATION_WINDOW_SECONDS,
    RdapDomainAdapter,
    SavedResponseWebApiAdapter,
    SubfinderPassiveDnsAdapter,
    SyftContainerArchiveSbomAdapter,
    SyftLocalSbomAdapter,
    TrivyContainerSbomVulnerabilityAdapter,
    TrivySbomVulnerabilityAdapter,
    TlsxTlsMetadataAdapter,
    WhoisDomainAdapter,
    acquire_campaign_http_rate_limit,
    validate_browser_evidence_source_config,
)
from cairn.server.playwright_capture import (
    CaptureState,
    CaptureConfigurationError,
    DurableRateLimiter,
    request_is_allowed,
    validate_capture_config,
)


def _context(
    *,
    targets: tuple[str, ...] = ("example.com",),
    packages: tuple[dict, ...] = (),
    vulnerabilities: tuple[dict, ...] = (),
    http_responses: tuple[dict, ...] = (),
    options: dict | None = None,
) -> AdapterContext:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute(
        """
        CREATE TABLE vuln_http_rate_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            campaign_id TEXT NOT NULL,
            task_id TEXT NOT NULL,
            observed_at REAL NOT NULL
        )
        """
    )
    return AdapterContext(
        conn=conn,
        campaign_id="vuln-test",
        task_id="task-test",
        source={"id": "source-test", "name": "test-source"},
        targets=targets,
        packages=packages,
        vulnerabilities=vulnerabilities,
        http_responses=http_responses,
        options=options or {},
    )


def test_saved_response_web_api_adapter_is_offline_and_detects_surfaces(
    monkeypatch,
) -> None:
    response_text = (
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n"
        '{"openapi":"3.1.0","paths":{}}'
    )
    context = _context(
        http_responses=(
            {
                "id": "http_response_001",
                "asset_id": "asset_001",
                "task_id": "capture_task_001",
                "domain": "example.com",
                "url": "https://example.com/openapi.json",
                "response_text": response_text,
                "response_hash": hashlib.sha256(response_text.encode()).hexdigest(),
                "content_truncated": 0,
            },
        )
    )
    monkeypatch.setattr(
        "cairn.server.vuln_adapters.subprocess.run",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("offline adapter must not start a subprocess")
        ),
    )
    adapter = SavedResponseWebApiAdapter()
    execution = adapter.execute(context)
    parsed = adapter.parse(execution)

    assert parsed["records"][0]["detections"] == ["openapi"]
    assert parsed["records"][0]["response_id"] == "http_response_001"
    assert adapter.estimate(context)["network_request_count"] == 0
    assert adapter.materialize(context) == []
    assert adapter.uses_http is False
    assert adapter.uses_network is False


def test_browser_archive_adapter_is_offline_and_extracts_structural_evidence(
    monkeypatch,
) -> None:
    response_text = (
        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"
        "<html><head><title> Account Portal </title>"
        "<script src='/static/app.js'></script></head>"
        "<body><a href='/api/v1/users'>users</a>"
        "<a href='https://outside.invalid/leak'>outside</a>"
        "<form action='/login' method='post'><input name='username'>"
        "<input name='password' type='password'></form>"
        "<script>fetch('/graphql')</script></body></html>"
    )
    context = _context(
        http_responses=(
            {
                "id": "http_response_archive",
                "asset_id": "asset_001",
                "task_id": "capture_task_001",
                "domain": "example.com",
                "url": "https://example.com/portal",
                "response_text": response_text,
                "response_hash": hashlib.sha256(response_text.encode()).hexdigest(),
                "content_truncated": 0,
            },
        )
    )
    monkeypatch.setattr(
        "cairn.server.vuln_adapters.subprocess.run",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("archive analysis must not start a subprocess")
        ),
    )

    adapter = BrowserArchiveAnalyzeAdapter()
    execution = adapter.execute(context)
    record = adapter.parse(execution)["records"][0]

    assert record["title"] == "Account Portal"
    assert "https://example.com/api/v1/users" in record["endpoint_candidates"]
    assert "https://example.com/graphql" in record["endpoint_candidates"]
    assert record["scripts"] == ["https://example.com/static/app.js"]
    assert record["forms"][0]["method"] == "POST"
    assert record["forms"][0]["fields"][1] == {
        "name": "password",
        "type": "password",
    }
    assert record["analysis_kind"] == "html"
    assert all("outside.invalid" not in item for item in record["endpoint_candidates"])
    assert adapter.estimate(context)["network_request_count"] == 0
    assert adapter.materialize(context) == []
    assert adapter.coverage_complete(context, {"records": [record]}) is False


def test_browser_archive_adapter_analyzes_saved_javascript_and_har_without_secrets(
    monkeypatch,
) -> None:
    javascript = (
        "fetch('/api/v2/users?all=true');\n"
        "axios.get(\"/graphql\");\n"
        "const telemetry = 'https://outside.invalid/collect';\n"
        "//# sourceMappingURL=app.js.map\n"
    )
    javascript_response = (
        "HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\n\r\n"
        + javascript
    )
    har_payload = {
        "log": {
            "version": "1.2",
            "entries": [
                {
                    "request": {
                        "method": "GET",
                        "url": "https://example.com/api/orders",
                        "headers": [{"name": "Authorization", "value": "secret"}],
                    },
                    "response": {
                        "status": 200,
                        "headers": [{"name": "Content-Type", "value": "application/json"}],
                        "content": {"size": 123, "mimeType": "application/json"},
                    },
                },
                {
                    "request": {
                        "method": "POST",
                        "url": "https://example.com/graphql",
                        "headers": [],
                        "postData": {"text": "top-secret-value"},
                    },
                    "response": {
                        "status": "200",
                        "headers": [],
                        "content": {"size": "45", "mimeType": "application/json"},
                    },
                },
                {
                    "request": {
                        "method": "GET",
                        "url": "https://example.com/static/chunk.js",
                        "headers": [],
                    },
                    "response": {
                        "status": 200,
                        "headers": [],
                        "content": {"size": 88, "mimeType": "application/javascript"},
                    },
                },
                {
                    "request": {
                        "method": "GET",
                        "url": "https://outside.invalid/private",
                        "headers": [],
                    },
                    "response": {"status": 200, "headers": [], "content": {}},
                },
            ],
        }
    }
    har_response = (
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n"
        + json.dumps(har_payload)
    )
    context = _context(
        http_responses=(
            {
                "id": "http_response_js",
                "asset_id": "asset_001",
                "task_id": "capture_task_001",
                "domain": "example.com",
                "url": "https://example.com/static/app.js",
                "response_text": javascript_response,
                "response_hash": hashlib.sha256(javascript_response.encode()).hexdigest(),
                "content_truncated": 0,
            },
            {
                "id": "http_response_har",
                "asset_id": "asset_001",
                "task_id": "capture_task_001",
                "domain": "example.com",
                "url": "https://example.com/capture.har",
                "response_text": har_response,
                "response_hash": hashlib.sha256(har_response.encode()).hexdigest(),
                "content_truncated": 0,
            },
        )
    )
    monkeypatch.setattr(
        "cairn.server.vuln_adapters.subprocess.run",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("archive analysis must remain fully offline")
        ),
    )

    adapter = BrowserArchiveAnalyzeAdapter()
    records = {
        record["analysis_kind"]: record
        for record in adapter.parse(adapter.execute(context))["records"]
    }

    assert set(records) == {"javascript", "har"}
    javascript_record = records["javascript"]
    assert {
        "https://example.com/api/v2/users?all=true",
        "https://example.com/graphql",
    } <= set(javascript_record["endpoint_candidates"])
    assert javascript_record["scripts"] == [
        "https://example.com/static/app.js.map"
    ]
    assert javascript_record["cross_origin_reference_count"] == 1
    har_record = records["har"]
    assert len(har_record["har_entries"]) == 3
    assert "https://example.com/api/orders" in har_record["endpoint_candidates"]
    assert har_record["scripts"] == ["https://example.com/static/chunk.js"]
    assert har_record["cross_origin_reference_count"] == 1
    serialized = json.dumps(records, sort_keys=True)
    assert "top-secret-value" not in serialized
    assert '"value": "secret"' not in serialized
    assert har_record["har_entries"][1]["request_body_sha256"] == hashlib.sha256(
        b"top-secret-value"
    ).hexdigest()


def test_playwright_runner_config_and_request_guard_enforce_safe_boundary() -> None:
    config = validate_capture_config(
        {
            "target": "https://example.com/start",
            "campaign_id": "vuln_001",
            "task_id": "task_001",
            "request_header": "X-Cairn-Research",
            "request_header_value": "campaign=vuln_001; task=task_001",
            "max_requests_per_second": 2,
            "max_requests": 20,
            "max_pages": 5,
            "depth": 2,
            "timeout_seconds": 60,
            "database_path": "",
            "proxy_url": "",
        }
    )
    assert config["target"] == "https://example.com/start"
    assert request_is_allowed(
        config["target"], "https://example.com/api", "GET", 0, 20
    ) == (True, "allowed")
    assert request_is_allowed(
        config["target"], "https://evil.invalid/", "GET", 0, 20
    ) == (False, "cross_origin")
    assert request_is_allowed(
        config["target"], "https://example.com/api", "POST", 0, 20
    ) == (False, "state_changing_method")
    assert request_is_allowed(
        config["target"], "https://example.com/api", "GET", 20, 20
    ) == (False, "request_budget_exhausted")
    with pytest.raises(CaptureConfigurationError, match="request header is unsafe"):
        validate_capture_config({**config, "request_header": "Host"})


def test_playwright_response_callback_never_waits_for_network_body() -> None:
    class FakeRequest:
        url = "https://example.com/start"
        method = "GET"
        resource_type = "document"
        headers = {"X-Cairn-Research": "bounded"}

    class FakeResponse:
        request = FakeRequest()
        headers = {"Content-Type": "text/html"}
        status = 200

        def body(self) -> bytes:
            raise AssertionError("response callback must not read a pending body")

    config = {"target": "https://example.com/start"}
    state = CaptureState(
        config=config,
        limiter=DurableRateLimiter(
            database_path=None,
            campaign_id="vuln-test",
            task_id="task-test",
            limit=2,
        ),
    )

    state.response(FakeResponse())
    assert state.responses is not None
    assert state.responses[0]["body_source"] == "not_captured"
    state.attach_document_body(
        "https://example.com/start", "<html><title>Captured</title></html>"
    )
    assert state.responses[0]["body_source"] == "rendered_dom"
    assert state.responses[0]["body_sha256"] == hashlib.sha256(
        b"<html><title>Captured</title></html>"
    ).hexdigest()


def test_browser_source_policy_rejects_session_material_and_unbounded_periodic_use() -> None:
    with pytest.raises(AdapterValidationError, match="forbidden fields"):
        validate_browser_evidence_source_config(
            {
                "adapter": "browser.evidence-session.v1",
                "cookies": [{"name": "session", "value": "secret"}],
            }
        )
    with pytest.raises(AdapterValidationError, match="exact URL target"):
        validate_browser_evidence_source_config(
            {
                "adapter": "browser.evidence-session.v1",
                "periodic_enabled": True,
                "targets": [],
            }
        )
    assert validate_browser_evidence_source_config(
        {
            "adapter": "browser.evidence-session.v1",
            "periodic_enabled": True,
            "targets": ["https://API.Example.com/start#fragment"],
            "max_requests": 10,
        }
    )["targets"] == ["https://api.example.com/start"]


def test_browser_evidence_adapter_materializes_stdin_only_and_extracts_screenshot(
    tmp_path: Path, monkeypatch
) -> None:
    db_path = tmp_path / "browser.db"
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute(
        "CREATE TABLE vuln_http_rate_events "
        "(id INTEGER PRIMARY KEY, campaign_id TEXT, task_id TEXT, observed_at REAL)"
    )
    context = AdapterContext(
        conn=conn,
        campaign_id="vuln-test",
        task_id="task-test",
        source={"id": "source-test", "name": "browser"},
        targets=("https://example.com/start",),
        max_requests_per_second=2,
        options={
            "depth": 2,
            "max_pages": 3,
            "max_requests": 8,
            "session_timeout_seconds": 30,
        },
    )
    adapter = BrowserEvidenceSessionAdapter()
    invocation = adapter.materialize(context)[0]
    materialized = json.loads(invocation.stdin or "{}")
    screenshot = b"bounded-jpeg-evidence"
    runner_output = {
        "target": "https://example.com/start",
        "pages": [
            {
                "url": "https://example.com/start",
                "final_url": "https://example.com/start",
                "depth": 1,
                "title": "Portal",
                "links": [],
                "scripts": [],
                "forms": [],
                "dom_sha256": "a" * 64,
                "screenshot_sha256": hashlib.sha256(screenshot).hexdigest(),
                "screenshot_base64": base64.b64encode(screenshot).decode(),
            }
        ],
        "responses": [],
        "blocked_requests": [],
        "request_count": 1,
        "request_budget": 8,
        "rate_limit": 2,
        "same_origin_only": True,
        "allowed_methods": ["GET", "HEAD"],
        "websockets_blocked": True,
        "service_workers_blocked": True,
        "persistent_profile": False,
        "network_path": "direct",
    }
    monkeypatch.setattr(
        adapter,
        "_execute_invocations",
        lambda unused_context, unused_invocations: AdapterExecution(
            (
                CommandResult(
                    target="https://example.com/start",
                    stdout=json.dumps(runner_output),
                    stderr="",
                    returncode=0,
                    duration_ms=10,
                ),
            )
        ),
    )

    execution = adapter.execute(context)
    parsed = adapter.parse(execution)

    assert invocation.argv == (
        adapter.binary,
        "-m",
        "cairn.server.playwright_capture",
        "--run",
    )
    assert "example.com" not in " ".join(invocation.argv)
    assert materialized["database_path"] == str(db_path.resolve())
    assert materialized["max_requests_per_second"] == 2
    assert materialized["max_requests"] == 8
    assert materialized["depth"] == 2
    assert "screenshot_base64" not in execution.results[0].stdout
    assert len(execution.sensitive_artifacts) == 1
    assert execution.sensitive_artifacts[0].content == screenshot
    assert parsed["sessions"][0]["pages"][0]["screenshot_artifact_key"]
    conn.close()


def test_nvd_kev_adapter_uses_fixed_official_https_endpoints_and_parses() -> None:
    context = _context(
        targets=("CVE-2026-12345",),
        vulnerabilities=(
            {"cve_id": "CVE-2026-12345", "finding_ids": ["finding_001"]},
        ),
    )
    adapter = NvdKevVulnerabilityIntelligenceAdapter()
    invocations = adapter.materialize(context)

    assert len(invocations) == 2
    assert invocations[0].target == "nvd:CVE-2026-12345"
    assert invocations[0].argv[-1] == (
        "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-12345"
    )
    assert invocations[1].target == "kev:CVE-2026-12345"
    assert invocations[1].argv[-1] == (
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    )
    assert all("http://" not in argument for item in invocations for argument in item.argv)
    parsed = adapter.parse(
        AdapterExecution(
            (
                CommandResult(
                    target="nvd:CVE-2026-12345",
                    stdout=json.dumps(
                        {
                            "vulnerabilities": [
                                {
                                    "cve": {
                                        "id": "CVE-2026-12345",
                                        "metrics": {
                                            "cvssMetricV31": [
                                                {
                                                    "type": "Primary",
                                                    "cvssData": {
                                                        "baseScore": 8.1,
                                                        "baseSeverity": "HIGH",
                                                    },
                                                }
                                            ]
                                        },
                                    }
                                }
                            ]
                        }
                    ),
                    stderr="",
                    returncode=0,
                    duration_ms=1,
                ),
                CommandResult(
                    target="kev:CVE-2026-12345",
                    stdout=json.dumps(
                        {
                            "vulnerabilities": [
                                {
                                    "cveID": "CVE-2026-12345",
                                    "vulnerabilityName": "Mock KEV entry",
                                }
                            ]
                        }
                    ),
                    stderr="",
                    returncode=0,
                    duration_ms=1,
                ),
            )
        )
    )
    assert parsed["enrichments"][0]["nvd"]["id"] == "CVE-2026-12345"
    assert parsed["enrichments"][0]["kev"]["vulnerabilityName"] == "Mock KEV entry"
    assert adapter.coverage_complete(context, parsed) is True


def test_fofa_adapter_uses_exact_bounded_queries_without_credential_in_argv(
    monkeypatch,
) -> None:
    api_key = "0123456789abcdef0123456789abcdef"
    monkeypatch.setenv(
        "CAIRN_FOFA_CREDENTIALS",
        json.dumps({"production-search": {"key": api_key}}),
    )
    base_context = _context(targets=("Example.COM", "203.0.113.9"))
    context = AdapterContext(
        **{
            **base_context.__dict__,
            "source": {
                "id": "source-fofa",
                "name": "FOFA scoped asset search",
                "config_json": json.dumps(
                    {"credential_ref": "production-search", "page_size": 25}
                ),
            },
            "cursor": {"next_by_target": {"example.com": "next-page-token"}},
        }
    )
    adapter = FofaAssetSearchAdapter()
    invocations = adapter.materialize(context)

    assert [item.target for item in invocations] == ["example.com", "203.0.113.9"]
    assert all(item.argv[-1] == "https://fofa.info/api/v1/search/next" for item in invocations)
    assert all(api_key not in "\0".join(item.argv) for item in invocations)
    assert all("full=false" in item.argv for item in invocations)
    assert all("size=25" in item.argv for item in invocations)
    encoded = next(
        value.removeprefix("qbase64=")
        for value in invocations[0].argv
        if value.startswith("qbase64=")
    )
    assert base64.b64decode(encoded).decode() == 'domain="example.com"'
    assert "next=next-page-token" in invocations[0].argv
    assert invocations[0].stdin == f'data-urlencode = "key={api_key}"\n'

    calls: list[tuple[list[str], dict]] = []

    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        target = "example.com" if len(calls) == 1 else "203.0.113.9"
        return subprocess.CompletedProcess(
            argv,
            0,
            json.dumps(
                {
                    "error": False,
                    "results": [
                        [
                            f"https://{target}",
                            "203.0.113.9",
                            443,
                            "https",
                            "example.com",
                            "Example",
                            "nginx",
                            "nginx",
                            "1.24",
                            "2026-09-01 00:00:00",
                            "CN",
                            "Beijing",
                            "AS64500",
                        ]
                    ],
                }
            ),
            "",
        )

    monkeypatch.setattr("cairn.server.vuln_adapters.subprocess.run", run)
    execution = adapter.execute(context)
    parsed = adapter.parse(execution)

    assert len(calls) == 2
    assert all(call[1]["shell"] is False for call in calls)
    assert all(call[1]["input"] == f'data-urlencode = "key={api_key}"\n' for call in calls)
    assert parsed["records"][0]["product"] == "nginx"
    assert parsed["records"][0]["query_target"] == "example.com"
    assert parsed["next_by_target"] == {}
    assert adapter.estimate(context)["network_request_count"] == 2


def test_fofa_adapter_rejects_plaintext_or_malformed_credentials(monkeypatch) -> None:
    base_context = _context()
    context = AdapterContext(
        **{
            **base_context.__dict__,
            "source": {
                "id": "source-fofa",
                "name": "FOFA scoped asset search",
                "config_json": json.dumps(
                    {"credential_ref": "production-search", "page_size": 100}
                ),
            },
        }
    )
    adapter = FofaAssetSearchAdapter()

    monkeypatch.setenv("CAIRN_FOFA_CREDENTIALS", '{"production-search":"bad\\nkey"}')
    with pytest.raises(AdapterUnavailableError, match="malformed"):
        adapter.validate(context)

    monkeypatch.setenv("CAIRN_FOFA_CREDENTIALS", "not-json")
    with pytest.raises(AdapterUnavailableError, match="must be a JSON object"):
        adapter.validate(context)


def test_gitleaks_adapter_is_local_redacted_and_path_allowlisted(
    tmp_path: Path, monkeypatch
) -> None:
    allowed_root = tmp_path / "authorized"
    repository = allowed_root / "repository"
    repository.mkdir(parents=True)
    binary = tmp_path / "gitleaks"
    binary.write_bytes(b"pinned-gitleaks-test-binary")
    monkeypatch.setenv("CAIRN_GITLEAKS_ALLOWED_ROOTS", str(allowed_root))
    monkeypatch.setattr(
        "cairn.server.vuln_adapters.GITLEAKS_BINARY_SHA256",
        hashlib.sha256(binary.read_bytes()).hexdigest(),
    )
    monkeypatch.setattr(
        "cairn.server.vuln_adapters.shutil.which", lambda value: str(binary)
    )
    context = _context(
        targets=(str(repository),),
    )
    context = AdapterContext(
        **{
            **context.__dict__,
            "repositories": (
                {"asset_id": "asset-repository", "path": str(repository)},
            ),
        }
    )
    adapter = GitleaksLocalRepositoryAdapter()
    adapter.binary = str(binary)
    invocation = adapter.materialize(context)[0]
    assert invocation.argv[-1] == str(repository.resolve())
    assert "--redact=100" in invocation.argv
    assert "--follow-symlinks" not in invocation.argv
    assert "--max-decode-depth" in invocation.argv
    assert adapter.uses_network is False
    assert adapter.uses_http is False
    assert adapter.requires_human_approval is True
    assert adapter.health()["healthy"] is True

    secret = "this-must-never-be-persisted"
    monkeypatch.setattr(
        "cairn.server.vuln_adapters.subprocess.run",
        lambda argv, **kwargs: subprocess.CompletedProcess(
            argv,
            0,
            json.dumps(
                [
                    {
                        "RuleID": "generic-api-key",
                        "Description": "Generic API key",
                        "File": "config/settings.py",
                        "StartLine": 7,
                        "EndLine": 7,
                        "Commit": "abc123",
                        "Secret": secret,
                        "Match": f"token={secret}",
                    }
                ]
            ),
            "",
        ),
    )
    parsed = adapter.parse(adapter.execute(context))
    serialized = json.dumps(parsed, sort_keys=True)
    assert secret not in serialized
    assert parsed["findings"][0]["file"] == "config/settings.py"
    assert parsed["findings"][0]["redacted"] is True


def test_gitleaks_adapter_rejects_repository_outside_allowed_root(
    tmp_path: Path, monkeypatch
) -> None:
    allowed_root = tmp_path / "authorized"
    outside = tmp_path / "outside"
    allowed_root.mkdir()
    outside.mkdir()
    monkeypatch.setenv("CAIRN_GITLEAKS_ALLOWED_ROOTS", str(allowed_root))
    context = AdapterContext(
        **{
            **_context(targets=(str(outside),)).__dict__,
            "repositories": (
                {"asset_id": "asset-repository", "path": str(outside)},
            ),
        }
    )
    with pytest.raises(AdapterValidationError, match="outside configured"):
        GitleaksLocalRepositoryAdapter().validate(context)


def test_cancellable_process_runner_terminates_before_hard_timeout() -> None:
    started = time.monotonic()
    context = AdapterContext(
        **{
            **_context(targets=()).__dict__,
            "cancellation_probe": lambda: (
                "Campaign paused" if time.monotonic() - started >= 0.2 else None
            ),
        }
    )
    adapter = GitleaksLocalRepositoryAdapter()
    adapter.timeout_seconds = 10
    with pytest.raises(AdapterCancellationError) as cancelled:
        adapter._execute_invocations(
            context,
            [
                AdapterInvocation(
                    argv=(sys.executable, "-c", "import time; time.sleep(30)"),
                    target="local-test-process",
                )
            ],
        )
    elapsed = time.monotonic() - started
    assert elapsed < 3
    assert cancelled.value.execution is not None
    assert cancelled.value.execution.results[0].returncode != 0


def test_syft_adapter_is_hash_pinned_no_network_and_parses_cyclonedx(
    tmp_path: Path, monkeypatch
) -> None:
    allowed_root = tmp_path / "authorized"
    repository = allowed_root / "repository"
    repository.mkdir(parents=True)
    (repository / "requirements.txt").write_text(
        "requests==2.31.0\n", encoding="utf-8"
    )
    binary = tmp_path / "syft"
    binary.write_bytes(b"pinned-syft-test-binary")
    monkeypatch.setenv("CAIRN_SUPPLY_CHAIN_ALLOWED_ROOTS", str(allowed_root))
    monkeypatch.setattr(
        "cairn.server.vuln_adapters.SYFT_BINARY_SHA256",
        hashlib.sha256(binary.read_bytes()).hexdigest(),
    )

    def fake_which(value: str) -> str | None:
        return str(binary) if Path(value).name == "syft" else "/usr/bin/unshare"

    monkeypatch.setattr("cairn.server.vuln_adapters.shutil.which", fake_which)
    context = AdapterContext(
        **{
            **_context(targets=(str(repository),)).__dict__,
            "repositories": (
                {"asset_id": "asset-repository", "path": str(repository)},
            ),
        }
    )
    adapter = SyftLocalSbomAdapter()
    adapter.binary = str(binary)
    invocation = adapter.materialize(context)[0]
    assert invocation.argv[:5] == (
        "/usr/bin/unshare",
        "--user",
        "--map-current-user",
        "--net",
        "--",
    )
    assert invocation.argv[5:8] == (
        str(binary),
        "scan",
        f"dir:{repository.resolve()}",
    )
    assert invocation.argv[invocation.argv.index("--parallelism") + 1] == "1"
    assert invocation.argv[-2:] == ("--output", "cyclonedx-json@1.6")
    assert adapter.uses_network is False
    assert adapter.requires_human_approval is True
    assert adapter.health()["healthy"] is True

    payload = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "components": [
            {
                "type": "library",
                "name": "requests",
                "version": "2.31.0",
                "purl": "pkg:pypi/requests@2.31.0",
                "licenses": [{"license": {"id": "Apache-2.0"}}],
                "hashes": [{"alg": "SHA-256", "content": "ab" * 32}],
                "properties": [{"name": "syft:location", "value": "/secret/path"}],
            }
        ],
    }
    calls: list[tuple[list[str], dict]] = []

    def fake_run(argv, **kwargs):
        calls.append((argv, kwargs))
        return subprocess.CompletedProcess(argv, 0, json.dumps(payload), "")

    monkeypatch.setattr("cairn.server.vuln_adapters.subprocess.run", fake_run)
    execution = adapter.execute(context)
    parsed = adapter.parse(execution)
    component = parsed["documents"][0]["components"][0]
    assert component["dependency"] == {
        "ecosystem": "PyPI",
        "name": "requests",
        "version": "2.31.0",
        "identifier": "PyPI:requests@2.31.0",
    }
    assert component["licenses"] == ["Apache-2.0"]
    assert "/secret/path" not in json.dumps(parsed)
    assert execution.sensitive_artifacts[0].artifact_kind == "cyclonedx_sbom"
    assert execution.sensitive_artifacts[0].content == json.dumps(payload).encode()
    assert calls[0][1]["shell"] is False
    assert calls[0][1]["stdin"] is subprocess.DEVNULL


def test_syft_adapter_rejects_outside_target_and_escaping_symlink(
    tmp_path: Path, monkeypatch
) -> None:
    allowed_root = tmp_path / "authorized"
    repository = allowed_root / "repository"
    outside = tmp_path / "outside"
    repository.mkdir(parents=True)
    outside.mkdir()
    monkeypatch.setenv("CAIRN_SUPPLY_CHAIN_ALLOWED_ROOTS", str(allowed_root))
    outside_context = AdapterContext(
        **{
            **_context(targets=(str(outside),)).__dict__,
            "repositories": ({"asset_id": "asset-outside", "path": str(outside)},),
        }
    )
    with pytest.raises(AdapterValidationError, match="outside configured Syft roots"):
        SyftLocalSbomAdapter().validate(outside_context)

    link = repository / "escape"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlinks are unavailable on this platform")
    linked_context = AdapterContext(
        **{
            **_context(targets=(str(repository),)).__dict__,
            "repositories": (
                {"asset_id": "asset-repository", "path": str(repository)},
            ),
        }
    )
    with pytest.raises(AdapterValidationError, match="symlink escaping"):
        SyftLocalSbomAdapter().validate(linked_context)


def test_syft_container_archive_adapter_is_bounded_offline_and_parses_cyclonedx(
    tmp_path: Path, monkeypatch
) -> None:
    allowed_root = tmp_path / "authorized-images"
    allowed_root.mkdir()
    archive_path = allowed_root / "demo-image.tar"

    def write_member(archive: tarfile.TarFile, name: str, content: bytes) -> None:
        member = tarfile.TarInfo(name)
        member.size = len(content)
        member.mode = 0o600
        archive.addfile(member, io.BytesIO(content))

    with tarfile.open(archive_path, "w") as archive:
        write_member(archive, "manifest.json", b"[]")
        write_member(archive, "config.json", b"{}")

    binary = tmp_path / "syft"
    binary.write_bytes(b"pinned-container-syft-test-binary")
    monkeypatch.setenv("CAIRN_SUPPLY_CHAIN_ALLOWED_ROOTS", str(allowed_root))
    monkeypatch.setattr(
        "cairn.server.vuln_adapters.SYFT_BINARY_SHA256",
        hashlib.sha256(binary.read_bytes()).hexdigest(),
    )
    monkeypatch.setattr(
        "cairn.server.vuln_adapters.shutil.which",
        lambda value: str(binary) if Path(value).name == "syft" else "/usr/bin/unshare",
    )
    context = AdapterContext(
        **{
            **_context(targets=(str(archive_path),)).__dict__,
            "container_archives": (
                {
                    "asset_id": "asset-container",
                    "asset_type": "container_image",
                    "path": str(archive_path),
                    "archive_format": "docker-archive",
                },
            ),
        }
    )
    adapter = SyftContainerArchiveSbomAdapter()
    adapter.binary = str(binary)
    invocation = adapter.materialize(context)[0]
    assert invocation.argv[:8] == (
        "/usr/bin/unshare",
        "--user",
        "--map-current-user",
        "--net",
        "--",
        str(binary),
        "scan",
        f"docker-archive:{archive_path.resolve()}",
    )
    assert invocation.argv[-2:] == ("--output", "cyclonedx-json@1.6")
    assert adapter.uses_network is False
    payload = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "components": [
            {
                "type": "library",
                "name": "requests",
                "version": "2.31.0",
                "purl": "pkg:pypi/requests@2.31.0",
                "properties": [{"name": "syft:location", "value": "/secret/layer"}],
            }
        ],
    }
    monkeypatch.setattr(
        "cairn.server.vuln_adapters.subprocess.run",
        lambda argv, **kwargs: subprocess.CompletedProcess(
            argv, 0, json.dumps(payload), f"scanned {archive_path}"
        ),
    )
    execution = adapter.execute(context)
    parsed = adapter.parse(execution)
    assert parsed["documents"][0]["components"][0]["dependency"] == {
        "ecosystem": "PyPI",
        "name": "requests",
        "version": "2.31.0",
        "identifier": "PyPI:requests@2.31.0",
    }
    assert "/secret/layer" not in execution.results[0].stdout
    assert str(archive_path) not in execution.results[0].stderr
    assert execution.sensitive_artifacts[0].content == json.dumps(payload).encode()

    unsafe_path = allowed_root / "unsafe.tar"
    with tarfile.open(unsafe_path, "w") as archive:
        write_member(archive, "manifest.json", b"[]")
        write_member(archive, "../escape", b"unsafe")
    unsafe_context = AdapterContext(
        **{
            **_context(targets=(str(unsafe_path),)).__dict__,
            "container_archives": (
                {"asset_id": "asset-unsafe", "path": str(unsafe_path)},
            ),
        }
    )
    with pytest.raises(AdapterValidationError, match="unsafe outer member"):
        adapter.validate(unsafe_context)

    symlink_path = allowed_root / "linked-image.tar"
    symlink_path.symlink_to(archive_path)
    symlink_context = AdapterContext(
        **{
            **_context(targets=(str(symlink_path),)).__dict__,
            "container_archives": (
                {"asset_id": "asset-linked", "path": str(symlink_path)},
            ),
        }
    )
    with pytest.raises(AdapterValidationError, match="regular local archive"):
        adapter.validate(symlink_context)


def test_trivy_container_adapter_uses_container_subjects() -> None:
    adapter = TrivyContainerSbomVulnerabilityAdapter()
    context = AdapterContext(
        **{
            **_context(targets=()).__dict__,
            "container_archives": (
                {"asset_id": "asset-container", "path": "/authorized/image.tar"},
            ),
        }
    )
    assert adapter._subjects(context) == context.container_archives
    assert adapter.tool_id == "trivy.container-sbom-vuln.v1"
    assert adapter.risk_class == "R0"
    assert adapter.uses_network is False


def test_trivy_adapter_is_offline_pinned_and_sanitizes_output(
    tmp_path, monkeypatch
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    binary = tmp_path / "trivy"
    binary.write_bytes(b"audited-trivy-test-binary")
    database_root = tmp_path / "trivy-db"
    database_dir = database_root / "db"
    database_dir.mkdir(parents=True)
    database = database_dir / "trivy.db"
    database.write_bytes(b"audited-db")
    metadata = database_dir / "metadata.json"
    metadata.write_text(
        json.dumps(
            {
                "Version": 2,
                "UpdatedAt": "2026-09-03T01:14:45.115995799Z",
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("CAIRN_TRIVY_DB_ROOT", str(database_root))
    monkeypatch.setattr(
        "cairn.server.vuln_adapters.TRIVY_BINARY_SHA256",
        hashlib.sha256(binary.read_bytes()).hexdigest(),
    )
    monkeypatch.setattr(
        "cairn.server.vuln_adapters.TRIVY_DB_SHA256",
        hashlib.sha256(database.read_bytes()).hexdigest(),
    )
    monkeypatch.setattr(
        "cairn.server.vuln_adapters.TRIVY_DB_METADATA_SHA256",
        hashlib.sha256(metadata.read_bytes()).hexdigest(),
    )
    adapter = TrivySbomVulnerabilityAdapter()
    monkeypatch.setattr(adapter, "binary", str(binary))
    monkeypatch.setattr(
        "cairn.server.vuln_adapters.shutil.which",
        lambda value: str(binary) if Path(value).name == "trivy" else "/usr/bin/unshare",
    )
    sbom_content = json.dumps(
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "components": [
                {
                    "type": "library",
                    "name": "requests",
                    "version": "2.31.0",
                    "purl": "pkg:pypi/requests@2.31.0",
                }
            ],
        }
    ).encode()
    context = AdapterContext(
        **{
            **_context().__dict__,
            "repositories": (
                {"asset_id": "asset-repository", "path": str(repository)},
            ),
            "sboms": (
                {
                    "id": "sbom-001",
                    "repository_asset_id": "asset-repository",
                    "document_hash": hashlib.sha256(sbom_content).hexdigest(),
                    "vault_ref": "vault-001",
                    "content": sbom_content,
                },
            ),
        }
    )
    captured: list[tuple[list[str], dict]] = []
    raw_output = {
        "ArtifactName": "/secret/repository/path",
        "Results": [
            {
                "Target": "/secret/repository/path/requirements.txt",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2026-12345",
                        "PkgName": "requests",
                        "PkgIdentifier": {"PURL": "pkg:pypi/requests@2.31.0"},
                        "InstalledVersion": "2.31.0",
                        "FixedVersion": "2.32.0",
                        "Severity": "HIGH",
                        "Title": "Example dependency issue",
                        "Description": "Bounded advisory detail",
                        "PrimaryURL": "https://example.invalid/CVE-2026-12345",
                        "References": ["https://example.invalid/reference"],
                        "CVSS": {"nvd": {"V3Score": 8.1, "V3Vector": "CVSS:3.1/test"}},
                    }
                ],
            }
        ],
    }
    hash_calls: list[Path] = []
    original_sha256_file = vuln_adapters_module._sha256_file

    def counting_sha256_file(path: Path) -> str:
        hash_calls.append(path)
        return original_sha256_file(path)

    monkeypatch.setattr(
        "cairn.server.vuln_adapters._sha256_file", counting_sha256_file
    )

    def fake_run(argv, **kwargs):
        captured.append((argv, kwargs))
        return subprocess.CompletedProcess(
            argv, 0, json.dumps(raw_output), "reading /secret/repository/path"
        )

    monkeypatch.setattr("cairn.server.vuln_adapters.subprocess.run", fake_run)
    assert adapter.health()["healthy"] is True
    execution = adapter.execute(context)
    parsed = adapter.parse(execution)

    assert len(captured) == 1
    argv = captured[0][0]
    assert argv[:5] == ["/usr/bin/unshare", "--user", "--map-current-user", "--net", "--"]
    assert "--offline-scan" in argv
    assert "--skip-db-update" in argv
    assert "--skip-java-db-update" in argv
    assert "--skip-vex-repo-update" in argv
    assert "http://" not in " ".join(argv)
    assert "https://" not in " ".join(argv)
    assert not Path(argv[-1]).exists()
    assert "/secret/repository/path" not in execution.results[0].stdout
    assert "/secret/repository/path" not in execution.results[0].stderr
    assert "TRIVY STDERR REDACTED" in execution.results[0].stderr
    finding = parsed["documents"][0]["findings"][0]
    assert finding["vulnerability_id"] == "CVE-2026-12345"
    assert finding["purl"] == "pkg:pypi/requests@2.31.0"
    assert finding["cvss_score"] == 8.1
    assert hash_calls.count(database) == 1
    assert hash_calls.count(metadata) == 1
    assert adapter.coverage_complete(context, parsed) is True
    assert adapter.uses_network is False
    assert adapter.requires_human_approval is True
    monkeypatch.setattr(
        "cairn.server.vuln_adapters.subprocess.run",
        lambda argv, **kwargs: subprocess.CompletedProcess(
            argv, 2, "/secret/repository/path", "failed at /secret/repository/path"
        ),
    )
    with pytest.raises(AdapterExecutionError) as failed:
        adapter.execute(context)
    assert failed.value.execution is not None
    failure_artifact = failed.value.execution.results[0]
    assert "/secret/repository/path" not in failure_artifact.stdout
    assert "/secret/repository/path" not in failure_artifact.stderr
    metadata.write_text(metadata.read_text(encoding="utf-8") + " ", encoding="utf-8")
    assert adapter.health()["healthy"] is False
    assert "metadata hash has drifted" in adapter.health()["error"]


ADAPTER_CASES = (
    (
        CertificateTransparencyAdapter(),
        _context(),
        '[{"name_value":"api.example.com\\n*.cdn.example.com"}]',
        lambda parsed: parsed["domains"] == ["api.example.com", "cdn.example.com"],
    ),
    (
        OsvVulnerabilityIntelligenceAdapter(),
        _context(
            targets=(),
            packages=(
                {
                    "asset_id": "asset-1",
                    "identifier": "PyPI:requests@2.31.0",
                    "normalized_identifier": "pypi:requests@2.31.0",
                    "scope_state": "in",
                    "ecosystem": "PyPI",
                    "name": "requests",
                    "version": "2.31.0",
                },
            ),
        ),
        '{"results":[{"vulns":[{"id":"OSV-TEST-1"}]}]}',
        lambda parsed: parsed["results"][0]["vulns"][0]["id"] == "OSV-TEST-1",
    ),
    (
        SubfinderPassiveDnsAdapter(),
        _context(),
        "api.example.com\nbilling.example.com\n",
        lambda parsed: parsed["domains"] == ["api.example.com", "billing.example.com"],
    ),
    (
        AmassPassiveEnumAdapter(),
        _context(),
        "api.example.com\n",
        lambda parsed: parsed["domains"] == ["api.example.com"],
    ),
    (
        RdapDomainAdapter(),
        _context(),
        json.dumps(
            {
                "handle": "EXAMPLE-COM",
                "ldhName": "EXAMPLE.COM",
                "status": ["active"],
                "nameservers": [{"ldhName": "NS1.EXAMPLE.COM"}],
                "entities": [{"vcardArray": ["vcard", [["email", {}, "text", "private@example.com"]]]}],
            }
        ),
        lambda parsed: parsed["records"][0] == {
            "domain": "example.com",
            "handle": "EXAMPLE-COM",
            "ldh_name": "EXAMPLE.COM",
            "unicode_name": None,
            "status": ["active"],
            "events": [],
            "nameservers": ["NS1.EXAMPLE.COM"],
            "delegation_signed": None,
        },
    ),
    (
        WhoisDomainAdapter(),
        _context(),
        "Domain Name: EXAMPLE.COM\nRegistrar: Example Registrar\nRegistrant Email: private@example.com\nName Server: NS1.EXAMPLE.COM\n",
        lambda parsed: parsed["records"][0] == {
            "domain": "example.com",
            "domain_name": "EXAMPLE.COM",
            "registrar": "Example Registrar",
            "name_servers": ["NS1.EXAMPLE.COM"],
        },
    ),
    (
        DnsxResolveAdapter(),
        _context(),
        json.dumps(
            {
                "host": "example.com",
                "status_code": "NOERROR",
                "a": ["93.184.216.34"],
                "aaaa": ["2606:2800:220:1:248:1893:25c8:1946"],
                "cname": ["edge.example.net"],
                "ns": ["a.iana-servers.net"],
                "resolver": ["1.1.1.1:53"],
            }
        ),
        lambda parsed: parsed["records"][0]["a"] == ["93.184.216.34"],
    ),
    (
        HttpxHttpMetadataAdapter(),
        _context(),
        json.dumps(
            {
                "input": "example.com",
                "url": "https://example.com",
                "scheme": "https",
                "method": "GET",
                "status_code": 200,
                "title": "Example Domain",
                "webserver": "nginx",
                "tech": ["nginx"],
                "host_ip": "93.184.216.34",
                "content_type": "text/html",
                "content_length": 1256,
            }
        ),
        lambda parsed: parsed["records"][0]["status_code"] == 200,
    ),
    (
        TlsxTlsMetadataAdapter(),
        _context(),
        json.dumps(
            {
                "host": "example.com",
                "port": "443",
                "probe_status": True,
                "tls_version": "tls13",
                "cipher": "TLS_AES_256_GCM_SHA384",
                "subject_cn": "example.com",
                "subject_an": ["example.com", "www.example.com"],
                "issuer_cn": "Example CA",
                "serial": "01",
                "not_before": "2026-01-01T00:00:00Z",
                "not_after": "2027-01-01T00:00:00Z",
                "chain": [
                    {
                        "subject_cn": "Example CA",
                        "issuer_cn": "Example Root",
                        "serial": "02",
                    }
                ],
            }
        ),
        lambda parsed: (
            parsed["records"][0]["tls_version"] == "tls13"
            and parsed["records"][0]["certificate_chain"][0]["issuer_cn"]
            == "Example Root"
        ),
    ),
)


@pytest.mark.parametrize(
    ("adapter", "context", "stdout", "assert_parsed"),
    ADAPTER_CASES,
    ids=[case[0].tool_id for case in ADAPTER_CASES],
)
def test_controlled_adapters_materialize_argument_arrays_and_parse_mocked_output(
    adapter, context, stdout, assert_parsed, monkeypatch
) -> None:
    calls: list[tuple[list[str], dict]] = []
    monkeypatch.setattr(
        "cairn.server.vuln_adapters.shutil.which",
        lambda binary: f"/mock/{binary}",
    )

    def fake_run(argv, **kwargs):
        calls.append((argv, kwargs))
        if str(argv[0]).startswith("/mock/"):
            return subprocess.CompletedProcess(argv, 0, f"{adapter.binary} mock 1.0\n", "")
        return subprocess.CompletedProcess(argv, 0, stdout, "")

    monkeypatch.setattr("cairn.server.vuln_adapters.subprocess.run", fake_run)
    adapter.validate(context)
    invocations = adapter.materialize(context)
    estimate = adapter.estimate(context)
    assert estimate["command_count"] == len(invocations)
    assert all(isinstance(invocation.argv, tuple) for invocation in invocations)
    assert all(isinstance(argument, str) for invocation in invocations for argument in invocation.argv)
    if adapter.tool_id == "amass.passive-enum.v1":
        assert "-passive" in invocations[0].argv
    if adapter.tool_id == "tlsx.tls-meta.v1":
        assert len(invocations) == 2
        assert {"-tls-version", "-cipher", "-probe-status"} <= set(invocations[0].argv)
        assert {"-certificate", "-tls-chain"} <= set(invocations[1].argv)
        assert {"-san", "-cn", "-so", "-serial"}.isdisjoint(
            argument for invocation in invocations for argument in invocation.argv
        )
    if adapter.tool_id == "httpx.http-meta.v1":
        assert "-include-response" in invocations[0].argv
        assert "-omit-body" not in invocations[0].argv
    if adapter.uses_http:
        assert "X-Cairn-Research: campaign=vuln-test; task=task-test" in invocations[0].argv

    health = adapter.health()
    execution = adapter.execute(context)
    parsed = adapter.parse(execution)

    assert health["healthy"] is True
    assert health["version"] == f"{adapter.binary} mock 1.0"
    assert assert_parsed(parsed)
    assert len(execution.output_hash) == 64
    assert execution.output_size == len(stdout.encode("utf-8")) * len(invocations)
    actual_call = calls[-1]
    assert actual_call[0] == list(invocations[-1].argv)
    assert actual_call[1]["capture_output"] is True
    assert actual_call[1]["text"] is True
    assert actual_call[1]["timeout"] == adapter.timeout_seconds
    assert actual_call[1]["shell"] is False
    if isinstance(adapter, DnsxResolveAdapter):
        assert actual_call[1]["input"] == "example.com\n"
        assert "stdin" not in actual_call[1]
    else:
        assert actual_call[1]["stdin"] is subprocess.DEVNULL


def test_adapter_registry_exposes_complete_lifecycle_metadata() -> None:
    assert set(ADAPTER_REGISTRY) == {
        "browser.archive-analyze.v1",
        "browser.evidence-session.v1",
        "crtsh.cert-transparency.v1",
        "fofa.asset-search.v1",
        "osv.vuln-intel.v1",
        "subfinder.passive-dns.v1",
        "amass.passive-enum.v1",
        "rdap.domain.v1",
        "whois.domain.v1",
        "dnsx.resolve.v1",
        "httpx.http-meta.v1",
        "tlsx.tls-meta.v1",
        "nuclei.passive-response.v1",
        "naabu.port-scan.v1",
        "katana.crawler.v1",
        "nvd-kev.vuln-intel.v1",
        "webapi.saved-response.v1",
        "gitleaks.secrets.v1",
        "syft.local-sbom.v1",
        "trivy.sbom-vuln.v1",
        "syft.container-archive-sbom.v1",
        "trivy.container-sbom-vuln.v1",
    }
    for tool_id, adapter in ADAPTER_REGISTRY.items():
        assert adapter.tool_id == tool_id
        assert adapter.version
        assert adapter.risk_class in {"R0", "R1", "R2", "R3"}
        assert adapter.input_schema["type"] == "object"
        assert adapter.output_schema["type"] == "object"
        for method in (
            "validate",
            "estimate",
            "materialize",
            "execute",
            "parse",
            "normalize",
            "coverage",
            "health",
        ):
            assert callable(getattr(adapter, method))


def test_r3_adapters_materialize_fixed_bounded_profiles() -> None:
    context = _context(targets=("api.example.com",))
    naabu = NaabuPortScanAdapter()
    katana = KatanaCrawlerAdapter()

    naabu_invocation = naabu.materialize(context)[0]
    assert naabu_invocation.argv[0].endswith("naabu")
    assert naabu_invocation.argv[1:3] == ("-host", "api.example.com")
    assert naabu_invocation.argv[naabu_invocation.argv.index("-top-ports") + 1] == "100"
    assert naabu_invocation.argv[naabu_invocation.argv.index("-c") + 1] == "1"
    assert all(";" not in value for value in naabu_invocation.argv)

    katana_invocation = katana.materialize(context)[0]
    assert katana_invocation.argv[0].endswith("katana")
    assert katana_invocation.argv[1:3] == ("-u", "https://api.example.com")
    assert katana_invocation.argv[katana_invocation.argv.index("-d") + 1] == "1"
    assert "-headless" not in katana_invocation.argv
    assert "-form-fill" not in katana_invocation.argv
    assert any("X-Cairn-Research: campaign=vuln-test" in value for value in katana_invocation.argv)


def test_r3_adapters_materialize_approved_ip_url_profile() -> None:
    naabu_context = _context(
        targets=("39.106.48.91",),
        options={"ports": [80, 443, 8080, 8443]},
    )
    katana_context = _context(
        targets=("http://39.106.48.91/",),
        options={"depth": 2},
    )
    naabu_context = AdapterContext(
        **{**naabu_context.__dict__, "max_requests_per_second": 2}
    )
    katana_context = AdapterContext(
        **{**katana_context.__dict__, "max_requests_per_second": 2}
    )

    naabu = NaabuPortScanAdapter()
    naabu.validate(naabu_context)
    naabu_argv = naabu.materialize(naabu_context)[0].argv
    assert naabu_argv[naabu_argv.index("-host") + 1] == "39.106.48.91"
    assert naabu_argv[naabu_argv.index("-p") + 1] == "80,443,8080,8443"
    assert "-top-ports" not in naabu_argv
    assert naabu_argv[naabu_argv.index("-rate") + 1] == "2"
    assert naabu_argv[naabu_argv.index("-c") + 1] == "1"
    assert naabu_argv[naabu_argv.index("-scan-type") + 1] == "c"
    assert "-Pn" in naabu_argv
    assert naabu_argv[naabu_argv.index("-timeout") + 1] == "1s"

    katana = KatanaCrawlerAdapter()
    katana.validate(katana_context)
    katana_argv = katana.materialize(katana_context)[0].argv
    assert katana_argv[katana_argv.index("-u") + 1] == "http://39.106.48.91/"
    assert katana_argv[katana_argv.index("-d") + 1] == "2"
    assert katana_argv[katana_argv.index("-fs") + 1] == "fqdn"
    assert katana_argv[katana_argv.index("-rl") + 1] == "2"
    assert katana_argv[katana_argv.index("-c") + 1] == "1"
    assert katana_argv[katana_argv.index("-p") + 1] == "1"
    assert katana_argv[katana_argv.index("-ct") + 1] == "60s"
    assert "-or" in katana_argv
    assert "-ob" in katana_argv
    assert "-jc" not in katana_argv
    assert "-kf" not in katana_argv


@pytest.mark.parametrize(
    ("adapter", "context"),
    [
        (NaabuPortScanAdapter(), _context(options={"ports": [0]})),
        (KatanaCrawlerAdapter(), _context(options={"depth": 3})),
    ],
)
def test_r3_adapters_reject_out_of_policy_options(adapter, context) -> None:
    with pytest.raises(AdapterValidationError):
        adapter.validate(context)


def test_r3_adapters_parse_only_bounded_in_scope_records() -> None:
    naabu = NaabuPortScanAdapter()
    ports = naabu.parse(
        AdapterExecution(
            (
                CommandResult(
                    target="api.example.com",
                    stdout=json.dumps({"host": "api.example.com", "ip": "203.0.113.7", "port": 443}),
                    stderr="",
                    returncode=0,
                    duration_ms=1,
                ),
            )
        )
    )
    assert ports == {
        "ports": [
            {"domain": "api.example.com", "ip": "203.0.113.7", "port": 443, "protocol": "tcp"}
        ]
    }

    katana = KatanaCrawlerAdapter()
    urls = katana.parse(
        AdapterExecution(
            (
                CommandResult(
                    target="api.example.com",
                    stdout="\n".join(
                        [
                            json.dumps({"url": "https://api.example.com/v1"}),
                            json.dumps({"url": "https://outside.invalid/ignored"}),
                        ]
                    ),
                    stderr="",
                    returncode=0,
                    duration_ms=1,
                ),
            )
        )
    )
    assert urls == {"urls": [{"domain": "api.example.com", "url": "https://api.example.com/v1"}]}


def test_r3_adapters_parse_realistic_projectdiscovery_jsonl() -> None:
    naabu = NaabuPortScanAdapter()
    naabu_execution = AdapterExecution(
        (
            CommandResult(
                target="39.106.48.91",
                stdout="\n".join(
                    [
                        json.dumps(
                            {
                                "ip": "39.106.48.91",
                                "port": 80,
                                "protocol": "tcp",
                                "tls": False,
                            }
                        ),
                        # Naabu can emit a duplicate during CONNECT verification.
                        json.dumps(
                            {
                                "ip": "39.106.48.91",
                                "port": 80,
                                "protocol": "tcp",
                                "tls": False,
                            }
                        ),
                    ]
                ),
                stderr="",
                returncode=0,
                duration_ms=100,
            ),
        )
    )
    assert naabu.parse(naabu_execution) == {
        "ports": [
            {
                "domain": "39.106.48.91",
                "ip": "39.106.48.91",
                "port": 80,
                "protocol": "tcp",
            }
        ]
    }

    katana = KatanaCrawlerAdapter()
    katana_execution = AdapterExecution(
        (
            CommandResult(
                target="http://39.106.48.91/",
                stdout=json.dumps(
                    {
                        "request": {
                            "method": "GET",
                            "endpoint": "http://39.106.48.91/login",
                        },
                        "response": {"status_code": 200},
                    }
                ),
                stderr="",
                returncode=0,
                duration_ms=100,
            ),
        )
    )
    assert katana.parse(katana_execution) == {
        "urls": [
            {"domain": "39.106.48.91", "url": "http://39.106.48.91/login"}
        ]
    }


@pytest.mark.parametrize(
    "adapter",
    [NaabuPortScanAdapter(), KatanaCrawlerAdapter()],
)
def test_r3_adapters_reject_empty_success_output(adapter) -> None:
    execution = AdapterExecution(
        (
            CommandResult(
                target="39.106.48.91",
                stdout="",
                stderr="",
                returncode=0,
                duration_ms=1,
            ),
        )
    )
    with pytest.raises(AdapterExecutionError, match="produced no JSONL output"):
        adapter.parse(execution)


def test_rdap_redirects_remain_https_only_and_bounded() -> None:
    invocation = RdapDomainAdapter().materialize(_context())[0]
    assert invocation.argv[invocation.argv.index("--max-redirs") + 1] == "5"
    assert invocation.argv[invocation.argv.index("--proto") + 1] == "=https"
    assert invocation.argv[invocation.argv.index("--proto-redir") + 1] == "=https"
    assert "--location" in invocation.argv


def test_tlsx_accepts_complete_json_emitted_before_hard_process_timeout(
    monkeypatch,
) -> None:
    adapter = TlsxTlsMetadataAdapter()
    context = _context()
    payload = json.dumps(
        {
            "host": "example.com",
            "tls_version": "tls13",
            "cipher": "TLS_AES_128_GCM_SHA256",
            "probe_status": True,
            "chain": [{"subject_cn": "Intermediate", "issuer_cn": "Root"}],
        }
    )
    monkeypatch.setattr(
        "cairn.server.vuln_adapters.shutil.which", lambda binary: f"/mock/{binary}"
    )

    def timeout_after_output(argv, **kwargs):
        raise subprocess.TimeoutExpired(
            argv,
            kwargs["timeout"],
            output=f"{payload}\n",
            stderr="",
        )

    monkeypatch.setattr(
        "cairn.server.vuln_adapters.subprocess.run", timeout_after_output
    )
    execution = adapter.execute(context)
    parsed = adapter.parse(execution)

    assert len(execution.results) == 2
    assert {result.returncode for result in execution.results} == {-1}
    assert parsed["records"][0]["tls_version"] == "tls13"
    assert parsed["records"][0]["process_timeout_after_output"] is True


def test_adapter_health_rejects_nonzero_version_probe(monkeypatch) -> None:
    adapter = AmassPassiveEnumAdapter()
    monkeypatch.setattr(
        "cairn.server.vuln_adapters.shutil.which", lambda binary: f"/mock/{binary}"
    )
    monkeypatch.setattr(
        "cairn.server.vuln_adapters.subprocess.run",
        lambda argv, **kwargs: subprocess.CompletedProcess(
            argv, 1, "", "sudo: a terminal is required"
        ),
    )
    health = adapter.health()
    assert health["healthy"] is False
    assert health["version"] is None
    assert "exited with code 1" in health["error"]


def test_r3_adapter_health_rejects_pinned_version_drift(monkeypatch) -> None:
    adapter = NaabuPortScanAdapter()
    monkeypatch.setattr(
        "cairn.server.vuln_adapters.shutil.which", lambda binary: str(binary)
    )
    monkeypatch.setattr(
        "cairn.server.vuln_adapters.subprocess.run",
        lambda argv, **kwargs: subprocess.CompletedProcess(
            argv, 0, "[INF] Current Version: 2.5.0\n", ""
        ),
    )
    health = adapter.health()
    assert health["healthy"] is False
    assert health["expected_version"] == "2.6.1"
    assert "Version drift" in health["error"]


def test_domain_adapter_rejects_shell_shaped_target_before_materialization() -> None:
    adapter = SubfinderPassiveDnsAdapter()
    context = _context(targets=("example.com;id",))
    with pytest.raises(AdapterValidationError):
        adapter.validate(context)


@pytest.mark.parametrize(
    "adapter",
    [
        CertificateTransparencyAdapter(),
        RdapDomainAdapter(),
        OsvVulnerabilityIntelligenceAdapter(),
    ],
)
def test_http_adapters_inject_validated_campaign_header(adapter) -> None:
    packages = ()
    targets = ("example.com",)
    if isinstance(adapter, OsvVulnerabilityIntelligenceAdapter):
        targets = ()
        packages = (
            {
                "asset_id": "asset-1",
                "identifier": "PyPI:requests@2.31.0",
                "normalized_identifier": "pypi:requests@2.31.0",
                "scope_state": "in",
                "ecosystem": "PyPI",
                "name": "requests",
                "version": "2.31.0",
            },
        )
    context = _context(targets=targets, packages=packages)
    context = AdapterContext(
        **{
            **context.__dict__,
            "request_header": "X-Authorized-Research",
        }
    )
    invocation = adapter.materialize(context)[0]
    assert (
        "X-Authorized-Research: campaign=vuln-test; task=task-test"
        in invocation.argv
    )
    assert not any(value.lower().startswith("host:") for value in invocation.argv)


@pytest.mark.parametrize("header", ["Host", "Content-Length", "X-Test\r\nX-Evil"])
def test_http_adapter_rejects_forbidden_or_injected_header(header: str) -> None:
    context = _context()
    context = AdapterContext(**{**context.__dict__, "request_header": header})
    with pytest.raises(AdapterValidationError):
        CertificateTransparencyAdapter().materialize(context)


def test_http_rate_limit_uses_durable_campaign_window(monkeypatch) -> None:
    context = _context()
    context = AdapterContext(
        **{**context.__dict__, "max_requests_per_second": 1}
    )
    clock = [100.0]
    sleeps: list[float] = []
    monkeypatch.setattr("cairn.server.vuln_adapters.time.time", lambda: clock[0])

    def advance(seconds: float) -> None:
        sleeps.append(seconds)
        clock[0] += seconds

    monkeypatch.setattr("cairn.server.vuln_adapters.time.sleep", advance)
    acquire_campaign_http_rate_limit(context)
    acquire_campaign_http_rate_limit(context)
    assert len(sleeps) == 1
    assert sleeps[0] == pytest.approx(RATE_LIMIT_RESERVATION_WINDOW_SECONDS)
    rows = context.conn.execute(
        "SELECT observed_at FROM vuln_http_rate_events WHERE campaign_id = ?",
        (context.campaign_id,),
    ).fetchall()
    assert [row["observed_at"] for row in rows] == [
        pytest.approx(100.0 + RATE_LIMIT_RESERVATION_WINDOW_SECONDS)
    ]


def _mock_nuclei_template_policy(tmp_path: Path, monkeypatch) -> Path:
    relative = "http/misconfiguration/http-missing-security-headers.yaml"
    template = tmp_path / relative
    template.parent.mkdir(parents=True)
    content = """id: http-missing-security-headers
info:
  name: HTTP Missing Security Headers
  severity: info
  tags: misconfig,headers
http:
  - method: GET
    path:
      - \"{{BaseURL}}\"
    matchers:
      - type: word
        part: header
        words: [\"Server:\"]
# digest: aabbcc:ddeeff
"""
    template.write_text(content, encoding="utf-8")
    monkeypatch.setenv("CAIRN_NUCLEI_TEMPLATES_ROOT", str(tmp_path))
    monkeypatch.setattr(
        "cairn.server.vuln_adapters.NUCLEI_TEMPLATE_ALLOWLIST",
        (
            (
                "http-missing-security-headers",
                relative,
                hashlib.sha256(content.encode("utf-8")).hexdigest(),
            ),
        ),
    )
    return template


def _mock_nuclei_runtime(
    tmp_path: Path, monkeypatch, adapter: NucleiPassiveResponseAdapter
) -> tuple[Path, Path]:
    binary = tmp_path / "nuclei"
    network_sandbox = tmp_path / "unshare"
    binary.write_bytes(b"audited nuclei test binary")
    network_sandbox.write_bytes(b"network namespace test wrapper")
    adapter.binary = str(binary)
    monkeypatch.setattr(
        "cairn.server.vuln_adapters.NUCLEI_BINARY_SHA256",
        hashlib.sha256(binary.read_bytes()).hexdigest(),
    )

    def fake_which(value: str) -> str | None:
        name = Path(value).name
        if name == "nuclei":
            return str(binary)
        if name == "unshare":
            return str(network_sandbox)
        return None

    monkeypatch.setattr("cairn.server.vuln_adapters.shutil.which", fake_which)
    return binary, network_sandbox


def test_nuclei_passive_adapter_only_reads_captured_response(
    tmp_path, monkeypatch
) -> None:
    _mock_nuclei_template_policy(tmp_path, monkeypatch)
    response_text = "HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\nhello"
    context = _context()
    context = AdapterContext(
        **{
            **context.__dict__,
            "http_responses": (
                {
                    "id": "http_response_001",
                    "domain": "example.com",
                    "asset_id": "asset_001",
                    "task_id": "capture_task_001",
                    "request_text": "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
                    "response_text": response_text,
                    "response_hash": hashlib.sha256(response_text.encode()).hexdigest(),
                    "content_truncated": 0,
                },
            ),
        }
    )
    adapter = NucleiPassiveResponseAdapter()
    binary, network_sandbox = _mock_nuclei_runtime(tmp_path, monkeypatch, adapter)
    calls: list[list[str]] = []
    captured_inputs: list[str] = []
    captured_paths: list[Path] = []

    def fake_run(argv, **kwargs):
        calls.append(argv)
        if argv[0] == str(binary):
            return subprocess.CompletedProcess(argv, 0, "Nuclei Engine Version: v3.11.1\n", "")
        assert argv[:5] == [
            str(network_sandbox),
            "--user",
            "--map-current-user",
            "--net",
            "--",
        ]
        assert argv[5] == str(binary)
        assert "-passive" in argv
        assert "-no-interactsh" in argv
        assert "-disable-unsigned-templates" in argv
        assert "-no-stdin" in argv
        assert "-disable-update-check" in argv
        assert "-disable-redirects" in argv
        assert "-restrict-local-network-access" in argv
        assert not any(
            str(argument).startswith(("http://", "https://")) for argument in argv
        )
        target_path = Path(argv[argv.index("-target") + 1])
        captured_paths.append(target_path)
        captured_inputs.append(target_path.read_text(encoding="utf-8"))
        return subprocess.CompletedProcess(
            argv,
            0,
            json.dumps(
                {
                    "template-id": "http-missing-security-headers",
                    "matcher-name": "strict-transport-security",
                    "matched-at": "https://example.com",
                    "info": {
                        "name": "HTTP Missing Security Headers",
                        "severity": "info",
                    },
                }
            )
            + "\n",
            "",
        )

    monkeypatch.setattr("cairn.server.vuln_adapters.subprocess.run", fake_run)
    assert adapter.health()["healthy"] is True
    execution = adapter.execute(context)
    parsed = adapter.parse(execution)

    assert len(calls) == 2
    assert "GET / HTTP/1.1" in captured_inputs[0]
    assert "HTTP/1.1 200 OK" in captured_inputs[0]
    assert captured_paths and all(not path.exists() for path in captured_paths)
    assert parsed["findings"][0]["response_id"] == "http_response_001"
    assert parsed["findings"][0]["template_id"] == "http-missing-security-headers"
    assert adapter.coverage_complete(context, parsed) is True
    assert adapter.uses_network is False
    assert adapter.uses_http is False
    assert adapter.requires_human_approval is True
    assert adapter.expected_tool_version == "3.11.1"
    assert adapter.release_sha256 == "ea63d4ae232808cd7c6bc00d0142428e231fab59dae01042246097d195835ab6"


def test_nuclei_passive_adapter_rejects_tampered_or_dangerous_template(
    tmp_path, monkeypatch
) -> None:
    template = _mock_nuclei_template_policy(tmp_path, monkeypatch)
    template.write_text(
        template.read_text(encoding="utf-8") + "\ncode:\n  - engine: python3\n",
        encoding="utf-8",
    )
    adapter = NucleiPassiveResponseAdapter()
    binary, _ = _mock_nuclei_runtime(tmp_path, monkeypatch, adapter)
    monkeypatch.setattr(
        "cairn.server.vuln_adapters.subprocess.run",
        lambda argv, **kwargs: subprocess.CompletedProcess(
            argv,
            0,
            "v3.11.1\n" if argv[0] == str(binary) else "",
            "",
        ),
    )

    health = adapter.health()
    assert health["healthy"] is False
    assert "hash mismatch" in health["error"]


def test_nuclei_passive_adapter_rejects_non_allowlisted_output(
    tmp_path, monkeypatch
) -> None:
    _mock_nuclei_template_policy(tmp_path, monkeypatch)
    adapter = NucleiPassiveResponseAdapter()
    execution = AdapterExecution(
        (
            CommandResult(
                target="http_response_001",
                stdout=json.dumps(
                    {
                        "template-id": "unreviewed-active-template",
                        "info": {"name": "Unexpected", "severity": "high"},
                    }
                ),
                stderr="",
                returncode=0,
                duration_ms=1,
            ),
        )
    )

    with pytest.raises(AdapterExecutionError, match="non-allowlisted template ID"):
        adapter.parse(execution)


def test_nuclei_passive_adapter_rejects_allowlist_category_drift(
    tmp_path, monkeypatch
) -> None:
    _mock_nuclei_template_policy(tmp_path, monkeypatch)
    monkeypatch.setattr(
        "cairn.server.vuln_adapters.NUCLEI_TEMPLATE_CATEGORIES",
        {"http-missing-security-headers": "fuzz"},
    )
    adapter = NucleiPassiveResponseAdapter()

    with pytest.raises(AdapterValidationError, match="category is not allowlisted"):
        adapter.validate(
            AdapterContext(
                **{
                    **_context().__dict__,
                    "http_responses": (
                        {
                            "id": "http_response_001",
                            "domain": "example.com",
                            "asset_id": "asset_001",
                            "task_id": "capture_task_001",
                            "request_text": "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
                            "response_text": "HTTP/1.1 200 OK\r\n\r\n",
                            "response_hash": hashlib.sha256(
                                b"HTTP/1.1 200 OK\r\n\r\n"
                            ).hexdigest(),
                        },
                    ),
                }
            )
        )
