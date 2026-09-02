from __future__ import annotations

import hashlib
import json
import sqlite3
import subprocess
from pathlib import Path

import pytest

from cairn.server.vuln_adapters import (
    ADAPTER_REGISTRY,
    AdapterContext,
    AdapterExecution,
    AdapterExecutionError,
    AdapterValidationError,
    AmassPassiveEnumAdapter,
    CertificateTransparencyAdapter,
    CommandResult,
    DnsxResolveAdapter,
    HttpxHttpMetadataAdapter,
    KatanaCrawlerAdapter,
    NaabuPortScanAdapter,
    NucleiPassiveResponseAdapter,
    OsvVulnerabilityIntelligenceAdapter,
    RATE_LIMIT_RESERVATION_WINDOW_SECONDS,
    RdapDomainAdapter,
    SubfinderPassiveDnsAdapter,
    TlsxTlsMetadataAdapter,
    WhoisDomainAdapter,
    acquire_campaign_http_rate_limit,
)


def _context(
    *,
    targets: tuple[str, ...] = ("example.com",),
    packages: tuple[dict, ...] = (),
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
        options=options or {},
    )


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
        "crtsh.cert-transparency.v1",
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
    }
    for tool_id, adapter in ADAPTER_REGISTRY.items():
        assert adapter.tool_id == tool_id
        assert adapter.version
        assert adapter.risk_class in {"R1", "R2", "R3"}
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
