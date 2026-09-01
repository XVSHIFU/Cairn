from __future__ import annotations

import json
import sqlite3
import subprocess

import pytest

from cairn.server.vuln_adapters import (
    ADAPTER_REGISTRY,
    AdapterContext,
    AdapterValidationError,
    AmassPassiveEnumAdapter,
    CertificateTransparencyAdapter,
    OsvVulnerabilityIntelligenceAdapter,
    RdapDomainAdapter,
    SubfinderPassiveDnsAdapter,
    WhoisDomainAdapter,
    acquire_campaign_http_rate_limit,
)


def _context(
    *,
    targets: tuple[str, ...] = ("example.com",),
    packages: tuple[dict, ...] = (),
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
)


@pytest.mark.parametrize(
    ("adapter", "context", "stdout", "assert_parsed"),
    ADAPTER_CASES,
    ids=[case[0].tool_id for case in ADAPTER_CASES],
)
def test_r1_adapters_materialize_argument_arrays_and_parse_mocked_output(
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
    assert estimate["command_count"] == 1
    assert all(isinstance(invocation.argv, tuple) for invocation in invocations)
    assert all(isinstance(argument, str) for invocation in invocations for argument in invocation.argv)
    if adapter.tool_id == "amass.passive-enum.v1":
        assert "-passive" in invocations[0].argv
    if adapter.uses_http:
        assert "X-Cairn-Research: campaign=vuln-test; task=task-test" in invocations[0].argv

    health = adapter.health()
    execution = adapter.execute(context)
    parsed = adapter.parse(execution)

    assert health["healthy"] is True
    assert health["version"] == f"{adapter.binary} mock 1.0"
    assert assert_parsed(parsed)
    assert len(execution.output_hash) == 64
    assert execution.output_size == len(stdout.encode("utf-8"))
    actual_call = calls[-1]
    assert actual_call[0] == list(invocations[0].argv)
    assert actual_call[1]["capture_output"] is True
    assert actual_call[1]["text"] is True
    assert actual_call[1]["timeout"] == adapter.timeout_seconds
    assert actual_call[1]["shell"] is False


def test_adapter_registry_exposes_complete_lifecycle_metadata() -> None:
    assert set(ADAPTER_REGISTRY) == {
        "crtsh.cert-transparency.v1",
        "osv.vuln-intel.v1",
        "subfinder.passive-dns.v1",
        "amass.passive-enum.v1",
        "rdap.domain.v1",
        "whois.domain.v1",
    }
    for tool_id, adapter in ADAPTER_REGISTRY.items():
        assert adapter.tool_id == tool_id
        assert adapter.version
        assert adapter.risk_class == "R1"
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
    assert sleeps[0] == pytest.approx(1.0)
    rows = context.conn.execute(
        "SELECT observed_at FROM vuln_http_rate_events WHERE campaign_id = ?",
        (context.campaign_id,),
    ).fetchall()
    assert [row["observed_at"] for row in rows] == [pytest.approx(101.0)]
