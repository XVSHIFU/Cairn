from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import shutil
import sqlite3
import subprocess
import tempfile
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import quote, urlsplit


USER_AGENT = "Cairn/0.2 authorized-passive-research"
DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}\.?$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.?$",
    re.IGNORECASE,
)
HTTP_HEADER_NAME_PATTERN = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
FORBIDDEN_REQUEST_HEADERS = {"host", "content-length"}
ANSI_ESCAPE_PATTERN = re.compile(r"\x1b\[[0-9;]*m")
RATE_LIMIT_RESERVATION_WINDOW_SECONDS = 1.01
HTTP_RESPONSE_MAX_BYTES = 262_144
HTTP_REQUEST_MAX_BYTES = 65_536
NUCLEI_TEMPLATES_COMMIT = "74e8267021b061b726fe997d322444d3c20988b7"
NUCLEI_TEMPLATE_ALLOWLIST: tuple[tuple[str, str, str], ...] = (
    (
        "http-missing-security-headers",
        "http/misconfiguration/http-missing-security-headers.yaml",
        "7f45803f73ac6810b9b302df6be2c472a82d9164a7807328614efa83e6eac275",
    ),
    (
        "nginx-version",
        "http/technologies/nginx/nginx-version.yaml",
        "aa410fb8361f2109ac247b16419040cc2cce1e3d9c76f0a51593806e7c1b7cd7",
    ),
)
NUCLEI_FORBIDDEN_TEMPLATE_PATTERN = re.compile(
    r"^(?:code|headless|javascript|fuzzing|payloads|workflows)\s*:|"
    r"interactsh|^\s*tags\s*:.*\b(?:dos|fuzz|bruteforce|intrusive)\b",
    re.IGNORECASE | re.MULTILINE,
)


def _configured_user_binary(name: str, environment_name: str) -> str:
    """Resolve an allowlisted tool without relying on an interactive-shell PATH."""

    configured = os.getenv(environment_name)
    if configured:
        return str(Path(configured).expanduser())
    user_local = Path.home() / ".local" / "bin" / name
    if user_local.is_file() and os.access(user_local, os.X_OK):
        return str(user_local)
    return name


class AdapterError(RuntimeError):
    """Base error for controlled collection adapter failures."""


class AdapterValidationError(AdapterError):
    pass


class AdapterUnavailableError(AdapterError):
    pass


class AdapterExecutionError(AdapterError):
    def __init__(self, message: str, execution: AdapterExecution | None = None):
        super().__init__(message)
        self.execution = execution


@dataclass(frozen=True)
class AdapterSpec:
    tool_id: str
    version: str
    risk_class: str
    input_schema: Mapping[str, Any]
    output_schema: Mapping[str, Any]
    source_type: str
    dimension: str
    expected_tool_version: str | None = None
    release_sha256: str | None = None

    @property
    def adapter_id(self) -> str:
        return self.tool_id

    @property
    def risk_tier(self) -> str:
        return self.risk_class


@dataclass(frozen=True)
class AdapterContext:
    conn: sqlite3.Connection
    campaign_id: str
    task_id: str
    source: Mapping[str, Any]
    targets: tuple[str, ...] = ()
    packages: tuple[Mapping[str, Any], ...] = ()
    http_responses: tuple[Mapping[str, Any], ...] = ()
    cursor: Mapping[str, Any] = field(default_factory=dict)
    request_header: str = "X-Cairn-Research"
    max_requests_per_second: int = 30
    proxy_url: str | None = None


@dataclass(frozen=True)
class AdapterInvocation:
    argv: tuple[str, ...]
    target: str | None = None
    stdin: str | None = None


@dataclass(frozen=True)
class CommandResult:
    target: str | None
    stdout: str
    stderr: str
    returncode: int
    duration_ms: int


@dataclass(frozen=True)
class AdapterExecution:
    results: tuple[CommandResult, ...]

    @property
    def output_size(self) -> int:
        return sum(len(result.stdout.encode("utf-8")) for result in self.results)

    @property
    def output_hash(self) -> str:
        digest = hashlib.sha256()
        for result in self.results:
            digest.update((result.target or "").encode("utf-8"))
            digest.update(b"\0")
            digest.update(result.stdout.encode("utf-8"))
            digest.update(b"\0")
        return digest.hexdigest()

    @property
    def stderr_hash(self) -> str:
        digest = hashlib.sha256()
        for result in self.results:
            digest.update(result.stderr.encode("utf-8"))
            digest.update(b"\0")
        return digest.hexdigest()


def normalize_domain(value: str) -> str:
    text = value.strip().lower().removeprefix("*.")
    if "://" in text:
        text = urlsplit(text).hostname or ""
    text = text.rstrip(".")
    try:
        ascii_domain = text.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise AdapterValidationError(f"Invalid domain target: {value}") from exc
    if not DOMAIN_PATTERN.fullmatch(ascii_domain):
        raise AdapterValidationError(f"Invalid domain target: {value}")
    return ascii_domain


def acquire_campaign_http_rate_limit(context: AdapterContext) -> None:
    """Reserve one HTTP request in a durable per-Campaign sliding window."""

    limit = max(1, int(context.max_requests_per_second))
    while True:
        now = time.time()
        if context.conn.in_transaction:
            context.conn.commit()
        try:
            context.conn.execute("BEGIN IMMEDIATE")
            context.conn.execute(
                "DELETE FROM vuln_http_rate_events WHERE campaign_id = ? AND observed_at <= ?",
                (context.campaign_id, now - RATE_LIMIT_RESERVATION_WINDOW_SECONDS),
            )
            rows = context.conn.execute(
                "SELECT observed_at FROM vuln_http_rate_events WHERE campaign_id = ? ORDER BY observed_at",
                (context.campaign_id,),
            ).fetchall()
            if len(rows) < limit:
                context.conn.execute(
                    "INSERT INTO vuln_http_rate_events (campaign_id, task_id, observed_at) VALUES (?, ?, ?)",
                    (context.campaign_id, context.task_id, now),
                )
                context.conn.commit()
                return
            oldest = float(rows[0]["observed_at"] if isinstance(rows[0], sqlite3.Row) else rows[0][0])
            context.conn.commit()
        except Exception:
            if context.conn.in_transaction:
                context.conn.rollback()
            raise
        # A small conservative margin absorbs scheduler/clock jitter between
        # reserving a token and starting the external process. This keeps the
        # actual one-second request window at or below the Campaign limit.
        time.sleep(
            max(0.001, oldest + RATE_LIMIT_RESERVATION_WINDOW_SECONDS - now)
        )


class VulnSourceAdapter(ABC):
    """Lifecycle contract for allowlisted, argument-array-only collectors."""

    tool_id: str
    version: str
    risk_class: str
    input_schema: Mapping[str, Any]
    output_schema: Mapping[str, Any]
    source_type: str
    dimension: str
    binary: str
    version_args: tuple[str, ...] = ("--version",)
    timeout_seconds: int = 30
    uses_http: bool = False
    uses_network: bool = False
    accept_complete_json_on_timeout: bool = False
    expected_tool_version: str | None = None
    release_sha256: str | None = None

    @property
    def spec(self) -> AdapterSpec:
        return AdapterSpec(
            tool_id=self.tool_id,
            version=self.version,
            risk_class=self.risk_class,
            input_schema=self.input_schema,
            output_schema=self.output_schema,
            source_type=self.source_type,
            dimension=self.dimension,
            expected_tool_version=self.expected_tool_version,
            release_sha256=self.release_sha256,
        )

    def validate(self, context: AdapterContext) -> None:
        if not context.campaign_id or not context.task_id:
            raise AdapterValidationError("Adapter context is missing campaign or task identity")

    def get_headers(self, context: AdapterContext) -> dict[str, str]:
        name = context.request_header.strip()
        if "\r" in name or "\n" in name or not HTTP_HEADER_NAME_PATTERN.fullmatch(name):
            raise AdapterValidationError("Campaign request_header is not a valid HTTP header name")
        if name.lower() in FORBIDDEN_REQUEST_HEADERS:
            raise AdapterValidationError("Campaign request_header may not override Host or Content-Length")
        value = f"campaign={context.campaign_id}; task={context.task_id}"
        if "\r" in value or "\n" in value:
            raise AdapterValidationError("Campaign request header value contains a line break")
        return {name: value}

    def _curl_header_args(self, context: AdapterContext) -> tuple[str, ...]:
        return tuple(
            argument
            for name, value in self.get_headers(context).items()
            for argument in ("--header", f"{name}: {value}")
        )

    def estimate(self, context: AdapterContext) -> dict[str, Any]:
        invocations = self.materialize(context)
        return {
            "command_count": len(invocations),
            "timeout_seconds": self.timeout_seconds,
            "risk_class": self.risk_class,
            "network_request_count": sum(
                1 for invocation in invocations if self.uses_http or self.uses_network
            ),
        }

    @abstractmethod
    def materialize(self, context: AdapterContext) -> list[AdapterInvocation]:
        """Return fixed executable argument arrays; never return a shell command string."""

    @abstractmethod
    def execute(self, context: AdapterContext) -> AdapterExecution:
        """Execute materialized argument arrays with bounded subprocess calls."""

    @abstractmethod
    def parse(self, execution: AdapterExecution) -> Any:
        """Parse raw stdout without mutating Cairn state."""

    @abstractmethod
    def normalize(self, context: AdapterContext, parsed: Any) -> dict[str, int]:
        """Normalize parsed output into Cairn assets, observations, or findings."""

    def coverage(
        self, context: AdapterContext, normalized: Mapping[str, int]
    ) -> dict[str, Any]:
        produced = sum(value for value in normalized.values() if isinstance(value, int))
        return {
            "dimension": self.dimension,
            "status": "completed",
            "produced": produced,
        }

    def coverage_complete(self, context: AdapterContext, parsed: Any) -> bool:
        """Whether absence in this successful response is authoritative."""
        return True

    def next_cursor(
        self,
        context: AdapterContext,
        parsed: Any,
        execution: AdapterExecution,
    ) -> dict[str, Any] | None:
        """Return the durable high-water mark to save after a successful run."""
        return None

    def health(self) -> dict[str, Any]:
        executable = shutil.which(self.binary)
        if executable is None:
            return {
                "healthy": False,
                "tool_id": self.tool_id,
                "version": None,
                "error": f"Executable not found: {self.binary}",
            }
        try:
            completed = subprocess.run(
                [executable, *self.version_args],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
                shell=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            return {
                "healthy": False,
                "tool_id": self.tool_id,
                "version": None,
                "error": f"Version probe failed: {type(exc).__name__}",
            }
        output = ANSI_ESCAPE_PATTERN.sub(
            "", completed.stdout.strip() or completed.stderr.strip()
        )
        lines = [line.strip() for line in output.splitlines() if line.strip()]
        first_line = lines[0][:256] if lines else None
        version_line = next(
            (
                line[:256]
                for line in lines
                if "version" in line.casefold()
                or re.fullmatch(r"v?\d+(?:\.\d+){1,3}", line)
                or (
                    self.expected_tool_version is not None
                    and self.expected_tool_version in line
                )
            ),
            first_line,
        )
        if completed.returncode != 0:
            detail = f": {first_line}" if first_line else ""
            return {
                "healthy": False,
                "tool_id": self.tool_id,
                "version": None,
                "error": f"Version probe exited with code {completed.returncode}{detail}",
            }
        if self.expected_tool_version and (
            not version_line or self.expected_tool_version not in version_line
        ):
            return {
                "healthy": False,
                "tool_id": self.tool_id,
                "version": version_line,
                "expected_version": self.expected_tool_version,
                "error": (
                    f"Version drift: expected {self.expected_tool_version}, "
                    f"received {version_line or 'no version output'}"
                ),
            }
        return {
            "healthy": True,
            "tool_id": self.tool_id,
            "version": version_line,
            "expected_version": self.expected_tool_version,
            "error": None,
        }

    def _execute_materialized(self, context: AdapterContext) -> AdapterExecution:
        self.validate(context)
        return self._execute_invocations(context, self.materialize(context))

    def _execute_invocations(
        self,
        context: AdapterContext,
        invocations: list[AdapterInvocation],
    ) -> AdapterExecution:
        results: list[CommandResult] = []
        for invocation in invocations:
            if self.uses_http or self.uses_network:
                acquire_campaign_http_rate_limit(context)
            started = time.monotonic()
            try:
                run_kwargs: dict[str, Any] = {
                    "capture_output": True,
                    "text": True,
                    "timeout": self.timeout_seconds,
                    "check": False,
                    "shell": False,
                }
                if invocation.stdin is not None:
                    run_kwargs["input"] = invocation.stdin
                completed = subprocess.run(list(invocation.argv), **run_kwargs)
            except subprocess.TimeoutExpired as exc:
                stdout = exc.stdout.decode() if isinstance(exc.stdout, bytes) else (exc.stdout or "")
                stderr = exc.stderr.decode() if isinstance(exc.stderr, bytes) else (exc.stderr or "")
                results.append(
                    CommandResult(
                        target=invocation.target,
                        stdout=stdout,
                        stderr=stderr,
                        returncode=-1,
                        duration_ms=round((time.monotonic() - started) * 1000),
                    )
                )
                execution = AdapterExecution(tuple(results))
                if self.accept_complete_json_on_timeout and stdout.strip():
                    try:
                        payloads = [
                            json.loads(line)
                            for line in stdout.splitlines()
                            if line.strip()
                        ]
                    except json.JSONDecodeError:
                        payloads = []
                    if payloads and all(isinstance(payload, dict) for payload in payloads):
                        # Some tlsx builds emit a complete JSON record but keep
                        # background goroutines alive. subprocess.run has killed
                        # the process at the hard boundary; retain the complete,
                        # auditable output and mark it in normalized evidence.
                        continue
                raise AdapterExecutionError(
                    f"{self.tool_id} timed out after {self.timeout_seconds}s", execution
                ) from exc
            except OSError as exc:
                raise AdapterUnavailableError(
                    f"Unable to execute allowlisted binary {self.binary}: {type(exc).__name__}"
                ) from exc
            result = CommandResult(
                target=invocation.target,
                stdout=completed.stdout,
                stderr=completed.stderr,
                returncode=completed.returncode,
                duration_ms=round((time.monotonic() - started) * 1000),
            )
            results.append(result)
            if completed.returncode != 0:
                execution = AdapterExecution(tuple(results))
                raise AdapterExecutionError(
                    f"{self.tool_id} exited with code {completed.returncode}", execution
                )
        return AdapterExecution(tuple(results))


class DomainAdapter(VulnSourceAdapter):
    input_schema = {
        "type": "object",
        "required": ["domains"],
        "properties": {
            "domains": {"type": "array", "items": {"type": "string"}, "maxItems": 10}
        },
        "additionalProperties": False,
    }

    def validate(self, context: AdapterContext) -> None:
        super().validate(context)
        if not context.targets:
            raise AdapterValidationError(f"{self.tool_id} requires at least one domain")
        if len(context.targets) > 10:
            raise AdapterValidationError(f"{self.tool_id} accepts at most 10 domains")
        for target in context.targets:
            normalize_domain(target)


class DomainDiscoveryAdapter(DomainAdapter):
    output_schema = {
        "type": "object",
        "required": ["domains"],
        "properties": {"domains": {"type": "array", "items": {"type": "string"}}},
    }

    def normalize(self, context: AdapterContext, parsed: Any) -> dict[str, int]:
        from cairn.server.vulnerability_models import AssetInput
        from cairn.server.vulnerability_services import (
            check_scope,
            record_collection_task_asset,
            upsert_asset,
        )

        created = 0
        updated = 0
        source_name = str(context.source["name"])
        for hostname in parsed.get("domains", []):
            scope = check_scope(context.conn, context.campaign_id, hostname, active=False)
            if not scope.allowed:
                continue
            asset, was_created = upsert_asset(
                context.conn,
                context.campaign_id,
                AssetInput(
                    asset_type="domain",
                    identifier=hostname,
                    source_name=source_name,
                ),
            )
            record_collection_task_asset(
                context.conn,
                context.task_id,
                str(context.source["id"]),
                asset.id,
            )
            created += int(was_created)
            updated += int(not was_created)
        return {"assets_created": created, "assets_updated": updated}


class CertificateTransparencyAdapter(DomainDiscoveryAdapter):
    tool_id = "crtsh.cert-transparency.v1"
    version = "1.0.0"
    risk_class = "R1"
    source_type = "passive_domain"
    dimension = "external"
    binary = "curl"
    version_args = ("--version",)
    timeout_seconds = 20
    uses_http = True

    def materialize(self, context: AdapterContext) -> list[AdapterInvocation]:
        return [
            AdapterInvocation(
                argv=(
                    self.binary,
                    "--silent",
                    "--show-error",
                    "--fail-with-body",
                    "--max-time",
                    str(self.timeout_seconds),
                    "--user-agent",
                    USER_AGENT,
                    *self._curl_header_args(context),
                    "--get",
                    "--data-urlencode",
                    f"q=%.{normalize_domain(domain)}",
                    "--data",
                    "output=json",
                    "https://crt.sh/",
                ),
                target=normalize_domain(domain),
            )
            for domain in context.targets
        ]

    def execute(self, context: AdapterContext) -> AdapterExecution:
        return self._execute_materialized(context)

    def parse(self, execution: AdapterExecution) -> dict[str, Any]:
        domains: set[str] = set()
        records: list[dict[str, Any]] = []
        high_water_id = 0
        high_water_timestamp = ""
        coverage_complete = True
        for result in execution.results:
            try:
                certificates = json.loads(result.stdout)
            except json.JSONDecodeError as exc:
                raise AdapterExecutionError("crt.sh returned invalid JSON", execution) from exc
            if not isinstance(certificates, list):
                raise AdapterExecutionError("crt.sh response must be a JSON array", execution)
            if len(certificates) >= 5000:
                coverage_complete = False
            for certificate in certificates[:5000]:
                if not isinstance(certificate, dict):
                    continue
                certificate_id = certificate.get("id") or certificate.get("min_cert_id")
                try:
                    numeric_id = int(certificate_id) if certificate_id is not None else None
                except (TypeError, ValueError):
                    numeric_id = None
                if numeric_id is not None:
                    high_water_id = max(high_water_id, numeric_id)
                timestamp = str(certificate.get("entry_timestamp") or "")
                high_water_timestamp = max(high_water_timestamp, timestamp)
                for value in str(certificate.get("name_value", "")).splitlines():
                    try:
                        domain = normalize_domain(value)
                        domains.add(domain)
                        records.append(
                            {
                                "domain": domain,
                                "certificate_id": numeric_id,
                                "entry_timestamp": timestamp or None,
                            }
                        )
                    except AdapterValidationError:
                        continue
        return {
            "domains": sorted(domains),
            "records": records,
            "_cursor": {
                "high_water_id": high_water_id or None,
                "high_water_timestamp": high_water_timestamp or None,
            },
            "_coverage_complete": coverage_complete,
        }

    def normalize(self, context: AdapterContext, parsed: Any) -> dict[str, int]:
        previous_id = context.cursor.get("high_water_id")
        try:
            numeric_previous = int(previous_id) if previous_id is not None else None
        except (TypeError, ValueError):
            numeric_previous = None
        if numeric_previous is None:
            domains = parsed.get("domains", [])
        else:
            domains = sorted(
                {
                    record["domain"]
                    for record in parsed.get("records", [])
                    if record.get("certificate_id") is None
                    or record["certificate_id"] > numeric_previous
                }
            )
        return super().normalize(context, {"domains": domains})

    def coverage_complete(self, context: AdapterContext, parsed: Any) -> bool:
        return bool(parsed.get("_coverage_complete", False))

    def next_cursor(
        self,
        context: AdapterContext,
        parsed: Any,
        execution: AdapterExecution,
    ) -> dict[str, Any]:
        current = dict(context.cursor)
        candidate = parsed.get("_cursor", {})
        previous_id = current.get("high_water_id") or 0
        candidate_id = candidate.get("high_water_id") or 0
        current.update(candidate)
        current["high_water_id"] = max(int(previous_id), int(candidate_id)) or None
        current["output_hash"] = execution.output_hash
        return current


class LineDomainDiscoveryAdapter(DomainDiscoveryAdapter):
    def parse(self, execution: AdapterExecution) -> dict[str, list[str]]:
        domains: set[str] = set()
        for result in execution.results:
            for line in result.stdout.splitlines()[:10000]:
                try:
                    domains.add(normalize_domain(line))
                except AdapterValidationError:
                    continue
        return {"domains": sorted(domains)}


class SubfinderPassiveDnsAdapter(LineDomainDiscoveryAdapter):
    tool_id = "subfinder.passive-dns.v1"
    version = "1.0.0"
    risk_class = "R1"
    source_type = "subfinder_passive"
    dimension = "external"
    binary = _configured_user_binary("subfinder", "CAIRN_SUBFINDER_BINARY")
    version_args = ("-version",)
    timeout_seconds = 120

    def materialize(self, context: AdapterContext) -> list[AdapterInvocation]:
        return [
            AdapterInvocation(
                argv=(self.binary, "-silent", "-d", normalize_domain(domain)),
                target=normalize_domain(domain),
            )
            for domain in context.targets
        ]

    def execute(self, context: AdapterContext) -> AdapterExecution:
        return self._execute_materialized(context)


class AmassPassiveEnumAdapter(LineDomainDiscoveryAdapter):
    tool_id = "amass.passive-enum.v1"
    version = "1.0.0"
    risk_class = "R1"
    source_type = "amass_passive"
    dimension = "external"
    binary = _configured_user_binary("amass", "CAIRN_AMASS_BINARY")
    version_args = ("-version",)
    timeout_seconds = 180

    def materialize(self, context: AdapterContext) -> list[AdapterInvocation]:
        return [
            AdapterInvocation(
                argv=(self.binary, "enum", "-passive", "-d", normalize_domain(domain)),
                target=normalize_domain(domain),
            )
            for domain in context.targets
        ]

    def execute(self, context: AdapterContext) -> AdapterExecution:
        return self._execute_materialized(context)


def _record_domain_metadata(
    context: AdapterContext,
    record_type: str,
    target: str,
    data: Mapping[str, Any],
    *,
    dimension: str = "external",
    confidence: float = 0.9,
) -> bool:
    from cairn.server.services import utcnow
    from cairn.server.vulnerability_services import (
        next_vulnerability_id,
        normalize_target,
        record_collection_task_asset,
    )

    now = utcnow()
    normalized = normalize_target(target)
    asset = context.conn.execute(
        "SELECT id FROM vuln_assets WHERE campaign_id = ? AND asset_type = 'domain' AND normalized_identifier = ?",
        (context.campaign_id, normalized),
    ).fetchone()
    payload = {"record_type": record_type, "domain": target, "data": data}
    digest = hashlib.sha256(
        f"{context.campaign_id}:{context.source['id']}:{record_type}:{target}:"
        f"{json.dumps(payload, sort_keys=True, ensure_ascii=False)}".encode("utf-8")
    ).hexdigest()
    existing = context.conn.execute(
        "SELECT 1 FROM vuln_observations WHERE campaign_id = ? AND evidence_hash = ?",
        (context.campaign_id, digest),
    ).fetchone()
    observation_id = next_vulnerability_id(context.conn, "observation", "observation")
    context.conn.execute(
        """
        INSERT INTO vuln_observations
            (id, campaign_id, asset_id, source_id, dimension, data_json, evidence_hash,
             confidence, status, raw_reference, first_seen_at, last_seen_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'current', ?, ?, ?)
        ON CONFLICT(campaign_id, evidence_hash) DO UPDATE SET last_seen_at = excluded.last_seen_at
        """,
        (
            observation_id,
            context.campaign_id,
            asset["id"] if asset is not None else None,
            context.source["id"],
            dimension,
            json.dumps(payload, ensure_ascii=False),
            digest,
            confidence,
            f"collection-task:{context.task_id}",
            now,
            now,
        ),
    )
    if asset is not None:
        record_collection_task_asset(
            context.conn,
            context.task_id,
            str(context.source["id"]),
            asset["id"],
        )
    return existing is None


class RdapDomainAdapter(DomainAdapter):
    tool_id = "rdap.domain.v1"
    version = "1.0.0"
    risk_class = "R1"
    source_type = "rdap_domain"
    dimension = "external"
    binary = "curl"
    version_args = ("--version",)
    timeout_seconds = 30
    uses_http = True
    output_schema = {
        "type": "object",
        "required": ["records"],
        "properties": {"records": {"type": "array", "items": {"type": "object"}}},
    }

    def materialize(self, context: AdapterContext) -> list[AdapterInvocation]:
        invocations = []
        for domain in context.targets:
            normalized = normalize_domain(domain)
            invocations.append(
                AdapterInvocation(
                    argv=(
                        self.binary,
                        "--silent",
                        "--show-error",
                        "--fail-with-body",
                        "--location",
                        "--max-redirs",
                        "5",
                        "--proto",
                        "=https",
                        "--proto-redir",
                        "=https",
                        "--max-time",
                        str(self.timeout_seconds),
                        "--user-agent",
                        USER_AGENT,
                        *self._curl_header_args(context),
                        f"https://rdap.org/domain/{quote(normalized, safe='')}",
                    ),
                    target=normalized,
                )
            )
        return invocations

    def execute(self, context: AdapterContext) -> AdapterExecution:
        return self._execute_materialized(context)

    def parse(self, execution: AdapterExecution) -> dict[str, list[dict[str, Any]]]:
        records: list[dict[str, Any]] = []
        for result in execution.results:
            try:
                payload = json.loads(result.stdout)
            except json.JSONDecodeError as exc:
                raise AdapterExecutionError("RDAP returned invalid JSON", execution) from exc
            if not isinstance(payload, dict):
                raise AdapterExecutionError("RDAP response must be a JSON object", execution)
            records.append(
                {
                    "domain": result.target,
                    "handle": payload.get("handle"),
                    "ldh_name": payload.get("ldhName"),
                    "unicode_name": payload.get("unicodeName"),
                    "status": [str(value) for value in payload.get("status", [])],
                    "events": [
                        {
                            "action": event.get("eventAction"),
                            "date": event.get("eventDate"),
                        }
                        for event in payload.get("events", [])
                        if isinstance(event, dict)
                    ],
                    "nameservers": [
                        server.get("ldhName")
                        for server in payload.get("nameservers", [])
                        if isinstance(server, dict) and server.get("ldhName")
                    ],
                    "delegation_signed": payload.get("secureDNS", {}).get("delegationSigned")
                    if isinstance(payload.get("secureDNS"), dict)
                    else None,
                }
            )
        return {"records": records}

    def normalize(self, context: AdapterContext, parsed: Any) -> dict[str, int]:
        created = 0
        updated = 0
        for record in parsed.get("records", []):
            target = record.get("domain")
            if not target:
                continue
            was_created = _record_domain_metadata(context, "rdap", target, record)
            created += int(was_created)
            updated += int(not was_created)
        return {"observations_created": created, "observations_updated": updated}


class WhoisDomainAdapter(DomainAdapter):
    tool_id = "whois.domain.v1"
    version = "1.0.0"
    risk_class = "R1"
    source_type = "whois_domain"
    dimension = "external"
    binary = "whois"
    version_args = ("--version",)
    timeout_seconds = 30
    output_schema = {
        "type": "object",
        "required": ["records"],
        "properties": {"records": {"type": "array", "items": {"type": "object"}}},
    }
    _allowed_fields = {
        "domain name": "domain_name",
        "registrar": "registrar",
        "creation date": "creation_date",
        "updated date": "updated_date",
        "registry expiry date": "expiry_date",
        "expiration date": "expiry_date",
        "name server": "name_servers",
        "domain status": "status",
        "dnssec": "dnssec",
    }

    def materialize(self, context: AdapterContext) -> list[AdapterInvocation]:
        return [
            AdapterInvocation(
                argv=(self.binary, "--", normalize_domain(domain)),
                target=normalize_domain(domain),
            )
            for domain in context.targets
        ]

    def execute(self, context: AdapterContext) -> AdapterExecution:
        return self._execute_materialized(context)

    def parse(self, execution: AdapterExecution) -> dict[str, list[dict[str, Any]]]:
        records: list[dict[str, Any]] = []
        for result in execution.results:
            fields: dict[str, Any] = {"domain": result.target}
            for line in result.stdout.splitlines():
                if ":" not in line:
                    continue
                key, value = line.split(":", 1)
                normalized_key = self._allowed_fields.get(key.strip().lower())
                text = value.strip()
                if normalized_key is None or not text:
                    continue
                if normalized_key in {"name_servers", "status"}:
                    fields.setdefault(normalized_key, []).append(text)
                elif normalized_key not in fields:
                    fields[normalized_key] = text
            records.append(fields)
        return {"records": records}

    def normalize(self, context: AdapterContext, parsed: Any) -> dict[str, int]:
        created = 0
        updated = 0
        for record in parsed.get("records", []):
            target = record.get("domain")
            if not target:
                continue
            was_created = _record_domain_metadata(context, "whois", target, record)
            created += int(was_created)
            updated += int(not was_created)
        return {"observations_created": created, "observations_updated": updated}


def _parse_json_lines(
    execution: AdapterExecution, *, tool_id: str
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for result in execution.results:
        for line in result.stdout.splitlines()[:10000]:
            if not line.strip():
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError as exc:
                raise AdapterExecutionError(
                    f"{tool_id} returned invalid JSONL", execution
                ) from exc
            if not isinstance(payload, dict):
                raise AdapterExecutionError(
                    f"{tool_id} JSONL record must be an object", execution
                )
            payload.setdefault("_invocation_target", result.target)
            payload.setdefault("_invocation_returncode", result.returncode)
            records.append(payload)
    return records


def _bounded_string_list(value: Any, *, limit: int = 100) -> list[str]:
    if isinstance(value, str):
        values = [value]
    elif isinstance(value, list):
        values = value
    else:
        return []
    return [str(item)[:2048] for item in values[:limit] if str(item).strip()]


def _update_domain_technologies(
    context: AdapterContext, domain: str, technologies: list[str]
) -> str | None:
    from cairn.server.services import utcnow
    from cairn.server.vulnerability_services import normalize_target, record_collection_task_asset

    row = context.conn.execute(
        "SELECT id, technology_json FROM vuln_assets WHERE campaign_id = ? AND asset_type = 'domain' AND normalized_identifier = ?",
        (context.campaign_id, normalize_target(domain)),
    ).fetchone()
    if row is None:
        return None
    existing = set(json.loads(row["technology_json"]))
    merged = sorted(existing | {item for item in technologies if item})
    context.conn.execute(
        "UPDATE vuln_assets SET technology_json = ?, last_seen_at = ? WHERE id = ?",
        (json.dumps(merged, ensure_ascii=False), utcnow(), row["id"]),
    )
    record_collection_task_asset(
        context.conn, context.task_id, str(context.source["id"]), row["id"]
    )
    return str(row["id"])


def _bounded_utf8(value: Any, limit: int) -> tuple[str, bool, int]:
    raw = str(value or "").encode("utf-8", errors="replace")
    original_size = len(raw)
    if original_size <= limit:
        return raw.decode("utf-8", errors="replace"), False, original_size
    return raw[:limit].decode("utf-8", errors="replace"), True, original_size


_SENSITIVE_HTTP_HEADER = re.compile(
    r"(?im)^(authorization|proxy-authorization|cookie|set-cookie|x-api-key)\s*:\s*.*$"
)


def _redact_http_message(value: str) -> str:
    return _SENSITIVE_HTTP_HEADER.sub(lambda match: f"{match.group(1)}: [REDACTED]", value)


def _http_response_envelope(
    payload: Mapping[str, Any], url: str, headers: Mapping[str, str]
) -> tuple[str, str, bool, int, str]:
    parsed_url = urlsplit(url)
    request = str(payload.get("request") or "")
    if not request.strip():
        path = parsed_url.path or "/"
        if parsed_url.query:
            path = f"{path}?{parsed_url.query}"
        request_lines = [
            f"{payload.get('method') or 'GET'} {path} HTTP/1.1",
            f"Host: {parsed_url.netloc}",
            *(f"{name}: {value}" for name, value in headers.items()),
        ]
        request = "\r\n".join(request_lines) + "\r\n\r\n"
    response = str(payload.get("response") or "")
    if not response.strip() and payload.get("raw_header"):
        response = f"{payload.get('raw_header') or ''}{payload.get('body') or ''}"
    if not response.strip():
        status_code = payload.get("status_code") or 0
        response_lines = [f"HTTP/1.1 {status_code} Captured"]
        for name, value in (
            ("Server", payload.get("webserver")),
            ("Content-Type", payload.get("content_type")),
            ("Content-Length", payload.get("content_length")),
        ):
            if value not in (None, ""):
                response_lines.append(f"{name}: {value}")
        response = "\r\n".join(response_lines) + "\r\n\r\n"
    request, request_truncated, _ = _bounded_utf8(
        _redact_http_message(request), HTTP_REQUEST_MAX_BYTES
    )
    response, response_truncated, response_bytes = _bounded_utf8(
        _redact_http_message(response), HTTP_RESPONSE_MAX_BYTES
    )
    response_hash = hashlib.sha256(response.encode("utf-8")).hexdigest()
    return (
        request,
        response,
        request_truncated or response_truncated or response_bytes >= HTTP_RESPONSE_MAX_BYTES,
        response_bytes,
        response_hash,
    )


class DnsxResolveAdapter(DomainAdapter):
    tool_id = "dnsx.resolve.v1"
    version = "1.0.0"
    risk_class = "R2"
    source_type = "dns"
    dimension = "external"
    binary = _configured_user_binary("dnsx", "CAIRN_DNSX_BINARY")
    version_args = ("-version",)
    timeout_seconds = 30
    uses_network = True
    output_schema = {
        "type": "object",
        "required": ["records"],
        "properties": {"records": {"type": "array", "items": {"type": "object"}}},
    }

    def materialize(self, context: AdapterContext) -> list[AdapterInvocation]:
        return [
            AdapterInvocation(
                argv=(
                    self.binary,
                    "-silent",
                    "-json",
                    "-omit-raw",
                    "-a",
                    "-aaaa",
                    "-cname",
                    "-ns",
                    "-threads",
                    "1",
                    "-rate-limit",
                    str(max(1, context.max_requests_per_second)),
                    "-retry",
                    "1",
                    "-disable-update-check",
                ),
                target=normalize_domain(domain),
                stdin=f"{normalize_domain(domain)}\n",
            )
            for domain in context.targets
        ]

    def execute(self, context: AdapterContext) -> AdapterExecution:
        return self._execute_materialized(context)

    def parse(self, execution: AdapterExecution) -> dict[str, Any]:
        records = []
        for payload in _parse_json_lines(execution, tool_id=self.tool_id):
            domain = normalize_domain(
                str(payload.get("host") or payload.get("input") or payload["_invocation_target"])
            )
            records.append(
                {
                    "domain": domain,
                    "rcode": payload.get("status_code") or payload.get("rcode"),
                    "a": _bounded_string_list(payload.get("a")),
                    "aaaa": _bounded_string_list(payload.get("aaaa")),
                    "cname": _bounded_string_list(payload.get("cname")),
                    "ns": _bounded_string_list(payload.get("ns")),
                    "resolver": _bounded_string_list(payload.get("resolver"), limit=10),
                }
            )
        return {"records": records}

    def normalize(self, context: AdapterContext, parsed: Any) -> dict[str, int]:
        from cairn.server.vulnerability_models import AssetInput
        from cairn.server.vulnerability_services import record_collection_task_asset, upsert_asset

        observations = 0
        assets_created = 0
        for record in parsed.get("records", []):
            data = {
                **record,
                "request": {"query_types": ["A", "AAAA", "CNAME", "NS"]},
                "network_path": "direct",
            }
            observations += int(
                _record_domain_metadata(context, "dns", record["domain"], data)
            )
            _update_domain_technologies(context, record["domain"], [])
            for address in [*record.get("a", []), *record.get("aaaa", [])]:
                try:
                    ipaddress.ip_address(address)
                except ValueError:
                    continue
                asset, created = upsert_asset(
                    context.conn,
                    context.campaign_id,
                    AssetInput(
                        asset_type="ip",
                        identifier=address,
                        source_name=str(context.source["name"]),
                    ),
                )
                record_collection_task_asset(
                    context.conn,
                    context.task_id,
                    str(context.source["id"]),
                    asset.id,
                )
                assets_created += int(created)
        return {
            "observations_created": observations,
            "assets_created": assets_created,
        }


class HttpxHttpMetadataAdapter(DomainAdapter):
    tool_id = "httpx.http-meta.v1"
    version = "1.0.0"
    risk_class = "R2"
    source_type = "http"
    dimension = "web"
    binary = _configured_user_binary("httpx-toolkit", "CAIRN_HTTPX_BINARY")
    version_args = ("-version",)
    timeout_seconds = 30
    uses_http = True
    output_schema = {
        "type": "object",
        "required": ["records"],
        "properties": {"records": {"type": "array", "items": {"type": "object"}}},
    }

    def materialize(self, context: AdapterContext) -> list[AdapterInvocation]:
        header_args = tuple(
            argument
            for name, value in self.get_headers(context).items()
            for argument in ("-H", f"{name}: {value}")
        )
        proxy_args = ("-http-proxy", context.proxy_url) if context.proxy_url else ()
        invocations: list[AdapterInvocation] = []
        for domain in context.targets:
            normalized = normalize_domain(domain)
            for scheme in ("https", "http"):
                url = f"{scheme}://{normalized}"
                invocations.append(
                    AdapterInvocation(
                        argv=(
                            self.binary,
                            "-u",
                            url,
                            "-no-fallback-scheme",
                            "-json",
                            "-include-response",
                            "-response-size-to-read",
                            str(HTTP_RESPONSE_MAX_BYTES),
                            "-response-size-to-save",
                            str(HTTP_RESPONSE_MAX_BYTES),
                            "-status-code",
                            "-title",
                            "-tech-detect",
                            "-server",
                            "-ip",
                            "-cname",
                            "-method",
                            "-response-time",
                            "-threads",
                            "1",
                            "-rate-limit",
                            str(max(1, context.max_requests_per_second)),
                            "-timeout",
                            "10",
                            "-no-stdin",
                            "-disable-update-check",
                            *header_args,
                            *proxy_args,
                        ),
                        target=url,
                    )
                )
        return invocations

    def execute(self, context: AdapterContext) -> AdapterExecution:
        return self._execute_materialized(context)

    def parse(self, execution: AdapterExecution) -> dict[str, Any]:
        records = []
        for payload in _parse_json_lines(execution, tool_id=self.tool_id):
            url = str(payload.get("url") or payload["_invocation_target"])
            domain = normalize_domain(str(payload.get("input") or url))
            request, response, content_truncated, response_bytes, response_hash = (
                _http_response_envelope(payload, url, {})
            )
            records.append(
                {
                    "domain": domain,
                    "url": url[:4096],
                    "scheme": payload.get("scheme") or urlsplit(url).scheme,
                    "method": payload.get("method") or "GET",
                    "status_code": payload.get("status_code"),
                    "title": str(payload.get("title") or "")[:1000] or None,
                    "server": str(payload.get("webserver") or "")[:512] or None,
                    "technologies": _bounded_string_list(payload.get("tech"), limit=100),
                    "host_ip": str(payload.get("host_ip") or "")[:128] or None,
                    "cname": _bounded_string_list(payload.get("cname"), limit=20),
                    "content_type": str(payload.get("content_type") or "")[:512] or None,
                    "content_length": payload.get("content_length"),
                    "response_time": str(payload.get("response_time") or "")[:128] or None,
                    "request_text": request,
                    "response_text": response,
                    "response_hash": response_hash,
                    "response_bytes": response_bytes,
                    "content_truncated": content_truncated,
                }
            )
        return {"records": records}

    def normalize(self, context: AdapterContext, parsed: Any) -> dict[str, int]:
        created = 0
        updated = 0
        for record in parsed.get("records", []):
            data = {
                **record,
                "request": {
                    "method": record.get("method") or "GET",
                    "url": record["url"],
                    "headers": self.get_headers(context),
                    "follow_redirects": False,
                },
                "response": {
                    "status_code": record.get("status_code"),
                    "title": record.get("title"),
                    "server": record.get("server"),
                    "technologies": record.get("technologies", []),
                    "content_type": record.get("content_type"),
                    "content_length": record.get("content_length"),
                    "response_time": record.get("response_time"),
                    "body_recorded": True,
                    "response_hash": record.get("response_hash"),
                    "content_truncated": bool(record.get("content_truncated")),
                },
                "network_path": "proxy" if context.proxy_url else "direct",
            }
            was_created = _record_domain_metadata(
                context,
                "http_metadata",
                record["domain"],
                data,
                dimension="web",
            )
            asset_id = _update_domain_technologies(
                context, record["domain"], record.get("technologies", [])
            )
            if asset_id is not None:
                from cairn.server.services import utcnow
                from cairn.server.vulnerability_services import next_vulnerability_id

                response_id = next_vulnerability_id(
                    context.conn, "http_response", "http_response"
                )
                context.conn.execute(
                    """
                    INSERT INTO vuln_http_responses
                        (id, campaign_id, task_id, source_id, asset_id, url, method,
                         status_code, request_text, response_text, response_hash,
                         response_bytes, content_truncated, redacted, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)
                    ON CONFLICT(task_id, url) DO UPDATE SET
                        method = excluded.method,
                        status_code = excluded.status_code,
                        request_text = excluded.request_text,
                        response_text = excluded.response_text,
                        response_hash = excluded.response_hash,
                        response_bytes = excluded.response_bytes,
                        content_truncated = excluded.content_truncated,
                        redacted = 1
                    """,
                    (
                        response_id,
                        context.campaign_id,
                        context.task_id,
                        context.source["id"],
                        asset_id,
                        record["url"],
                        record.get("method") or "GET",
                        record.get("status_code"),
                        record["request_text"],
                        record["response_text"],
                        record["response_hash"],
                        record["response_bytes"],
                        int(record["content_truncated"]),
                        utcnow(),
                    ),
                )
            created += int(was_created)
            updated += int(not was_created)
        return {"observations_created": created, "observations_updated": updated}


def _certificate_chain_summary(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    summaries: list[dict[str, Any]] = []
    for certificate in value[:20]:
        if not isinstance(certificate, dict):
            continue
        summaries.append(
            {
                key: certificate.get(key)
                for key in (
                    "subject_cn",
                    "subject_dn",
                    "subject_org",
                    "issuer_cn",
                    "issuer_dn",
                    "issuer_org",
                    "serial",
                    "not_before",
                    "not_after",
                    "fingerprint_hash",
                )
                if certificate.get(key) is not None
            }
        )
    return summaries


class TlsxTlsMetadataAdapter(DomainAdapter):
    tool_id = "tlsx.tls-meta.v1"
    version = "1.0.0"
    risk_class = "R2"
    source_type = "tls"
    dimension = "web"
    binary = _configured_user_binary("tlsx", "CAIRN_TLSX_BINARY")
    version_args = ("-version",)
    timeout_seconds = 30
    uses_network = True
    accept_complete_json_on_timeout = True
    output_schema = {
        "type": "object",
        "required": ["records"],
        "properties": {"records": {"type": "array", "items": {"type": "object"}}},
    }

    def materialize(self, context: AdapterContext) -> list[AdapterInvocation]:
        proxy_args = (
            ("-proxy", context.proxy_url)
            if context.proxy_url and urlsplit(context.proxy_url).scheme == "socks5"
            else ()
        )
        invocations: list[AdapterInvocation] = []
        for domain in context.targets:
            normalized = normalize_domain(domain)
            common = (
                self.binary,
                "-u",
                normalized,
                "-json",
                "-silent",
                "-concurrency",
                "1",
                "-retry",
                "1",
                "-timeout",
                "10",
                "-disable-update-check",
                *proxy_args,
            )
            # tlsx rejects SAN/CN projection flags when combined with other
            # probes. Separate negotiated metadata from certificate-chain
            # materialization and merge their bounded JSON below.
            invocations.extend(
                (
                    AdapterInvocation(
                        argv=(*common, "-tls-version", "-cipher", "-probe-status"),
                        target=normalized,
                    ),
                    AdapterInvocation(
                        argv=(*common, "-certificate", "-tls-chain"),
                        target=normalized,
                    ),
                )
            )
        return invocations

    def execute(self, context: AdapterContext) -> AdapterExecution:
        return self._execute_materialized(context)

    def parse(self, execution: AdapterExecution) -> dict[str, Any]:
        records: dict[str, dict[str, Any]] = {}
        for payload in _parse_json_lines(execution, tool_id=self.tool_id):
            domain = normalize_domain(
                str(payload.get("host") or payload.get("input") or payload["_invocation_target"])
            )
            certificate = payload.get("certificate_response")
            certificate = certificate if isinstance(certificate, dict) else payload
            raw_chain = (
                payload.get("certificate_chain")
                or payload.get("chain")
                or payload.get("tls_chain")
                or certificate.get("certificate_chain")
                or []
            )
            candidate = {
                "domain": domain,
                "port": payload.get("port") or 443,
                "probe_status": payload.get("probe_status"),
                "tls_version": payload.get("tls_version"),
                "cipher": payload.get("cipher"),
                "key_exchange": payload.get("key_exchange"),
                "subject_cn": certificate.get("subject_cn"),
                "subject_an": _bounded_string_list(certificate.get("subject_an"), limit=200),
                "subject_org": _bounded_string_list(certificate.get("subject_org"), limit=20),
                "issuer_cn": certificate.get("issuer_cn"),
                "serial": certificate.get("serial"),
                "not_before": certificate.get("not_before"),
                "not_after": certificate.get("not_after"),
                "fingerprint_hash": certificate.get("fingerprint_hash"),
                "certificate_chain": _certificate_chain_summary(raw_chain),
                "process_timeout_after_output": payload.get("_invocation_returncode") == -1,
            }
            current = records.setdefault(domain, {"domain": domain})
            for key, value in candidate.items():
                if value not in (None, "", []):
                    current[key] = value
        return {"records": list(records.values())}

    def normalize(self, context: AdapterContext, parsed: Any) -> dict[str, int]:
        created = 0
        updated = 0
        for record in parsed.get("records", []):
            data = {
                **record,
                "request": {
                    "host": record["domain"],
                    "port": record.get("port") or 443,
                    "handshake_only": True,
                },
                "network_path": (
                    "socks5_proxy"
                    if context.proxy_url and urlsplit(context.proxy_url).scheme == "socks5"
                    else "direct"
                ),
            }
            was_created = _record_domain_metadata(
                context,
                "tls_metadata",
                record["domain"],
                data,
                dimension="web",
            )
            _update_domain_technologies(context, record["domain"], [])
            created += int(was_created)
            updated += int(not was_created)
        return {"observations_created": created, "observations_updated": updated}


def _audited_nuclei_template_paths() -> tuple[Path, ...]:
    configured_root = os.getenv("CAIRN_NUCLEI_TEMPLATES_ROOT")
    root = Path(configured_root).expanduser() if configured_root else (
        Path.home()
        / ".local"
        / "share"
        / "cairn"
        / "nuclei-templates"
        / NUCLEI_TEMPLATES_COMMIT
    )
    root = root.resolve()
    paths: list[Path] = []
    for template_id, relative_path, expected_hash in NUCLEI_TEMPLATE_ALLOWLIST:
        path = (root / relative_path).resolve()
        try:
            path.relative_to(root)
        except ValueError as exc:
            raise AdapterValidationError("Nuclei template path escapes the audited root") from exc
        try:
            content = path.read_bytes()
        except OSError as exc:
            raise AdapterUnavailableError(
                f"Audited Nuclei template is unavailable: {relative_path}"
            ) from exc
        actual_hash = hashlib.sha256(content).hexdigest()
        if not expected_hash or actual_hash != expected_hash:
            raise AdapterValidationError(
                f"Nuclei template hash mismatch: {relative_path}"
            )
        text = content.decode("utf-8", errors="strict")
        if not re.search(rf"(?m)^id:\s*{re.escape(template_id)}\s*$", text):
            raise AdapterValidationError(
                f"Nuclei template ID mismatch: {relative_path}"
            )
        if not re.search(r"(?m)^# digest:\s*[0-9a-f]+:[0-9a-f]+\s*$", text):
            raise AdapterValidationError(
                f"Nuclei template is not signed: {relative_path}"
            )
        if NUCLEI_FORBIDDEN_TEMPLATE_PATTERN.search(text):
            raise AdapterValidationError(
                f"Nuclei template violates the offline passive policy: {relative_path}"
            )
        if '"{{BaseURL}}"' not in text or text.count("{{BaseURL}}") != 1:
            raise AdapterValidationError(
                f"Nuclei template is not a single BaseURL passive matcher: {relative_path}"
            )
        paths.append(path)
    return tuple(paths)


class NaabuPortScanAdapter(DomainAdapter):
    """Constrained R3 port discovery; never materializes arbitrary CLI arguments."""

    tool_id = "naabu.port-scan.v1"
    version = "0.1.0"
    risk_class = "R3"
    source_type = "naabu_port_scan"
    dimension = "external"
    binary = _configured_user_binary("naabu", "CAIRN_NAABU_BINARY")
    expected_tool_version = "2.6.1"
    release_sha256 = "018c4c9884dea971eda860435ede3021d1150732f34cfd245498c6726d8cab90"
    version_args = ("-version",)
    timeout_seconds = 90
    uses_network = True
    output_schema = {
        "type": "object",
        "required": ["ports"],
        "properties": {"ports": {"type": "array", "items": {"type": "object"}}},
    }

    def materialize(self, context: AdapterContext) -> list[AdapterInvocation]:
        rate = min(25, max(1, context.max_requests_per_second))
        return [
            AdapterInvocation(
                argv=(
                    self.binary,
                    "-host",
                    normalize_domain(domain),
                    "-top-ports",
                    "100",
                    "-rate",
                    str(rate),
                    "-c",
                    "1",
                    "-retries",
                    "1",
                    "-json",
                    "-silent",
                    "-disable-update-check",
                ),
                target=normalize_domain(domain),
            )
            for domain in context.targets
        ]

    def execute(self, context: AdapterContext) -> AdapterExecution:
        return self._execute_materialized(context)

    def parse(self, execution: AdapterExecution) -> dict[str, Any]:
        ports: list[dict[str, Any]] = []
        for payload in _parse_json_lines(execution, tool_id=self.tool_id):
            port = payload.get("port")
            if not isinstance(port, int) or not 1 <= port <= 65535:
                continue
            ports.append(
                {
                    "domain": normalize_domain(
                        str(payload.get("host") or payload.get("input") or payload["_invocation_target"])
                    ),
                    "ip": str(payload.get("ip") or "")[:128] or None,
                    "port": port,
                    "protocol": str(payload.get("protocol") or "tcp")[:16],
                }
            )
        return {"ports": ports}

    def normalize(self, context: AdapterContext, parsed: Any) -> dict[str, int]:
        created = 0
        updated = 0
        grouped: dict[str, list[dict[str, Any]]] = {}
        for record in parsed.get("ports", []):
            grouped.setdefault(record["domain"], []).append(record)
        for domain, ports in grouped.items():
            was_created = _record_domain_metadata(
                context,
                "open_ports",
                domain,
                {
                    "domain": domain,
                    "ports": ports,
                    "scan_profile": "fixed-top-100-tcp",
                    "network_path": "direct",
                },
                dimension="external",
            )
            created += int(was_created)
            updated += int(not was_created)
        return {"observations_created": created, "observations_updated": updated}


class KatanaCrawlerAdapter(DomainAdapter):
    """Depth-one, no-form, no-headless R3 discovery profile."""

    tool_id = "katana.crawler.v1"
    version = "0.1.0"
    risk_class = "R3"
    source_type = "katana_crawler"
    dimension = "web"
    binary = _configured_user_binary("katana", "CAIRN_KATANA_BINARY")
    expected_tool_version = "1.7.0"
    release_sha256 = "fe1142d92f418549338ea46d67a472124878482e225d279e9a42700c75d76a4d"
    version_args = ("-version",)
    timeout_seconds = 90
    uses_http = True
    output_schema = {
        "type": "object",
        "required": ["urls"],
        "properties": {"urls": {"type": "array", "items": {"type": "object"}}},
    }

    def materialize(self, context: AdapterContext) -> list[AdapterInvocation]:
        headers = tuple(
            argument
            for name, value in self.get_headers(context).items()
            for argument in ("-H", f"{name}: {value}")
        )
        return [
            AdapterInvocation(
                argv=(
                    self.binary,
                    "-u",
                    f"https://{normalize_domain(domain)}",
                    "-d",
                    "1",
                    "-c",
                    "1",
                    "-p",
                    "1",
                    "-rl",
                    str(min(10, max(1, context.max_requests_per_second))),
                    "-timeout",
                    "10",
                    "-jsonl",
                    "-silent",
                    "-disable-update-check",
                    *headers,
                ),
                target=normalize_domain(domain),
            )
            for domain in context.targets
        ]

    def execute(self, context: AdapterContext) -> AdapterExecution:
        return self._execute_materialized(context)

    def parse(self, execution: AdapterExecution) -> dict[str, Any]:
        urls: list[dict[str, str]] = []
        for payload in _parse_json_lines(execution, tool_id=self.tool_id):
            request = payload.get("request") if isinstance(payload.get("request"), dict) else {}
            endpoint = str(payload.get("url") or request.get("endpoint") or "")[:4096]
            parsed = urlsplit(endpoint)
            if parsed.scheme not in {"http", "https"} or not parsed.hostname:
                continue
            invocation_domain = normalize_domain(str(payload["_invocation_target"]))
            endpoint_domain = normalize_domain(parsed.hostname)
            if endpoint_domain != invocation_domain and not endpoint_domain.endswith(f".{invocation_domain}"):
                continue
            urls.append({"domain": invocation_domain, "url": endpoint})
        return {"urls": urls}

    def normalize(self, context: AdapterContext, parsed: Any) -> dict[str, int]:
        created = 0
        updated = 0
        grouped: dict[str, list[str]] = {}
        for record in parsed.get("urls", []):
            grouped.setdefault(record["domain"], []).append(record["url"])
        for domain, urls in grouped.items():
            was_created = _record_domain_metadata(
                context,
                "web_discovery",
                domain,
                {
                    "domain": domain,
                    "urls": sorted(set(urls))[:1000],
                    "crawl_profile": "depth-1-no-headless-no-form-submission",
                    "request_headers": self.get_headers(context),
                },
                dimension="web",
            )
            created += int(was_created)
            updated += int(not was_created)
        return {"observations_created": created, "observations_updated": updated}


class NucleiPassiveResponseAdapter(DomainAdapter):
    """Run a fixed signed-template allowlist against captured HTTP responses only."""

    tool_id = "nuclei.passive-response.v1"
    version = "1.0.0"
    risk_class = "R2"
    source_type = "nuclei_passive"
    dimension = "intelligence"
    binary = _configured_user_binary("nuclei", "CAIRN_NUCLEI_BINARY")
    version_args = ("-version",)
    timeout_seconds = 60
    uses_http = False
    uses_network = False
    input_schema = {
        "type": "object",
        "required": ["domains", "http_responses"],
        "properties": {
            "domains": {"type": "array", "items": {"type": "string"}},
            "http_responses": {"type": "array", "items": {"type": "object"}},
        },
        "additionalProperties": False,
    }
    output_schema = {
        "type": "object",
        "required": ["findings", "coverage_complete"],
        "properties": {
            "findings": {"type": "array", "items": {"type": "object"}},
            "coverage_complete": {"type": "boolean"},
        },
    }

    def validate(self, context: AdapterContext) -> None:
        super().validate(context)
        if not context.http_responses:
            raise AdapterValidationError(
                "Nuclei passive analysis requires a captured HTTP response"
            )
        if len(context.http_responses) > 20:
            raise AdapterValidationError(
                "Nuclei passive analysis accepts at most 20 captured responses per task"
            )
        allowed_targets = {normalize_domain(target) for target in context.targets}
        for response in context.http_responses:
            response_domain = normalize_domain(str(response.get("domain") or ""))
            if response_domain not in allowed_targets:
                raise AdapterValidationError(
                    "Captured HTTP response does not match the task target"
                )
            if not response.get("file_path") and not response.get("response_text"):
                raise AdapterValidationError("Captured HTTP response content is missing")
        _audited_nuclei_template_paths()

    def estimate(self, context: AdapterContext) -> dict[str, Any]:
        return {
            "command_count": len(context.http_responses),
            "timeout_seconds": self.timeout_seconds,
            "risk_class": self.risk_class,
            "network_request_count": 0,
            "offline_only": True,
            "template_count": len(NUCLEI_TEMPLATE_ALLOWLIST),
        }

    def health(self) -> dict[str, Any]:
        result = super().health()
        if not result.get("healthy"):
            return result
        try:
            paths = _audited_nuclei_template_paths()
        except AdapterError as exc:
            return {
                "healthy": False,
                "tool_id": self.tool_id,
                "version": result.get("version"),
                "error": str(exc),
            }
        return {
            **result,
            "templates_commit": NUCLEI_TEMPLATES_COMMIT,
            "template_ids": [item[0] for item in NUCLEI_TEMPLATE_ALLOWLIST],
            "template_count": len(paths),
        }

    def materialize(self, context: AdapterContext) -> list[AdapterInvocation]:
        template_paths = _audited_nuclei_template_paths()
        template_args = tuple(
            argument
            for path in template_paths
            for argument in ("-templates", str(path))
        )
        template_ids = ",".join(item[0] for item in NUCLEI_TEMPLATE_ALLOWLIST)
        invocations: list[AdapterInvocation] = []
        for response in context.http_responses:
            file_path = str(response.get("file_path") or "")
            if not file_path:
                raise AdapterValidationError("Nuclei response file was not materialized")
            invocations.append(
                AdapterInvocation(
                    argv=(
                        self.binary,
                        "-passive",
                        "-target",
                        file_path,
                        *template_args,
                        "-template-id",
                        template_ids,
                        "-type",
                        "http",
                        "-disable-unsigned-templates",
                        "-exclude-tags",
                        "code,headless,fuzz,dos,bruteforce,intrusive",
                        "-no-interactsh",
                        "-jsonl",
                        "-silent",
                        "-omit-raw",
                        "-concurrency",
                        "1",
                        "-bulk-size",
                        "1",
                        "-rate-limit",
                        "1",
                        "-retries",
                        "0",
                        "-timeout",
                        "5",
                        "-no-stdin",
                        "-disable-update-check",
                    ),
                    target=str(response["id"]),
                )
            )
        return invocations

    def execute(self, context: AdapterContext) -> AdapterExecution:
        self.validate(context)
        with tempfile.TemporaryDirectory(prefix="cairn-nuclei-passive-") as directory:
            materialized: list[Mapping[str, Any]] = []
            for index, response in enumerate(context.http_responses):
                request_text = str(response.get("request_text") or "").rstrip()
                response_text = str(response.get("response_text") or "").lstrip()
                # Nuclei's offlinehttp parser accepts the exact wire-shaped
                # request followed by the response, matching httpx
                # -store-response output. No URL is passed back to the network.
                capture = (
                    request_text.rstrip("\r\n")
                    + "\r\n\r\n"
                    + response_text.lstrip("\r\n")
                )
                path = Path(directory) / f"response-{index:03d}.txt"
                path.write_text(capture, encoding="utf-8")
                materialized.append({**response, "file_path": str(path)})
            execution_context = replace(
                context, http_responses=tuple(materialized)
            )
            return self._execute_invocations(
                execution_context, self.materialize(execution_context)
            )

    def parse(self, execution: AdapterExecution) -> dict[str, Any]:
        findings: list[dict[str, Any]] = []
        for payload in _parse_json_lines(execution, tool_id=self.tool_id):
            info = payload.get("info")
            info = info if isinstance(info, dict) else {}
            classification = info.get("classification")
            classification = classification if isinstance(classification, dict) else {}
            findings.append(
                {
                    "response_id": payload.get("_invocation_target"),
                    "template_id": str(payload.get("template-id") or "")[:256],
                    "matcher_name": str(payload.get("matcher-name") or "")[:256] or None,
                    "title": str(info.get("name") or payload.get("template-id") or "Nuclei passive match")[:1000],
                    "description": str(info.get("description") or "Offline passive response match")[:8000],
                    "severity": str(info.get("severity") or "unknown").lower(),
                    "cwe": str(classification.get("cwe-id") or "")[:128] or None,
                    "remediation": str(info.get("remediation") or "")[:8000] or None,
                    "matched_at": str(payload.get("matched-at") or payload.get("host") or "")[:4096],
                }
            )
        return {"findings": findings}

    def normalize(self, context: AdapterContext, parsed: Any) -> dict[str, int]:
        from cairn.server.vulnerability_services import reconcile_passive_findings

        coverage_complete = self.coverage_complete(context, parsed)
        return reconcile_passive_findings(
            context.conn,
            campaign_id=context.campaign_id,
            task_id=context.task_id,
            adapter=self.tool_id,
            targets=list(context.targets),
            responses=list(context.http_responses),
            matches=list(parsed.get("findings", [])),
            coverage_complete=coverage_complete,
        )

    def coverage_complete(self, context: AdapterContext, parsed: Any) -> bool:
        return bool(context.http_responses) and all(
            not bool(response.get("content_truncated"))
            for response in context.http_responses
        )


class OsvVulnerabilityIntelligenceAdapter(VulnSourceAdapter):
    tool_id = "osv.vuln-intel.v1"
    version = "1.0.0"
    risk_class = "R1"
    source_type = "vulnerability_intelligence"
    dimension = "intelligence"
    binary = "curl"
    version_args = ("--version",)
    timeout_seconds = 30
    uses_http = True
    input_schema = {
        "type": "object",
        "required": ["packages"],
        "properties": {"packages": {"type": "array", "items": {"type": "object"}}},
        "additionalProperties": False,
    }
    output_schema = {
        "type": "object",
        "required": ["results"],
        "properties": {"results": {"type": "array", "items": {"type": "object"}}},
    }

    def validate(self, context: AdapterContext) -> None:
        super().validate(context)
        if len(context.packages) > 1000:
            raise AdapterValidationError("OSV adapter accepts at most 1000 packages")
        for package in context.packages:
            if not all(str(package.get(key, "")).strip() for key in ("ecosystem", "name", "version")):
                raise AdapterValidationError("OSV package input is incomplete")

    def materialize(self, context: AdapterContext) -> list[AdapterInvocation]:
        if not context.packages:
            return []
        payload = {
            "queries": [
                {
                    "version": package["version"],
                    "package": {
                        "ecosystem": package["ecosystem"],
                        "name": package["name"],
                    },
                }
                for package in context.packages
            ]
        }
        return [
            AdapterInvocation(
                argv=(
                    self.binary,
                    "--silent",
                    "--show-error",
                    "--fail-with-body",
                    "--max-time",
                    str(self.timeout_seconds),
                    "--user-agent",
                    USER_AGENT,
                    *self._curl_header_args(context),
                    "--header",
                    "Content-Type: application/json",
                    "--request",
                    "POST",
                    "--data-binary",
                    json.dumps(payload, separators=(",", ":")),
                    "https://api.osv.dev/v1/querybatch",
                )
            )
        ]

    def execute(self, context: AdapterContext) -> AdapterExecution:
        return self._execute_materialized(context)

    def parse(self, execution: AdapterExecution) -> dict[str, Any]:
        if not execution.results:
            return {"results": []}
        try:
            payload = json.loads(execution.results[0].stdout)
        except json.JSONDecodeError as exc:
            raise AdapterExecutionError("OSV returned invalid JSON", execution) from exc
        if not isinstance(payload, dict) or not isinstance(payload.get("results", []), list):
            raise AdapterExecutionError("OSV response has an invalid result structure", execution)
        return payload

    def normalize(self, context: AdapterContext, parsed: Any) -> dict[str, int]:
        from cairn.server.vulnerability_services import reconcile_osv_findings

        return reconcile_osv_findings(
            context.conn,
            campaign_id=context.campaign_id,
            task_id=context.task_id,
            source_id=str(context.source["id"]),
            adapter=self.tool_id,
            packages=list(context.packages),
            results=list(parsed.get("results", [])),
            coverage_complete=self.coverage_complete(context, parsed),
        )

    def coverage_complete(self, context: AdapterContext, parsed: Any) -> bool:
        return len(parsed.get("results", [])) == len(context.packages)

    def next_cursor(
        self,
        context: AdapterContext,
        parsed: Any,
        execution: AdapterExecution,
    ) -> dict[str, Any]:
        package_hashes: dict[str, str] = {}
        high_water_modified = ""
        for package, result in zip(
            context.packages, parsed.get("results", []), strict=False
        ):
            package_hashes[str(package["normalized_identifier"])] = hashlib.sha256(
                json.dumps(result, sort_keys=True, separators=(",", ":")).encode("utf-8")
            ).hexdigest()
            for vulnerability in result.get("vulns", []):
                high_water_modified = max(
                    high_water_modified,
                    str(vulnerability.get("modified") or ""),
                )
        return {
            "package_hashes": package_hashes,
            "high_water_modified": high_water_modified or None,
            "output_hash": execution.output_hash,
        }


_ADAPTERS: tuple[VulnSourceAdapter, ...] = (
    CertificateTransparencyAdapter(),
    OsvVulnerabilityIntelligenceAdapter(),
    SubfinderPassiveDnsAdapter(),
    AmassPassiveEnumAdapter(),
    RdapDomainAdapter(),
    WhoisDomainAdapter(),
    DnsxResolveAdapter(),
    HttpxHttpMetadataAdapter(),
    TlsxTlsMetadataAdapter(),
    NucleiPassiveResponseAdapter(),
    NaabuPortScanAdapter(),
    KatanaCrawlerAdapter(),
)

ADAPTER_REGISTRY: dict[str, VulnSourceAdapter] = {
    adapter.tool_id: adapter for adapter in _ADAPTERS
}
ADAPTER_SPECS: dict[str, AdapterSpec] = {
    adapter.tool_id: adapter.spec for adapter in _ADAPTERS
}
SOURCE_TYPE_ADAPTERS: dict[str, str] = {
    adapter.source_type: adapter.tool_id for adapter in _ADAPTERS
}


def get_adapter(tool_id: str) -> VulnSourceAdapter | None:
    return ADAPTER_REGISTRY.get(tool_id)


def adapter_spec(tool_id: str) -> AdapterSpec | None:
    return ADAPTER_SPECS.get(tool_id)


def adapter_id_for_source_type(source_type: str) -> str | None:
    return SOURCE_TYPE_ADAPTERS.get(source_type)
