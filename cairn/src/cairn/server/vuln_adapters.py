from __future__ import annotations

import hashlib
import json
import re
import shutil
import sqlite3
import subprocess
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Mapping
from urllib.parse import quote, urlsplit


USER_AGENT = "Cairn/0.2 authorized-passive-research"
DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}\.?$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.?$",
    re.IGNORECASE,
)
HTTP_HEADER_NAME_PATTERN = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
FORBIDDEN_REQUEST_HEADERS = {"host", "content-length"}


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
    cursor: Mapping[str, Any] = field(default_factory=dict)
    request_header: str = "X-Cairn-Research"
    max_requests_per_second: int = 30


@dataclass(frozen=True)
class AdapterInvocation:
    argv: tuple[str, ...]
    target: str | None = None


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
                (context.campaign_id, now - 1.0),
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
        time.sleep(max(0.001, oldest + 1.0 - now))


class VulnSourceAdapter(ABC):
    """Lifecycle contract for allowlisted, argument-array-only R1 collectors."""

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
        output = completed.stdout.strip() or completed.stderr.strip()
        first_line = output.splitlines()[0][:256] if output else None
        if completed.returncode != 0:
            detail = f": {first_line}" if first_line else ""
            return {
                "healthy": False,
                "tool_id": self.tool_id,
                "version": None,
                "error": f"Version probe exited with code {completed.returncode}{detail}",
            }
        return {
            "healthy": True,
            "tool_id": self.tool_id,
            "version": first_line,
            "error": None,
        }

    def _execute_materialized(self, context: AdapterContext) -> AdapterExecution:
        self.validate(context)
        results: list[CommandResult] = []
        for invocation in self.materialize(context):
            if self.uses_http:
                acquire_campaign_http_rate_limit(context)
            started = time.monotonic()
            try:
                completed = subprocess.run(
                    list(invocation.argv),
                    capture_output=True,
                    text=True,
                    timeout=self.timeout_seconds,
                    check=False,
                    shell=False,
                )
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
    binary = "subfinder"
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
    binary = "amass"
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
        VALUES (?, ?, ?, ?, 'external', ?, ?, 0.9, 'current', ?, ?, ?)
        ON CONFLICT(campaign_id, evidence_hash) DO UPDATE SET last_seen_at = excluded.last_seen_at
        """,
        (
            observation_id,
            context.campaign_id,
            asset["id"] if asset is not None else None,
            context.source["id"],
            json.dumps(payload, ensure_ascii=False),
            digest,
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
        from fastapi import HTTPException

        from cairn.server.vulnerability_models import FindingInput
        from cairn.server.vulnerability_services import (
            create_finding,
            record_audit,
            record_collection_task_asset,
        )

        created = 0
        duplicates = 0
        unmatched = 0
        results = parsed.get("results", [])
        for package, result in zip(context.packages, results, strict=False):
            identifier = str(
                package.get("identifier")
                or f"{package['ecosystem']}:{package['name']}@{package['version']}"
            )
            asset = context.conn.execute(
                """
                SELECT id
                FROM vuln_assets
                WHERE campaign_id = ?
                  AND asset_type IN ('dependency', 'package')
                  AND identifier = ? COLLATE BINARY
                ORDER BY id
                LIMIT 1
                """,
                (context.campaign_id, identifier),
            ).fetchone()
            asset_id = str(asset["id"]) if asset is not None else None
            if asset_id is not None:
                record_collection_task_asset(
                    context.conn,
                    context.task_id,
                    str(context.source["id"]),
                    asset_id,
                )
            else:
                unmatched += 1
                record_audit(
                    context.conn,
                    context.campaign_id,
                    "osv.asset_unmatched",
                    actor="osv.vuln-intel.v1",
                    target=context.task_id,
                    detail={"identifier": identifier},
                )
            package_key = str(package["normalized_identifier"])
            result_hash = hashlib.sha256(
                json.dumps(result, sort_keys=True, separators=(",", ":")).encode("utf-8")
            ).hexdigest()
            previous_hashes = context.cursor.get("package_hashes", {})
            if isinstance(previous_hashes, Mapping) and previous_hashes.get(package_key) == result_hash:
                continue
            for vulnerability in result.get("vulns", []):
                vulnerability_id = vulnerability.get("id", "OSV-UNKNOWN")
                severity = str(
                    vulnerability.get("database_specific", {}).get("severity", "unknown")
                ).lower()
                if severity not in {"low", "medium", "high", "critical"}:
                    severity = "unknown"
                try:
                    create_finding(
                        context.conn,
                        context.campaign_id,
                        FindingInput(
                            asset_id=asset_id,
                            title=f"{vulnerability_id}: {vulnerability.get('summary') or 'Dependency vulnerability'}",
                            description=vulnerability.get("details")
                            or vulnerability.get("summary")
                            or vulnerability_id,
                            finding_type="dependency_vulnerability",
                            severity=severity,
                            confidence=0.85,
                            fingerprint=(
                                f"osv:{package['normalized_identifier']}:{vulnerability_id}"
                            ),
                        ),
                    )
                    created += 1
                except HTTPException as exc:
                    if exc.status_code == 409:
                        duplicates += 1
                    else:
                        raise
        return {
            "findings_created": created,
            "duplicates": duplicates,
            "unmatched_assets": unmatched,
        }

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
