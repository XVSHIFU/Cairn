from __future__ import annotations

import base64
import hashlib
import importlib.metadata
import ipaddress
import json
import os
import re
import shutil
import signal
import sqlite3
import stat
import subprocess
import sys
import tarfile
import threading
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field, replace
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Callable, Mapping
from urllib.parse import quote, unquote, urljoin, urlsplit, urlunsplit

from cairn.server.vulnerability_workspaces import managed_task_workspace


USER_AGENT = "Cairn/0.2 authorized-passive-research"
DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}\.?$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.?$",
    re.IGNORECASE,
)
CVE_ID_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
HTTP_HEADER_NAME_PATTERN = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
FORBIDDEN_REQUEST_HEADERS = {"host", "content-length"}
ANSI_ESCAPE_PATTERN = re.compile(r"\x1b\[[0-9;]*m")
RATE_LIMIT_RESERVATION_WINDOW_SECONDS = 1.01
HTTP_RESPONSE_MAX_BYTES = 262_144
HTTP_REQUEST_MAX_BYTES = 65_536
NUCLEI_TEMPLATES_COMMIT = "74e8267021b061b726fe997d322444d3c20988b7"
NUCLEI_ENGINE_VERSION = "3.11.1"
NUCLEI_RELEASE_SHA256 = "ea63d4ae232808cd7c6bc00d0142428e231fab59dae01042246097d195835ab6"
NUCLEI_BINARY_SHA256 = "c49588140f357cbdddd5436dec11201953a4c5390faeec90777f9ee2cfd70251"
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
NUCLEI_TEMPLATE_CATEGORIES = {
    "http-missing-security-headers": "misconfiguration",
    "nginx-version": "exposure",
}
NUCLEI_ALLOWED_TEMPLATE_CATEGORIES = frozenset(
    {"exposure", "cve", "misconfiguration"}
)
NUCLEI_FORBIDDEN_TEMPLATE_PATTERN = re.compile(
    r"^(?:code|headless|javascript|fuzzing|payloads|workflows)\s*:|"
    r"interactsh|^\s*tags\s*:.*\b(?:dos|fuzz|bruteforce|intrusive)\b",
    re.IGNORECASE | re.MULTILINE,
)
GITLEAKS_PACKAGE_VERSION = "8.26.0-1+b1"
GITLEAKS_PACKAGE_SHA256 = "b228ade47a811ffc94d258bd84b1c257458b4e81e37c55201c9d912c0e01bfdb"
GITLEAKS_BINARY_SHA256 = "9f44b29dac56e2c43fc54735e7847f4e959b5ed157fdb890266b39e80328725b"
GITLEAKS_CONFIG_SHA256 = "97930f7ef782a6cca176f6b71e6a1fae8a2fb12a665bb35078b1bce81e52e7cc"
SYFT_PACKAGE_VERSION = "1.49.0+ds-0kali1"
SYFT_PACKAGE_SHA256 = "10d84d0f96f10577259efb3ea36a51c4ed5904f3c007dd147264ffbab23fae09"
SYFT_BINARY_SHA256 = "198b45660ac0f4cd8a4a2d48c6695b9b55c154115bdeaf0a2dc03c1500e56653"
SYFT_MAX_OUTPUT_BYTES = 5 * 1024 * 1024
SYFT_MAX_COMPONENTS = 10_000
SYFT_MAX_TREE_ENTRIES = 100_000
SYFT_MAX_TREE_BYTES = 5 * 1024 * 1024 * 1024
SYFT_MAX_ARCHIVE_BYTES = 10 * 1024 * 1024 * 1024
SYFT_MAX_ARCHIVE_ENTRIES = 100_000
SYFT_MAX_ARCHIVE_EXPANDED_BYTES = 20 * 1024 * 1024 * 1024
TRIVY_PACKAGE_VERSION = "0.66.0-0kali1"
TRIVY_PACKAGE_SHA256 = "e462c332d23e12ae6f33d5e966eb641061e9a8103b25f05356f3521d82d943ed"
TRIVY_BINARY_SHA256 = "1a45dfa3ab217194fc7dae5e0d58f96da4789d14fb9a6588b0351cefdc2820a8"
TRIVY_DB_SNAPSHOT = "2026-09-03"
TRIVY_DB_UPDATED_AT = "2026-09-03T01:14:45.115995799Z"
TRIVY_DB_SHA256 = "13f48e8b37a9067a620a2bb641eca947619c9ff642384188d4d8e8f419221189"
TRIVY_DB_METADATA_SHA256 = "4dc1c3cac248f81aa8be6801d556065406842fb0f77341b0664948aa45c5d03b"
TRIVY_MAX_OUTPUT_BYTES = 5 * 1024 * 1024
TRIVY_MAX_VULNERABILITIES = 10_000
FOFA_CREDENTIALS_ENV = "CAIRN_FOFA_CREDENTIALS"
FOFA_API_ENDPOINT = "https://fofa.info/api/v1/search/next"
FOFA_FIELDS = (
    "host",
    "ip",
    "port",
    "protocol",
    "domain",
    "title",
    "server",
    "product",
    "version",
    "lastupdatetime",
    "country",
    "city",
    "asn",
)
FOFA_SECRET_PATTERN = re.compile(r"^[A-Za-z0-9._~-]{8,256}$")
FOFA_CREDENTIAL_REF_PATTERN = re.compile(r"^[A-Za-z0-9._~-]{1,128}$")
ADAPTER_PROCESS_FACTORY = subprocess.Popen
PROCESS_CANCELLATION_POLL_SECONDS = 0.25
PROCESS_TERMINATION_GRACE_SECONDS = 2.0
_TRIVY_DB_VERIFICATION_LOCK = threading.Lock()
_TRIVY_DB_VERIFICATION_CACHE: dict[str, tuple[object, ...]] = {}


def _configured_user_binary(name: str, environment_name: str) -> str:
    """Resolve an allowlisted tool without relying on an interactive-shell PATH."""

    configured = os.getenv(environment_name)
    if configured:
        return str(Path(configured).expanduser())
    user_local = Path.home() / ".local" / "bin" / name
    if user_local.is_file() and os.access(user_local, os.X_OK):
        return str(user_local)
    return name


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sha256_normalized_text_file(path: Path) -> str:
    """Hash an audited text policy independent of checkout line endings.

    Git can materialize tracked text as CRLF on Windows, while the audited
    release digest is calculated from the canonical LF form.  Only text
    policies/templates use this helper; executable and database artifacts
    remain byte-for-byte pinned with ``_sha256_file``.
    """

    return hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def _audited_gitleaks_config_path() -> Path:
    path = Path(__file__).with_name("policies") / "gitleaks-r1.toml"
    if not path.is_file() or _sha256_normalized_text_file(path) != GITLEAKS_CONFIG_SHA256:
        raise AdapterValidationError("Gitleaks policy is missing or its hash has drifted")
    return path


def authorized_local_repository(value: str) -> Path:
    configured = os.getenv("CAIRN_GITLEAKS_ALLOWED_ROOTS", "")
    if not configured.strip():
        raise AdapterValidationError("CAIRN_GITLEAKS_ALLOWED_ROOTS is not configured")
    candidate = Path(value).expanduser().resolve(strict=True)
    if not candidate.is_dir():
        raise AdapterValidationError("Gitleaks target must be an existing local directory")
    allowed = False
    for raw_root in configured.split(os.pathsep):
        if not raw_root.strip():
            continue
        root = Path(raw_root).expanduser().resolve(strict=True)
        if root == Path(root.anchor) or root == Path.home().resolve():
            raise AdapterValidationError("Gitleaks allowed roots may not be filesystem or home roots")
        try:
            candidate.relative_to(root)
            allowed = True
            break
        except ValueError:
            continue
    if not allowed:
        raise AdapterValidationError("Repository path is outside configured Gitleaks roots")
    return candidate


def authorized_local_supply_chain_target(value: str) -> Path:
    """Resolve an exact local directory under the dedicated SBOM allow-roots."""

    configured = os.getenv("CAIRN_SUPPLY_CHAIN_ALLOWED_ROOTS", "")
    if not configured.strip():
        raise AdapterValidationError("CAIRN_SUPPLY_CHAIN_ALLOWED_ROOTS is not configured")
    candidate = Path(value).expanduser().resolve(strict=True)
    if not candidate.is_dir():
        raise AdapterValidationError("Syft target must be an existing local directory")
    for raw_root in configured.split(os.pathsep):
        if not raw_root.strip():
            continue
        root = Path(raw_root).expanduser().resolve(strict=True)
        if root == Path(root.anchor) or root == Path.home().resolve():
            raise AdapterValidationError(
                "Syft allowed roots may not be filesystem or home roots"
            )
        try:
            candidate.relative_to(root)
            return candidate
        except ValueError:
            continue
    raise AdapterValidationError("Repository path is outside configured Syft roots")


def authorized_local_supply_chain_archive(value: str) -> Path:
    """Resolve one exact local container archive under SBOM allow-roots."""

    configured = os.getenv("CAIRN_SUPPLY_CHAIN_ALLOWED_ROOTS", "")
    if not configured.strip():
        raise AdapterValidationError("CAIRN_SUPPLY_CHAIN_ALLOWED_ROOTS is not configured")
    requested = Path(value).expanduser()
    try:
        requested_metadata = requested.lstat()
        candidate = requested.resolve(strict=True)
    except OSError as exc:
        raise AdapterValidationError(
            "Container image target must be an existing regular local archive"
        ) from exc
    if stat.S_ISLNK(requested_metadata.st_mode) or not candidate.is_file():
        raise AdapterValidationError("Container image target must be a regular local archive")
    metadata = candidate.stat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > SYFT_MAX_ARCHIVE_BYTES:
        raise AdapterValidationError("Container image archive exceeds the 10 GiB limit")
    for raw_root in configured.split(os.pathsep):
        if not raw_root.strip():
            continue
        root = Path(raw_root).expanduser().resolve(strict=True)
        if root == Path(root.anchor) or root == Path.home().resolve():
            raise AdapterValidationError(
                "Syft allowed roots may not be filesystem or home roots"
            )
        try:
            candidate.relative_to(root)
            return candidate
        except ValueError:
            continue
    raise AdapterValidationError("Container image archive is outside configured Syft roots")


def _container_archive_format(path: Path) -> str:
    """Classify a bounded Docker/OCI archive without extracting any member."""

    names: set[str] = set()
    expanded_bytes = 0
    try:
        with tarfile.open(path, mode="r:") as archive:
            member_count = 0
            for member in archive:
                member_count += 1
                if member_count > SYFT_MAX_ARCHIVE_ENTRIES:
                    raise AdapterValidationError(
                        "Container image archive exceeds the 100000 entry limit"
                    )
                member_path = Path(member.name)
                if (
                    member_path.is_absolute()
                    or ".." in member_path.parts
                    or member.issym()
                    or member.islnk()
                    or not (member.isfile() or member.isdir())
                ):
                    raise AdapterValidationError(
                        "Container image archive contains an unsafe outer member"
                    )
                expanded_bytes += max(0, int(member.size))
                if expanded_bytes > SYFT_MAX_ARCHIVE_EXPANDED_BYTES:
                    raise AdapterValidationError(
                        "Container image archive exceeds the expanded-size limit"
                    )
                names.add(member.name.removeprefix("./"))
    except (tarfile.TarError, OSError) as exc:
        raise AdapterValidationError("Container image target is not a valid tar archive") from exc
    if "manifest.json" in names:
        return "docker-archive"
    if {"oci-layout", "index.json"} <= names:
        return "oci-archive"
    raise AdapterValidationError("Container archive is neither Docker archive nor OCI archive")


def _validate_supply_chain_tree(root: Path) -> None:
    """Bound local traversal and reject special files or escaping symlinks."""

    entry_count = 0
    byte_count = 0
    for directory, dirnames, filenames in os.walk(root, followlinks=False):
        for name in [*dirnames, *filenames]:
            entry_count += 1
            if entry_count > SYFT_MAX_TREE_ENTRIES:
                raise AdapterValidationError("Syft target exceeds the file-count limit")
            entry = Path(directory) / name
            try:
                metadata = entry.lstat()
            except OSError as exc:
                raise AdapterValidationError(
                    "Syft target contains an unreadable filesystem entry"
                ) from exc
            if stat.S_ISLNK(metadata.st_mode):
                try:
                    resolved = entry.resolve(strict=True)
                    resolved.relative_to(root)
                except (OSError, ValueError) as exc:
                    raise AdapterValidationError(
                        "Syft target contains a symlink escaping the approved repository"
                    ) from exc
                continue
            if stat.S_ISREG(metadata.st_mode):
                byte_count += metadata.st_size
                if byte_count > SYFT_MAX_TREE_BYTES:
                    raise AdapterValidationError("Syft target exceeds the byte-size limit")
            elif not stat.S_ISDIR(metadata.st_mode):
                raise AdapterValidationError(
                    "Syft target contains an unsupported special filesystem entry"
                )


def _audited_trivy_database() -> tuple[Path, Path, Path]:
    """Resolve one immutable Trivy DB snapshot and fail closed on drift."""

    configured = os.getenv("CAIRN_TRIVY_DB_ROOT", "").strip()
    root = (
        Path(configured).expanduser()
        if configured
        else Path.home() / ".local" / "share" / "cairn" / "trivy-db" / TRIVY_DB_SNAPSHOT
    )
    if not root.is_absolute() or root.is_symlink():
        raise AdapterValidationError("Trivy database root must be an absolute non-symlink path")
    try:
        resolved_root = root.resolve(strict=True)
    except OSError as exc:
        raise AdapterUnavailableError("Audited Trivy database snapshot is unavailable") from exc
    database = resolved_root / "db" / "trivy.db"
    metadata = resolved_root / "db" / "metadata.json"
    identities: list[tuple[int, int, int, int]] = []
    for path, _expected_hash, label in (
        (database, TRIVY_DB_SHA256, "database"),
        (metadata, TRIVY_DB_METADATA_SHA256, "metadata"),
    ):
        if not path.is_file() or path.is_symlink():
            raise AdapterUnavailableError(f"Audited Trivy {label} file is unavailable")
        item = path.stat()
        identities.append((item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns))
    cache_value: tuple[object, ...] = (
        *identities,
        TRIVY_DB_SHA256,
        TRIVY_DB_METADATA_SHA256,
        TRIVY_DB_UPDATED_AT,
    )
    cache_key = str(resolved_root)
    with _TRIVY_DB_VERIFICATION_LOCK:
        cached = _TRIVY_DB_VERIFICATION_CACHE.get(cache_key) == cache_value
    if not cached:
        for path, expected_hash, label in (
            (database, TRIVY_DB_SHA256, "database"),
            (metadata, TRIVY_DB_METADATA_SHA256, "metadata"),
        ):
            if _sha256_file(path) != expected_hash:
                raise AdapterValidationError(f"Audited Trivy {label} hash has drifted")
    try:
        value = json.loads(metadata.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AdapterValidationError("Trivy database metadata is invalid") from exc
    if not isinstance(value, Mapping) or value.get("Version") != 2:
        raise AdapterValidationError("Trivy database schema version is not audited")
    if str(value.get("UpdatedAt") or "") != TRIVY_DB_UPDATED_AT:
        raise AdapterValidationError("Trivy database timestamp has drifted")
    if not cached:
        with _TRIVY_DB_VERIFICATION_LOCK:
            _TRIVY_DB_VERIFICATION_CACHE[cache_key] = cache_value
    return resolved_root, database, metadata


def _fofa_api_key(credential_ref: str) -> str:
    """Resolve one server-side FOFA credential without persisting the value."""

    reference = credential_ref.strip()
    if not reference or "\r" in reference or "\n" in reference:
        raise AdapterValidationError("FOFA source requires a valid credential_ref")
    raw = os.getenv(FOFA_CREDENTIALS_ENV, "").strip()
    if not raw:
        raise AdapterUnavailableError(f"{FOFA_CREDENTIALS_ENV} is not configured")
    try:
        credentials = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise AdapterUnavailableError(
            f"{FOFA_CREDENTIALS_ENV} must be a JSON object"
        ) from exc
    if not isinstance(credentials, dict) or reference not in credentials:
        raise AdapterUnavailableError("FOFA credential reference was not found")
    entry = credentials[reference]
    key = entry.get("key") if isinstance(entry, dict) else entry
    if not isinstance(key, str) or not FOFA_SECRET_PATTERN.fullmatch(key):
        raise AdapterUnavailableError("FOFA credential is malformed")
    return key


def validate_fofa_source_config(
    value: Mapping[str, Any], *, require_credential_ref: bool
) -> dict[str, Any]:
    """Return persistable FOFA settings while rejecting all credential material."""

    if not isinstance(value, Mapping):
        raise AdapterValidationError("FOFA source configuration must be an object")
    allowed = {"adapter", "credential_ref", "page_size", "default_disabled"}
    unknown = set(value) - allowed
    if unknown:
        raise AdapterValidationError(
            f"FOFA source configuration contains forbidden fields: {', '.join(sorted(unknown))}"
        )
    adapter = str(value.get("adapter") or "fofa.asset-search.v1")
    if adapter != "fofa.asset-search.v1":
        raise AdapterValidationError("FOFA source adapter is immutable")
    credential_ref = str(value.get("credential_ref") or "").strip()
    if credential_ref and not FOFA_CREDENTIAL_REF_PATTERN.fullmatch(credential_ref):
        raise AdapterValidationError("FOFA credential_ref is malformed")
    if require_credential_ref and not credential_ref:
        raise AdapterValidationError(
            "FOFA source must reference a server-side credential before it is enabled"
        )
    page_size_raw = value.get("page_size", 100)
    if isinstance(page_size_raw, bool):
        raise AdapterValidationError("FOFA page_size must be an integer")
    try:
        page_size = int(page_size_raw)
    except (TypeError, ValueError) as exc:
        raise AdapterValidationError("FOFA page_size must be an integer") from exc
    if page_size < 1 or page_size > 1000:
        raise AdapterValidationError("FOFA page_size must be between 1 and 1000")
    return {
        "adapter": adapter,
        "credential_ref": credential_ref,
        "page_size": page_size,
        "default_disabled": bool(value.get("default_disabled", True)),
    }


def validate_browser_evidence_source_config(
    value: Mapping[str, Any], *, require_periodic_targets: bool = False
) -> dict[str, Any]:
    """Validate persistable browser controls; credentials and cookies are forbidden."""

    if not isinstance(value, Mapping):
        raise AdapterValidationError("Browser source configuration must be an object")
    allowed = {
        "adapter",
        "default_disabled",
        "periodic_enabled",
        "targets",
        "depth",
        "max_pages",
        "max_requests",
        "session_timeout_seconds",
    }
    unknown = set(value) - allowed
    if unknown:
        raise AdapterValidationError(
            "Browser source configuration contains forbidden fields: "
            + ", ".join(sorted(unknown))
        )
    adapter = str(value.get("adapter") or "browser.evidence-session.v1")
    if adapter != "browser.evidence-session.v1":
        raise AdapterValidationError("Browser source adapter is immutable")
    periodic_enabled = bool(value.get("periodic_enabled", False))
    targets_value = value.get("targets", [])
    if not isinstance(targets_value, list) or len(targets_value) > 10:
        raise AdapterValidationError("Browser source accepts at most 10 exact URL targets")
    targets = []
    for target in targets_value:
        if not isinstance(target, str):
            raise AdapterValidationError("Browser source targets must be URL strings")
        targets.append(normalize_web_target(target))
    targets = list(dict.fromkeys(targets))
    if (periodic_enabled or require_periodic_targets) and not targets:
        raise AdapterValidationError(
            "Periodic browser collection requires at least one exact URL target"
        )
    controls: dict[str, int] = {}
    for key, default, low, high in (
        ("depth", 1, 1, 2),
        ("max_pages", 5, 1, 10),
        ("max_requests", 20, 1, 50),
        ("session_timeout_seconds", 60, 5, 60),
    ):
        item = value.get(key, default)
        if isinstance(item, bool):
            raise AdapterValidationError(f"Browser {key} must be an integer")
        try:
            item = int(item)
        except (TypeError, ValueError) as exc:
            raise AdapterValidationError(f"Browser {key} must be an integer") from exc
        if not low <= item <= high:
            raise AdapterValidationError(
                f"Browser {key} must be between {low} and {high}"
            )
        controls[key] = item
    return {
        "adapter": adapter,
        "default_disabled": bool(value.get("default_disabled", True)),
        "periodic_enabled": periodic_enabled,
        "targets": targets,
        **controls,
    }


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


class AdapterCancellationError(AdapterExecutionError):
    """A durable task or Campaign revocation interrupted the tool process."""


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
    requires_human_approval: bool = False

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
    vulnerabilities: tuple[Mapping[str, Any], ...] = ()
    repositories: tuple[Mapping[str, Any], ...] = ()
    container_archives: tuple[Mapping[str, Any], ...] = ()
    sboms: tuple[Mapping[str, Any], ...] = ()
    cursor: Mapping[str, Any] = field(default_factory=dict)
    request_header: str = "X-Cairn-Research"
    max_requests_per_second: int = 30
    proxy_url: str | None = None
    options: Mapping[str, Any] = field(default_factory=dict)
    cancellation_probe: Callable[[], str | None] | None = None


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
class SensitiveArtifact:
    key: str
    target: str | None
    artifact_kind: str
    media_type: str
    content: bytes

    @property
    def content_hash(self) -> str:
        return hashlib.sha256(self.content).hexdigest()


@dataclass(frozen=True)
class AdapterExecution:
    results: tuple[CommandResult, ...]
    sensitive_artifacts: tuple[SensitiveArtifact, ...] = ()

    @property
    def output_size(self) -> int:
        return sum(len(result.stdout.encode("utf-8")) for result in self.results) + sum(
            len(artifact.content) for artifact in self.sensitive_artifacts
        )

    @property
    def output_hash(self) -> str:
        digest = hashlib.sha256()
        for result in self.results:
            digest.update((result.target or "").encode("utf-8"))
            digest.update(b"\0")
            digest.update(result.stdout.encode("utf-8"))
            digest.update(b"\0")
        for artifact in self.sensitive_artifacts:
            digest.update(artifact.key.encode("utf-8"))
            digest.update(b"\0")
            digest.update(artifact.content_hash.encode("ascii"))
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


def normalize_network_host(value: str) -> str:
    """Return one exact IP or FQDN from an approved network target."""

    text = value.strip()
    if text.startswith(("http://", "https://")):
        parsed = urlsplit(text)
        if parsed.username is not None or parsed.password is not None:
            raise AdapterValidationError("Network targets may not contain credentials")
        text = parsed.hostname or ""
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return normalize_domain(text)


def normalize_web_target(value: str) -> str:
    """Normalize an exact HTTP(S) crawl root without query or fragment data."""

    text = value.strip()
    if not text.startswith(("http://", "https://")):
        return f"https://{normalize_network_host(text)}"
    parsed = urlsplit(text)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise AdapterValidationError("Web targets must use http or https")
    if parsed.username is not None or parsed.password is not None:
        raise AdapterValidationError("Web targets may not contain credentials")
    host = normalize_network_host(parsed.hostname)
    try:
        port = parsed.port
    except ValueError as exc:
        raise AdapterValidationError("Web target contains an invalid port") from exc
    if ":" in host:
        host = f"[{host}]"
    netloc = host if port is None else f"{host}:{port}"
    return urlunsplit((parsed.scheme.lower(), netloc, parsed.path or "/", "", ""))


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
    internally_rate_limited: bool = False
    accept_complete_json_on_timeout: bool = False
    expected_tool_version: str | None = None
    release_sha256: str | None = None
    requires_human_approval: bool = False

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
            requires_human_approval=self.requires_human_approval,
        )

    def validate(self, context: AdapterContext) -> None:
        if not context.campaign_id or not context.task_id:
            raise AdapterValidationError("Adapter context is missing campaign or task identity")

    def normalize_task_target(self, value: str) -> str:
        return value.strip()

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
                stdin=subprocess.DEVNULL,
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

    @staticmethod
    def _terminate_process_group(process: Any) -> tuple[str, str]:
        """Terminate the allowlisted process and descendants, then drain pipes."""

        try:
            if os.name == "posix" and getattr(process, "pid", None):
                os.killpg(int(process.pid), signal.SIGTERM)
            else:
                process.terminate()
        except (OSError, ProcessLookupError):
            pass
        try:
            stdout, stderr = process.communicate(
                timeout=PROCESS_TERMINATION_GRACE_SECONDS
            )
        except subprocess.TimeoutExpired:
            try:
                if os.name == "posix" and getattr(process, "pid", None):
                    os.killpg(int(process.pid), signal.SIGKILL)
                else:
                    process.kill()
            except (OSError, ProcessLookupError):
                pass
            stdout, stderr = process.communicate()
        if isinstance(stdout, bytes):
            stdout = stdout.decode("utf-8", errors="replace")
        if isinstance(stderr, bytes):
            stderr = stderr.decode("utf-8", errors="replace")
        return stdout or "", stderr or ""

    def _execute_cancellable_invocation(
        self,
        context: AdapterContext,
        invocation: AdapterInvocation,
        previous_results: list[CommandResult],
    ) -> tuple[CommandResult, bool]:
        started = time.monotonic()
        try:
            process = ADAPTER_PROCESS_FACTORY(
                list(invocation.argv),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                shell=False,
                stdin=(
                    subprocess.PIPE
                    if invocation.stdin is not None
                    else subprocess.DEVNULL
                ),
                start_new_session=os.name == "posix",
            )
        except OSError as exc:
            raise AdapterUnavailableError(
                f"Unable to execute allowlisted binary {self.binary}: {type(exc).__name__}"
            ) from exc

        deadline = started + self.timeout_seconds
        pending_input = invocation.stdin
        while True:
            try:
                cancellation_reason = (
                    context.cancellation_probe()
                    if context.cancellation_probe is not None
                    else None
                )
            except Exception as exc:
                cancellation_reason = (
                    "Execution authority probe failed closed: "
                    f"{type(exc).__name__}"
                )
            if cancellation_reason:
                stdout, stderr = self._terminate_process_group(process)
                result = CommandResult(
                    target=invocation.target,
                    stdout=stdout,
                    stderr=stderr,
                    returncode=(
                        int(process.returncode)
                        if process.returncode is not None
                        else -15
                    ),
                    duration_ms=round((time.monotonic() - started) * 1000),
                )
                raise AdapterCancellationError(
                    f"{self.tool_id} cancelled: {cancellation_reason}",
                    AdapterExecution(tuple([*previous_results, result])),
                )

            remaining = deadline - time.monotonic()
            if remaining <= 0:
                stdout, stderr = self._terminate_process_group(process)
                result = CommandResult(
                    target=invocation.target,
                    stdout=stdout,
                    stderr=stderr,
                    returncode=-1,
                    duration_ms=round((time.monotonic() - started) * 1000),
                )
                execution = AdapterExecution(tuple([*previous_results, result]))
                if self.accept_complete_json_on_timeout and stdout.strip():
                    try:
                        payloads = [
                            json.loads(line)
                            for line in stdout.splitlines()
                            if line.strip()
                        ]
                    except json.JSONDecodeError:
                        payloads = []
                    if payloads and all(
                        isinstance(payload, dict) for payload in payloads
                    ):
                        return result, True
                raise AdapterExecutionError(
                    f"{self.tool_id} timed out after {self.timeout_seconds}s",
                    execution,
                )
            try:
                stdout, stderr = process.communicate(
                    input=pending_input,
                    timeout=min(PROCESS_CANCELLATION_POLL_SECONDS, remaining),
                )
                return (
                    CommandResult(
                        target=invocation.target,
                        stdout=stdout or "",
                        stderr=stderr or "",
                        returncode=int(process.returncode or 0),
                        duration_ms=round((time.monotonic() - started) * 1000),
                    ),
                    False,
                )
            except subprocess.TimeoutExpired:
                pending_input = None

    def _execute_invocations(
        self,
        context: AdapterContext,
        invocations: list[AdapterInvocation],
    ) -> AdapterExecution:
        results: list[CommandResult] = []
        for invocation in invocations:
            if (self.uses_http or self.uses_network) and not self.internally_rate_limited:
                acquire_campaign_http_rate_limit(context)
            if context.cancellation_probe is not None:
                result, accepted_timeout = self._execute_cancellable_invocation(
                    context, invocation, results
                )
                results.append(result)
                if result.returncode != 0 and not accepted_timeout:
                    execution = AdapterExecution(tuple(results))
                    raise AdapterExecutionError(
                        f"{self.tool_id} exited with code {result.returncode}",
                        execution,
                    )
                continue
            started = time.monotonic()
            try:
                run_kwargs: dict[str, Any] = {
                    "capture_output": True,
                    "text": True,
                    "timeout": self.timeout_seconds,
                    "check": False,
                    "shell": False,
                    # Long-running collectors have an open inherited stdin.
                    # ProjectDiscovery tools wait for pipeline input before
                    # starting when that stream is left open, so commands that
                    # do not intentionally consume input must see immediate EOF.
                    "stdin": subprocess.DEVNULL,
                }
                if invocation.stdin is not None:
                    run_kwargs.pop("stdin")
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


class ActiveNetworkTargetAdapter(VulnSourceAdapter):
    input_schema = {
        "type": "object",
        "required": ["active_targets"],
        "properties": {
            "active_targets": {
                "type": "array",
                "items": {"type": "string"},
                "maxItems": 10,
            }
        },
        "additionalProperties": False,
    }

    def validate(self, context: AdapterContext) -> None:
        super().validate(context)
        if not context.targets:
            raise AdapterValidationError(f"{self.tool_id} requires an explicit target")
        if len(context.targets) > 10:
            raise AdapterValidationError(f"{self.tool_id} accepts at most 10 targets")
        for target in context.targets:
            self.normalize_task_target(target)


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
            upsert_discovered_asset,
        )

        created = 0
        updated = 0
        source_name = str(context.source["name"])
        for hostname in parsed.get("domains", []):
            scope = check_scope(context.conn, context.campaign_id, hostname, active=False)
            if scope.reason == "target matches an explicit exclusion":
                continue
            parent_identifier = context.targets[0] if context.targets else None
            asset, was_created, lineage = upsert_discovered_asset(
                context.conn,
                context.campaign_id,
                AssetInput(
                    asset_type="domain",
                    identifier=hostname,
                    source_name=source_name,
                ),
                discovery_kind="domain_discovery",
                parent_identifier=parent_identifier,
                source_id=str(context.source["id"]),
                task_id=context.task_id,
            )
            if asset is None or lineage is None:
                continue
            record_collection_task_asset(
                context.conn,
                context.task_id,
                str(context.source["id"]),
                asset.id,
            )
            created += int(was_created)
            updated += int(not was_created)
        return {"assets_created": created, "assets_updated": updated}


class FofaAssetSearchAdapter(VulnSourceAdapter):
    """Query FOFA for exact authorized domain/IP seeds through one bounded page."""

    tool_id = "fofa.asset-search.v1"
    version = "1.0.0"
    risk_class = "R1"
    source_type = "fofa_asset_search"
    dimension = "external"
    binary = "curl"
    version_args = ("--version",)
    timeout_seconds = 30
    uses_http = True
    requires_human_approval = True
    input_schema = {
        "type": "object",
        "required": ["search_targets"],
        "properties": {
            "search_targets": {
                "type": "array",
                "items": {"type": "string"},
                "maxItems": 10,
            }
        },
        "additionalProperties": False,
    }
    output_schema = {
        "type": "object",
        "required": ["records"],
        "properties": {
            "records": {"type": "array", "items": {"type": "object"}},
            "next_by_target": {"type": "object"},
        },
    }

    def normalize_task_target(self, value: str) -> str:
        text = value.strip()
        try:
            return str(ipaddress.ip_address(text))
        except ValueError:
            return normalize_domain(text)

    def _config(self, context: AdapterContext) -> tuple[str, int]:
        source_keys = set(context.source.keys()) if hasattr(context.source, "keys") else set()
        raw_config = context.source["config_json"] if "config_json" in source_keys else "{}"
        try:
            config = json.loads(str(raw_config or "{}"))
        except (TypeError, json.JSONDecodeError) as exc:
            raise AdapterValidationError("FOFA source configuration is invalid") from exc
        normalized = validate_fofa_source_config(
            config, require_credential_ref=True
        )
        return str(normalized["credential_ref"]), int(normalized["page_size"])

    def validate(self, context: AdapterContext) -> None:
        super().validate(context)
        if not context.targets:
            raise AdapterValidationError("FOFA requires at least one exact search target")
        if len(context.targets) > 10:
            raise AdapterValidationError("FOFA accepts at most 10 exact search targets")
        for target in context.targets:
            self.normalize_task_target(target)
        credential_ref, _ = self._config(context)
        _fofa_api_key(credential_ref)

    def materialize(self, context: AdapterContext) -> list[AdapterInvocation]:
        credential_ref, page_size = self._config(context)
        api_key = _fofa_api_key(credential_ref)
        previous = context.cursor.get("next_by_target")
        previous = previous if isinstance(previous, dict) else {}
        invocations: list[AdapterInvocation] = []
        for target in context.targets:
            normalized = self.normalize_task_target(target)
            try:
                ipaddress.ip_address(normalized)
                query = f'ip="{normalized}"'
            except ValueError:
                query = f'domain="{normalized}"'
            query_b64 = base64.b64encode(query.encode("utf-8")).decode("ascii")
            next_token = previous.get(normalized)
            next_args: tuple[str, ...] = ()
            if isinstance(next_token, str) and next_token and len(next_token) <= 4096:
                next_args = ("--data-urlencode", f"next={next_token}")
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
                        "--get",
                        "--data-urlencode",
                        f"qbase64={query_b64}",
                        "--data",
                        f"fields={','.join(FOFA_FIELDS)}",
                        "--data",
                        f"size={page_size}",
                        "--data",
                        "full=false",
                        *next_args,
                        "--config",
                        "-",
                        FOFA_API_ENDPOINT,
                    ),
                    target=normalized,
                    # Keep the credential out of argv, task plans, process
                    # listings, logs, and persisted execution metadata.
                    stdin=f'data-urlencode = "key={api_key}"\n',
                )
            )
        return invocations

    def execute(self, context: AdapterContext) -> AdapterExecution:
        return self._execute_materialized(context)

    def parse(self, execution: AdapterExecution) -> dict[str, Any]:
        records: list[dict[str, Any]] = []
        next_by_target: dict[str, str] = {}
        for result in execution.results:
            try:
                payload = json.loads(result.stdout)
            except json.JSONDecodeError as exc:
                raise AdapterExecutionError("FOFA returned invalid JSON", execution) from exc
            if not isinstance(payload, dict):
                raise AdapterExecutionError("FOFA response must be a JSON object", execution)
            if payload.get("error") is True:
                raise AdapterExecutionError("FOFA rejected the bounded search request", execution)
            result_rows = payload.get("results")
            if not isinstance(result_rows, list):
                raise AdapterExecutionError("FOFA response is missing a results array", execution)
            if len(result_rows) > 1000:
                raise AdapterExecutionError("FOFA response exceeded the configured page bound", execution)
            for row in result_rows:
                if not isinstance(row, list):
                    continue
                record = {
                    field_name: row[index] if index < len(row) else None
                    for index, field_name in enumerate(FOFA_FIELDS)
                }
                record["query_target"] = result.target
                records.append(record)
            next_token = payload.get("next")
            if (
                result.target
                and isinstance(next_token, str)
                and next_token
                and len(next_token) <= 4096
                and "\r" not in next_token
                and "\n" not in next_token
            ):
                next_by_target[result.target] = next_token
        return {
            "records": records,
            "next_by_target": next_by_target,
            "_coverage_complete": not next_by_target,
        }

    def normalize(self, context: AdapterContext, parsed: Any) -> dict[str, int]:
        from cairn.server.services import utcnow
        from cairn.server.vulnerability_models import AssetInput
        from cairn.server.vulnerability_services import (
            check_scope,
            next_vulnerability_id,
            normalize_target,
            record_collection_task_asset,
            recalculate_asset_scores,
            upsert_discovered_asset,
        )

        counts = {
            "assets_created": 0,
            "assets_updated": 0,
            "observations_created": 0,
            "observations_updated": 0,
            "relations_created": 0,
            "quarantined_results": 0,
        }
        source_name = str(context.source["name"])
        now = utcnow()
        for record in parsed.get("records", []):
            if not isinstance(record, dict):
                continue
            candidates: list[tuple[str, str]] = []
            raw_domain = str(record.get("domain") or "").strip()
            if raw_domain:
                try:
                    candidates.append(("domain", normalize_domain(raw_domain)))
                except AdapterValidationError:
                    pass
            raw_ip = str(record.get("ip") or "").strip()
            if raw_ip:
                try:
                    candidates.append(("ip", str(ipaddress.ip_address(raw_ip))))
                except ValueError:
                    pass
            raw_host = str(record.get("host") or "").strip()
            if raw_host.startswith(("http://", "https://")):
                try:
                    candidates.append(("url", normalize_web_target(raw_host)))
                except AdapterValidationError:
                    pass

            assets: dict[str, str] = {}
            for asset_type, identifier in dict.fromkeys(candidates):
                scope = check_scope(
                    context.conn, context.campaign_id, identifier, active=False
                )
                if not scope.allowed:
                    continue
                technology = [
                    str(value).strip()
                    for value in (record.get("product"), record.get("server"))
                    if str(value or "").strip()
                ]
                version = str(record.get("version") or "").strip()
                if version and technology:
                    technology[0] = f"{technology[0]} {version}"[:256]
                asset, created, lineage = upsert_discovered_asset(
                    context.conn,
                    context.campaign_id,
                    AssetInput(
                        asset_type=asset_type,
                        identifier=identifier,
                        technology=list(dict.fromkeys(technology))[:20],
                        source_name=source_name,
                    ),
                    discovery_kind="fofa_asset_discovery",
                    parent_identifier=str(record.get("query_target") or "") or None,
                    source_id=str(context.source["id"]),
                    task_id=context.task_id,
                )
                if asset is None or lineage is None:
                    continue
                assets[asset_type] = asset.id
                record_collection_task_asset(
                    context.conn,
                    context.task_id,
                    str(context.source["id"]),
                    asset.id,
                )
                counts["assets_created" if created else "assets_updated"] += 1

                evidence_payload = {
                    "record_type": "fofa_asset_search",
                    "query_target": record.get("query_target"),
                    "host": record.get("host"),
                    "ip": record.get("ip"),
                    "port": record.get("port"),
                    "protocol": record.get("protocol"),
                    "domain": record.get("domain"),
                    "title": record.get("title"),
                    "server": record.get("server"),
                    "product": record.get("product"),
                    "version": record.get("version"),
                    "last_updated_at": record.get("lastupdatetime"),
                    "country": record.get("country"),
                    "city": record.get("city"),
                    "asn": record.get("asn"),
                }
                digest = hashlib.sha256(
                    json.dumps(
                        {
                            "campaign_id": context.campaign_id,
                            "source_id": str(context.source["id"]),
                            "asset_id": asset.id,
                            "data": evidence_payload,
                        },
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    ).encode("utf-8")
                ).hexdigest()
                existed = context.conn.execute(
                    "SELECT 1 FROM vuln_observations WHERE campaign_id = ? AND evidence_hash = ?",
                    (context.campaign_id, digest),
                ).fetchone()
                observation_id = next_vulnerability_id(
                    context.conn, "observation", "observation"
                )
                context.conn.execute(
                    """
                    INSERT INTO vuln_observations
                        (id, campaign_id, asset_id, source_id, dimension, data_json,
                         evidence_hash, confidence, status, raw_reference,
                         first_seen_at, last_seen_at)
                    VALUES (?, ?, ?, ?, 'external', ?, ?, 0.8, 'current', ?, ?, ?)
                    ON CONFLICT(campaign_id, evidence_hash)
                    DO UPDATE SET last_seen_at = excluded.last_seen_at
                    """,
                    (
                        observation_id,
                        context.campaign_id,
                        asset.id,
                        context.source["id"],
                        json.dumps(evidence_payload, ensure_ascii=False),
                        digest,
                        f"collection-task:{context.task_id}",
                        now,
                        now,
                    ),
                )
                counts[
                    "observations_created" if existed is None else "observations_updated"
                ] += 1
                recalculate_asset_scores(context.conn, context.campaign_id, [asset.id])

            if not assets:
                counts["quarantined_results"] += 1
                continue
            if assets.get("domain") and assets.get("ip"):
                existing_relation = context.conn.execute(
                    """
                    SELECT id FROM vuln_asset_relations
                    WHERE campaign_id = ? AND source_asset_id = ?
                      AND target_asset_id = ? AND relation_type = 'resolves_to'
                    """,
                    (context.campaign_id, assets["domain"], assets["ip"]),
                ).fetchone()
                if existing_relation is None:
                    relation_id = next_vulnerability_id(
                        context.conn, "asset_relation", "relation"
                    )
                    context.conn.execute(
                        """
                        INSERT INTO vuln_asset_relations
                            (id, campaign_id, source_asset_id, target_asset_id,
                             relation_type, confidence, visible, review_state,
                             first_seen_at, last_seen_at)
                        VALUES (?, ?, ?, ?, 'resolves_to', 0.8, 1,
                                'auto_visible', ?, ?)
                        """,
                        (
                            relation_id,
                            context.campaign_id,
                            assets["domain"],
                            assets["ip"],
                            now,
                            now,
                        ),
                    )
                    counts["relations_created"] += 1
                else:
                    context.conn.execute(
                        "UPDATE vuln_asset_relations SET last_seen_at = ? WHERE id = ?",
                        (now, existing_relation["id"]),
                    )
        return counts

    def coverage_complete(self, context: AdapterContext, parsed: Any) -> bool:
        return bool(parsed.get("_coverage_complete", False))

    def next_cursor(
        self,
        context: AdapterContext,
        parsed: Any,
        execution: AdapterExecution,
    ) -> dict[str, Any]:
        return {
            "next_by_target": dict(parsed.get("next_by_target") or {}),
            "output_hash": execution.output_hash,
        }


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
        """
        SELECT id FROM vuln_assets
        WHERE campaign_id = ?
          AND asset_type IN ('domain', 'ip', 'ipv4', 'ipv6', 'url')
          AND normalized_identifier = ?
        ORDER BY CASE WHEN asset_type IN ('ip', 'ipv4', 'ipv6') THEN 0 ELSE 1 END, id
        LIMIT 1
        """,
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
        from cairn.server.vulnerability_services import (
            record_collection_task_asset,
            upsert_discovered_asset,
        )

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
                asset, created, _lineage = upsert_discovered_asset(
                    context.conn,
                    context.campaign_id,
                    AssetInput(
                        asset_type="ip",
                        identifier=address,
                        source_name=str(context.source["name"]),
                    ),
                    discovery_kind="dns_resolves",
                    parent_identifier=record["domain"],
                    source_id=str(context.source["id"]),
                    task_id=context.task_id,
                )
                if asset is None:
                    continue
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
        category = NUCLEI_TEMPLATE_CATEGORIES.get(template_id)
        if category not in NUCLEI_ALLOWED_TEMPLATE_CATEGORIES:
            raise AdapterValidationError(
                f"Nuclei template category is not allowlisted: {template_id}"
            )
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
        # Nuclei templates are audited text.  Canonicalize checkout CRLF so
        # the pinned release digest remains valid on Windows as well as Kali.
        actual_hash = hashlib.sha256(content.replace(b"\r\n", b"\n")).hexdigest()
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


def _connection_database_path(conn: sqlite3.Connection) -> str | None:
    rows = conn.execute("PRAGMA database_list").fetchall()
    for row in rows:
        name = row[1] if not isinstance(row, sqlite3.Row) else row["name"]
        file_name = row[2] if not isinstance(row, sqlite3.Row) else row["file"]
        if name == "main" and file_name and file_name != ":memory:":
            return str(Path(str(file_name)).resolve())
    return None


class BrowserEvidenceSessionAdapter(ActiveNetworkTargetAdapter):
    """Collect bounded same-origin browser evidence in an ephemeral context."""

    tool_id = "browser.evidence-session.v1"
    version = "1.0.0"
    risk_class = "R3"
    source_type = "browser_evidence_session"
    dimension = "web"
    binary = sys.executable
    version_args = ("-m", "cairn.server.playwright_capture", "--version")
    timeout_seconds = 90
    uses_http = True
    uses_network = True
    internally_rate_limited = True
    requires_human_approval = True
    input_schema = ActiveNetworkTargetAdapter.input_schema
    output_schema = {
        "type": "object",
        "required": ["sessions"],
        "properties": {
            "sessions": {"type": "array", "items": {"type": "object"}}
        },
    }

    def normalize_task_target(self, value: str) -> str:
        return normalize_web_target(value)

    def validate(self, context: AdapterContext) -> None:
        super().validate(context)
        for key, default, low, high in (
            ("depth", 1, 1, 2),
            ("max_pages", 5, 1, 10),
            ("max_requests", 20, 1, 50),
            ("session_timeout_seconds", 60, 5, 60),
        ):
            value = context.options.get(key, default)
            if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
                raise AdapterValidationError(
                    f"Browser {key} must be between {low} and {high}"
                )
        if _connection_database_path(context.conn) is None:
            raise AdapterValidationError(
                "Browser evidence collection requires a durable collection database"
            )

    def estimate(self, context: AdapterContext) -> dict[str, Any]:
        return {
            "command_count": len(context.targets),
            "timeout_seconds": self.timeout_seconds,
            "risk_class": self.risk_class,
            "network_request_count": len(context.targets)
            * int(context.options.get("max_requests", 20)),
            "max_pages": int(context.options.get("max_pages", 5)),
            "same_origin_only": True,
            "allowed_methods": ["GET", "HEAD"],
            "persistent_profile": False,
        }

    def health(self) -> dict[str, Any]:
        runner = Path(__file__).with_name("playwright_capture.py")
        if not runner.is_file():
            return {
                "healthy": False,
                "tool_id": self.tool_id,
                "version": None,
                "error": "Cairn Playwright runner is missing",
            }
        try:
            package_version = importlib.metadata.version("playwright")
            completed = subprocess.run(
                [
                    self.binary,
                    "-m",
                    "cairn.server.playwright_capture",
                    "--probe",
                ],
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
                shell=False,
                stdin=subprocess.DEVNULL,
            )
            if completed.returncode != 0:
                raise RuntimeError(completed.stderr.strip() or "runtime probe failed")
            probe = json.loads(completed.stdout)
            executable = Path(str(probe["browser_executable"]))
        except Exception as exc:
            return {
                "healthy": False,
                "tool_id": self.tool_id,
                "version": None,
                "error": f"Playwright runtime probe failed: {type(exc).__name__}",
            }
        if not executable.is_file():
            return {
                "healthy": False,
                "tool_id": self.tool_id,
                "version": package_version,
                "error": "Playwright Chromium is not installed",
            }
        return {
            "healthy": True,
            "tool_id": self.tool_id,
            "version": package_version,
            "browser_version": str(probe.get("browser_version") or "")[:128],
            "expected_version": ">=1.48,<2",
            "runner_sha256": _sha256_file(runner),
            "browser_executable_sha256": _sha256_file(executable),
            "browser_engine": "chromium",
            "persistent_profile": False,
            "error": None,
        }

    def materialize(self, context: AdapterContext) -> list[AdapterInvocation]:
        headers = self.get_headers(context)
        header_name, header_value = next(iter(headers.items()))
        database_path = _connection_database_path(context.conn)
        return [
            AdapterInvocation(
                argv=(
                    self.binary,
                    "-m",
                    "cairn.server.playwright_capture",
                    "--run",
                ),
                target=normalize_web_target(target),
                stdin=json.dumps(
                    {
                        "target": normalize_web_target(target),
                        "campaign_id": context.campaign_id,
                        "task_id": context.task_id,
                        "request_header": header_name,
                        "request_header_value": header_value,
                        "max_requests_per_second": max(
                            1, context.max_requests_per_second
                        ),
                        "max_requests": int(context.options.get("max_requests", 20)),
                        "max_pages": int(context.options.get("max_pages", 5)),
                        "depth": int(context.options.get("depth", 1)),
                        "timeout_seconds": int(
                            context.options.get("session_timeout_seconds", 60)
                        ),
                        "database_path": database_path or "",
                        "proxy_url": context.proxy_url or "",
                    },
                    ensure_ascii=False,
                    sort_keys=True,
                ),
            )
            for target in context.targets
        ]

    def execute(self, context: AdapterContext) -> AdapterExecution:
        self.validate(context)
        execution = self._execute_invocations(context, self.materialize(context))
        sanitized: list[CommandResult] = []
        artifacts: list[SensitiveArtifact] = []
        for result in execution.results:
            try:
                payload = json.loads(result.stdout)
            except json.JSONDecodeError as exc:
                raise AdapterExecutionError(
                    "Playwright runner returned invalid JSON", execution
                ) from exc
            if not isinstance(payload, dict):
                raise AdapterExecutionError(
                    "Playwright runner output must be an object", execution
                )
            pages = payload.get("pages")
            if not isinstance(pages, list):
                raise AdapterExecutionError(
                    "Playwright runner output is missing pages", execution
                )
            for index, page in enumerate(pages):
                if not isinstance(page, dict):
                    continue
                encoded = page.pop("screenshot_base64", None)
                if not encoded:
                    continue
                try:
                    content = base64.b64decode(str(encoded), validate=True)
                except (ValueError, TypeError) as exc:
                    raise AdapterExecutionError(
                        "Playwright screenshot is not valid base64"
                    ) from exc
                if not content or len(content) > 1_048_576:
                    raise AdapterExecutionError(
                        "Playwright screenshot exceeds the 1 MiB evidence limit"
                    )
                expected_hash = str(page.get("screenshot_sha256") or "")
                actual_hash = hashlib.sha256(content).hexdigest()
                if expected_hash != actual_hash:
                    raise AdapterExecutionError("Playwright screenshot hash mismatch")
                key = f"{result.target or 'target'}#screenshot-{index}"
                page["screenshot_artifact_key"] = key
                artifacts.append(
                    SensitiveArtifact(
                        key=key,
                        target=result.target,
                        artifact_kind="browser_screenshot",
                        media_type="image/jpeg",
                        content=content,
                    )
                )
            sanitized.append(
                CommandResult(
                    target=result.target,
                    stdout=json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n",
                    stderr=result.stderr,
                    returncode=result.returncode,
                    duration_ms=result.duration_ms,
                )
            )
        return AdapterExecution(tuple(sanitized), tuple(artifacts))

    def parse(self, execution: AdapterExecution) -> dict[str, Any]:
        sessions = _parse_json_lines(execution, tool_id=self.tool_id)
        for session in sessions:
            target = normalize_web_target(str(session.get("target") or ""))
            max_requests = int(session.get("request_budget") or 0)
            request_count = int(session.get("request_count") or 0)
            if not 1 <= max_requests <= 50 or not 0 <= request_count <= max_requests:
                raise AdapterExecutionError(
                    "Playwright runner exceeded its immutable request budget", execution
                )
            if session.get("same_origin_only") is not True or session.get(
                "persistent_profile"
            ) is not False:
                raise AdapterExecutionError(
                    "Playwright runner did not attest its isolation policy", execution
                )
            if session.get("allowed_methods") != ["GET", "HEAD"]:
                raise AdapterExecutionError(
                    "Playwright runner returned an unsafe method policy", execution
                )
            for record in [
                *list(session.get("pages") or []),
                *list(session.get("responses") or []),
            ]:
                record_url = record.get("final_url") or record.get("url")
                if record_url and _same_origin_archived_url(target, str(record_url)) is None:
                    raise AdapterExecutionError(
                        "Playwright runner returned cross-origin evidence", execution
                    )
            for page in session.get("pages") or []:
                for linked_url in [
                    *list(page.get("links") or []),
                    *list(page.get("scripts") or []),
                    *[
                        form.get("action")
                        for form in list(page.get("forms") or [])
                        if isinstance(form, dict)
                    ],
                ]:
                    if linked_url and _same_origin_archived_url(
                        target, str(linked_url)
                    ) is None:
                        raise AdapterExecutionError(
                            "Playwright runner returned cross-origin page metadata",
                            execution,
                        )
            for response in session.get("responses") or []:
                if str(response.get("method") or "").upper() not in {"GET", "HEAD"}:
                    raise AdapterExecutionError(
                        "Playwright runner returned a state-changing request", execution
                    )
        return {"sessions": sessions}

    def normalize(self, context: AdapterContext, parsed: Any) -> dict[str, int]:
        from cairn.server.services import utcnow
        from cairn.server.vulnerability_services import (
            next_vulnerability_id,
            normalize_target,
        )

        artifact_refs = parsed.get("_sensitive_artifact_refs", {})
        observations = 0
        response_count = 0
        screenshot_count = 0
        for session in parsed.get("sessions", []):
            target = normalize_web_target(str(session["target"]))
            host = normalize_network_host(str(urlsplit(target).hostname or ""))
            pages = []
            for page in session.get("pages", []):
                page_copy = dict(page)
                key = page_copy.pop("screenshot_artifact_key", None)
                if key and key in artifact_refs:
                    page_copy["screenshot_evidence_ref"] = artifact_refs[key]
                    screenshot_count += 1
                pages.append(page_copy)
            data = {
                "target": target,
                "pages": pages,
                "responses": [
                    {
                        key: response.get(key)
                        for key in (
                            "url",
                            "method",
                            "resource_type",
                            "status_code",
                            "body_sha256",
                            "body_truncated",
                        )
                    }
                    for response in session.get("responses", [])
                ],
                "blocked_requests": session.get("blocked_requests", []),
                "request_count": session.get("request_count"),
                "request_budget": session.get("request_budget"),
                "rate_limit": session.get("rate_limit"),
                "same_origin_only": True,
                "allowed_methods": ["GET", "HEAD"],
                "websockets_blocked": True,
                "service_workers_blocked": True,
                "persistent_profile": False,
                "network_path": session.get("network_path"),
            }
            observations += int(
                _record_domain_metadata(
                    context,
                    "browser_evidence_session",
                    host,
                    data,
                    dimension="web",
                )
            )
            asset = context.conn.execute(
                "SELECT id FROM vuln_assets WHERE campaign_id = ? "
                "AND asset_type IN ('domain', 'ip', 'ipv4', 'ipv6') "
                "AND normalized_identifier = ? ORDER BY id LIMIT 1",
                (context.campaign_id, normalize_target(host)),
            ).fetchone()
            if asset is None:
                continue
            for response in session.get("responses", []):
                response_headers = response.get("response_headers") or {}
                raw_header = "\r\n".join(
                    [
                        f"HTTP/1.1 {int(response.get('status_code') or 0)} Captured",
                        *(
                            f"{str(name)[:256]}: {str(value)[:4096]}"
                            for name, value in list(response_headers.items())[:100]
                        ),
                        "",
                        "",
                    ]
                )
                request_headers = response.get("request_headers") or {}
                request, response_text, truncated, response_bytes, response_hash = (
                    _http_response_envelope(
                        {
                            "method": response.get("method") or "GET",
                            "raw_header": raw_header,
                            "body": response.get("body_text") or "",
                            "status_code": response.get("status_code"),
                        },
                        str(response["url"]),
                        request_headers,
                    )
                )
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
                        asset["id"],
                        str(response["url"])[:4096],
                        str(response.get("method") or "GET")[:16],
                        response.get("status_code"),
                        request,
                        response_text,
                        response_hash,
                        response_bytes,
                        int(truncated or bool(response.get("body_truncated"))),
                        utcnow(),
                    ),
                )
                response_count += 1
        return {
            "observations_created": observations,
            "http_responses_captured": response_count,
            "screenshots_captured": screenshot_count,
        }

    def coverage_complete(self, context: AdapterContext, parsed: Any) -> bool:
        # A bounded browser session is evidence of what was visited, never proof
        # that the full web surface was enumerated.
        return False


class NaabuPortScanAdapter(ActiveNetworkTargetAdapter):
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

    def normalize_task_target(self, value: str) -> str:
        return normalize_network_host(value)

    def validate(self, context: AdapterContext) -> None:
        super().validate(context)
        ports = context.options.get("ports")
        if ports is None:
            return
        if (
            not isinstance(ports, list)
            or not ports
            or len(ports) > 32
            or any(not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535 for port in ports)
        ):
            raise AdapterValidationError("Naabu requires 1-32 explicit TCP ports")

    def materialize(self, context: AdapterContext) -> list[AdapterInvocation]:
        rate = min(25, max(1, context.max_requests_per_second))
        configured_ports = context.options.get("ports")
        port_arguments = (
            ("-p", ",".join(str(port) for port in dict.fromkeys(configured_ports)))
            if configured_ports is not None
            else ("-top-ports", "100")
        )
        return [
            AdapterInvocation(
                argv=(
                    self.binary,
                    "-host",
                    normalize_network_host(target),
                    *port_arguments,
                    "-scan-type",
                    "c",
                    "-Pn",
                    "-timeout",
                    "1s",
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
                target=normalize_network_host(target),
            )
            for target in context.targets
        ]

    def execute(self, context: AdapterContext) -> AdapterExecution:
        return self._execute_materialized(context)

    def parse(self, execution: AdapterExecution) -> dict[str, Any]:
        if not any(result.stdout.strip() for result in execution.results):
            raise AdapterExecutionError(
                f"{self.tool_id} produced no JSONL output; open-port coverage cannot be evidenced",
                execution,
            )
        ports: list[dict[str, Any]] = []
        seen: set[tuple[str, str | None, int, str]] = set()
        for payload in _parse_json_lines(execution, tool_id=self.tool_id):
            port = payload.get("port")
            if not isinstance(port, int) or not 1 <= port <= 65535:
                continue
            record = {
                "domain": normalize_network_host(
                    str(payload.get("host") or payload.get("input") or payload["_invocation_target"])
                ),
                "ip": str(payload.get("ip") or "")[:128] or None,
                "port": port,
                "protocol": str(payload.get("protocol") or "tcp")[:16],
            }
            identity = (
                str(record["domain"]),
                record["ip"],
                int(record["port"]),
                str(record["protocol"]),
            )
            if identity not in seen:
                ports.append(record)
                seen.add(identity)
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
                    "scan_profile": (
                        "explicit-tcp-ports:"
                        + ",".join(str(port) for port in context.options.get("ports", []))
                        if context.options.get("ports") is not None
                        else "fixed-top-100-tcp"
                    ),
                    "network_path": "direct",
                },
                dimension="external",
            )
            created += int(was_created)
            updated += int(not was_created)
        return {"observations_created": created, "observations_updated": updated}


class KatanaCrawlerAdapter(ActiveNetworkTargetAdapter):
    """Bounded same-host, no-form, no-headless R3 discovery profile."""

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

    def normalize_task_target(self, value: str) -> str:
        return normalize_web_target(value)

    def validate(self, context: AdapterContext) -> None:
        super().validate(context)
        depth = context.options.get("depth", 1)
        if not isinstance(depth, int) or isinstance(depth, bool) or not 1 <= depth <= 2:
            raise AdapterValidationError("Katana depth must be between 1 and 2")

    def materialize(self, context: AdapterContext) -> list[AdapterInvocation]:
        depth = int(context.options.get("depth", 1))
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
                    normalize_web_target(target),
                    "-d",
                    str(depth),
                    "-ct",
                    "60s",
                    "-fs",
                    "fqdn",
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
                    "-or",
                    "-ob",
                    "-disable-update-check",
                    *headers,
                ),
                target=normalize_web_target(target),
            )
            for target in context.targets
        ]

    def execute(self, context: AdapterContext) -> AdapterExecution:
        return self._execute_materialized(context)

    def parse(self, execution: AdapterExecution) -> dict[str, Any]:
        if not any(result.stdout.strip() for result in execution.results):
            raise AdapterExecutionError(
                f"{self.tool_id} produced no JSONL output; crawl coverage cannot be evidenced",
                execution,
            )
        urls: list[dict[str, str]] = []
        for payload in _parse_json_lines(execution, tool_id=self.tool_id):
            request = payload.get("request") if isinstance(payload.get("request"), dict) else {}
            endpoint = str(payload.get("url") or request.get("endpoint") or "")[:4096]
            parsed = urlsplit(endpoint)
            if parsed.scheme not in {"http", "https"} or not parsed.hostname:
                continue
            invocation_domain = normalize_network_host(str(payload["_invocation_target"]))
            endpoint_domain = normalize_network_host(parsed.hostname)
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
                    "crawl_profile": (
                        f"depth-{int(context.options.get('depth', 1))}"
                        "-fqdn-scope-no-headless-no-form-submission"
                    ),
                    "request_headers": self.get_headers(context),
                },
                dimension="web",
            )
            created += int(was_created)
            updated += int(not was_created)
        return {"observations_created": created, "observations_updated": updated}


class GitleaksLocalRepositoryAdapter(VulnSourceAdapter):
    """Scan only explicitly allowlisted local repository snapshots, fully redacted."""

    tool_id = "gitleaks.secrets.v1"
    version = "1.0.0"
    risk_class = "R1"
    source_type = "gitleaks_local"
    dimension = "code"
    binary = _configured_user_binary("gitleaks", "CAIRN_GITLEAKS_BINARY")
    expected_tool_version = GITLEAKS_PACKAGE_VERSION
    release_sha256 = GITLEAKS_PACKAGE_SHA256
    requires_human_approval = True
    uses_http = False
    uses_network = False
    timeout_seconds = 60
    input_schema = {
        "type": "object",
        "required": ["repositories"],
        "properties": {
            "repositories": {"type": "array", "items": {"type": "object"}}
        },
        "additionalProperties": False,
    }
    output_schema = {
        "type": "object",
        "required": ["findings"],
        "properties": {"findings": {"type": "array", "items": {"type": "object"}}},
    }

    def validate(self, context: AdapterContext) -> None:
        super().validate(context)
        if not context.repositories:
            raise AdapterValidationError(
                "Gitleaks requires an authorized local repository asset"
            )
        if len(context.repositories) > 5:
            raise AdapterValidationError("Gitleaks accepts at most five repositories per task")
        _audited_gitleaks_config_path()
        for repository in context.repositories:
            path = authorized_local_repository(str(repository.get("path") or ""))
            if path != Path(str(repository.get("path") or "")).expanduser().resolve():
                raise AdapterValidationError("Repository path did not resolve deterministically")
            if not repository.get("asset_id"):
                raise AdapterValidationError("Repository input is not linked to an asset")

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
            binary_hash = _sha256_file(Path(executable))
            config_path = _audited_gitleaks_config_path()
        except (OSError, AdapterError) as exc:
            return {
                "healthy": False,
                "tool_id": self.tool_id,
                "version": None,
                "error": str(exc),
            }
        if binary_hash != GITLEAKS_BINARY_SHA256:
            return {
                "healthy": False,
                "tool_id": self.tool_id,
                "version": self.expected_tool_version,
                "error": "Gitleaks executable hash does not match the audited package",
            }
        return {
            "healthy": True,
            "tool_id": self.tool_id,
            "version": self.expected_tool_version,
            "expected_version": self.expected_tool_version,
            "release_sha256": self.release_sha256,
            "binary_sha256": binary_hash,
            "config_sha256": _sha256_file(config_path),
            "offline_only": True,
            "error": None,
        }

    def materialize(self, context: AdapterContext) -> list[AdapterInvocation]:
        config_path = _audited_gitleaks_config_path()
        return [
            AdapterInvocation(
                argv=(
                    self.binary,
                    "dir",
                    "--config",
                    str(config_path),
                    "--no-banner",
                    "--no-color",
                    "--redact=100",
                    "--report-format",
                    "json",
                    "--report-path",
                    "-",
                    "--exit-code",
                    "0",
                    "--max-decode-depth",
                    "0",
                    "--max-target-megabytes",
                    "5",
                    str(authorized_local_repository(str(repository["path"]))),
                ),
                target=str(repository["path"]),
            )
            for repository in context.repositories
        ]

    def execute(self, context: AdapterContext) -> AdapterExecution:
        return self._execute_materialized(context)

    def parse(self, execution: AdapterExecution) -> dict[str, Any]:
        findings: list[dict[str, Any]] = []
        for result in execution.results:
            try:
                payload = json.loads(result.stdout or "[]")
            except json.JSONDecodeError as exc:
                raise AdapterExecutionError("Gitleaks returned invalid JSON", execution) from exc
            if not isinstance(payload, list):
                raise AdapterExecutionError("Gitleaks output must be a JSON array", execution)
            repository = authorized_local_repository(str(result.target or ""))
            for item in payload[:1000]:
                if not isinstance(item, Mapping):
                    continue
                file_value = str(item.get("File") or "")
                file_path = Path(file_value)
                try:
                    relative = (
                        file_path.resolve(strict=False).relative_to(repository)
                        if file_path.is_absolute()
                        else file_path
                    )
                except ValueError as exc:
                    raise AdapterExecutionError(
                        "Gitleaks finding path escaped the approved repository", execution
                    ) from exc
                if relative.is_absolute() or ".." in relative.parts:
                    raise AdapterExecutionError(
                        "Gitleaks finding path escaped the approved repository", execution
                    )
                rule_id = str(item.get("RuleID") or "unknown-rule")[:256]
                start_line = max(0, int(item.get("StartLine") or 0))
                fingerprint = hashlib.sha256(
                    (
                        f"{repository}\0{relative.as_posix()}\0{rule_id}\0{start_line}\0"
                        f"{str(item.get('Commit') or '')[:128]}"
                    ).encode()
                ).hexdigest()
                findings.append(
                    {
                        "repository": str(repository),
                        "rule_id": rule_id,
                        "description": str(item.get("Description") or rule_id)[:1000],
                        "file": relative.as_posix()[:2048],
                        "start_line": start_line,
                        "end_line": max(start_line, int(item.get("EndLine") or start_line)),
                        "commit": str(item.get("Commit") or "")[:128] or None,
                        "fingerprint": fingerprint,
                        "redacted": True,
                    }
                )
        return {"findings": findings}

    def normalize(self, context: AdapterContext, parsed: Any) -> dict[str, int]:
        from cairn.server.vulnerability_services import reconcile_gitleaks_findings

        return reconcile_gitleaks_findings(
            context.conn,
            campaign_id=context.campaign_id,
            task_id=context.task_id,
            source_id=str(context.source["id"]),
            adapter=self.tool_id,
            repositories=list(context.repositories),
            matches=list(parsed.get("findings", [])),
            coverage_complete=True,
        )


def _cyclonedx_license_values(component: Mapping[str, Any]) -> list[str]:
    values: list[str] = []
    raw_licenses = component.get("licenses")
    if not isinstance(raw_licenses, list):
        return values
    for item in raw_licenses[:100]:
        if not isinstance(item, Mapping):
            continue
        expression = item.get("expression")
        if isinstance(expression, str) and expression.strip():
            values.append(expression.strip()[:512])
            continue
        license_value = item.get("license")
        if not isinstance(license_value, Mapping):
            continue
        value = license_value.get("id") or license_value.get("name")
        if isinstance(value, str) and value.strip():
            values.append(value.strip()[:512])
    return list(dict.fromkeys(values))


def _cyclonedx_hash_values(component: Mapping[str, Any]) -> dict[str, str]:
    values: dict[str, str] = {}
    raw_hashes = component.get("hashes")
    if not isinstance(raw_hashes, list):
        return values
    for item in raw_hashes[:50]:
        if not isinstance(item, Mapping):
            continue
        algorithm = str(item.get("alg") or "").strip().upper()[:32]
        content = str(item.get("content") or "").strip().lower()[:256]
        if algorithm and content and re.fullmatch(r"[0-9a-f]+", content):
            values[algorithm] = content
    return dict(sorted(values.items()))


_PURL_OSV_ECOSYSTEMS = {
    "cargo": "crates.io",
    "composer": "Packagist",
    "gem": "RubyGems",
    "github": "GitHub Actions",
    "golang": "Go",
    "hex": "Hex",
    "maven": "Maven",
    "npm": "npm",
    "nuget": "NuGet",
    "pub": "Pub",
    "pypi": "PyPI",
    "swift": "SwiftURL",
}


def _purl_dependency_identity(purl: str | None) -> dict[str, str] | None:
    if not purl or not purl.startswith("pkg:"):
        return None
    body = purl[4:].split("#", 1)[0].split("?", 1)[0]
    if "/" not in body or "@" not in body:
        return None
    package_type, remainder = body.split("/", 1)
    path, version = remainder.rsplit("@", 1)
    ecosystem = _PURL_OSV_ECOSYSTEMS.get(package_type.casefold())
    if not ecosystem:
        return None
    decoded_path = unquote(path).strip("/")
    decoded_version = unquote(version).strip()
    if not decoded_path or not decoded_version:
        return None
    if package_type.casefold() == "maven" and "/" in decoded_path:
        namespace, name = decoded_path.rsplit("/", 1)
        decoded_path = f"{namespace.replace('/', '.')}:{name}"
    return {
        "ecosystem": ecosystem,
        "name": decoded_path[:1024],
        "version": decoded_version[:512],
        "identifier": f"{ecosystem}:{decoded_path}@{decoded_version}"[:2048],
    }


class SyftLocalSbomAdapter(VulnSourceAdapter):
    """Generate a bounded CycloneDX inventory inside a no-network namespace."""

    tool_id = "syft.local-sbom.v1"
    version = "1.0.0"
    risk_class = "R1"
    source_type = "syft_local_sbom"
    dimension = "supply_chain"
    binary = _configured_user_binary("syft", "CAIRN_SYFT_BINARY")
    expected_tool_version = SYFT_PACKAGE_VERSION
    release_sha256 = SYFT_PACKAGE_SHA256
    requires_human_approval = True
    uses_http = False
    uses_network = False
    timeout_seconds = 60
    input_schema = {
        "type": "object",
        "required": ["repositories"],
        "properties": {
            "repositories": {"type": "array", "items": {"type": "object"}}
        },
        "additionalProperties": False,
    }
    output_schema = {
        "type": "object",
        "required": ["documents"],
        "properties": {"documents": {"type": "array", "items": {"type": "object"}},},
    }

    def validate(self, context: AdapterContext) -> None:
        super().validate(context)
        if not context.repositories:
            raise AdapterValidationError("Syft requires an authorized local repository asset")
        if len(context.repositories) > 5:
            raise AdapterValidationError("Syft accepts at most five repositories per task")
        for repository in context.repositories:
            path = authorized_local_supply_chain_target(
                str(repository.get("path") or "")
            )
            if path != Path(str(repository.get("path") or "")).expanduser().resolve():
                raise AdapterValidationError("Repository path did not resolve deterministically")
            if not repository.get("asset_id"):
                raise AdapterValidationError("Repository input is not linked to an asset")
            _validate_supply_chain_tree(path)

    def health(self) -> dict[str, Any]:
        executable = shutil.which(self.binary)
        namespace_tool = shutil.which("unshare")
        if executable is None or namespace_tool is None:
            missing = self.binary if executable is None else "unshare"
            return {
                "healthy": False,
                "tool_id": self.tool_id,
                "version": None,
                "error": f"Executable not found: {missing}",
            }
        try:
            binary_hash = _sha256_file(Path(executable))
        except OSError as exc:
            return {
                "healthy": False,
                "tool_id": self.tool_id,
                "version": None,
                "error": f"Syft executable cannot be hashed: {type(exc).__name__}",
            }
        if binary_hash != SYFT_BINARY_SHA256:
            return {
                "healthy": False,
                "tool_id": self.tool_id,
                "version": self.expected_tool_version,
                "error": "Syft executable hash does not match the audited Kali package",
            }
        return {
            "healthy": True,
            "tool_id": self.tool_id,
            "version": self.expected_tool_version,
            "expected_version": self.expected_tool_version,
            "release_sha256": self.release_sha256,
            "binary_sha256": binary_hash,
            "network_namespace": "disabled",
            "offline_only": True,
            "error": None,
        }

    def materialize(self, context: AdapterContext) -> list[AdapterInvocation]:
        namespace_tool = shutil.which("unshare") or "unshare"
        return [
            AdapterInvocation(
                argv=(
                    namespace_tool,
                    "--user",
                    "--map-current-user",
                    "--net",
                    "--",
                    self.binary,
                    "scan",
                    f"dir:{authorized_local_supply_chain_target(str(repository['path']))}",
                    "--base-path",
                    str(authorized_local_supply_chain_target(str(repository["path"]))),
                    "--parallelism",
                    "1",
                    "--quiet",
                    "--output",
                    "cyclonedx-json@1.6",
                ),
                target=str(
                    authorized_local_supply_chain_target(str(repository["path"]))
                ),
            )
            for repository in context.repositories
        ]

    @staticmethod
    def _redacted_execution(execution: AdapterExecution) -> AdapterExecution:
        """Preserve deterministic diagnostics without exposing local filesystem data."""

        return AdapterExecution(
            tuple(
                replace(
                    result,
                    stdout=(
                        "[SYFT RAW OUTPUT REDACTED] "
                        f"sha256={hashlib.sha256(result.stdout.encode('utf-8')).hexdigest()} "
                        f"bytes={len(result.stdout.encode('utf-8'))}"
                        if result.stdout
                        else ""
                    ),
                    stderr=(
                        "[SYFT STDERR REDACTED] "
                        f"sha256={hashlib.sha256(result.stderr.encode('utf-8')).hexdigest()} "
                        f"bytes={len(result.stderr.encode('utf-8'))}"
                        if result.stderr
                        else ""
                    ),
                )
                for result in execution.results
            )
        )

    def execute(self, context: AdapterContext) -> AdapterExecution:
        try:
            execution = self._execute_materialized(context)
        except AdapterExecutionError as exc:
            sanitized = (
                self._redacted_execution(exc.execution)
                if exc.execution is not None
                else None
            )
            raise AdapterExecutionError(str(exc), sanitized) from exc
        redacted_failure = self._redacted_execution(execution)
        repositories = {
            str(authorized_local_supply_chain_target(str(item["path"]))): str(
                item["asset_id"]
            )
            for item in context.repositories
        }
        artifacts: list[SensitiveArtifact] = []
        sanitized_results: list[CommandResult] = []
        for result in execution.results:
            raw = result.stdout.encode("utf-8")
            if not raw:
                raise AdapterExecutionError(
                    "Syft produced no CycloneDX document", redacted_failure
                )
            if len(raw) > SYFT_MAX_OUTPUT_BYTES:
                raise AdapterExecutionError(
                    "Syft CycloneDX document exceeds the 5 MiB evidence limit",
                    redacted_failure,
                )
            asset_id = repositories.get(str(result.target or ""))
            if not asset_id:
                raise AdapterExecutionError(
                    "Syft output target is not linked to an approved repository",
                    redacted_failure,
                )
            try:
                payload = json.loads(result.stdout)
            except json.JSONDecodeError as exc:
                raise AdapterExecutionError(
                    "Syft returned invalid CycloneDX JSON", redacted_failure
                ) from exc
            if not isinstance(payload, Mapping) or not isinstance(
                payload.get("components"), list
            ):
                raise AdapterExecutionError(
                    "Syft output is not a CycloneDX component document",
                    redacted_failure,
                )
            if len(payload["components"]) > SYFT_MAX_COMPONENTS:
                raise AdapterExecutionError(
                    "Syft component count exceeds the 10000 component limit",
                    redacted_failure,
                )
            safe_components = []
            for component in payload["components"]:
                if not isinstance(component, Mapping):
                    safe_components.append(None)
                    continue
                safe_components.append(
                    {
                        "type": component.get("type"),
                        "name": component.get("name"),
                        "version": component.get("version"),
                        "purl": component.get("purl"),
                        "licenses": component.get("licenses"),
                        "hashes": component.get("hashes"),
                    }
                )
            sanitized_results.append(
                replace(
                    result,
                    stdout=json.dumps(
                        {
                            "bomFormat": "CycloneDX",
                            "components": safe_components,
                            "_raw_document_hash": hashlib.sha256(raw).hexdigest(),
                            "_component_count": len(payload["components"]),
                        },
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    ),
                    stderr=(
                        "[SYFT STDERR REDACTED] "
                        f"sha256={hashlib.sha256(result.stderr.encode('utf-8')).hexdigest()} "
                        f"bytes={len(result.stderr.encode('utf-8'))}"
                        if result.stderr
                        else ""
                    ),
                )
            )
            artifacts.append(
                SensitiveArtifact(
                    key=f"sbom:{asset_id}",
                    target=result.target,
                    artifact_kind="cyclonedx_sbom",
                    media_type="application/vnd.cyclonedx+json",
                    content=raw,
                )
            )
        return AdapterExecution(
            results=tuple(sanitized_results),
            sensitive_artifacts=tuple(artifacts),
        )

    def parse(self, execution: AdapterExecution) -> dict[str, Any]:
        documents: list[dict[str, Any]] = []
        for result in execution.results:
            try:
                payload = json.loads(result.stdout)
            except json.JSONDecodeError as exc:
                raise AdapterExecutionError(
                    "Syft returned invalid CycloneDX JSON", execution
                ) from exc
            if not isinstance(payload, Mapping) or not isinstance(
                payload.get("components"), list
            ):
                raise AdapterExecutionError(
                    "Syft output is not a CycloneDX component document", execution
                )
            raw_components = payload["components"]
            if len(raw_components) > SYFT_MAX_COMPONENTS:
                raise AdapterExecutionError(
                    "Syft component count exceeds the 10000 component limit",
                    execution,
                )
            components: list[dict[str, Any]] = []
            coverage_complete = True
            for item in raw_components:
                if not isinstance(item, Mapping):
                    coverage_complete = False
                    continue
                purl = str(item.get("purl") or "").strip()[:2048] or None
                name = str(item.get("name") or purl or "").strip()[:1024]
                if not name:
                    coverage_complete = False
                    continue
                component = {
                    "purl": purl,
                    "name": name,
                    "version": str(item.get("version") or "").strip()[:512] or None,
                    "component_type": str(item.get("type") or "library").strip()[:64],
                    "licenses": _cyclonedx_license_values(item),
                    "hashes": _cyclonedx_hash_values(item),
                    "dependency": _purl_dependency_identity(purl),
                }
                component["component_hash"] = hashlib.sha256(
                    json.dumps(
                        component,
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    ).encode("utf-8")
                ).hexdigest()
                components.append(component)
            documents.append(
                {
                    "target": str(result.target or ""),
                    "artifact_key": "",
                    "document_hash": str(
                        payload.get("_raw_document_hash")
                        or hashlib.sha256(result.stdout.encode("utf-8")).hexdigest()
                    ),
                    "component_count": int(
                        payload.get("_component_count") or len(raw_components)
                    ),
                    "coverage_complete": coverage_complete
                    and len(components) == len(raw_components),
                    "components": components,
                }
            )
        return {"documents": documents}

    def normalize(self, context: AdapterContext, parsed: Any) -> dict[str, int]:
        from cairn.server.vulnerability_services import reconcile_syft_sbom

        documents = list(parsed.get("documents", []))
        refs = parsed.get("_sensitive_artifact_refs", {})
        refs = refs if isinstance(refs, Mapping) else {}
        repository_ids = {
            str(authorized_local_supply_chain_target(str(item["path"]))): str(
                item["asset_id"]
            )
            for item in context.repositories
        }
        for document in documents:
            asset_id = repository_ids.get(str(document.get("target") or ""), "")
            document["artifact_key"] = f"sbom:{asset_id}"
            document["vault_ref"] = refs.get(document["artifact_key"])
        return reconcile_syft_sbom(
            context.conn,
            campaign_id=context.campaign_id,
            task_id=context.task_id,
            source_id=str(context.source["id"]),
            adapter=self.tool_id,
            source_name=str(
                context.source["name"]
                if "name" in context.source.keys()
                else "Syft authorized local SBOM"
            ),
            repositories=list(context.repositories),
            documents=documents,
        )

    def coverage_complete(self, context: AdapterContext, parsed: Any) -> bool:
        documents = parsed.get("documents", [])
        return bool(documents) and all(
            bool(item.get("coverage_complete")) for item in documents
        )


class SyftContainerArchiveSbomAdapter(SyftLocalSbomAdapter):
    """Generate a CycloneDX inventory from an authorized local image archive."""

    tool_id = "syft.container-archive-sbom.v1"
    version = "1.0.0"
    risk_class = "R1"
    source_type = "syft_container_archive_sbom"
    dimension = "supply_chain"
    requires_human_approval = True
    input_schema = {
        "type": "object",
        "required": ["container_archives"],
        "properties": {
            "container_archives": {
                "type": "array",
                "items": {"type": "object"},
                "maxItems": 2,
            }
        },
        "additionalProperties": False,
    }

    def normalize_task_target(self, value: str) -> str:
        return str(authorized_local_supply_chain_archive(value))

    def validate(self, context: AdapterContext) -> None:
        VulnSourceAdapter.validate(self, context)
        if not context.container_archives:
            raise AdapterValidationError(
                "Syft requires an authorized local container image archive"
            )
        if len(context.container_archives) > 2:
            raise AdapterValidationError(
                "Syft accepts at most two container archives per task"
            )
        for subject in context.container_archives:
            path = authorized_local_supply_chain_archive(str(subject.get("path") or ""))
            if path != Path(str(subject.get("path") or "")).expanduser().resolve():
                raise AdapterValidationError(
                    "Container archive path did not resolve deterministically"
                )
            if not subject.get("asset_id"):
                raise AdapterValidationError(
                    "Container archive input is not linked to an asset"
                )
            archive_format = _container_archive_format(path)
            declared = str(subject.get("archive_format") or "")
            if declared and declared != archive_format:
                raise AdapterValidationError("Container archive format changed after policy validation")

    def materialize(self, context: AdapterContext) -> list[AdapterInvocation]:
        namespace_tool = shutil.which("unshare") or "unshare"
        invocations: list[AdapterInvocation] = []
        for subject in context.container_archives:
            path = authorized_local_supply_chain_archive(str(subject["path"]))
            archive_format = _container_archive_format(path)
            invocations.append(
                AdapterInvocation(
                    argv=(
                        namespace_tool,
                        "--user",
                        "--map-current-user",
                        "--net",
                        "--",
                        self.binary,
                        "scan",
                        f"{archive_format}:{path}",
                        "--parallelism",
                        "1",
                        "--quiet",
                        "--output",
                        "cyclonedx-json@1.6",
                    ),
                    target=str(path),
                )
            )
        return invocations

    def execute(self, context: AdapterContext) -> AdapterExecution:
        self.validate(context)
        subjects = {
            str(authorized_local_supply_chain_archive(str(item["path"]))): str(
                item["asset_id"]
            )
            for item in context.container_archives
        }
        try:
            execution = self._execute_invocations(context, self.materialize(context))
        except AdapterExecutionError as exc:
            sanitized = (
                self._redacted_execution(exc.execution)
                if exc.execution is not None
                else None
            )
            raise AdapterExecutionError(str(exc), sanitized) from exc
        redacted_failure = self._redacted_execution(execution)
        artifacts: list[SensitiveArtifact] = []
        sanitized_results: list[CommandResult] = []
        for result in execution.results:
            raw = result.stdout.encode("utf-8")
            if not raw:
                raise AdapterExecutionError(
                    "Syft produced no CycloneDX document", redacted_failure
                )
            if len(raw) > SYFT_MAX_OUTPUT_BYTES:
                raise AdapterExecutionError(
                    "Syft CycloneDX document exceeds the 5 MiB evidence limit",
                    redacted_failure,
                )
            asset_id = subjects.get(str(result.target or ""))
            if not asset_id:
                raise AdapterExecutionError(
                    "Syft output target is not linked to an approved container image",
                    redacted_failure,
                )
            try:
                payload = json.loads(result.stdout)
            except json.JSONDecodeError as exc:
                raise AdapterExecutionError(
                    "Syft returned invalid CycloneDX JSON", redacted_failure
                ) from exc
            if not isinstance(payload, Mapping) or not isinstance(
                payload.get("components"), list
            ):
                raise AdapterExecutionError(
                    "Syft output is not a CycloneDX component document",
                    redacted_failure,
                )
            if len(payload["components"]) > SYFT_MAX_COMPONENTS:
                raise AdapterExecutionError(
                    "Syft component count exceeds the 10000 component limit",
                    redacted_failure,
                )
            safe_components = []
            for component in payload["components"]:
                if not isinstance(component, Mapping):
                    safe_components.append(None)
                    continue
                safe_components.append(
                    {
                        "type": component.get("type"),
                        "name": component.get("name"),
                        "version": component.get("version"),
                        "purl": component.get("purl"),
                        "licenses": component.get("licenses"),
                        "hashes": component.get("hashes"),
                    }
                )
            sanitized_results.append(
                replace(
                    result,
                    stdout=json.dumps(
                        {
                            "bomFormat": "CycloneDX",
                            "components": safe_components,
                            "_raw_document_hash": hashlib.sha256(raw).hexdigest(),
                            "_component_count": len(payload["components"]),
                        },
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    ),
                    stderr=(
                        "[SYFT STDERR REDACTED] "
                        f"sha256={hashlib.sha256(result.stderr.encode('utf-8')).hexdigest()} "
                        f"bytes={len(result.stderr.encode('utf-8'))}"
                        if result.stderr
                        else ""
                    ),
                )
            )
            artifacts.append(
                SensitiveArtifact(
                    key=f"sbom:{asset_id}",
                    target=result.target,
                    artifact_kind="cyclonedx_sbom",
                    media_type="application/vnd.cyclonedx+json",
                    content=raw,
                )
            )
        return AdapterExecution(
            results=tuple(sanitized_results),
            sensitive_artifacts=tuple(artifacts),
        )

    def normalize(self, context: AdapterContext, parsed: Any) -> dict[str, int]:
        from cairn.server.vulnerability_services import reconcile_syft_sbom

        documents = list(parsed.get("documents", []))
        refs = parsed.get("_sensitive_artifact_refs", {})
        refs = refs if isinstance(refs, Mapping) else {}
        subject_ids = {
            str(authorized_local_supply_chain_archive(str(item["path"]))): str(
                item["asset_id"]
            )
            for item in context.container_archives
        }
        subjects = []
        for item in context.container_archives:
            subjects.append(
                {**item, "asset_type": str(item.get("asset_type") or "container_image")}
            )
        for document in documents:
            asset_id = subject_ids.get(str(document.get("target") or ""), "")
            document["artifact_key"] = f"sbom:{asset_id}"
            document["vault_ref"] = refs.get(document["artifact_key"])
        return reconcile_syft_sbom(
            context.conn,
            campaign_id=context.campaign_id,
            task_id=context.task_id,
            source_id=str(context.source["id"]),
            adapter=self.tool_id,
            source_name=str(
                context.source["name"]
                if "name" in context.source.keys()
                else "Syft authorized container archive SBOM"
            ),
            repositories=subjects,
            documents=documents,
        )


class TrivySbomVulnerabilityAdapter(VulnSourceAdapter):
    """Match saved encrypted SBOM evidence against an audited offline DB."""

    tool_id = "trivy.sbom-vuln.v1"
    version = "1.0.0"
    risk_class = "R0"
    source_type = "trivy_sbom_vulnerability"
    dimension = "supply_chain"
    binary = _configured_user_binary("trivy", "CAIRN_TRIVY_BINARY")
    expected_tool_version = TRIVY_PACKAGE_VERSION
    release_sha256 = TRIVY_PACKAGE_SHA256
    requires_human_approval = True
    uses_http = False
    uses_network = False
    timeout_seconds = 90
    input_schema = {
        "type": "object",
        "required": ["repositories", "sboms"],
        "properties": {
            "repositories": {"type": "array", "items": {"type": "object"}},
            "sboms": {"type": "array", "items": {"type": "object"}, "maxItems": 5},
        },
        "additionalProperties": False,
    }
    output_schema = {
        "type": "object",
        "required": ["documents", "coverage_complete"],
        "properties": {
            "documents": {"type": "array", "items": {"type": "object"}},
            "coverage_complete": {"type": "boolean"},
        },
    }

    def _subjects(self, context: AdapterContext) -> tuple[Mapping[str, Any], ...]:
        return context.repositories

    def validate(self, context: AdapterContext) -> None:
        super().validate(context)
        subjects = self._subjects(context)
        if not subjects or not context.sboms:
            raise AdapterValidationError(
                "Trivy requires a saved SBOM for an approved supply-chain subject"
            )
        if len(context.sboms) > 5 or len(context.sboms) != len(subjects):
            raise AdapterValidationError(
                "Trivy accepts one saved SBOM per approved supply-chain subject"
            )
        subject_ids = {str(item.get("asset_id") or "") for item in subjects}
        for sbom in context.sboms:
            if str(sbom.get("subject_asset_id") or sbom.get("repository_asset_id") or "") not in subject_ids:
                raise AdapterValidationError(
                    "Saved SBOM is not linked to the approved supply-chain subject"
                )
            content = sbom.get("content")
            if not isinstance(content, bytes) or not content:
                raise AdapterValidationError("Saved SBOM content is unavailable")
            if len(content) > SYFT_MAX_OUTPUT_BYTES:
                raise AdapterValidationError("Saved SBOM exceeds the 5 MiB input limit")
            if hashlib.sha256(content).hexdigest() != str(sbom.get("document_hash") or ""):
                raise AdapterValidationError("Saved SBOM content hash mismatch")
            try:
                document = json.loads(content)
            except json.JSONDecodeError as exc:
                raise AdapterValidationError("Saved SBOM is not valid JSON") from exc
            if not isinstance(document, Mapping) or document.get("bomFormat") != "CycloneDX":
                raise AdapterValidationError("Saved SBOM is not a CycloneDX document")
            if str(document.get("specVersion") or "") not in {"1.3", "1.4", "1.5", "1.6"}:
                raise AdapterValidationError("Saved SBOM uses an unsupported CycloneDX version")
            if not isinstance(document.get("components"), list):
                raise AdapterValidationError("Saved SBOM has no component inventory")

    def estimate(self, context: AdapterContext) -> dict[str, Any]:
        return {
            "command_count": len(context.sboms),
            "timeout_seconds": self.timeout_seconds,
            "risk_class": self.risk_class,
            "network_request_count": 0,
            "offline_only": True,
            "database_snapshot": TRIVY_DB_SNAPSHOT,
        }

    def health(self) -> dict[str, Any]:
        executable = shutil.which(self.binary)
        namespace_tool = shutil.which("unshare")
        if executable is None or namespace_tool is None:
            missing = self.binary if executable is None else "unshare"
            return {"healthy": False, "tool_id": self.tool_id, "version": None,
                    "error": f"Executable not found: {missing}"}
        try:
            binary_hash = _sha256_file(Path(executable))
            root, _database, _metadata = _audited_trivy_database()
        except (OSError, AdapterError) as exc:
            return {"healthy": False, "tool_id": self.tool_id,
                    "version": self.expected_tool_version, "error": str(exc)}
        if binary_hash != TRIVY_BINARY_SHA256:
            return {"healthy": False, "tool_id": self.tool_id,
                    "version": self.expected_tool_version,
                    "error": "Trivy executable hash does not match the audited Kali package"}
        return {
            "healthy": True,
            "tool_id": self.tool_id,
            "version": self.expected_tool_version,
            "expected_version": self.expected_tool_version,
            "release_sha256": self.release_sha256,
            "binary_sha256": binary_hash,
            "database_root_hash": hashlib.sha256(str(root).encode("utf-8")).hexdigest(),
            "database_snapshot": TRIVY_DB_SNAPSHOT,
            "database_sha256": TRIVY_DB_SHA256,
            "database_metadata_sha256": TRIVY_DB_METADATA_SHA256,
            "database_updated_at": TRIVY_DB_UPDATED_AT,
            "network_namespace": "disabled",
            "offline_only": True,
            "error": None,
        }

    def materialize(self, context: AdapterContext) -> list[AdapterInvocation]:
        database_root, _database, _metadata = _audited_trivy_database()
        namespace_tool = shutil.which("unshare")
        if namespace_tool is None:
            raise AdapterUnavailableError("Trivy requires a Linux user network namespace")
        invocations: list[AdapterInvocation] = []
        for sbom in context.sboms:
            file_path = str(sbom.get("file_path") or "")
            if not file_path:
                raise AdapterValidationError("Trivy SBOM file was not materialized")
            invocations.append(
                AdapterInvocation(
                    argv=(
                        namespace_tool, "--user", "--map-current-user", "--net", "--",
                        self.binary, "sbom", "--cache-dir", str(database_root),
                        "--skip-db-update", "--skip-java-db-update",
                        "--skip-vex-repo-update", "--offline-scan",
                        "--disable-telemetry", "--skip-version-check",
                        "--scanners", "vuln", "--detection-priority", "precise",
                        "--format", "json", file_path,
                    ),
                    target=str(sbom["id"]),
                )
            )
        return invocations

    @staticmethod
    def _sanitize_output(payload: Mapping[str, Any], sbom_id: str) -> dict[str, Any]:
        findings: list[dict[str, Any]] = []
        results = payload.get("Results")
        if not isinstance(results, list):
            raise AdapterExecutionError("Trivy output has no Results array")
        for result in results:
            if not isinstance(result, Mapping):
                continue
            vulnerabilities = result.get("Vulnerabilities") or []
            if not isinstance(vulnerabilities, list):
                raise AdapterExecutionError("Trivy vulnerability result is malformed")
            for vulnerability in vulnerabilities:
                if not isinstance(vulnerability, Mapping):
                    continue
                if len(findings) >= TRIVY_MAX_VULNERABILITIES:
                    raise AdapterExecutionError("Trivy vulnerability count exceeds the 10000 limit")
                package_identifier = vulnerability.get("PkgIdentifier")
                package_identifier = package_identifier if isinstance(package_identifier, Mapping) else {}
                cvss_score: float | None = None
                cvss_vector: str | None = None
                cvss = vulnerability.get("CVSS")
                if isinstance(cvss, Mapping):
                    for authority in cvss.values():
                        if not isinstance(authority, Mapping):
                            continue
                        for key in ("V40Score", "V3Score", "V2Score"):
                            try:
                                candidate = float(authority[key])
                            except (KeyError, TypeError, ValueError):
                                continue
                            if cvss_score is None or candidate > cvss_score:
                                cvss_score = candidate
                                cvss_vector = str(authority.get(key.replace("Score", "Vector")) or "")[:256] or None
                references = vulnerability.get("References")
                references = references if isinstance(references, list) else []
                findings.append({
                    "vulnerability_id": str(vulnerability.get("VulnerabilityID") or "")[:256],
                    "purl": str(package_identifier.get("PURL") or "")[:2048],
                    "package_name": str(vulnerability.get("PkgName") or "")[:1024],
                    "installed_version": str(vulnerability.get("InstalledVersion") or "")[:512],
                    "fixed_version": str(vulnerability.get("FixedVersion") or "")[:512] or None,
                    "status": str(vulnerability.get("Status") or "")[:128] or None,
                    "severity": str(vulnerability.get("Severity") or "unknown").lower()[:32],
                    "title": str(vulnerability.get("Title") or "")[:1000] or None,
                    "description": str(vulnerability.get("Description") or "")[:8000] or None,
                    "primary_url": str(vulnerability.get("PrimaryURL") or "")[:4096] or None,
                    "references": [str(item)[:4096] for item in references[:20] if isinstance(item, str)],
                    "cvss_score": cvss_score,
                    "cvss_vector": cvss_vector,
                })
        return {
            "sbom_id": sbom_id,
            "findings": findings,
            "coverage_complete": True,
            "database": {"snapshot": TRIVY_DB_SNAPSHOT, "sha256": TRIVY_DB_SHA256,
                         "metadata_sha256": TRIVY_DB_METADATA_SHA256,
                         "updated_at": TRIVY_DB_UPDATED_AT},
        }

    @staticmethod
    def _redacted_execution(execution: AdapterExecution) -> AdapterExecution:
        """Retain diagnostic hashes without persisting local paths or raw output."""

        return AdapterExecution(tuple(
            replace(
                result,
                stdout=(
                    "[TRIVY RAW OUTPUT REDACTED] "
                    f"sha256={hashlib.sha256(result.stdout.encode('utf-8')).hexdigest()} "
                    f"bytes={len(result.stdout.encode('utf-8'))}"
                    if result.stdout else ""
                ),
                stderr=(
                    "[TRIVY STDERR REDACTED] "
                    f"sha256={hashlib.sha256(result.stderr.encode('utf-8')).hexdigest()} "
                    f"bytes={len(result.stderr.encode('utf-8'))}"
                    if result.stderr else ""
                ),
            )
            for result in execution.results
        ))

    def execute(self, context: AdapterContext) -> AdapterExecution:
        self.validate(context)
        with managed_task_workspace(context.conn, campaign_id=context.campaign_id,
                                    task_id=context.task_id, purpose="trivy-offline-sbom") as workspace:
            materialized: list[Mapping[str, Any]] = []
            for index, sbom in enumerate(context.sboms):
                path = workspace.write_bytes(
                    f"sbom-{index:03d}.cdx.json", bytes(sbom["content"]),
                    artifact_kind="trivy_offline_sbom_input",
                    source_reference=f"collection-evidence:{sbom['vault_ref']}",
                    source_promoted=True,
                )
                materialized.append({**sbom, "file_path": str(path)})
            execution_context = replace(context, sboms=tuple(materialized))
            try:
                raw_execution = self._execute_invocations(
                    execution_context, self.materialize(execution_context)
                )
            except AdapterExecutionError as exc:
                sanitized = (
                    self._redacted_execution(exc.execution)
                    if exc.execution is not None else None
                )
                raise AdapterExecutionError(str(exc), sanitized) from exc
            sanitized_results: list[CommandResult] = []
            for result in raw_execution.results:
                raw = result.stdout.encode("utf-8")
                if not raw:
                    raise AdapterExecutionError(
                        "Trivy produced no JSON output",
                        self._redacted_execution(raw_execution),
                    )
                if len(raw) > TRIVY_MAX_OUTPUT_BYTES:
                    raise AdapterExecutionError(
                        "Trivy JSON output exceeds the 5 MiB limit",
                        self._redacted_execution(raw_execution),
                    )
                try:
                    payload = json.loads(result.stdout)
                except json.JSONDecodeError as exc:
                    raise AdapterExecutionError(
                        "Trivy returned invalid JSON",
                        self._redacted_execution(raw_execution),
                    ) from exc
                if not isinstance(payload, Mapping):
                    raise AdapterExecutionError(
                        "Trivy returned a non-object JSON document",
                        self._redacted_execution(raw_execution),
                    )
                try:
                    sanitized_payload = self._sanitize_output(
                        payload, str(result.target or "")
                    )
                except AdapterExecutionError as exc:
                    raise AdapterExecutionError(
                        str(exc), self._redacted_execution(raw_execution)
                    ) from exc
                sanitized_results.append(replace(
                    result,
                    stdout=json.dumps(sanitized_payload,
                                      ensure_ascii=False, sort_keys=True, separators=(",", ":")),
                    stderr=(
                        "[TRIVY STDERR REDACTED] "
                        f"sha256={hashlib.sha256(result.stderr.encode('utf-8')).hexdigest()} "
                        f"bytes={len(result.stderr.encode('utf-8'))}"
                        if result.stderr else ""
                    ),
                ))
            return AdapterExecution(tuple(sanitized_results))

    def parse(self, execution: AdapterExecution) -> dict[str, Any]:
        documents: list[dict[str, Any]] = []
        for result in execution.results:
            try:
                payload = json.loads(result.stdout)
            except json.JSONDecodeError as exc:
                raise AdapterExecutionError("Sanitized Trivy output is invalid", execution) from exc
            if not isinstance(payload, dict) or not isinstance(payload.get("findings"), list):
                raise AdapterExecutionError("Sanitized Trivy output is malformed", execution)
            documents.append(payload)
        return {"documents": documents, "coverage_complete": bool(documents) and all(
            item.get("coverage_complete") is True for item in documents)}

    def normalize(self, context: AdapterContext, parsed: Any) -> dict[str, int]:
        from cairn.server.vulnerability_services import reconcile_trivy_findings

        return reconcile_trivy_findings(
            context.conn, campaign_id=context.campaign_id, task_id=context.task_id,
            source_id=str(context.source["id"]), adapter=self.tool_id,
            repositories=list(self._subjects(context)), sboms=list(context.sboms),
            documents=list(parsed.get("documents", [])),
            coverage_complete=self.coverage_complete(context, parsed),
        )

    def coverage_complete(self, context: AdapterContext, parsed: Any) -> bool:
        return bool(context.sboms) and parsed.get("coverage_complete") is True


class TrivyContainerSbomVulnerabilityAdapter(TrivySbomVulnerabilityAdapter):
    """Apply the fixed offline vulnerability DB to saved container SBOMs."""

    tool_id = "trivy.container-sbom-vuln.v1"
    version = "1.0.0"
    source_type = "trivy_container_sbom_vulnerability"
    input_schema = {
        "type": "object",
        "required": ["container_archives", "sboms"],
        "properties": {
            "container_archives": {
                "type": "array",
                "items": {"type": "object"},
                "maxItems": 2,
            },
            "sboms": {"type": "array", "items": {"type": "object"}, "maxItems": 2},
        },
        "additionalProperties": False,
    }

    def _subjects(self, context: AdapterContext) -> tuple[Mapping[str, Any], ...]:
        return context.container_archives


class _ArchivedHTMLParser(HTMLParser):
    """Extract bounded structural metadata without evaluating untrusted markup."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.title_parts: list[str] = []
        self.links: list[str] = []
        self.scripts: list[str] = []
        self.forms: list[dict[str, Any]] = []
        self._in_title = False
        self._current_form: dict[str, Any] | None = None

    def handle_starttag(
        self, tag: str, attrs: list[tuple[str, str | None]]
    ) -> None:
        values = {name.casefold(): value or "" for name, value in attrs}
        lowered = tag.casefold()
        if lowered == "title":
            self._in_title = True
        elif lowered in {"a", "link"} and values.get("href") and len(self.links) < 200:
            self.links.append(values["href"][:4096])
        elif lowered == "script" and values.get("src") and len(self.scripts) < 100:
            self.scripts.append(values["src"][:4096])
        elif lowered == "form" and len(self.forms) < 50:
            self._current_form = {
                "action": values.get("action", "")[:4096],
                "method": (values.get("method") or "get").upper()[:16],
                "fields": [],
            }
            self.forms.append(self._current_form)
        elif lowered in {"input", "select", "textarea", "button"} and self._current_form:
            fields = self._current_form["fields"]
            if len(fields) < 100:
                fields.append(
                    {
                        "name": values.get("name", "")[:256],
                        "type": (values.get("type") or lowered)[:64],
                    }
                )

    def handle_endtag(self, tag: str) -> None:
        lowered = tag.casefold()
        if lowered == "title":
            self._in_title = False
        elif lowered == "form":
            self._current_form = None

    def handle_data(self, data: str) -> None:
        if self._in_title and sum(len(item) for item in self.title_parts) < 1000:
            self.title_parts.append(data)


def _http_message_body(value: str) -> str:
    normalized = value.replace("\r\n", "\n")
    return normalized.split("\n\n", 1)[1] if "\n\n" in normalized else ""


def _http_message_headers(value: str) -> dict[str, str]:
    normalized = value.replace("\r\n", "\n")
    head = normalized.split("\n\n", 1)[0]
    headers: dict[str, str] = {}
    for line in head.splitlines()[1:101]:
        if ":" not in line:
            continue
        name, header_value = line.split(":", 1)
        lowered = name.strip().casefold()
        if lowered and lowered not in headers:
            headers[lowered] = header_value.strip()[:4096]
    return headers


def _same_origin_archived_url(base_url: str, candidate: str) -> str | None:
    try:
        resolved = urljoin(base_url, candidate.strip())
        base = urlsplit(base_url)
        parsed = urlsplit(resolved)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
        ):
            return None
        base_port = base.port or (443 if base.scheme == "https" else 80)
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        if (
            parsed.scheme != base.scheme
            or parsed.hostname.casefold().rstrip(".")
            != str(base.hostname).casefold().rstrip(".")
            or port != base_port
        ):
            return None
        return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.query, ""))
    except (TypeError, ValueError):
        return None


def _archived_url_candidates(base_url: str, body: str) -> tuple[set[str], int]:
    candidates: set[str] = set()
    rejected = 0
    for match in re.finditer(
        r"(?P<quote>['\"])(?P<path>(?:https?://|//|/)(?!/\*)[^'\"\s<>]{1,2048})(?P=quote)",
        body[:HTTP_RESPONSE_MAX_BYTES],
        re.IGNORECASE,
    ):
        resolved = _same_origin_archived_url(base_url, match.group("path"))
        if resolved is None:
            rejected += 1
        else:
            candidates.add(resolved)
    return candidates, rejected


def _analyze_archived_har(base_url: str, body: str) -> dict[str, Any] | None:
    try:
        payload = json.loads(body)
    except (TypeError, json.JSONDecodeError):
        return None
    if not isinstance(payload, Mapping):
        return None
    log = payload.get("log")
    if not isinstance(log, Mapping) or not isinstance(log.get("entries"), list):
        return None
    entries: list[dict[str, Any]] = []
    endpoints: set[str] = set()
    scripts: set[str] = set()
    rejected = 0

    def nonnegative_int(value: Any) -> int:
        try:
            return max(0, int(value or 0))
        except (TypeError, ValueError, OverflowError):
            return 0

    for item in list(log["entries"])[:200]:
        if not isinstance(item, Mapping):
            continue
        request = item.get("request")
        response = item.get("response")
        if not isinstance(request, Mapping) or not isinstance(response, Mapping):
            continue
        raw_url = str(request.get("url") or "")
        resolved = _same_origin_archived_url(base_url, raw_url)
        if resolved is None:
            rejected += 1
            continue
        method = str(request.get("method") or "GET").upper()[:16]
        content = response.get("content")
        content = content if isinstance(content, Mapping) else {}
        mime_type = str(content.get("mimeType") or "")[:256]
        request_headers = request.get("headers")
        response_headers = response.get("headers")

        def header_names(value: Any) -> list[str]:
            if not isinstance(value, list):
                return []
            return sorted(
                {
                    str(header.get("name") or "").strip().casefold()[:256]
                    for header in value[:100]
                    if isinstance(header, Mapping) and header.get("name")
                }
            )

        post_data = request.get("postData")
        post_text = (
            str(post_data.get("text") or "")
            if isinstance(post_data, Mapping)
            else ""
        )
        entry = {
            "url": resolved,
            "method": method,
            "status_code": nonnegative_int(response.get("status")),
            "mime_type": mime_type,
            "response_bytes": nonnegative_int(content.get("size")),
            "request_header_names": header_names(request_headers),
            "response_header_names": header_names(response_headers),
            "request_body_sha256": (
                hashlib.sha256(post_text.encode("utf-8")).hexdigest()
                if post_text
                else None
            ),
        }
        entries.append(entry)
        endpoints.add(resolved)
        path = urlsplit(resolved).path.casefold()
        if "javascript" in mime_type.casefold() or path.endswith((".js", ".mjs")):
            scripts.add(resolved)
    return {
        "entries": entries,
        "endpoint_candidates": endpoints,
        "scripts": scripts,
        "cross_origin_reference_count": rejected,
    }


class BrowserArchiveAnalyzeAdapter(DomainAdapter):
    """Analyze saved HTML/JS/HTTP evidence without starting a browser or network."""

    tool_id = "browser.archive-analyze.v1"
    version = "1.0.0"
    risk_class = "R0"
    source_type = "browser_archive_analysis"
    dimension = "web"
    binary = "builtin:python-html-parser"
    uses_http = False
    uses_network = False
    requires_human_approval = True
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
        "required": ["records"],
        "properties": {"records": {"type": "array", "items": {"type": "object"}}},
    }

    def health(self) -> dict[str, Any]:
        return {
            "healthy": True,
            "tool_id": self.tool_id,
            "version": self.version,
            "expected_version": self.version,
            "offline_only": True,
            "error": None,
        }

    def validate(self, context: AdapterContext) -> None:
        super().validate(context)
        if not context.http_responses:
            raise AdapterValidationError(
                "Browser archive analysis requires captured HTTP responses"
            )
        if len(context.http_responses) > 20:
            raise AdapterValidationError(
                "Browser archive analysis accepts at most 20 responses per task"
            )
        allowed = {normalize_domain(target) for target in context.targets}
        for response in context.http_responses:
            response_domain = normalize_domain(str(response.get("domain") or ""))
            if response_domain not in allowed:
                raise AdapterValidationError(
                    "Captured HTTP response does not match the archive task target"
                )
            if not all(
                response.get(key)
                for key in ("id", "asset_id", "task_id", "url", "response_hash")
            ):
                raise AdapterValidationError(
                    "Captured HTTP response provenance is incomplete"
                )
            try:
                response_url = urlsplit(str(response["url"]))
                response_host = normalize_domain(str(response_url.hostname or ""))
                response_url.port
            except (TypeError, ValueError) as exc:
                raise AdapterValidationError(
                    "Captured HTTP response URL is invalid"
                ) from exc
            if (
                response_url.scheme not in {"http", "https"}
                or response_url.username is not None
                or response_url.password is not None
                or response_host != response_domain
            ):
                raise AdapterValidationError(
                    "Captured HTTP response URL does not match its asset provenance"
                )
            response_text = str(response.get("response_text") or "")
            if len(response_text.encode("utf-8")) > HTTP_RESPONSE_MAX_BYTES:
                raise AdapterValidationError("Captured HTTP response exceeds the offline limit")
            if hashlib.sha256(response_text.encode("utf-8")).hexdigest() != str(
                response["response_hash"]
            ):
                raise AdapterValidationError("Captured HTTP response hash mismatch")

    def estimate(self, context: AdapterContext) -> dict[str, Any]:
        return {
            "command_count": 0,
            "timeout_seconds": 0,
            "risk_class": self.risk_class,
            "network_request_count": 0,
            "offline_only": True,
            "response_count": len(context.http_responses),
        }

    def materialize(self, context: AdapterContext) -> list[AdapterInvocation]:
        return []

    @staticmethod
    def _analyze(response: Mapping[str, Any]) -> dict[str, Any]:
        url = str(response["url"])
        response_text = str(response.get("response_text") or "")
        body = _http_message_body(response_text)
        headers = _http_message_headers(response_text)
        content_type = str(headers.get("content-type") or "")[:256]
        har = _analyze_archived_har(url, body)
        is_javascript = (
            "javascript" in content_type.casefold()
            or urlsplit(url).path.casefold().endswith((".js", ".mjs"))
        )
        parser = _ArchivedHTMLParser()
        same_origin_links: list[str] = []
        same_origin_scripts: list[str] = []
        forms: list[dict[str, Any]] = []
        endpoint_candidates: set[str] = set()
        cross_origin_reference_count = 0
        title: str | None = None
        har_entries: list[dict[str, Any]] = []
        if har is not None:
            analysis_kind = "har"
            endpoint_candidates.update(har["endpoint_candidates"])
            same_origin_scripts = sorted(har["scripts"])[:100]
            cross_origin_reference_count = int(har["cross_origin_reference_count"])
            har_entries = list(har["entries"])
        elif is_javascript:
            analysis_kind = "javascript"
            discovered, rejected = _archived_url_candidates(url, body)
            endpoint_candidates.update(discovered)
            cross_origin_reference_count = rejected
            for match in re.finditer(
                r"(?m)(?:^|\s)//[#@]\s*sourceMappingURL\s*=\s*(\S+)",
                body[:HTTP_RESPONSE_MAX_BYTES],
            ):
                resolved = _same_origin_archived_url(url, match.group(1))
                if resolved is None:
                    cross_origin_reference_count += 1
                else:
                    same_origin_scripts.append(resolved)
        else:
            analysis_kind = "html"
            try:
                parser.feed(body[:HTTP_RESPONSE_MAX_BYTES])
                parser.close()
            except Exception as exc:
                raise AdapterExecutionError(
                    f"Stored markup could not be parsed: {type(exc).__name__}"
                ) from exc
            same_origin_links = sorted(
                {
                    resolved
                    for value in parser.links
                    if (resolved := _same_origin_archived_url(url, value)) is not None
                }
            )[:200]
            same_origin_scripts = sorted(
                {
                    resolved
                    for value in parser.scripts
                    if (resolved := _same_origin_archived_url(url, value)) is not None
                }
            )[:100]
            cross_origin_reference_count += (
                len(parser.links) - len(same_origin_links)
                + len(parser.scripts) - len(same_origin_scripts)
            )
            endpoint_candidates.update(same_origin_links)
            endpoint_candidates.update(same_origin_scripts)
            discovered, rejected = _archived_url_candidates(url, body)
            endpoint_candidates.update(discovered)
            cross_origin_reference_count += rejected
            for form in parser.forms:
                action = _same_origin_archived_url(url, str(form.get("action") or ""))
                if action is None:
                    cross_origin_reference_count += 1
                    continue
                forms.append(
                    {
                        "action": action,
                        "method": str(form.get("method") or "GET")[:16],
                        "fields": list(form.get("fields") or [])[:100],
                    }
                )
            title = " ".join("".join(parser.title_parts).split())[:1000] or None
        return {
            "response_id": response["id"],
            "asset_id": response["asset_id"],
            "domain": normalize_domain(str(response["domain"])),
            "url": url[:4096],
            "response_hash": response["response_hash"],
            "content_truncated": bool(response.get("content_truncated")),
            "analysis_kind": analysis_kind,
            "content_type": content_type,
            "title": title,
            "links": same_origin_links,
            "scripts": sorted(set(same_origin_scripts))[:100],
            "forms": forms,
            "endpoint_candidates": sorted(endpoint_candidates)[:300],
            "har_entries": har_entries,
            "cross_origin_reference_count": cross_origin_reference_count,
            "body_bytes": len(body.encode("utf-8")),
            "body_sha256": hashlib.sha256(body.encode("utf-8")).hexdigest(),
            "offline_only": True,
        }

    def execute(self, context: AdapterContext) -> AdapterExecution:
        self.validate(context)
        return AdapterExecution(
            tuple(
                CommandResult(
                    target=str(response["id"]),
                    stdout=json.dumps(
                        self._analyze(response), ensure_ascii=False, sort_keys=True
                    )
                    + "\n",
                    stderr="",
                    returncode=0,
                    duration_ms=0,
                )
                for response in context.http_responses
            )
        )

    def parse(self, execution: AdapterExecution) -> dict[str, Any]:
        return {"records": _parse_json_lines(execution, tool_id=self.tool_id)}

    def normalize(self, context: AdapterContext, parsed: Any) -> dict[str, int]:
        from cairn.server.vulnerability_services import record_collection_task_asset

        created = 0
        endpoints = 0
        forms = 0
        javascript_responses = 0
        har_entries = 0
        for record in parsed.get("records", []):
            record_collection_task_asset(
                context.conn,
                context.task_id,
                str(context.source["id"]),
                str(record["asset_id"]),
            )
            endpoints += len(record.get("endpoint_candidates", []))
            forms += len(record.get("forms", []))
            javascript_responses += int(record.get("analysis_kind") == "javascript")
            har_entries += len(record.get("har_entries", []))
            created += int(
                _record_domain_metadata(
                    context,
                    "browser_archive_analysis",
                    str(record["domain"]),
                    record,
                    dimension="web",
                    confidence=0.9,
                )
            )
        return {
            "responses_inspected": len(parsed.get("records", [])),
            "endpoints_detected": endpoints,
            "forms_detected": forms,
            "javascript_responses_analyzed": javascript_responses,
            "har_entries_analyzed": har_entries,
            "observations_created": created,
        }

    def coverage_complete(self, context: AdapterContext, parsed: Any) -> bool:
        # A complete saved file is not proof that the application surface was
        # completely captured.  This adapter therefore never authorizes a
        # negative/removal conclusion by itself.
        return False


class SavedResponseWebApiAdapter(DomainAdapter):
    """Identify API surfaces in already captured HTTP responses without networking."""

    tool_id = "webapi.saved-response.v1"
    version = "1.0.0"
    risk_class = "R1"
    source_type = "web_api_offline"
    dimension = "web"
    binary = "builtin:python"
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
        "required": ["records"],
        "properties": {"records": {"type": "array", "items": {"type": "object"}}},
    }

    def health(self) -> dict[str, Any]:
        return {
            "healthy": True,
            "tool_id": self.tool_id,
            "version": self.version,
            "expected_version": self.version,
            "error": None,
            "offline_only": True,
        }

    def validate(self, context: AdapterContext) -> None:
        super().validate(context)
        if not context.http_responses:
            raise AdapterValidationError(
                "Saved-response API discovery requires captured HTTP responses"
            )
        if len(context.http_responses) > 20:
            raise AdapterValidationError(
                "Saved-response API discovery accepts at most 20 responses per task"
            )
        allowed_targets = {normalize_domain(target) for target in context.targets}
        for response in context.http_responses:
            if normalize_domain(str(response.get("domain") or "")) not in allowed_targets:
                raise AdapterValidationError(
                    "Captured HTTP response does not match the task target"
                )
            if not all(response.get(key) for key in ("id", "asset_id", "url", "response_hash")):
                raise AdapterValidationError(
                    "Captured HTTP response provenance is incomplete"
                )

    def estimate(self, context: AdapterContext) -> dict[str, Any]:
        return {
            "command_count": 0,
            "timeout_seconds": 0,
            "risk_class": self.risk_class,
            "network_request_count": 0,
            "offline_only": True,
            "response_count": len(context.http_responses),
        }

    def materialize(self, context: AdapterContext) -> list[AdapterInvocation]:
        return []

    @staticmethod
    def _classify(response: Mapping[str, Any]) -> list[str]:
        url = str(response.get("url") or "")
        response_text = str(response.get("response_text") or "")
        lowered_url = url.casefold()
        lowered = response_text[:HTTP_RESPONSE_MAX_BYTES].casefold()
        detections: set[str] = set()
        if (
            re.search(r"/(?:openapi|swagger)(?:[./_-]|$)", lowered_url)
            or '"openapi"' in lowered
            or '"swagger"' in lowered
            or "swagger-ui" in lowered
        ):
            detections.add("openapi")
        if (
            re.search(r"/(?:graphql|graphiql)(?:[/?#]|$)", lowered_url)
            or '"__schema"' in lowered
            or "graphiql" in lowered
            or "graphql-playground" in lowered
        ):
            detections.add("graphql")
        return sorted(detections)

    def execute(self, context: AdapterContext) -> AdapterExecution:
        self.validate(context)
        results: list[CommandResult] = []
        for response in context.http_responses:
            payload = {
                "response_id": response["id"],
                "asset_id": response["asset_id"],
                "domain": response["domain"],
                "url": response["url"],
                "response_hash": response["response_hash"],
                "content_truncated": bool(response.get("content_truncated")),
                "detections": self._classify(response),
            }
            results.append(
                CommandResult(
                    target=str(response["id"]),
                    stdout=json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n",
                    stderr="",
                    returncode=0,
                    duration_ms=0,
                )
            )
        return AdapterExecution(tuple(results))

    def parse(self, execution: AdapterExecution) -> dict[str, Any]:
        return {"records": _parse_json_lines(execution, tool_id=self.tool_id)}

    def normalize(self, context: AdapterContext, parsed: Any) -> dict[str, int]:
        from cairn.server.vulnerability_services import record_collection_task_asset

        created = 0
        detections = 0
        for record in parsed.get("records", []):
            record_collection_task_asset(
                context.conn,
                context.task_id,
                str(context.source["id"]),
                str(record["asset_id"]),
            )
            if not record.get("detections"):
                continue
            detections += len(record["detections"])
            created += int(
                _record_domain_metadata(
                    context,
                    "web_api_discovery",
                    str(record["domain"]),
                    {
                        "response_id": record["response_id"],
                        "url": record["url"],
                        "response_hash": record["response_hash"],
                        "detections": record["detections"],
                        "offline_only": True,
                    },
                    dimension="web",
                    confidence=0.9,
                )
            )
        return {
            "responses_inspected": len(parsed.get("records", [])),
            "api_surfaces_detected": detections,
            "observations_created": created,
        }

    def coverage_complete(self, context: AdapterContext, parsed: Any) -> bool:
        return bool(context.http_responses) and all(
            not bool(response.get("content_truncated"))
            for response in context.http_responses
        )


class NucleiPassiveResponseAdapter(DomainAdapter):
    """Run a fixed signed-template allowlist against captured HTTP responses only."""

    tool_id = "nuclei.passive-response.v1"
    version = "1.0.0"
    risk_class = "R2"
    source_type = "nuclei_passive"
    dimension = "intelligence"
    binary = _configured_user_binary("nuclei", "CAIRN_NUCLEI_BINARY")
    expected_tool_version = NUCLEI_ENGINE_VERSION
    release_sha256 = NUCLEI_RELEASE_SHA256
    requires_human_approval = True
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
            missing = [
                key
                for key in (
                    "id",
                    "asset_id",
                    "task_id",
                    "request_text",
                    "response_text",
                    "response_hash",
                )
                if not response.get(key)
            ]
            if missing:
                raise AdapterValidationError(
                    "Captured HTTP response provenance is incomplete: "
                    + ", ".join(missing)
                )
            request_text = str(response["request_text"])
            response_text = str(response["response_text"])
            if len(request_text.encode("utf-8")) > HTTP_REQUEST_MAX_BYTES:
                raise AdapterValidationError("Captured HTTP request exceeds the offline limit")
            if len(response_text.encode("utf-8")) > HTTP_RESPONSE_MAX_BYTES:
                raise AdapterValidationError("Captured HTTP response exceeds the offline limit")
            if not re.match(r"^[A-Z]+\s+\S+\s+HTTP/\d(?:\.\d)?(?:\r?\n|$)", request_text):
                raise AdapterValidationError("Captured HTTP request is not wire-shaped")
            if not re.match(r"^HTTP/\d(?:\.\d)?\s+\d{3}(?:\s|\r?\n|$)", response_text):
                raise AdapterValidationError("Captured HTTP response is not wire-shaped")
            actual_hash = hashlib.sha256(response_text.encode("utf-8")).hexdigest()
            if actual_hash != str(response["response_hash"]):
                raise AdapterValidationError("Captured HTTP response hash mismatch")
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
        executable = shutil.which(self.binary)
        assert executable is not None
        try:
            binary_sha256 = _sha256_file(Path(executable))
        except OSError as exc:
            return {
                "healthy": False,
                "tool_id": self.tool_id,
                "version": result.get("version"),
                "error": f"Unable to hash the Nuclei executable: {type(exc).__name__}",
            }
        if binary_sha256 != NUCLEI_BINARY_SHA256:
            return {
                "healthy": False,
                "tool_id": self.tool_id,
                "version": result.get("version"),
                "error": "Nuclei executable hash does not match the audited release",
            }
        network_sandbox = shutil.which("unshare")
        if network_sandbox is None:
            return {
                "healthy": False,
                "tool_id": self.tool_id,
                "version": result.get("version"),
                "error": "Required offline network namespace tool is unavailable: unshare",
            }
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
            "release_sha256": self.release_sha256,
            "binary_sha256": binary_sha256,
            "network_isolation": "linux-user-network-namespace",
            "templates_commit": NUCLEI_TEMPLATES_COMMIT,
            "template_ids": [item[0] for item in NUCLEI_TEMPLATE_ALLOWLIST],
            "template_categories": dict(NUCLEI_TEMPLATE_CATEGORIES),
            "template_count": len(paths),
        }

    def materialize(self, context: AdapterContext) -> list[AdapterInvocation]:
        template_paths = _audited_nuclei_template_paths()
        network_sandbox = shutil.which("unshare")
        if network_sandbox is None:
            raise AdapterUnavailableError(
                "Nuclei passive analysis requires a Linux user network namespace"
            )
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
                        network_sandbox,
                        "--user",
                        "--map-current-user",
                        "--net",
                        "--",
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
                        "-disable-redirects",
                        "-restrict-local-network-access",
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
        with managed_task_workspace(
            context.conn,
            campaign_id=context.campaign_id,
            task_id=context.task_id,
            purpose="nuclei-passive-response",
        ) as workspace:
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
                path = workspace.write_text(
                    f"response-{index:03d}.txt",
                    capture,
                    artifact_kind="nuclei_passive_input",
                    source_reference=f"http-response:{response['id']}",
                    source_promoted=True,
                )
                materialized.append({**response, "file_path": str(path)})
            execution_context = replace(
                context, http_responses=tuple(materialized)
            )
            return self._execute_invocations(
                execution_context, self.materialize(execution_context)
            )

    def parse(self, execution: AdapterExecution) -> dict[str, Any]:
        findings: list[dict[str, Any]] = []
        allowed_template_ids = {item[0] for item in NUCLEI_TEMPLATE_ALLOWLIST}
        for payload in _parse_json_lines(execution, tool_id=self.tool_id):
            template_id = str(payload.get("template-id") or "")[:256]
            if template_id not in allowed_template_ids:
                raise AdapterExecutionError(
                    f"{self.tool_id} returned a non-allowlisted template ID",
                    execution,
                )
            info = payload.get("info")
            info = info if isinstance(info, dict) else {}
            classification = info.get("classification")
            classification = classification if isinstance(classification, dict) else {}
            findings.append(
                {
                    "response_id": payload.get("_invocation_target"),
                    "template_id": template_id,
                    "matcher_name": str(payload.get("matcher-name") or "")[:256] or None,
                    "title": str(info.get("name") or payload.get("template-id") or "Nuclei passive match")[:1000],
                    "description": str(info.get("description") or "Offline passive response match")[:8000],
                    "severity": str(info.get("severity") or "unknown").lower(),
                    "cwe": str(classification.get("cwe-id") or "")[:128] or None,
                    "remediation": str(info.get("remediation") or "")[:8000] or None,
                    "matched_at": str(payload.get("matched-at") or payload.get("host") or "")[:4096],
                    "extracted_results": _bounded_string_list(
                        payload.get("extracted-results"), limit=20
                    ),
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


class NvdKevVulnerabilityIntelligenceAdapter(VulnSourceAdapter):
    """Enrich existing CVE findings from the official NVD and CISA KEV feeds."""

    tool_id = "nvd-kev.vuln-intel.v1"
    version = "1.0.0"
    risk_class = "R1"
    source_type = "nvd_kev_intelligence"
    dimension = "intelligence"
    binary = "curl"
    version_args = ("--version",)
    timeout_seconds = 30
    uses_http = True
    input_schema = {
        "type": "object",
        "required": ["vulnerabilities"],
        "properties": {
            "vulnerabilities": {"type": "array", "items": {"type": "object"}}
        },
        "additionalProperties": False,
    }
    output_schema = {
        "type": "object",
        "required": ["enrichments"],
        "properties": {
            "enrichments": {"type": "array", "items": {"type": "object"}}
        },
    }

    def validate(self, context: AdapterContext) -> None:
        super().validate(context)
        if not context.vulnerabilities:
            raise AdapterValidationError(
                "NVD/KEV enrichment requires an existing Campaign CVE finding"
            )
        if len(context.vulnerabilities) > 20:
            raise AdapterValidationError("NVD/KEV accepts at most 20 CVEs per task")
        for item in context.vulnerabilities:
            cve_id = str(item.get("cve_id") or "")
            if not CVE_ID_PATTERN.fullmatch(cve_id):
                raise AdapterValidationError("NVD/KEV input contains an invalid CVE ID")
            if not item.get("finding_ids"):
                raise AdapterValidationError("NVD/KEV input is not linked to a Finding")

    def materialize(self, context: AdapterContext) -> list[AdapterInvocation]:
        header_args = self._curl_header_args(context)
        common = (
            self.binary,
            "--silent",
            "--show-error",
            "--fail-with-body",
            "--location",
            "--proto",
            "=https",
            "--tlsv1.2",
            "--connect-timeout",
            "5",
            "--max-time",
            str(self.timeout_seconds),
            "--user-agent",
            USER_AGENT,
            *header_args,
        )
        invocations: list[AdapterInvocation] = []
        for item in context.vulnerabilities:
            cve_id = str(item["cve_id"]).upper()
            invocations.extend(
                (
                    AdapterInvocation(
                        argv=(
                            *common,
                            f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={quote(cve_id, safe='-')}",
                        ),
                        target=f"nvd:{cve_id}",
                    ),
                    AdapterInvocation(
                        argv=(
                            *common,
                            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
                        ),
                        target=f"kev:{cve_id}",
                    ),
                )
            )
        return invocations

    def execute(self, context: AdapterContext) -> AdapterExecution:
        # The public NVD endpoint has a lower anonymous allowance than a typical
        # Campaign. This is a stricter adapter cap, never a relaxation.
        limited_context = replace(
            context,
            max_requests_per_second=min(2, context.max_requests_per_second),
        )
        return self._execute_materialized(limited_context)

    def parse(self, execution: AdapterExecution) -> dict[str, Any]:
        grouped: dict[str, dict[str, Any]] = {}
        for result in execution.results:
            kind, separator, cve_id = str(result.target or "").partition(":")
            if not separator or kind not in {"nvd", "kev"}:
                raise AdapterExecutionError("NVD/KEV invocation provenance is invalid", execution)
            try:
                payload = json.loads(result.stdout)
            except json.JSONDecodeError as exc:
                raise AdapterExecutionError("NVD/KEV returned invalid JSON", execution) from exc
            if not isinstance(payload, dict):
                raise AdapterExecutionError("NVD/KEV response must be an object", execution)
            item = grouped.setdefault(cve_id, {"cve_id": cve_id})
            if kind == "nvd":
                vulnerabilities = payload.get("vulnerabilities")
                if not isinstance(vulnerabilities, list):
                    raise AdapterExecutionError("NVD response has an invalid structure", execution)
                matching = [
                    candidate.get("cve")
                    for candidate in vulnerabilities
                    if isinstance(candidate, dict)
                    and isinstance(candidate.get("cve"), dict)
                    and str(candidate["cve"].get("id") or "").upper() == cve_id
                ]
                item["nvd"] = matching[0] if matching else None
                item["nvd_complete"] = True
            else:
                vulnerabilities = payload.get("vulnerabilities")
                if not isinstance(vulnerabilities, list):
                    raise AdapterExecutionError("CISA KEV response has an invalid structure", execution)
                item["kev"] = next(
                    (
                        candidate
                        for candidate in vulnerabilities
                        if isinstance(candidate, dict)
                        and str(candidate.get("cveID") or "").upper() == cve_id
                    ),
                    None,
                )
                item["kev_complete"] = True
        return {"enrichments": [grouped[key] for key in sorted(grouped)]}

    def normalize(self, context: AdapterContext, parsed: Any) -> dict[str, int]:
        from cairn.server.vulnerability_services import apply_nvd_kev_intelligence

        return apply_nvd_kev_intelligence(
            context.conn,
            campaign_id=context.campaign_id,
            task_id=context.task_id,
            source_id=str(context.source["id"]),
            adapter=self.tool_id,
            vulnerabilities=list(context.vulnerabilities),
            enrichments=list(parsed.get("enrichments", [])),
        )

    def coverage_complete(self, context: AdapterContext, parsed: Any) -> bool:
        enrichments = parsed.get("enrichments", [])
        return len(enrichments) == len(context.vulnerabilities) and all(
            item.get("nvd_complete") is True and item.get("kev_complete") is True
            for item in enrichments
        )


_ADAPTERS: tuple[VulnSourceAdapter, ...] = (
    BrowserArchiveAnalyzeAdapter(),
    CertificateTransparencyAdapter(),
    FofaAssetSearchAdapter(),
    OsvVulnerabilityIntelligenceAdapter(),
    NvdKevVulnerabilityIntelligenceAdapter(),
    SubfinderPassiveDnsAdapter(),
    AmassPassiveEnumAdapter(),
    RdapDomainAdapter(),
    WhoisDomainAdapter(),
    DnsxResolveAdapter(),
    HttpxHttpMetadataAdapter(),
    TlsxTlsMetadataAdapter(),
    GitleaksLocalRepositoryAdapter(),
    SyftLocalSbomAdapter(),
    SyftContainerArchiveSbomAdapter(),
    TrivySbomVulnerabilityAdapter(),
    TrivyContainerSbomVulnerabilityAdapter(),
    SavedResponseWebApiAdapter(),
    NucleiPassiveResponseAdapter(),
    NaabuPortScanAdapter(),
    KatanaCrawlerAdapter(),
    BrowserEvidenceSessionAdapter(),
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
