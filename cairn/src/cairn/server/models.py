from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field, field_validator


class Settings(BaseModel):
    intent_timeout: int = Field(ge=5)
    reason_timeout: int = Field(ge=5)


class Fact(BaseModel):
    id: str
    description: str


class Intent(BaseModel):
    id: str
    from_: list[str] = Field(alias="from")
    to: str | None = None
    description: str
    creator: str
    worker: str | None = None
    last_heartbeat_at: str | None = None
    created_at: str
    concluded_at: str | None = None

    model_config = {"populate_by_name": True}


class Hint(BaseModel):
    id: str
    content: str
    creator: str
    created_at: str


class ProjectReason(BaseModel):
    worker: str
    trigger: str
    started_at: str
    last_heartbeat_at: str


class ProjectMeta(BaseModel):
    id: str
    title: str
    status: Literal["active", "stopped", "completed"]
    bootstrap_enabled: bool
    project_kind: Literal["general", "vulnerability"] = "general"
    created_at: str
    reason: ProjectReason | None = None


class ProjectSummary(ProjectMeta):
    fact_count: int
    intent_count: int
    working_intent_count: int
    unclaimed_intent_count: int
    hint_count: int


class ProjectDetail(BaseModel):
    project: ProjectMeta
    facts: list[Fact]
    intents: list[Intent]
    hints: list[Hint]


class CreateHintInline(BaseModel):
    content: str
    creator: str

    @field_validator("content", "creator")
    @classmethod
    def validate_non_empty_text(cls, value: str) -> str:
        text = value.strip()
        if not text:
            raise ValueError("must not be empty")
        return text


class CreateProjectRequest(BaseModel):
    title: str
    origin: str
    goal: str
    bootstrap_enabled: bool = True
    hints: list[CreateHintInline] | None = None

    @field_validator("title", "origin", "goal")
    @classmethod
    def validate_non_empty_text(cls, value: str) -> str:
        text = value.strip()
        if not text:
            raise ValueError("must not be empty")
        return text


class CreateHintRequest(BaseModel):
    content: str
    creator: str

    @field_validator("content", "creator")
    @classmethod
    def validate_non_empty_text(cls, value: str) -> str:
        text = value.strip()
        if not text:
            raise ValueError("must not be empty")
        return text


class CreateIntentRequest(BaseModel):
    from_: list[str] = Field(alias="from", min_length=1)
    description: str
    creator: str
    worker: str | None = None

    model_config = {"populate_by_name": True}

    @field_validator("description", "creator", "worker")
    @classmethod
    def validate_non_empty_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        text = value.strip()
        if not text:
            raise ValueError("must not be empty")
        return text

    @field_validator("from_")
    @classmethod
    def validate_fact_ids(cls, value: list[str]) -> list[str]:
        cleaned = []
        for item in value:
            text = item.strip()
            if not text:
                raise ValueError("fact ids must not be empty")
            cleaned.append(text)
        return cleaned


class HeartbeatRequest(BaseModel):
    worker: str

    @field_validator("worker")
    @classmethod
    def validate_non_empty_text(cls, value: str) -> str:
        text = value.strip()
        if not text:
            raise ValueError("must not be empty")
        return text


class ReasonClaimRequest(BaseModel):
    worker: str
    trigger: str

    @field_validator("worker", "trigger")
    @classmethod
    def validate_non_empty_text(cls, value: str) -> str:
        text = value.strip()
        if not text:
            raise ValueError("must not be empty")
        return text


class ConcludeRequest(BaseModel):
    worker: str
    description: str

    @field_validator("worker", "description")
    @classmethod
    def validate_non_empty_text(cls, value: str) -> str:
        text = value.strip()
        if not text:
            raise ValueError("must not be empty")
        return text


class CompleteRequest(BaseModel):
    from_: list[str] = Field(alias="from", min_length=1)
    description: str
    worker: str

    model_config = {"populate_by_name": True}

    @field_validator("description", "worker")
    @classmethod
    def validate_non_empty_text(cls, value: str) -> str:
        text = value.strip()
        if not text:
            raise ValueError("must not be empty")
        return text

    @field_validator("from_")
    @classmethod
    def validate_fact_ids(cls, value: list[str]) -> list[str]:
        cleaned = []
        for item in value:
            text = item.strip()
            if not text:
                raise ValueError("fact ids must not be empty")
            cleaned.append(text)
        return cleaned


class ConcludeResponse(BaseModel):
    fact: Fact
    intent: Intent


class UpdateProjectStatusRequest(BaseModel):
    status: Literal["active", "stopped"]


class UpdateProjectTitleRequest(BaseModel):
    title: str

    @field_validator("title")
    @classmethod
    def validate_non_empty_text(cls, value: str) -> str:
        text = value.strip()
        if not text:
            raise ValueError("must not be empty")
        return text


class ReopenRequest(BaseModel):
    description: str
    creator: str

    @field_validator("description", "creator")
    @classmethod
    def validate_non_empty_text(cls, value: str) -> str:
        text = value.strip()
        if not text:
            raise ValueError("must not be empty")
        return text


class ReopenResponse(BaseModel):
    project: ProjectMeta
    fact: Fact
    intent: Intent


class CtfMode(str, Enum):
    MANUAL = "manual"
    CTF = "ctf"


class CtfConfig(BaseModel):
    mode: CtfMode = CtfMode.MANUAL
    adapter: str = "ctfd"
    base_url: str = ""
    token: str = ""
    team_name: str = ""
    flag_regex: str = "flag\\{[^}]+\\}"
    auto_submit: bool = True
    max_concurrent: int = Field(default=2, ge=1, le=32)
    poll_interval: int = Field(default=10, ge=3, le=3600)
    env_poll_interval: int = Field(default=5, ge=1, le=300)
    env_timeout: int = Field(default=180, ge=10, le=3600)
    submission_max_retries: int = Field(default=5, ge=1, le=50)
    rate_limit_backoff: int = Field(default=30, ge=1, le=3600)
    model_base_url: str = ""
    model_name: str = ""
    model_api_key: str = ""
    last_model_error: str | None = None
    model_health_at: str | None = None
    # Per-challenge agent-task budget (concluded intents), tiered by difficulty.
    budget_easy: int = Field(default=12, ge=1, le=10000)
    budget_medium: int = Field(default=25, ge=1, le=10000)
    budget_hard: int = Field(default=40, ge=1, le=10000)
    last_sync_at: str | None = None
    bridge_heartbeat_at: str | None = None
    bridge_error: str | None = None
    sync_requested: bool = False


class CtfConfigUpdate(BaseModel):
    adapter: str | None = None
    base_url: str | None = None
    token: str | None = None
    team_name: str | None = None
    flag_regex: str | None = None
    auto_submit: bool | None = None
    max_concurrent: int | None = Field(default=None, ge=1, le=32)
    poll_interval: int | None = Field(default=None, ge=3, le=3600)
    env_poll_interval: int | None = Field(default=None, ge=1, le=300)
    env_timeout: int | None = Field(default=None, ge=10, le=3600)
    submission_max_retries: int | None = Field(default=None, ge=1, le=50)
    rate_limit_backoff: int | None = Field(default=None, ge=1, le=3600)
    model_base_url: str | None = None
    model_name: str | None = None
    model_api_key: str | None = None
    budget_easy: int | None = Field(default=None, ge=1, le=10000)
    budget_medium: int | None = Field(default=None, ge=1, le=10000)
    budget_hard: int | None = Field(default=None, ge=1, le=10000)

    @field_validator("adapter", "base_url", "team_name", "flag_regex", "model_base_url", "model_name")
    @classmethod
    def validate_text_fields(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return value.strip()


class CtfModeRequest(BaseModel):
    mode: CtfMode


class CtfChallenge(BaseModel):
    id: int
    external_id: str
    title: str
    category: str = ""
    points: int = 0
    description: str = ""
    target: str = ""
    attachments: list[str] = []
    hints: list[str] = []
    status: str = "queued"
    project_id: str | None = None
    last_flag: str | None = None
    attempt_count: int = 0
    needs_refresh: bool = False
    created_at: str
    updated_at: str


class CtfSubmitRequest(BaseModel):
    challenge_id: str
    flag: str

    @field_validator("challenge_id", "flag")
    @classmethod
    def validate_non_empty_text(cls, value: str) -> str:
        text = value.strip()
        if not text:
            raise ValueError("must not be empty")
        return text


class CtfHeartbeatRequest(BaseModel):
    error: str | None = None
    model_ok: bool | None = None
    model_error: str | None = None


class CtfTestResult(BaseModel):
    ok: bool
    detail: str
