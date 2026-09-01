from __future__ import annotations

import json

import pytest

from cairn.dispatcher.contracts import (
    parse_json_output,
    validate_explore_payload,
    validate_reason_payload,
)
from cairn.dispatcher.runtime.process import ManagedProcess
from cairn.dispatcher.workers.adapters.pi import PiDriver
from cairn.dispatcher.workers.adapters.claudecode import ClaudeCodeDriver
from cairn.dispatcher.workers.adapters.codex import CodexDriver

from conftest import make_config


def test_parse_json_output_extracts_object_from_markdown_noise() -> None:
    assert parse_json_output('result:\n```json\n{"accepted": true, "data": {}}\n```') == {
        "accepted": True,
        "data": {},
    }


def test_reason_payload_limits_number_of_intents() -> None:
    kind, intents = validate_reason_payload(
        {
            "accepted": True,
            "data": {
                "intents": [
                    {"from": ["f001"], "description": "one"},
                    {"from": ["f001"], "description": "two"},
                ]
            },
        },
        open_intents_empty=True,
        max_intents=1,
    )

    assert kind == "intents"
    assert intents == [{"from": ["f001"], "description": "one"}]


def test_reason_payload_requires_intent_when_none_are_open() -> None:
    with pytest.raises(ValueError, match="intents is required"):
        validate_reason_payload(
            {"accepted": True, "data": {}},
            open_intents_empty=True,
            max_intents=3,
        )


def test_explore_payload_rejects_planning_text() -> None:
    with pytest.raises(ValueError):
        validate_explore_payload(parse_json_output("Need inspect files and keep working."))


def test_pi_driver_extracts_session_and_last_assistant_text() -> None:
    driver = PiDriver()
    stdout = "\n".join(
        [
            json.dumps({"type": "session", "id": "session-123"}),
            json.dumps(
                {
                    "type": "turn_end",
                    "message": {
                        "role": "assistant",
                        "content": [{"type": "text", "text": '{"accepted":true,"data":{}}'}],
                    },
                }
            ),
        ]
    )

    assert driver.extract_session(None, stdout, "") == "session-123"
    assert driver.extract_response_text(stdout, "") == '{"accepted":true,"data":{}}'


def test_close_stream_closes_response_even_when_stream_close_fails() -> None:
    class Response:
        def __init__(self) -> None:
            self.closed = False

        def close(self) -> None:
            self.closed = True

    class Stream:
        def __init__(self) -> None:
            self._response = Response()

        def close(self) -> None:
            raise ValueError("already closed")

    stream = Stream()
    ManagedProcess._close_stream(stream)

    assert stream._response.closed


def test_analysis_driver_commands_disable_dangerous_tool_access() -> None:
    base_worker = make_config().workers[0]
    claude_worker = base_worker.model_copy(update={"type": "claudecode"})
    claude = ClaudeCodeDriver().build_analysis(claude_worker, "analyze").argv
    assert "--dangerously-skip-permissions" not in claude
    assert claude[claude.index("--tools") + 1] == ""
    assert claude[claude.index("--output-format") + 1] == "json"

    codex_worker = base_worker.model_copy(
        update={
            "type": "codex",
            "env": {
                "CODEX_MODEL": "mock",
                "CODEX_BASE_URL": "http://example.invalid",
                "OPENAI_API_KEY": "test",
            },
        }
    )
    codex = CodexDriver().build_analysis(codex_worker, "analyze").argv
    assert "--dangerously-bypass-approvals-and-sandbox" not in codex
    assert codex[codex.index("--sandbox") + 1] == "read-only"

    pi_worker = base_worker.model_copy(
        update={
            "type": "pi",
            "env": {
                "PI_MODEL": "mock",
                "PI_BASE_URL": "http://example.invalid",
                "PI_API_KEY": "test",
                "PI_PROVIDER_API": "openai-completions",
            },
        }
    )
    pi = PiDriver().build_analysis(pi_worker, "analyze").argv
    assert pi[pi.index("--tools") + 1] == ""


def test_claude_analysis_response_extracts_bounded_usage_metadata() -> None:
    response = ClaudeCodeDriver().extract_analysis_response(
        json.dumps(
            {
                "type": "result",
                "subtype": "success",
                "is_error": False,
                "result": '{"accepted":true,"data":{"summary":"ok"}}',
                "duration_ms": 1234,
                "duration_api_ms": 900,
                "num_turns": 1,
                "total_cost_usd": 0.0123,
                "usage": {
                    "input_tokens": 111,
                    "output_tokens": 22,
                    "cache_creation_input_tokens": 33,
                    "cache_read_input_tokens": 44,
                    "ignored_future_field": "not persisted",
                },
                "modelUsage": {"claude-sonnet-test": {"inputTokens": 111}},
                "session_id": "must-not-be-persisted",
            }
        ),
        "",
    )

    assert response.text.startswith('{"accepted":true')
    assert response.model == "claude-sonnet-test"
    assert response.metadata == {
        "provider": "claude-code",
        "provider_duration_ms": 1234,
        "provider_api_duration_ms": 900,
        "num_turns": 1,
        "input_tokens": 111,
        "output_tokens": 22,
        "cache_creation_input_tokens": 33,
        "cache_read_input_tokens": 44,
        "total_cost_usd": 0.0123,
    }
