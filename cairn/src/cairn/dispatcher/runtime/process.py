from __future__ import annotations

from contextlib import suppress
from dataclasses import dataclass
import logging
import threading
import time
from typing import Any, Protocol, runtime_checkable

from docker.errors import APIError, DockerException
from docker.models.containers import Container

LOG = logging.getLogger(__name__)
EXEC_KILL_JOIN_TIMEOUT_SECONDS = 5.0
DEFAULT_WORKER_STDOUT_LIMIT_BYTES = 2_000_000
DEFAULT_WORKER_STDERR_LIMIT_BYTES = 512_000


class BoundedTextBuffer:
    """Retain a UTF-8 prefix while detecting output beyond a hard byte limit."""

    def __init__(self, maximum_bytes: int) -> None:
        if maximum_bytes < 1:
            raise ValueError("output limit must be positive")
        self.maximum_bytes = maximum_bytes
        self.byte_count = 0
        self.retained_bytes = 0
        self.truncated = False
        self._chunks: list[str] = []

    def append(self, value: str) -> bool:
        encoded = value.encode("utf-8", errors="replace")
        self.byte_count += len(encoded)
        remaining = self.maximum_bytes - self.retained_bytes
        if remaining > 0:
            retained = encoded[:remaining].decode("utf-8", errors="ignore")
            self._chunks.append(retained)
            self.retained_bytes += len(retained.encode("utf-8"))
        if len(encoded) > max(0, remaining):
            self.truncated = True
        return not self.truncated

    def text(self) -> str:
        return "".join(self._chunks)


@dataclass(slots=True)
class ProcessResult:
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False
    cancelled: bool = False
    cancel_reason: str | None = None
    output_limit_exceeded: bool = False
    stdout_bytes: int = 0
    stderr_bytes: int = 0


@runtime_checkable
class ExecProcess(Protocol):
    """A worker process, regardless of whether it runs inside a container or on the host.

    Container mode uses ManagedProcess; local mode uses LocalProcess. Both expose this
    surface so the task runners, heartbeat lease and cancellation stay backend-agnostic.
    """

    def start(self) -> None: ...

    def communicate(self, timeout: float | None) -> ProcessResult: ...

    def kill(self) -> None: ...

    def cancel(self, reason: str) -> None: ...


class ManagedProcess:
    def __init__(
        self,
        container: Container,
        command: list[str],
        env: dict[str, str],
        *,
        max_stdout_bytes: int = DEFAULT_WORKER_STDOUT_LIMIT_BYTES,
        max_stderr_bytes: int = DEFAULT_WORKER_STDERR_LIMIT_BYTES,
    ):
        self.command = command
        self.env = env
        self._container = container
        self._api = container.client.api
        self._exec_id: str | None = None
        self._reader: threading.Thread | None = None
        self._stdout = BoundedTextBuffer(max_stdout_bytes)
        self._stderr = BoundedTextBuffer(max_stderr_bytes)
        self._returncode: int | None = None
        self._timed_out = False
        self._cancel_reason: str | None = None
        self._read_error: str | None = None
        self._done = threading.Event()
        self._output_limit_exceeded = threading.Event()

    def start(self) -> None:
        exec_info = self._api.exec_create(
            self._container.id,
            self.command,
            stdout=True,
            stderr=True,
            stdin=False,
            tty=False,
            environment=self.env,
        )
        self._exec_id = exec_info["Id"]
        self._reader = threading.Thread(target=self._read_stream, daemon=True)
        self._reader.start()

    def communicate(self, timeout: float | None) -> ProcessResult:
        assert self._reader is not None
        self._reader.join(timeout=timeout)
        if self._reader.is_alive():
            self._timed_out = True
            self.kill()
            self._reader.join(timeout=EXEC_KILL_JOIN_TIMEOUT_SECONDS)
        if self._reader.is_alive():
            if self._returncode is None:
                self._returncode = 137
            self._done.set()
        self._done.wait(timeout=0)
        stderr = self._stderr.text()
        if self._read_error and not stderr:
            stderr = self._read_error
        if self._output_limit_exceeded.is_set():
            stderr = (
                stderr
                + "\nCairn stopped the worker because its stdout/stderr byte limit was exceeded."
            ).lstrip()
        returncode = self._returncode if self._returncode is not None else 1
        if self._output_limit_exceeded.is_set() and returncode == 0:
            returncode = 1
        return ProcessResult(
            returncode=returncode,
            stdout=self._stdout.text(),
            stderr=stderr,
            timed_out=self._timed_out,
            cancelled=self._cancel_reason is not None,
            cancel_reason=self._cancel_reason,
            output_limit_exceeded=self._output_limit_exceeded.is_set(),
            stdout_bytes=self._stdout.byte_count,
            stderr_bytes=self._stderr.byte_count,
        )

    def kill(self) -> None:
        if self._exec_id is None:
            return
        try:
            details = self._api.exec_inspect(self._exec_id)
        except DockerException as exc:
            LOG.warning("failed to inspect exec before kill exec_id=%s error=%s", self._exec_id, exc)
            return
        if not details.get("Running"):
            return
        pid = details.get("Pid")
        if not pid:
            LOG.warning("container exec missing pid for kill exec_id=%s", self._exec_id)
            return
        self._kill_pid(int(pid))

    def cancel(self, reason: str) -> None:
        if self._cancel_reason is None:
            self._cancel_reason = reason
        self.kill()

    def _read_stream(self) -> None:
        assert self._exec_id is not None
        stream: Any | None = None
        try:
            stream = self._api.exec_start(
                self._exec_id,
                detach=False,
                tty=False,
                stream=True,
                demux=True,
            )
            for chunk in stream:
                stdout, stderr = self._split_chunk(chunk)
                within_limit = True
                if stdout:
                    within_limit = self._stdout.append(stdout) and within_limit
                if stderr:
                    within_limit = self._stderr.append(stderr) and within_limit
                if not within_limit:
                    self._output_limit_exceeded.set()
                    self.kill()
                    break
        except DockerException as exc:
            self._read_error = str(exc)
        finally:
            self._close_stream(stream)
            self._returncode = self._resolve_exit_code()
            self._done.set()

    @staticmethod
    def _close_stream(stream: Any | None) -> None:
        if stream is None:
            return
        close = getattr(stream, "close", None)
        if callable(close):
            with suppress(Exception):
                close()
        response = getattr(stream, "_response", None)
        response_close = getattr(response, "close", None)
        if callable(response_close):
            with suppress(Exception):
                response_close()

    def _resolve_exit_code(self) -> int:
        assert self._exec_id is not None
        deadline = time.monotonic() + EXEC_KILL_JOIN_TIMEOUT_SECONDS
        while True:
            try:
                details = self._api.exec_inspect(self._exec_id)
            except DockerException as exc:
                if self._read_error is None:
                    self._read_error = str(exc)
                return 137 if self._timed_out else 1
            exit_code = details.get("ExitCode")
            if exit_code is not None:
                return int(exit_code)
            if time.monotonic() >= deadline:
                return 137 if self._timed_out else 1
            time.sleep(0.1)

    def _kill_pid(self, pid: int) -> None:
        last_error: str | None = None
        for command in (
            ["kill", "-KILL", str(pid)],
            ["/bin/sh", "-lc", f"kill -KILL {pid}"],
            ["sh", "-lc", f"kill -KILL {pid}"],
        ):
            try:
                result = self._container.exec_run(command, stdout=False, stderr=False)
            except APIError as exc:
                last_error = str(exc)
                continue
            exit_code = result.exit_code if hasattr(result, "exit_code") else None
            if exit_code in (None, 0, 1):
                return
        if last_error is not None:
            LOG.warning("failed to kill container exec pid=%s container=%s error=%s", pid, self._container.name, last_error)

    @staticmethod
    def _split_chunk(chunk: Any) -> tuple[str, str]:
        if isinstance(chunk, tuple):
            stdout, stderr = chunk
        else:
            stdout, stderr = chunk, None
        return ManagedProcess._decode(stdout), ManagedProcess._decode(stderr)

    @staticmethod
    def _decode(chunk: bytes | str | None) -> str:
        if chunk is None:
            return ""
        if isinstance(chunk, bytes):
            return chunk.decode("utf-8", errors="replace")
        return chunk
