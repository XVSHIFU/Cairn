from __future__ import annotations

import logging
import os
import signal
import subprocess
import threading
from contextlib import suppress

from cairn.dispatcher.runtime.process import (
    BoundedTextBuffer,
    DEFAULT_WORKER_STDERR_LIMIT_BYTES,
    DEFAULT_WORKER_STDOUT_LIMIT_BYTES,
    ProcessResult,
)

LOG = logging.getLogger(__name__)

READ_CHUNK_SIZE = 65536
STREAM_JOIN_TIMEOUT_SECONDS = 5.0
FORCE_KILL_REAP_TIMEOUT_SECONDS = 2.0


class LocalProcess:
    """Runs a worker command as a host subprocess.

    Mirrors the container ManagedProcess surface (start/communicate/kill/cancel) but
    executes on the dispatcher host: its own process group so children are killed as a
    group, a Python-enforced timeout instead of the ``timeout`` coreutil, and a
    SIGTERM -> grace -> SIGKILL shutdown so the CLI can flush its session before dying.
    """

    def __init__(
        self,
        command: list[str],
        cwd: str,
        env: dict[str, str],
        timeout_seconds: int | None = None,
        term_grace_seconds: int = 5,
        max_stdout_bytes: int = DEFAULT_WORKER_STDOUT_LIMIT_BYTES,
        max_stderr_bytes: int = DEFAULT_WORKER_STDERR_LIMIT_BYTES,
    ):
        self.command = command
        self.env = env
        self._cwd = cwd
        self._timeout_seconds = timeout_seconds
        self._term_grace = max(1.0, float(term_grace_seconds))
        self._process: subprocess.Popen[str] | None = None
        self._stdout = BoundedTextBuffer(max_stdout_bytes)
        self._stderr = BoundedTextBuffer(max_stderr_bytes)
        self._stdout_thread: threading.Thread | None = None
        self._stderr_thread: threading.Thread | None = None
        self._timed_out = False
        self._cancel_reason: str | None = None
        self._kill_lock = threading.Lock()
        self._output_limit_exceeded = threading.Event()

    def start(self) -> None:
        process_kwargs = {
            "cwd": self._cwd,
            "env": self.env,
            "stdout": subprocess.PIPE,
            "stderr": subprocess.PIPE,
            "text": True,
            "encoding": "utf-8",
            "errors": "replace",
        }
        if os.name == "posix":
            process_kwargs["start_new_session"] = True
        elif hasattr(subprocess, "CREATE_NEW_PROCESS_GROUP"):
            process_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
        self._process = subprocess.Popen(self.command, **process_kwargs)
        self._stdout_thread = threading.Thread(
            target=self._drain, args=(self._process.stdout, self._stdout), daemon=True
        )
        self._stderr_thread = threading.Thread(
            target=self._drain, args=(self._process.stderr, self._stderr), daemon=True
        )
        self._stdout_thread.start()
        self._stderr_thread.start()

    def communicate(self, timeout: float | None) -> ProcessResult:
        assert self._process is not None
        wait_for = float(self._timeout_seconds) if self._timeout_seconds is not None else timeout
        try:
            self._process.wait(timeout=wait_for)
        except subprocess.TimeoutExpired:
            self._timed_out = True
            self._terminate()
        with suppress(subprocess.TimeoutExpired):
            self._process.wait(timeout=FORCE_KILL_REAP_TIMEOUT_SECONDS)
        if self._stdout_thread is not None:
            self._stdout_thread.join(timeout=STREAM_JOIN_TIMEOUT_SECONDS)
        if self._stderr_thread is not None:
            self._stderr_thread.join(timeout=STREAM_JOIN_TIMEOUT_SECONDS)
        returncode = self._process.returncode
        if returncode is None:
            returncode = 137 if self._timed_out else 1
        stderr = self._stderr.text()
        if self._output_limit_exceeded.is_set():
            stderr = (
                stderr
                + "\nCairn stopped the worker because its stdout/stderr byte limit was exceeded."
            ).lstrip()
            if returncode == 0:
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
        self._terminate()

    def cancel(self, reason: str) -> None:
        if self._cancel_reason is None:
            self._cancel_reason = reason
        self._terminate()

    def _terminate(self) -> None:
        with self._kill_lock:
            process = self._process
            if process is None or process.poll() is not None:
                return
            self._signal_group(process, signal.SIGTERM)
            try:
                process.wait(timeout=self._term_grace)
                return
            except subprocess.TimeoutExpired:
                pass
            if os.name == "posix":
                self._signal_group(process, signal.SIGKILL)
            else:
                with suppress(ProcessLookupError, PermissionError, ValueError):
                    process.kill()

    @staticmethod
    def _signal_group(process: subprocess.Popen[str], sig: int) -> None:
        if os.name != "posix":
            with suppress(ProcessLookupError, PermissionError, ValueError):
                process.terminate()
            return
        try:
            os.killpg(os.getpgid(process.pid), sig)
        except (ProcessLookupError, PermissionError):
            with suppress(ProcessLookupError, PermissionError, ValueError):
                process.send_signal(sig)

    def _drain(self, pipe, sink: BoundedTextBuffer) -> None:
        try:
            for chunk in iter(lambda: pipe.read(READ_CHUNK_SIZE), ""):
                if not sink.append(chunk):
                    self._output_limit_exceeded.set()
                    self._terminate()
                    break
        except (ValueError, OSError):
            pass
        finally:
            with suppress(Exception):
                pipe.close()
