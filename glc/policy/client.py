"""Fail-closed client for the isolated policy evaluator process."""

from __future__ import annotations

import json
import os
import selectors
import subprocess
import sys
import threading
from pathlib import Path
from typing import Any

from glc.policy.schemas import PolicyVerdict

STARTUP_TIMEOUT_SECONDS = 5.0
OPERATION_TIMEOUT_SECONDS = 2.0
_UNAVAILABLE = PolicyVerdict(action="deny", reason="policy worker unavailable")
_ENV_ALLOWLIST = {
    "GLC_CONFIG_DIR",
    "HOME",
    "LANG",
    "LC_ALL",
    "PATH",
    "SYSTEMROOT",
    "TEMP",
    "TMP",
    "TMPDIR",
    "VIRTUAL_ENV",
    "WINDIR",
}


class PolicyWorkerError(RuntimeError):
    """The isolated evaluator cannot produce a trusted response."""


class ProcessPolicyClient:
    def __init__(
        self,
        *,
        startup_timeout: float = STARTUP_TIMEOUT_SECONDS,
        operation_timeout: float = OPERATION_TIMEOUT_SECONDS,
    ):
        self.startup_timeout = startup_timeout
        self.operation_timeout = operation_timeout
        self._lock = threading.Lock()
        self._process: subprocess.Popen[str] | None = None
        self._next_id = 0
        self._healthy = False
        self._worker_pid: int | None = None

    @property
    def worker_pid(self) -> int | None:
        return self._worker_pid

    def start(self) -> None:
        with self._lock:
            if self._process is not None:
                raise RuntimeError("policy worker already started")
            env = {key: value for key, value in os.environ.items() if key in _ENV_ALLOWLIST}
            env["PYTHONUNBUFFERED"] = "1"
            env["PYTHONUTF8"] = "1"
            self._process = subprocess.Popen(
                [sys.executable, "-u", "-m", "glc.policy.worker"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                text=True,
                bufsize=1,
                env=env,
                cwd=str(Path(__file__).resolve().parents[2]),
            )
            try:
                result = self._exchange_locked("ping", timeout=self.startup_timeout)
                pid = result.get("pid")
                secrets_present = result.get("sensitive_environment_present")
                pythonpath_present = result.get("pythonpath_present")
                if (
                    not isinstance(pid, int)
                    or secrets_present is not False
                    or pythonpath_present is not False
                ):
                    raise PolicyWorkerError("policy worker returned an invalid readiness response")
                self._worker_pid = pid
                self._healthy = True
            except Exception:
                self._terminate_locked()
                raise RuntimeError("policy worker failed to start") from None

    def evaluate(self, tool_call: dict[str, Any], context: dict[str, Any]) -> PolicyVerdict:
        try:
            result = self._request("evaluate", tool_call=tool_call, context=context)
            return PolicyVerdict.model_validate(result.get("verdict"))
        except Exception:
            self._fail_closed()
            return _UNAVAILABLE.model_copy()

    def reload(self) -> bool:
        try:
            result = self._request("reload")
            if result.get("reloaded") is not True:
                raise PolicyWorkerError("policy worker rejected reload")
            return True
        except Exception:
            self._fail_closed()
            return False

    def ping(self) -> bool:
        try:
            result = self._request("ping")
            if (
                result.get("pid") != self._worker_pid
                or result.get("sensitive_environment_present") is not False
                or result.get("pythonpath_present") is not False
            ):
                raise PolicyWorkerError("policy worker returned an invalid readiness response")
            return True
        except Exception:
            self._fail_closed()
            return False

    def close(self) -> None:
        process = self._process
        if process is None:
            return
        if process.poll() is None and self._healthy:
            try:
                self._request("shutdown")
            except Exception:
                pass
        try:
            process.wait(timeout=self.operation_timeout)
        except subprocess.TimeoutExpired:
            process.terminate()
            try:
                process.wait(timeout=self.operation_timeout)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=self.operation_timeout)
        self._close_pipes(process)
        self._healthy = False
        self._process = None
        self._worker_pid = None

    def _request(self, op: str, **payload: Any) -> dict[str, Any]:
        with self._lock:
            if not self._healthy:
                raise PolicyWorkerError("policy worker is unavailable")
            return self._exchange_locked(op, timeout=self.operation_timeout, **payload)

    def _exchange_locked(self, op: str, *, timeout: float, **payload: Any) -> dict[str, Any]:
        process = self._process
        if process is None or process.poll() is not None or process.stdin is None or process.stdout is None:
            raise PolicyWorkerError("policy worker is not running")
        self._next_id += 1
        request_id = self._next_id
        request = {"id": request_id, "op": op, **payload}
        try:
            process.stdin.write(json.dumps(request, separators=(",", ":")) + "\n")
            process.stdin.flush()
        except (BrokenPipeError, OSError, TypeError, ValueError) as exc:
            raise PolicyWorkerError("policy worker request failed") from exc

        selector = selectors.DefaultSelector()
        try:
            selector.register(process.stdout, selectors.EVENT_READ)
            if not selector.select(timeout):
                raise PolicyWorkerError("policy worker response timed out")
        finally:
            selector.close()

        line = process.stdout.readline()
        if not line:
            raise PolicyWorkerError("policy worker closed its response stream")
        try:
            response = json.loads(line)
        except json.JSONDecodeError as exc:
            raise PolicyWorkerError("policy worker returned malformed JSON") from exc
        if not isinstance(response, dict) or response.get("id") != request_id:
            raise PolicyWorkerError("policy worker response did not match the request")
        if response.get("ok") is not True or not isinstance(response.get("result"), dict):
            raise PolicyWorkerError("policy worker rejected the request")
        return response["result"]

    def _fail_closed(self) -> None:
        with self._lock:
            self._healthy = False
            self._terminate_locked()

    def _terminate_locked(self) -> None:
        process = self._process
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=self.operation_timeout)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=self.operation_timeout)
        if process is not None:
            self._close_pipes(process)
        self._healthy = False
        self._process = None
        self._worker_pid = None

    @staticmethod
    def _close_pipes(process: subprocess.Popen[str]) -> None:
        if process.stdin is not None:
            try:
                process.stdin.close()
            except (BrokenPipeError, OSError):
                pass
        if process.stdout is not None:
            try:
                process.stdout.close()
            except OSError:
                pass
