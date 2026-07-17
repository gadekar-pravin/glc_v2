"""JSON-lines policy evaluator running in a dedicated child interpreter."""

from __future__ import annotations

import json
import os
import sys
from typing import Any

from glc.config import policy_yaml_path
from glc.policy.engine import PolicyEngine

_SENSITIVE_EXACT = {
    "CEREBRAS_API_KEY",
    "GEMINI_API_KEY",
    "GITHUB_ACCESS_TOKEN",
    "GLC_CREDS_SIGNING_KEY",
    "GLC_INSTALL_TOKEN",
    "GLC_LEDGER_SIGNING_KEY",
    "GROQ_API_KEY",
    "NVIDIA_API_KEY",
    "OPEN_ROUTER_API_KEY",
}


def _sensitive_environment_present() -> bool:
    return any(key in _SENSITIVE_EXACT or key.startswith("GLC_SLOT_IDENTITY_") for key in os.environ)


def _reply(request_id: int | None, *, result: dict[str, Any] | None = None, error: str | None = None):
    payload: dict[str, Any] = {"id": request_id, "ok": error is None}
    if error is None:
        payload["result"] = result or {}
    else:
        payload["error"] = error
    print(json.dumps(payload, separators=(",", ":")), flush=True)


def main() -> int:
    engine = PolicyEngine.from_yaml(policy_yaml_path())
    for line in sys.stdin:
        request_id: int | None = None
        try:
            request = json.loads(line)
            if not isinstance(request, dict):
                raise ValueError("request must be an object")
            request_id = request.get("id")
            if not isinstance(request_id, int):
                raise ValueError("request id must be an integer")
            op = request.get("op")

            if op == "ping":
                _reply(
                    request_id,
                    result={
                        "pid": os.getpid(),
                        "sensitive_environment_present": _sensitive_environment_present(),
                        "pythonpath_present": "PYTHONPATH" in os.environ,
                    },
                )
            elif op == "evaluate":
                tool_call = request.get("tool_call")
                context = request.get("context")
                if not isinstance(tool_call, dict) or not isinstance(context, dict):
                    raise ValueError("tool_call and context must be objects")
                verdict = engine.evaluate(tool_call, context)
                _reply(request_id, result={"verdict": verdict.model_dump(mode="json")})
            elif op == "reload":
                engine.reload(policy_yaml_path())
                _reply(request_id, result={"reloaded": True})
            elif op == "shutdown":
                _reply(request_id, result={"shutdown": True})
                return 0
            else:
                raise ValueError("unknown policy worker operation")
        except Exception as exc:
            print(f"[glc.policy.worker] request failed: {exc!r}", file=sys.stderr)
            _reply(request_id, error="policy worker request failed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
