"""Client for the read-only ops endpoint.

The agent never executes anything itself. It names a tool and passes typed
arguments; the endpoint validates both against a fixed allowlist.
"""
import json
import urllib.error
import urllib.request

from app.config import OPS_TOKEN, OPS_URL, log, why


class OpsUnavailable(RuntimeError):
    """The ops endpoint is not configured or not reachable."""


def enabled() -> bool:
    return bool(OPS_URL and OPS_TOKEN)


def _request(path, payload=None, timeout=30):
    if not enabled():
        raise OpsUnavailable("未配置只读运维接口（OPS_URL / OPS_TOKEN）")
    request = urllib.request.Request(
        OPS_URL.rstrip("/") + path,
        json.dumps(payload).encode("utf-8") if payload is not None else None,
        {"X-Ops-Token": OPS_TOKEN, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.load(response)
    except urllib.error.HTTPError as exc:
        raise OpsUnavailable(f"接口返回 {exc.code}") from exc
    except Exception as exc:
        raise OpsUnavailable(why(exc)) from exc


def available_tools() -> dict:
    """Tool name -> description, limited to what the host can actually run."""
    if not enabled():
        return {}
    try:
        return _request("/tools", timeout=10).get("tools", {})
    except OpsUnavailable as exc:
        log.info("ops endpoint unavailable: %s", exc)
        return {}


def execute(name: str, args: dict) -> dict:
    """Run one read-only tool. Never raises: failures come back as text."""
    try:
        return _request("/exec", {"tool": name, "args": args or {}})
    except OpsUnavailable as exc:
        return {"ok": False, "output": f"运维接口不可用：{exc}"}
