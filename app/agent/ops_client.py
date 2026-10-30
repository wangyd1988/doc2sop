"""Client for the read-only ops endpoint.

The agent never executes anything itself. It names a tool and passes typed
arguments; the endpoint validates both against a fixed allowlist.

调用方（项目 Agent 的会话、对外 MCP 的客户端）经 calling() 放进上下文，/exec 带上 X-Ops-Caller，
工具服务写进日志，两边的日志对得上。
"""
import contextlib
import contextvars
import json
import urllib.error
import urllib.request

from app.config import OPS_TOKEN, OPS_URL, log, why

CALLER_HEADER = "X-Ops-Caller"
_caller = contextvars.ContextVar("ops_caller", default="")


class OpsUnavailable(RuntimeError):
    """The ops endpoint is not configured or not reachable."""


def enabled() -> bool:
    return bool(OPS_URL and OPS_TOKEN)


@contextlib.contextmanager
def calling(caller: str):
    """这段代码里发出的 /exec 都带上调用方（只记录，不改变权限）。"""
    token = _caller.set(" ".join(str(caller or "").split())[:200])
    try:
        yield
    finally:
        _caller.reset(token)


def _request(path, payload=None, timeout=30, headers=None):
    if not enabled():
        raise OpsUnavailable("未配置只读工具接口（OPS_URL / OPS_TOKEN）")
    request = urllib.request.Request(
        OPS_URL.rstrip("/") + path,
        json.dumps(payload).encode("utf-8") if payload is not None else None,
        {"X-Ops-Token": OPS_TOKEN, "Content-Type": "application/json", **(headers or {})})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.load(response)
    except urllib.error.HTTPError as exc:
        detail = ""
        try:
            detail = json.load(exc).get("error", "")
        except Exception:
            pass
        raise OpsUnavailable(detail or f"接口返回 {exc.code}") from exc
    except Exception as exc:
        raise OpsUnavailable(why(exc)) from exc


def available_tools() -> dict:
    """Tool name -> {desc, params}, limited to what the host can actually run."""
    if not enabled():
        return {}
    try:
        return _request("/tools", timeout=10).get("tools", {})
    except OpsUnavailable as exc:
        log.info("ops endpoint unavailable: %s", exc)
        return {}


def describe_tools() -> dict:
    """Full definitions for the management page, including disabled ones."""
    if not enabled():
        return {"tools": {}, "pending": 0, "error": "未配置只读工具接口"}
    try:
        return _request("/tools/full", timeout=10)
    except OpsUnavailable as exc:
        return {"tools": {}, "pending": 0, "error": str(exc)}


def list_pending() -> list:
    if not enabled():
        return []
    try:
        return _request("/tools/pending", timeout=10).get("pending", [])
    except OpsUnavailable:
        return []


def list_scripts() -> dict:
    """Scripts on the ops host plus the directory they live in."""
    if not enabled():
        return {"scripts": [], "directory": ""}
    try:
        data = _request("/tools/scripts", timeout=10)
        return {"scripts": data.get("scripts", []), "directory": data.get("directory", "")}
    except OpsUnavailable:
        return {"scripts": [], "directory": ""}


def override(name: str, enabled_flag=None, desc=None, label=None, reset=False) -> dict:
    """Toggle a tool, reword it, or rename it for display. Never changes commands."""
    payload = {"name": name, "reset": bool(reset)}
    if enabled_flag is not None:
        payload["enabled"] = bool(enabled_flag)
    if desc is not None:
        payload["desc"] = desc
    if label is not None:
        payload["label"] = label
    return _request("/tools/override", payload).get("tool", {})


def propose(tool: dict, author: str = "web") -> dict:
    """Queue a new tool for host-side review. It is inert until approved."""
    return _request("/tools/propose", {"tool": tool, "author": author})


def execute(name: str, args: dict) -> dict:
    """Run one read-only tool. Never raises: failures come back as text."""
    caller = _caller.get()
    # 头的值只能是 latin-1；调用方由应用拼出（会话 id、令牌 id），这里再兜一次底
    headers = {CALLER_HEADER: caller.encode("ascii", "replace").decode("ascii")} if caller else None
    try:
        return _request("/exec", {"tool": name, "args": args or {}}, headers=headers)
    except OpsUnavailable as exc:
        return {"ok": False, "output": f"工具接口不可用：{exc}"}
