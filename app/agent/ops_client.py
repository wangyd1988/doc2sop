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
    """The ops endpoint is not configured, not reachable, or refused the request.

    status：工具服务回的 HTTP 状态码（连不上、没配置时是 None）；data：它回的 JSON（比如提交并批准失败时申请的编号）。"""

    def __init__(self, message, status=None, data=None):
        super().__init__(message)
        self.status = status
        self.data = data if isinstance(data, dict) else {}


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
        data = {}
        try:
            data = json.load(exc)
        except Exception:
            pass
        detail = data.get("error", "") if isinstance(data, dict) else ""
        raise OpsUnavailable(detail or f"接口返回 {exc.code}", status=exc.code, data=data) from exc
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


# --- 页面审批 ---------------------------------------------------------------------------
# 口令原样转交给工具服务核对：这里不保存、不记录，也判断不了对错。caller 是「谁、从哪里」，工具服务只写进日志。

OLD_SERVICE = "工具服务版本较旧，不支持页面审批：升级宿主机上的 ops_readonly.py（和 ops_exec.py 一起拷）"


def _caller_headers(caller):
    caller = " ".join(str(caller or "").split())[:200]
    return {CALLER_HEADER: caller.encode("ascii", "replace").decode("ascii")} if caller else None


def _no_approval(problem):
    return {"configured": False, "locked": False, "unlock_minutes": 0, "problem": problem}


def approval_status() -> dict:
    """审批口令的状态：设没设、锁没锁、还有几分钟解锁。不含哈希和参数（工具服务本来就不给）。"""
    if not enabled():
        return _no_approval("未配置只读工具接口（OPS_URL / OPS_TOKEN）")
    try:
        return _request("/tools/approval", timeout=10).get("approval") or _no_approval(OLD_SERVICE)
    except OpsUnavailable as exc:
        return _no_approval(OLD_SERVICE if exc.status == 404 else str(exc))


def review() -> dict:
    """页面审批要看的：待审申请（带完整内容和风险提示）、要重新确认的脚本、审批口令的状态。

    老工具服务没有 /tools/review：退回只有待审列表，页面上能看能拒绝、不能批。"""
    if not enabled():
        return {"pending": [], "held": [], "approval": _no_approval("未配置只读工具接口（OPS_URL / OPS_TOKEN）")}
    try:
        data = _request("/tools/review", timeout=20)
    except OpsUnavailable as exc:
        if exc.status == 404:
            return {"pending": list_pending(), "held": [], "approval": _no_approval(OLD_SERVICE)}
        return {"pending": [], "held": [], "approval": _no_approval(str(exc)), "error": str(exc)}
    return {"pending": data.get("pending") or [], "held": data.get("held") or [],
            "approval": data.get("approval") or _no_approval(OLD_SERVICE)}


def _action(path, payload, caller):
    try:
        return _request(path, payload, timeout=60, headers=_caller_headers(caller))
    except OpsUnavailable as exc:
        if exc.status == 404 and str(exc) in ("Not found", "接口返回 404"):
            raise OpsUnavailable(OLD_SERVICE, status=501) from None
        raise


def approve(ident: str, passphrase: str, attest_readonly=False, script_sha256="", caller="") -> dict:
    payload = {"id": ident, "passphrase": passphrase, "attest_readonly": bool(attest_readonly)}
    if script_sha256:
        payload["script_sha256"] = script_sha256
    return _action("/tools/approve", payload, caller)


def reject(ident: str, caller="") -> dict:
    return _action("/tools/reject", {"id": ident}, caller)


def trust(script: str, passphrase: str, sha256: str, caller="") -> dict:
    return _action("/tools/trust", {"script": script, "passphrase": passphrase, "sha256": sha256}, caller)


def propose_approve(tool: dict, author: str, passphrase: str, script_sha256="", caller="") -> dict:
    payload = {"tool": tool, "author": author, "passphrase": passphrase}
    if script_sha256:
        payload["script_sha256"] = script_sha256
    return _action("/tools/propose-approve", payload, caller)


def execute(name: str, args: dict) -> dict:
    """Run one read-only tool. Never raises: failures come back as text."""
    caller = _caller.get()
    # 头的值只能是 latin-1；调用方由应用拼出（会话 id、令牌 id），这里再兜一次底
    headers = {CALLER_HEADER: caller.encode("ascii", "replace").decode("ascii")} if caller else None
    try:
        return _request("/exec", {"tool": name, "args": args or {}}, headers=headers)
    except OpsUnavailable as exc:
        return {"ok": False, "output": f"工具接口不可用：{exc}"}
