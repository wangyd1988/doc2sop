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
import urllib.parse
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


def propose(tool: dict, author: str = "web", caller: str = "") -> dict:
    """Queue a new tool for host-side review. It is inert until approved."""
    return _request("/tools/propose", {"tool": tool, "author": author}, headers=_caller_headers(caller))


# --- 页面审批 ---------------------------------------------------------------------------
# 口令原样转交给工具服务核对：这里不保存、不记录，也判断不了对错。caller 是「谁、从哪里」，工具服务只写进日志。

OLD_SERVICE = "工具服务版本较旧，不支持页面审批：升级宿主机上的 ops_readonly.py（和 ops_exec.py 一起拷）"
OLD_SERVICE_SET = ("工具服务版本较旧，页面上不能设置审批口令：升级宿主机上的 ops_readonly.py（和 ops_exec.py 一起拷），"
                   "或在宿主机上用 set-approval-passphrase 设置")
OLD_SERVICE_CHECK = "工具服务版本较旧，没有自动检查：升级宿主机上的 ops_readonly.py（和 ops_exec.py 一起拷）后才能用"


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


def review(caller: str = "", wait: bool = True) -> dict:
    """页面审批要看的：待审申请（带完整内容、风险提示和自动检查）、要重新确认的脚本、审批口令的状态。

    wait=False 给工作台和导航徽标：工具服务不等没做完的自动检查（照样交给后台去做），立刻回。
    老工具服务没有 /tools/review：退回只有待审列表，页面上能看能拒绝、不能批。caller 只进工具服务的 [precheck] 日志。"""
    if not enabled():
        return {"pending": [], "held": [], "approval": _no_approval("未配置只读工具接口（OPS_URL / OPS_TOKEN）")}
    try:
        data = _request("/tools/review" if wait else "/tools/review?wait=0", timeout=20,
                        headers=_caller_headers(caller))
    except OpsUnavailable as exc:
        if exc.status == 404 and not wait:   # 比这一版老的工具服务不认 ?wait=0（它也没有自动检查，不会等）
            return review(caller)
        if exc.status == 404:
            return {"pending": list_pending(), "held": [], "approval": _no_approval(OLD_SERVICE)}
        return {"pending": [], "held": [], "approval": _no_approval(str(exc)), "error": str(exc)}
    return {"pending": data.get("pending") or [], "held": data.get("held") or [],
            "approval": data.get("approval") or _no_approval(OLD_SERVICE)}


def _action(path, payload, caller, old=OLD_SERVICE):
    try:
        return _request(path, payload, timeout=60, headers=_caller_headers(caller))
    except OpsUnavailable as exc:
        if exc.status == 404 and str(exc) in ("Not found", "接口返回 404"):
            raise OpsUnavailable(old, status=501) from None
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


def set_passphrase(new: str, current: str = "", caller="") -> dict:
    """页面上设置或修改审批口令：还没设时只要新口令，已经设了要带旧口令（工具服务核对、计数）。"""
    payload = {"new": new}
    if current:
        payload["current"] = current
    return _action("/tools/set-passphrase", payload, caller, old=OLD_SERVICE_SET)


def check_draft(tool: dict, author: str = "web", caller="") -> dict:
    """「检查一下」：工具服务对表单里的草稿做风险提示和自动检查，不入队。工具服务限频（429）。"""
    return _action("/tools/check", {"tool": tool, "author": author}, caller, old=OLD_SERVICE_CHECK)


def recheck(ident: str = "", script: str = "", caller="") -> dict:
    """「重新检查」：一条待审申请（ident），或一个要重新确认的脚本（script），不用缓存再试探一遍。"""
    payload = {"script": script} if script else {"id": ident}
    return _action("/tools/recheck", payload, caller, old=OLD_SERVICE_CHECK)


# --- 页面上配置主机与数据源 ----------------------------------------------------------------
# 连接、远程 MCP server、对外开放、远程主机。口令和凭据原样转交给工具服务（它核对口令、存凭据），这里不保存、不记录。

OLD_SERVICE_CONFIG = ("工具服务版本较旧，页面上不能配置主机与数据源：升级宿主机上的 ops_readonly.py（和 ops_exec.py 一起拷），"
                      "或者照旧在宿主机上配置")


def config_view(caller="") -> dict:
    """页面「主机与数据源」要的全部（主配置的只读，页面上加的能改）。老工具服务没有这个接口：supported=False，页面照旧只读。"""
    if not enabled():
        return {"supported": False, "error": "未配置只读工具接口（OPS_URL / OPS_TOKEN）"}
    try:
        data = _request("/tools/config", timeout=20, headers=_caller_headers(caller))
    except OpsUnavailable as exc:
        return {"supported": False, "error": OLD_SERVICE_CONFIG if exc.status == 404 else str(exc)}
    return {"supported": True, **data}


def config_action(action: str, payload: dict, caller="") -> dict:
    """一个页面配置动作（connection-save、host-trust……），由工具服务做；要口令的由它核对。"""
    return _action(f"/tools/config/{action}", payload, caller, old=OLD_SERVICE_CONFIG)


def config_bundle(name: str) -> dict:
    """页面加的主机的安装包：A 上那个文件原样（base64）和它的 sha256。"""
    try:
        return _request("/tools/config/bundle/" + urllib.parse.quote(name, safe=""), timeout=20)
    except OpsUnavailable as exc:
        if exc.status == 404 and str(exc) in ("Not found", "接口返回 404"):
            raise OpsUnavailable(OLD_SERVICE_CONFIG, status=501) from None
        raise


# --- 只核对审批口令（应用自己存的设置：自动执行的发件邮箱、收件组、告警令牌） ---------------------------------

OLD_SERVICE_VERIFY = "工具服务较旧：升级 ops_readonly.py（和 ops_exec.py 一起拷）后才能在页面上改；现在只能看"
VERIFY_REFUSALS = (400, 403, 409, 423, 429)
VERIFY_TIMEOUT = 20


def verify_support(timeout=5) -> dict:
    """工具服务有没有「只核对口令」的接口、页面配置开没开。reason 为空才能在页面上改；不碰口令。"""
    if not enabled():
        return {"supported": False, "reason": "没有配工具服务（OPS_URL / OPS_TOKEN），核对不了审批口令：页面上只能看"}
    try:
        data = _request("/tools/approval/verify", timeout=timeout)
    except OpsUnavailable as exc:
        if exc.status == 404:
            return {"supported": False, "reason": OLD_SERVICE_VERIFY}
        return {"supported": False, "reason": f"连不上工具服务（{exc}）：页面上暂时只能看"}
    if not isinstance(data, dict) or not isinstance(data.get("page_config"), bool):
        return {"supported": False, "reason": "工具服务回的内容不对：页面上暂时只能看"}
    if not data["page_config"]:
        return {"supported": True, "reason": "页面配置在服务器上关了（OPS_PAGE_CONFIG=off）：页面上只能看"}
    return {"supported": True, "reason": ""}


def verify_passphrase(passphrase: str, action: str, target: str, caller="", timeout=None) -> None:
    """请工具服务核对审批口令（和批准工具共用输错计数、锁定）。只有 200 且回 {"ok": true} 才算通过，别的都抛 OpsUnavailable：
    口令不对、锁定、没设口令这些拒绝带着原来的状态码（400 / 403 / 409 / 423 / 429）；老工具服务 404；
    连不上、超时 503；其余（5xx、令牌不对、回的不是 JSON 或字段不对）502——一律不算通过。口令不进任何输出。"""
    if not enabled():
        raise OpsUnavailable("没有配工具服务，核对不了审批口令：没有改", status=503)
    payload = json.dumps({"passphrase": passphrase, "action": action, "target": target}).encode("utf-8")
    request = urllib.request.Request(OPS_URL.rstrip("/") + "/tools/approval/verify", payload,
                                     {"X-Ops-Token": OPS_TOKEN, "Content-Type": "application/json",
                                      **(_caller_headers(caller) or {})})
    try:
        with urllib.request.urlopen(request, timeout=timeout or VERIFY_TIMEOUT) as response:
            status, body = response.status, response.read(64 * 1024)
    except urllib.error.HTTPError as exc:
        try:
            data = json.loads(exc.read(64 * 1024) or b"{}")
        except Exception:   # 不是 JSON，或者读到一半连接断了
            data = {}
        detail = data.get("error") if isinstance(data, dict) and isinstance(data.get("error"), str) else ""
        if exc.code in VERIFY_REFUSALS:
            raise OpsUnavailable(detail[:300] or f"工具服务拒绝了（{exc.code}）", status=exc.code) from None
        if exc.code == 404:
            raise OpsUnavailable(OLD_SERVICE_VERIFY, status=404) from None
        raise OpsUnavailable(f"工具服务核对口令时出错（HTTP {exc.code}）：没有改", status=502) from None
    except Exception as exc:   # 连不上、超时、连接被重置
        raise OpsUnavailable(f"连不上工具服务（{why(exc)}），没有核对口令：没有改", status=503) from None
    try:
        data = json.loads(body)
    except ValueError:
        raise OpsUnavailable("工具服务回的不是 JSON：没有改", status=502) from None
    if status != 200 or not isinstance(data, dict) or data.get("ok") is not True:
        raise OpsUnavailable("工具服务的回复不对，不算核对通过：没有改", status=502)


def execute(name: str, args: dict) -> dict:
    """Run one read-only tool. Never raises: failures come back as text."""
    caller = _caller.get()
    # 头的值只能是 latin-1；调用方由应用拼出（会话 id、令牌 id），这里再兜一次底
    headers = {CALLER_HEADER: caller.encode("ascii", "replace").decode("ascii")} if caller else None
    try:
        return _request("/exec", {"tool": name, "args": args or {}}, headers=headers)
    except OpsUnavailable as exc:
        return {"ok": False, "output": f"工具接口不可用：{exc}"}
