"""对外接入页的「测一下」「试调」：用粘贴的令牌真实走一遍 /mcp，告诉人哪一步不通、为什么、怎么修。

不在浏览器里直接 fetch /mcp：配了 MCP_ALLOWED_HOSTS 时 SDK 开着 DNS 重绑定防护、不认任何 Origin，浏览器的 POST
带 Origin，一律 403——放开它就是改 /mcp 的安全设置。也不由后端经网络连自己：经回环连进来会被 app/peer.py 当成来源不明。

做法：在这次页面请求的处理里拼一个 ASGI 请求，直接交给 /mcp 的 TokenGate（和 TokenGate.disconnect 关会话一样）。

    来源      本次页面请求经 peer.py 算好的来源：MCP_CLIENTS 按它判断，和从这台电脑连的客户端一样
    Host      页面给的接入地址候选（addresses）里选一个：SDK 按它查 MCP_ALLOWED_HOSTS
    令牌      粘贴的令牌（Authorization: Bearer）：范围、分类白名单、限额、吊销、过期、限流全照常
    Origin    不带（外部客户端本来就不带）
    via       scope 里放 "page"：审计标「页面试调」；HTTP 头伪造不了

测不到的：客户端那台机器到这里的网络、防火墙、证书——页面让人在那台机器上跑 curl。

2025 版握手（initialize → notifications/initialized → … → DELETE）：大多数客户端现在这样连。不管成败，开了会话就关掉，
否则点几次就把这枚令牌的会话名额（mcp_server.SESSIONS_PER_TOKEN）占满，真客户端 429。

令牌只在这次请求的内存里：不进日志（只记令牌 id）、不进回复、不进审计；请求体手工解析（FastAPI 的 422 会回显输入）。
接口本身在页面的 Basic 鉴权和同源检查之后；/mcp 照样只认令牌，页面登录态替代不了令牌。
"""
import json
import re
import time
from contextlib import asynccontextmanager

import anyio
from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse
from mcp_types.version import LATEST_HANDSHAKE_VERSION

from app import access, approval, serve
from app import mcp_server as ms
from app.config import log, why

STEP_TIMEOUT = 20            # 测一下的每一步
TRY_TIMEOUT = 60             # 试调的那次调用：数据工具（K8s、主机命令）慢；工具服务 /exec 自己 30 秒超时，60 秒兜底
MAX_RUNNING = 2              # 同时最多几个测试 / 试调在跑（整个应用）
TEXT_SHOWN = 600             # 测一下里那次只读调用，返回给页面看多少字
CLIENT_INFO = {"name": "doc2sop-page-probe", "version": "1.0"}
ACCEPT = b"application/json, text/event-stream"
TOKEN = re.compile(r"^[\x21-\x7e]{1,200}$")
HOST = re.compile(r"^(?:\[[0-9A-Fa-f:.]{2,45}\]|[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?)(?::[0-9]{1,5})?$")
TOOL = re.compile(r"^[\x21-\x7e]{1,120}$")
STEPS = {"probe": ["initialize", "initialized", "tools/list", "tools/call", "close"],
         "try": ["initialize", "initialized", "tools/call", "close"]}
SAMPLE_CALLS = ("kb_catalog", "sop_list")     # 测一下的只读调用：不花模型、向量的钱；只有数据工具时不替人去打宿主机

_running = {"count": 0}


# --- 接入地址候选 ---------------------------------------------------------------------------

def _authority(name, port, default):
    name = f"[{name}]" if ":" in name else name
    return name if port == default else f"{name}:{port}"


def addresses(request: Request) -> list:
    """给页面的接入地址候选：本页地址；开了内置 TLS 时证书里的每个名字 × PORT；留了本机明文口时经 SSH 隧道的地址。
    「测一下」的 Host 只能是这里面的。"""
    out, seen = [], set()

    def add(scheme, host, label):
        if host and HOST.match(host) and host.lower() not in seen:
            seen.add(host.lower())
            out.append({"url": f"{scheme}://{host}{ms.PATH}", "host": host, "label": label})

    scheme = "https" if request.scope.get("scheme") in ("https", "wss") else "http"
    add(scheme, request.headers.get("host", ""), "本页地址")
    tls = serve.tls_status()
    if tls.get("builtin") and not tls.get("problem") and tls.get("port"):
        for name in tls.get("names") or []:
            if not str(name).startswith("*"):
                add("https", _authority(str(name), tls["port"], 443), "证书里的名字")
    if tls.get("local_port"):
        add("http", f"127.0.0.1:{tls['local_port']}", "经 SSH 隧道")
    return out


# --- 进程内转给 TokenGate ---------------------------------------------------------------------

class Answer:
    def __init__(self):
        self.status = None
        self.headers = {}
        self.chunks = []
        self.done = anyio.Event()

    @property
    def body(self) -> bytes:
        return b"".join(self.chunks)


async def exchange(gate, request, token, host, method, message=None, session="", version="") -> Answer:
    """一个 HTTP 请求：拼好 scope 直接交给 TokenGate，收下状态码、响应头、正文（SSE 或 JSON）。"""
    body = json.dumps(message, ensure_ascii=False).encode("utf-8") if message is not None else b""
    headers = [(b"host", host.encode("ascii")), (b"authorization", b"Bearer " + token.encode("ascii")),
               (b"accept", ACCEPT), (b"user-agent", b"doc2sop-page-probe"),
               (b"content-length", str(len(body)).encode())]
    if message is not None:
        headers.append((b"content-type", b"application/json"))
    if session:
        headers += [(b"mcp-session-id", session.encode("latin-1")), (b"mcp-protocol-version", version.encode("ascii"))]
    scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": method,
             "scheme": request.scope.get("scheme", "http"), "path": ms.PATH, "raw_path": ms.PATH.encode(),
             "query_string": b"", "root_path": "", "headers": headers,
             "client": request.scope.get("client") or ("", 0), "server": request.scope.get("server") or ("", 0),
             ms.VIA_KEY: "page"}
    answer, sent = Answer(), [False]

    async def receive():
        if not sent[0]:
            sent[0] = True
            return {"type": "http.request", "body": body, "more_body": False}
        await answer.done.wait()          # 像一个一直连着的客户端：回复发完才算断开
        return {"type": "http.disconnect"}

    async def send(event):
        if event["type"] == "http.response.start":
            answer.status = event["status"]
            answer.headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in event.get("headers") or []}
        elif event["type"] == "http.response.body":
            answer.chunks.append(event.get("body", b""))
            if not event.get("more_body"):
                answer.done.set()

    try:
        await gate(scope, receive, send)
    finally:
        answer.done.set()
    return answer


def reply_of(answer: Answer, want_id):
    """回复正文里 id 对得上的 JSON-RPC 消息：SDK 默认回 SSE（data: 一行一条），也可能是 JSON。"""
    kind = answer.headers.get("content-type", "")
    text = answer.body.decode("utf-8", "replace")
    if kind.startswith("text/event-stream"):
        for event in text.replace("\r\n", "\n").split("\n\n"):
            data = "\n".join(line[5:].removeprefix(" ") for line in event.split("\n") if line.startswith("data:"))
            try:
                message = json.loads(data) if data else None
            except ValueError:
                continue
            if isinstance(message, dict) and message.get("id") == want_id:
                return message
        return None
    if kind.startswith("application/json"):
        try:
            message = json.loads(text)
        except ValueError:
            return None
        return message if isinstance(message, dict) else None
    return None


def refusal(answer: Answer) -> tuple:
    """HTTP 层被拒：(错误码, 说明)。TokenGate 回 {error, error_description}；SDK 的 Host 检查回 421 纯文本；
    SDK 别的拒绝是 JSON-RPC 错误或纯文本。"""
    text = answer.body.decode("utf-8", "replace")
    data = None
    if answer.headers.get("content-type", "").startswith("application/json"):
        try:
            data = json.loads(text)
        except ValueError:
            data = None
    if isinstance(data, dict) and isinstance(data.get("error"), str):
        return data["error"][:60], str(data.get("error_description") or "")[:300]
    if isinstance(data, dict) and isinstance(data.get("error"), dict):
        return f"http_{answer.status}", str(data["error"].get("message") or "")[:300]
    if answer.status == 421:
        return "invalid_host", text[:300]
    return f"http_{answer.status}", text[:300]


def _row(name, ok, started, code="", detail="", status=None):
    return {"step": name, "ok": ok, "ms": int((time.monotonic() - started) * 1000) if started else 0,
            "code": code, "detail": detail, "status": status}


async def _step(steps, name, call, timeout, want_id=None, expect=200):
    """跑一步，结果追加到 steps：(这一行, Answer, JSON-RPC 回复)；没成功时 Answer、回复是 None。"""
    started = time.monotonic()
    try:
        with anyio.fail_after(timeout):
            answer = await call()
    except TimeoutError:
        steps.append(_row(name, False, started, "timeout", f"{timeout} 秒没有回应"))
        return steps[-1], None, None
    except Exception as exc:      # 意外：给页面一句话，日志里只有异常类型和说明（不会有令牌：令牌只在请求头里）
        log.warning("mcp page step %s failed: %s", name, why(exc))
        steps.append(_row(name, False, started, "error", why(exc)[:300]))
        return steps[-1], None, None
    if answer.status != expect:
        code, detail = refusal(answer) if (answer.status or 0) >= 400 else (f"http_{answer.status}", "")
        steps.append(_row(name, False, started, code, detail, answer.status))
        return steps[-1], None, None
    reply = None
    if want_id is not None:
        reply = reply_of(answer, want_id)
        if reply is None:
            steps.append(_row(name, False, started, "bad_reply", "没有读到 JSON-RPC 回复", answer.status))
            return steps[-1], None, None
        if "error" in reply:
            error = reply["error"] if isinstance(reply["error"], dict) else {}
            steps.append(_row(name, False, started, "rpc_error", str(error.get("message") or "")[:300], answer.status))
            return steps[-1], None, None
    steps.append(_row(name, True, started, status=answer.status))
    return steps[-1], answer, reply


def _rpc(id_, method, params=None):
    return {"jsonrpc": "2.0", "id": id_, "method": method, **({"params": params} if params is not None else {})}


def _text_of(result) -> str:
    content = result.get("content") if isinstance(result, dict) else None
    return "\n".join(str(c.get("text", "")) for c in content or [] if isinstance(c, dict) and c.get("type") == "text")


class Run:
    """一次测试或试调：握手、做事、关会话。"""

    def __init__(self, gate, request, token, host, kind):
        self.gate, self.request, self.token, self.host, self.kind = gate, request, token, host, kind
        self.steps = []
        self.session = ""
        self.version = LATEST_HANDSHAKE_VERSION
        self.server = None

    def send(self, method, message=None):
        return exchange(self.gate, self.request, self.token, self.host, method, message, self.session, self.version)

    async def handshake(self) -> bool:
        params = {"protocolVersion": self.version, "capabilities": {}, "clientInfo": CLIENT_INFO}
        row, answer, reply = await _step(self.steps, "initialize", lambda: self.send("POST", _rpc(1, "initialize", params)),
                                         STEP_TIMEOUT, 1)
        if not row["ok"]:
            return False
        result = reply.get("result") or {}
        self.session = answer.headers.get("mcp-session-id", "")[:200]
        self.version = str(result.get("protocolVersion") or self.version)[:20]
        info = result.get("serverInfo") or {}
        self.server = {"name": str(info.get("name", ""))[:60], "version": str(info.get("version", ""))[:30],
                       "protocol": self.version}
        row["detail"] = f"{self.server['name']} {self.server['version']}，协议 {self.version}" + \
            ("" if self.session else "，没有给会话 id")
        notice = {"jsonrpc": "2.0", "method": "notifications/initialized"}
        row, _, _ = await _step(self.steps, "initialized", lambda: self.send("POST", notice), STEP_TIMEOUT, expect=202)
        return row["ok"]

    async def call(self, tool, arguments, timeout, id_=3):
        """tools/call：(这一行, 结果)。结果是 {is_error, text, raw}，没拿到回复时 None。"""
        message = _rpc(id_, "tools/call", {"name": tool, "arguments": arguments})
        row, _, reply = await _step(self.steps, "tools/call", lambda: self.send("POST", message), timeout, id_)
        if not row["ok"]:
            return row, None
        result = reply.get("result") or {}
        text = _text_of(result)
        out = {"is_error": bool(result.get("isError")), "text": text, "raw": reply}
        if out["is_error"]:
            row.update(ok=False, code="tool_error", detail=(text.splitlines() or [""])[0][:300])
        else:
            row["detail"] = f"{tool}：返回 {len(text)} 字"
        return row, out

    async def close(self):
        """关掉开的会话；失败只记一行，不算测试失败。"""
        if not self.session:
            return
        row, _, _ = await _step(self.steps, "close", lambda: self.send("DELETE"), STEP_TIMEOUT)
        row["optional"] = True
        if not row["ok"]:
            log.warning("mcp page %s: closing the session failed (%s)", self.kind, row["code"])

    def finish(self):
        """没跑到的步骤补上「没跑」，页面总是看到完整的几步。"""
        done = {row["step"] for row in self.steps}
        for name in STEPS[self.kind]:
            if name not in done and not (name == "close" and not self.session):
                self.steps.append(_row(name, None, None, "not_run"))
        return all(row["ok"] is not False for row in self.steps if not row.get("optional"))


def _token_view(info):
    if not info:
        return None
    keys = ("id", "name", "scopes", "categories", "rate_per_minute", "max_result_chars", "expires_at", "revoked_at",
            "status")
    return {k: info[k] for k in keys}


async def probe(gate, request, token, host) -> dict:
    """测一下：握手 → 列工具 → 一次只读调用（kb_catalog / sop_list）→ 关会话。"""
    run = Run(gate, request, token, host, "probe")
    tools, sample = [], None
    try:
        if await run.handshake():
            row, _, reply = await _step(run.steps, "tools/list", lambda: run.send("POST", _rpc(2, "tools/list")),
                                        STEP_TIMEOUT, 2)
            if row["ok"]:
                listed = (reply.get("result") or {}).get("tools") or []
                tools = [{"name": t.get("name"), "title": t.get("title") or "", "description": t.get("description") or "",
                          "inputSchema": t.get("inputSchema") or {"type": "object"}} for t in listed if isinstance(t, dict)]
                row["detail"] = f"看得到 {len(tools)} 个工具"
                if not tools:
                    row.update(ok=False, code="no_tools", detail="这枚令牌的范围里没有开放的工具")
                names = [t["name"] for t in tools]
                pick = next((n for n in SAMPLE_CALLS if n in names), None)
                if pick:
                    _, out = await run.call(pick, {}, STEP_TIMEOUT)
                    if out:
                        sample = {"tool": pick, "is_error": out["is_error"], "text": out["text"][:TEXT_SHOWN],
                                  "chars": len(out["text"])}
                elif tools:
                    run.steps.append(_row("tools/call", True, None, "skipped",
                                          "只有数据工具：不替你去调宿主机，到下面「试调」里挑一个"))
    finally:
        with anyio.CancelScope(shield=True):
            await run.close()
    ok = run.finish()
    info = await anyio.to_thread.run_sync(access.describe, token)
    return {"ok": ok, "steps": run.steps, "source": ms.peers.address(request, ""), "host": host,
            "server": run.server, "token": _token_view(info), "tools": tools, "call": sample}


async def try_tool(gate, request, token, host, tool, arguments) -> dict:
    """试调：握手 → 调一个工具 → 关会话。返回原始 JSON-RPC 回复。"""
    run = Run(gate, request, token, host, "try")
    result = None
    try:
        if await run.handshake():
            _, result = await run.call(tool, arguments, TRY_TIMEOUT)
    finally:
        with anyio.CancelScope(shield=True):
            await run.close()
    ok = run.finish()
    info = await anyio.to_thread.run_sync(access.describe, token)
    return {"ok": ok, "steps": run.steps, "source": ms.peers.address(request, ""), "host": host,
            "token": _token_view(info), "tool": tool, "result": result}


# --- 管理接口 -------------------------------------------------------------------------------

@asynccontextmanager
async def _slot():
    """同时最多 MAX_RUNNING 个在跑（只在事件循环里用，不用加锁）。"""
    if _running["count"] >= MAX_RUNNING:
        raise HTTPException(429, f"已经有 {MAX_RUNNING} 个测试或试调在跑，等它们跑完再试")
    _running["count"] += 1
    try:
        yield
    finally:
        _running["count"] -= 1


def _token_of(data) -> str:
    token = data.get("token")
    if not isinstance(token, str) or not token.strip():
        raise HTTPException(400, "先粘贴令牌")
    token = token.strip()
    if token[:7].lower() == "bearer ":
        token = token[7:].strip()
    if not TOKEN.match(token):
        raise HTTPException(400, "令牌里有空格、换行或中文这类字符：请重新复制（只要 d2s_ 开头的那一串）")
    return token


def _host_of(request, data) -> str:
    host = data.get("host")
    known = [a["host"] for a in addresses(request)]
    if host in (None, ""):
        if not known:
            raise HTTPException(400, "这个页面的地址认不出来，选一个接入地址再测")
        return known[0]
    if not isinstance(host, str) or not HOST.match(host) or host not in known:
        raise HTTPException(400, "接入地址只能从页面给的候选里选")
    return host


def _log(kind, request, info, result):
    log.info("mcp page %s token=%s host=%s ip=%s ok=%s", kind, (info or {}).get("id") or "?", result["host"],
             approval.address(request), result["ok"])


def install(router, gate):
    """挂到 admin_router 上（在页面的 Basic 鉴权、同源检查之后）。"""

    @router.post("/api/mcp/probe")
    async def probe_endpoint(request: Request):
        """测一下：{token, host?}。结果每一步都有：成没成、耗时、错误码、说明。"""
        data = await approval.json_body(request)
        token, host = _token_of(data), _host_of(request, data)
        async with _slot():
            result = await probe(gate, request, token, host)
        _log("probe", request, result["token"], result)
        return JSONResponse(result, headers=ms.NO_STORE)

    @router.post("/api/mcp/try")
    async def try_endpoint(request: Request):
        """试调：{token, host?, tool, arguments}。"""
        data = await approval.json_body(request)
        token, host = _token_of(data), _host_of(request, data)
        tool, arguments = data.get("tool"), data.get("arguments", {})
        if not isinstance(tool, str) or not TOOL.match(tool):
            raise HTTPException(400, "要选一个工具")
        if not isinstance(arguments, dict):
            raise HTTPException(400, "参数必须是 JSON 对象")
        async with _slot():
            result = await try_tool(gate, request, token, host, tool, arguments)
        _log("try", request, result["token"], result)
        return JSONResponse(result, headers=ms.NO_STORE)
