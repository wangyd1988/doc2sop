"""kb-app 这一侧调转接程序（deploy/ccwork/ccwork_bridge.py）的本机接口（docs/正式部署.md「云上协同」）。

地址只认字面量的 http://127.0.0.1:端口 或 http://[::1]:端口：配错成别的地址时不能把令牌发出去。不走环境代理、
不跟重定向。每个请求带令牌（X-Chat-Bridge-Token）和协议版本（X-Chat-Bridge-Protocol）。

回复只能按 handle（收到消息时转接程序给的，24 小时内有效），推送只能按名字（转接程序的 targets.yaml 里配的）：
kb-app 拿不到、也用不着原始的会话 ID 去发消息。
"""
import json
import urllib.error
import urllib.parse
import urllib.request

PROTOCOL = 1
TOKEN_HEADER = "X-Chat-Bridge-Token"
PROTOCOL_HEADER = "X-Chat-Bridge-Protocol"
TIMEOUT = 30.0              # 发消息时转接程序可能要等限速桶（最多 10 秒）再调平台接口
POLL_SLACK = 10.0           # 长轮询在 wait 之外多等这么久
BODY_MAX = 4 * 1024 * 1024


class BridgeError(Exception):
    """调转接程序失败。

    status    转接程序回的 HTTP 状态；连不上、超时是 0
    definite  平台那边是不是「确定没收到」：False 表示结果不明（超时、断网、平台 5xx），同一包可以原样重发
    """

    def __init__(self, message, status=0, definite=False, data=None):
        super().__init__(message)
        self.status, self.definite, self.data = status, definite, data or {}

    @property
    def retryable(self) -> bool:
        """同一包（同一个 seq、同样的内容）还值得再发：结果不明，或者转接程序嫌发得太快（429，确定没发）。"""
        return self.status == 429 or (self.status in (0, 502) and not self.definite)

    @property
    def rejected(self) -> bool:
        """平台（或转接程序的格式检查）明确拒了这一包：换成普通文字发一次还有机会。"""
        return (self.status == 502 and self.definite) or self.status == 400


class EpochChanged(Exception):
    """转接程序重启过：编号从 0 重新取（靠消息键去重）。"""

    def __init__(self, epoch):
        super().__init__(epoch)
        self.epoch = epoch


def check_url(url) -> str:
    """地址有问题时返回说明，没问题返回空串。"""
    if not url:
        return "没有配 CHAT_BRIDGE_URL"
    try:
        parts = urllib.parse.urlsplit(url or "")
        host, port = parts.hostname, parts.port
    except ValueError:
        return "CHAT_BRIDGE_URL 写得不对"
    if parts.scheme != "http" or parts.username or parts.password or parts.query or parts.fragment \
            or parts.path not in ("", "/"):
        return "CHAT_BRIDGE_URL 只能写成 http://127.0.0.1:端口 或 http://[::1]:端口"
    if host not in ("127.0.0.1", "::1") or port is None:
        return "CHAT_BRIDGE_URL 只能是本机的字面地址加端口（http://127.0.0.1:8796），不能写主机名或别的地址"
    return ""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):    # 令牌在请求头里，不能跟着跳走
        return None


class Bridge:
    def __init__(self, url, token, timeout=TIMEOUT):
        problem = check_url(url)
        if problem:
            raise ValueError(problem)
        if not token:
            raise ValueError("没有配 CHAT_BRIDGE_TOKEN")
        self.base = url.rstrip("/")
        self.token = token
        self.timeout = timeout
        self._opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())

    def _call(self, method, path, body=None, timeout=None):
        data = None if body is None else json.dumps(body, ensure_ascii=False).encode("utf-8")
        request = urllib.request.Request(self.base + path, data=data, method=method)
        request.add_header(TOKEN_HEADER, self.token)
        request.add_header(PROTOCOL_HEADER, str(PROTOCOL))
        if data is not None:
            request.add_header("Content-Type", "application/json")
        try:
            with self._opener.open(request, timeout=timeout or self.timeout) as response:
                status, raw = response.status, response.read(BODY_MAX + 1)
        except urllib.error.HTTPError as exc:
            status, raw = exc.code, exc.read(BODY_MAX + 1)
        except (urllib.error.URLError, OSError, ValueError) as exc:
            reason = getattr(exc, "reason", exc)
            raise BridgeError(f"连不上转接程序：{reason.__class__.__name__}") from None
        try:
            payload = json.loads(raw[:BODY_MAX] or b"{}")
        except ValueError:
            payload = {}
        payload = payload if isinstance(payload, dict) else {}
        if status >= 300:
            message = str(payload.get("error") or f"HTTP {status}")[:200]
            raise BridgeError(message, status=status, definite=bool(payload.get("definite", status != 502)),
                              data=payload)
        return payload

    def health(self) -> dict:
        return self._call("GET", "/health", timeout=5)

    def status(self) -> dict:
        return self._call("GET", "/status", timeout=5)

    def events(self, epoch, after, wait=25.0) -> tuple:
        """(epoch, [消息…])。after 是已经落库的最后编号，同时算确认。转接程序重启过时抛 EpochChanged。"""
        query = urllib.parse.urlencode({"epoch": epoch or "", "after": int(after), "wait": wait})
        try:
            payload = self._call("GET", f"/events?{query}", timeout=wait + POLL_SLACK)
        except BridgeError as exc:
            if exc.status == 409 and exc.data.get("epoch"):
                raise EpochChanged(str(exc.data["epoch"])) from None
            raise
        events = payload.get("events")
        return str(payload.get("epoch") or ""), [e for e in events if isinstance(e, dict)] if isinstance(events, list) else []

    def reply_text(self, handle, text, mention=False) -> dict:
        return self._call("POST", "/reply", {"handle": handle, "text": text, "mention": bool(mention)})

    def reply_stream(self, handle, packet) -> dict:
        return self._call("POST", "/reply", {"handle": handle, "stream": packet})

    def push(self, target, text) -> dict:
        return self._call("POST", "/push", {"target": target, "text": text})


# 打开了云上协同时 chat_api.install 配好一个；推送（chat_push）从这里取。关着时是 None：什么都不推、不碰 chat.db
_current = {"bridge": None}


def configure(url, token) -> Bridge:
    _current["bridge"] = Bridge(url, token)
    return _current["bridge"]


def current() -> Bridge | None:
    return _current["bridge"]


def reset():
    _current["bridge"] = None
