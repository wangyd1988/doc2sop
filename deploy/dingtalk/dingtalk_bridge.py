#!/usr/bin/env python3
"""钉钉转接程序：doc2sop 和钉钉（企业内部应用的机器人，Stream 模式）之间的搬运工。

它只做三件事，不懂任何策略——谁能用、能查什么都在 kb-app：
    收    主动连钉钉的 Stream 通道（出站 WebSocket，不要公网地址、不开端口），只订阅机器人消息这一个 topic。
          群里只有 @ 机器人的消息才会推过来，私聊全推。整理好排队，立刻回 ack
    交    kb-app 带令牌来长轮询取走（GET /events），落库后在下一次轮询时确认
    发    替 kb-app 发消息：回复只能拿收消息时发出的 handle（24 小时内有效），推送只能按 targets.yaml 里
          root 配好的名字——kb-app 拿不到原始的会话 ID、用户 ID、sessionWebhook 去发
    从不自己回话：未开通、暂停、kb-app 不在，这些话都由 kb-app 查过白名单之后再说

对 kb-app 说的是和云上协同转接程序（deploy/ccwork/ccwork_bridge.py）同一套本地接口（协议 1），事件里
platform 是 dingtalk。和平台无关的部分（待取队列、handle、推送目标、本地接口、set-credentials）照着那边写了一份：
systemd 用 python3 -I 跑，两个程序各自独立，不互相 import。

Stream 协议按钉钉官方的协议说明（open-dingtalk/developerpedia docs/learn/stream/protocol.md）自己实现，没有用
官方 SDK（它要的 websockets、aiohttp 比 Ubuntu 24.04 apt 里的新；用 requests 会走环境变量里的代理、跟重定向；
出错时把整帧原文打进日志）。WebSocket 用 apt 的 python3-websocket（websocket-client 1.7），TCP 和 TLS 由这里自己建好
再交给它：不读代理环境变量、不跟重定向、只信系统根证书（或 DINGTALK_CA_FILE）。

收消息：
    机器人消息是 fire-and-forget：断线期间的消息钉钉不补，也不会因为没 ack 重推。仍可能偶发重复 → 按 msgId 去重
    （和 kb-app 的收件表各挡一次）。钉钉推 disconnect 时马上另开一条新连接，旧的等服务端断开（新旧并存期间靠
    msgId 去重，同一把锁里判断）。同一个应用在别处也连着时，钉钉会把消息随机分给其中一条：一个应用只在一处连。
回复：
    用消息里带的 sessionWebhook（约 90 分钟有效，群里能真 @ 提问人）；过期了、或钉钉说它不能用了，就地改走机器人
    发消息接口（群 groupMessages/send、单聊 oToMessages/batchSend，不能 @）。
流式：
    kb-app 发来的流式包不逐包转发（钉钉的普通消息不能改）：中间包只缓存；3 秒内来了 done 就只发一条最终回答，
    没来就先把第一包（「🔎 正在查…」）发一条，done 时再发最终回答。每问最多 2 条。
安全：
    凭据      只从环境变量读（systemd 从 root 600 的 /etc/doc2sop-dingtalk.env 读进来），从不打印。access token、
              Stream 的 ticket、sessionWebhook 都当密钥：不进日志、不进 /status、不进异常说明（websocket 的报错
              只记类名，URL 里有 ticket）
    出网      只连 api.dingtalk.com / oapi.dingtalk.com / *.dingtalk.com 的 443 端口（https、wss），钉钉给的
              endpoint、sessionWebhook 都先核对主机、端口、路径
    本地接口   只听 127.0.0.1 / ::1；全部接口都要令牌（X-Chat-Bridge-Token），带协议版本（X-Chat-Bridge-Protocol）
    节制      单帧不超过 64 KB；每个发送人每分钟 10 条、每个会话 30 条；队列 200 条 / 1 MB；发往钉钉共用一个限速桶，
              每个会话每分钟最多 20 条；每个推送目标每小时最多 20 条，多的合并成一条

用法（依赖：python3-websocket、python3-yaml，都从 apt 装）：
    python3 dingtalk_bridge.py serve             # systemd 里跑这个
    python3 dingtalk_bridge.py check --env-file /etc/doc2sop-dingtalk.env
                                                 # root 手工跑：换 access token、取一次 Stream 的 endpoint（不连），
                                                 # 对 endpoint 的主机只做 TLS 握手
    python3 dingtalk_bridge.py set-credentials   # 从标准输入读 Client ID、Client Secret，写进环境文件（root 600）

本地接口（都要令牌；除 /health 外都要协议版本头）：
    GET  /health                           {"ok": true, "protocol": [1, 1]}
    GET  /status                           连接、计数、推送目标的名字、问题、platform、formats；不含密钥，ID 只有末 4 位
    GET  /events?epoch=&after=&wait=        长轮询取消息；after 是 kb-app 已经落库的最后编号，同时算确认
    POST /reply   {"handle", "text", "mention", "format"} 或 {"handle", "stream": {request_id, seq, type, message_type,
                  content, format}}
    POST /push    {"target": 名字, "text", "format"}
    format 是 text（默认）或 markdown（/status 的 formats 里列着）。
"""
import argparse
import getpass
import hashlib
import hmac
import http.client
import ipaddress
import json
import logging
import os
import re
import secrets
import signal
import socket
import ssl
import sys
import threading
import time
import urllib.parse
from collections import OrderedDict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

try:
    import websocket                    # apt: python3-websocket（websocket-client）
except ImportError:  # 缺包时 serve 照样能起来回 /health，状态里写明
    websocket = None
try:
    import yaml
except ImportError:
    yaml = None

PLATFORM = "dingtalk"
PROTOCOL = (1, 1)
FORMATS = ("text", "markdown")
TOKEN_HEADER = "X-Chat-Bridge-Token"
PROTOCOL_HEADER = "X-Chat-Bridge-Protocol"
LISTEN_DEFAULT = "127.0.0.1:8795"
ENV_FILE = "/etc/doc2sop-dingtalk.env"
TARGETS_FILE = "/etc/doc2sop-dingtalk/targets.yaml"
TZ = timezone(timedelta(hours=8))
UA = "doc2sop-dingtalk/1"

# --- 钉钉接口 -------------------------------------------------------------------------------
API_HOST = "api.dingtalk.com"
OAPI_HOST = "oapi.dingtalk.com"
TOKEN_PATH = "/v1.0/oauth2/accessToken"
OPEN_PATH = "/v1.0/gateway/connections/open"
GROUP_SEND_PATH = "/v1.0/robot/groupMessages/send"
USER_SEND_PATH = "/v1.0/robot/oToMessages/batchSend"
BOT_TOPIC = "/v1.0/im/bot/messages/get"
WEBHOOK_PATH = re.compile(r"^/robot/sendBySession(/[A-Za-z0-9_-]*)?$")
ENDPOINT_PATH = re.compile(r"^/[A-Za-z0-9/_.-]{0,200}$")
HOST_CHARS = re.compile(r"^[a-z0-9.-]{1,253}$")
THROTTLE_CODES = (130101, 130102, 660026)
HTTP_TIMEOUT = 10
RESPONSE_MAX = 256 * 1024
TOKEN_MARGIN = 300                      # access token 到期前 5 分钟就换

# --- 收 ------------------------------------------------------------------------------------
FRAME_MAX = 64 * 1024
TEXT_MAX = 8 * 1024
QUEUE_MAX, QUEUE_BYTES, PER_CHAT_MAX = 200, 1024 * 1024, 50
EVENT_TTL = 600
SENDER_PER_MINUTE, CHAT_PER_MINUTE = 10, 30
SEEN_TTL, SEEN_MAX = 24 * 3600, 20000
FETCH_MAX, WAIT_MAX = 50, 25
CID = re.compile(r"^cid[A-Za-z0-9+/=_-]{4,124}$")
STAFF_ID = re.compile(r"^[!-~]{1,64}$")
MSG_ID = re.compile(r"^[!-~]{1,128}$")

# --- 发 ------------------------------------------------------------------------------------
HANDLE_TTL, HANDLES_MAX = 24 * 3600, 5000
WEBHOOK_MARGIN = 60                     # sessionWebhook 到期前 1 分钟就不用了
OUT_TEXT_MAX = 6000
SEND_RATE, SEND_BURST, SEND_WAIT = 5.0, 10, 10.0
CHAT_SEND_PER_MINUTE = 20
PUSH_PER_HOUR = 20
STREAM_TTL, STREAMS_MAX = 600, 2000
HINT_DELAY = 3.0
REQUEST_ID = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
STREAM_TYPES = ("delta", "done", "error")
STREAM_MODES = ("", "append", "cover")
BODY_MAX = 64 * 1024
SECRET_VALUE = re.compile(r"^[!#-&(-\[\]-~]{1,256}$")    # 可见 ASCII，不含空白、引号、反斜杠

log = logging.getLogger("dingtalk")
_wslog = logging.getLogger("websocket")     # websocket-client 自己的日志：报错里可能带 URL（有 ticket），一律不要
_wslog.disabled = True
_wslog.propagate = False


def tail(value) -> str:
    """会话 ID、用户 ID 在日志和状态里只留末 4 位。"""
    text = str(value or "")
    return "…" + text[-4:] if text else "-"


def now_iso(wall=None) -> str:
    return datetime.fromtimestamp(wall if wall is not None else time.time(), TZ).isoformat(timespec="seconds")


def _clean(text, limit=120) -> str:
    return re.sub(r"[\x00-\x1f\x7f]+", " ", str(text or ""))[:limit]


# === 地址核对 ==================================================================================

def dingtalk_host(host) -> bool:
    """api.dingtalk.com、oapi.dingtalk.com，或以「.dingtalk.com」结尾（带点：evildingtalk.com 不算）。"""
    host = str(host or "")
    if not HOST_CHARS.match(host) or host.startswith(".") or host.endswith(".") or ".." in host:
        return False
    return host in (API_HOST, OAPI_HOST) or host.endswith(".dingtalk.com")


def check_url(url, kind):
    """钉钉的地址（kind = endpoint / webhook / api）：核对过返回 (主机, 443, 请求路径)，不对返回 None。

    endpoint  wss://<*.dingtalk.com>[:443]/路径，不带查询串（ticket 由这里拼上去）
    webhook   https://<*.dingtalk.com>[:443]/robot/sendBySession?…
    api       https://<*.dingtalk.com>[:443]/路径
    都不许带账号密码、片段、反斜杠、空白，端口只能是 443，主机名只能是小写字母、数字、点、减号。"""
    if not isinstance(url, str) or len(url) > 2048 or re.search(r"[\x00-\x20\x7f\\]", url):
        return None
    try:
        parts = urllib.parse.urlsplit(url)
        port = parts.port
    except ValueError:
        return None
    scheme = "wss" if kind == "endpoint" else "https"
    if parts.scheme != scheme or "@" in parts.netloc or parts.fragment or port not in (None, 443):
        return None
    host = parts.hostname or ""
    if parts.netloc not in (host, f"{host}:443") or not dingtalk_host(host):
        return None
    path = parts.path or ""
    if ".." in path or not path.startswith("/"):
        return None
    if kind == "endpoint":
        if parts.query or not ENDPOINT_PATH.match(path):
            return None
    elif kind == "webhook":
        if not WEBHOOK_PATH.match(path) or not parts.query:
            return None
    return host, 443, path + (f"?{parts.query}" if parts.query else "")


# === 配置 ====================================================================================

@dataclass(frozen=True)
class Config:
    enabled: bool = False
    client_id: str = ""
    client_secret: str = ""
    robot_code: str = ""
    send: bool = False
    token: str = ""
    listen: tuple = ("127.0.0.1", 8795)
    targets_file: str = TARGETS_FILE
    ca_file: str = ""

    def __repr__(self):                 # 凭据和令牌不出现在任何字符串里
        return f"Config(enabled={self.enabled}, send={self.send}, listen={self.listen})"


def parse_listen(text):
    host, sep, port = text.strip().rpartition(":")
    host = host.strip("[]")
    if not sep or not ipaddress.ip_address(host).is_loopback:
        raise ValueError
    port = int(port)
    if not 1 <= port <= 65535:
        raise ValueError
    return host, port


def load_config(env=None):
    """(Config, 问题列表)。写错的项按「没配」处理，问题里不带任何密钥。"""
    env = os.environ if env is None else env
    problems = []

    def get(name, default=""):
        return (env.get(name) or default).strip()

    send = get("DINGTALK_SEND", "off").lower()
    if send not in ("on", "off"):
        problems.append("DINGTALK_SEND 只能是 on 或 off，按 off 处理")
    token = get("CHAT_BRIDGE_TOKEN")
    if token and (len(token) < 32 or re.search(r"\s", token)):
        problems.append("CHAT_BRIDGE_TOKEN 至少 32 个字符、不能有空白（建议 openssl rand -hex 32）")
        token = ""
    try:
        listen = parse_listen(get("DINGTALK_LISTEN", LISTEN_DEFAULT))
    except ValueError:
        problems.append("DINGTALK_LISTEN 只能是 127.0.0.1:端口 或 [::1]:端口")
        listen = None
    ca_file = get("DINGTALK_CA_FILE")
    if ca_file and not Path(ca_file).is_file():
        problems.append("DINGTALK_CA_FILE 指的文件不存在")
        ca_file = ""
    client_id = get("DINGTALK_CLIENT_ID")
    robot_code = get("DINGTALK_ROBOT_CODE") or client_id
    if robot_code and not SECRET_VALUE.match(robot_code):
        problems.append("DINGTALK_ROBOT_CODE 写得不对")
        robot_code = ""
    cfg = Config(enabled=get("DINGTALK_ENABLED").lower() in ("1", "true", "yes", "on"), client_id=client_id,
                 client_secret=get("DINGTALK_CLIENT_SECRET"), robot_code=robot_code, send=send == "on", token=token,
                 listen=listen, targets_file=get("DINGTALK_TARGETS_FILE", TARGETS_FILE), ca_file=ca_file)
    return cfg, problems


def tls_context(ca_file=""):
    """校验证书和主机名；配了 DINGTALK_CA_FILE 就只信它（测试），否则用系统根证书。"""
    context = ssl.create_default_context(cafile=ca_file or None)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


# === HTTPS 和 TLS 连接 =========================================================================

class PlatformError(Exception):
    """调钉钉失败。

    definite  钉钉明确没收（业务错误码、参数不对、没连上）；False 是结果不明（发出去以后超时、断开、5xx、回包看不懂）
    sent      请求可能已经到了钉钉；False 时原样重发一定安全
    throttled 钉钉限流（确定没发）
    说明里从不带地址（ticket、sessionWebhook 都在地址里）和请求正文。
    """

    def __init__(self, message, *, status=0, code="", definite=True, sent=True, throttled=False):
        super().__init__(message)
        self.status, self.code, self.definite, self.sent, self.throttled = status, code, definite, sent, throttled


class Net:
    """出网都经这里：TCP 由 dial 建（默认直连，不看代理环境变量），TLS 用我们的上下文、校验证书和主机名。
    dial 可以换（测试里把钉钉的主机名接到本机的假服务上，证书照样按主机名校验）。"""

    def __init__(self, context, dial=None, timeout=HTTP_TIMEOUT):
        self.context, self.timeout = context, timeout
        self._dial = dial or (lambda host, port, timeout: socket.create_connection((host, port), timeout=timeout))

    def connect(self, host, port, timeout=None):
        if not dingtalk_host(host) or port != 443:
            raise PlatformError("地址不是钉钉的", sent=False)
        raw = self._dial(host, port, timeout or self.timeout)
        try:
            raw.settimeout(timeout or self.timeout)
            return self.context.wrap_socket(raw, server_hostname=host)
        except BaseException:
            raw.close()
            raise

    def post(self, url, payload, kind="api", headers=None):
        """(HTTP 状态, JSON 对象)。连不上 → PlatformError(sent=False)；发出去以后出的错 → definite=False。"""
        where = check_url(url, kind)
        if where is None:
            raise PlatformError("地址不是钉钉的", sent=False)
        host, port, target = where
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        try:
            sock = self.connect(host, port)
        except PlatformError:
            raise
        except (OSError, ssl.SSLError, ValueError) as exc:
            raise PlatformError(f"连不上钉钉：{exc.__class__.__name__}", definite=False, sent=False) from None
        conn = http.client.HTTPSConnection(host, port, timeout=self.timeout, context=self.context)
        conn.sock = sock
        try:
            conn.request("POST", target, body, {"Content-Type": "application/json", "Accept": "application/json",
                                                "User-Agent": UA, **(headers or {})})
            response = conn.getresponse()
            status = response.status
            raw = response.read(RESPONSE_MAX + 1)
        except (OSError, ssl.SSLError, http.client.HTTPException, ValueError) as exc:
            raise PlatformError(f"钉钉没有回应：{exc.__class__.__name__}", definite=False) from None
        finally:
            conn.close()
        if 300 <= status < 400:
            raise PlatformError(f"钉钉返回 HTTP {status}（不跟重定向）", status=status)
        if len(raw) > RESPONSE_MAX:
            raise PlatformError("钉钉的响应太大", status=status, definite=False)
        try:
            data = json.loads(raw or b"{}")
        except ValueError:
            data = None
        if not isinstance(data, dict):
            if status >= 500 or status < 300:
                raise PlatformError(f"钉钉的响应看不懂（HTTP {status}）", status=status, definite=False)
            data = {}
        return status, data


def _err(status, data, what):
    code = str(data.get("code") or data.get("errcode") or "")
    message = _clean(data.get("message") or data.get("errmsg"), 80)
    return f"{what}：HTTP {status} {code} {message}".rstrip()


def title_of(text) -> str:
    """markdown 消息的标题（通知栏里显示）：正文第一行去掉 Markdown 记号，最多 20 字。"""
    for line in str(text or "").splitlines():
        line = re.sub(r"[#*_`>\[\]]+", "", line).strip()
        if line:
            return line[:20]
    return "doc2sop"


class Platform:
    """钉钉开放平台：access token、Stream 连接凭证、三种发消息的办法。"""

    def __init__(self, cfg, net):
        self.cfg, self.net = cfg, net
        self.expires_in = 0
        self._token, self._until = "", 0.0
        self._lock = threading.Lock()

    def _fetch_token(self):
        status, data = self.net.post(f"https://{API_HOST}{TOKEN_PATH}",
                                     {"appKey": self.cfg.client_id, "appSecret": self.cfg.client_secret})
        token = data.get("accessToken")
        if status != 200 or not isinstance(token, str) or not token:
            raise PlatformError(_err(status, data, "换 access token 失败"), status=status,
                                code=str(data.get("code") or ""), definite=status < 500)
        try:
            self.expires_in = int(data.get("expireIn") or 7200)
        except (TypeError, ValueError):
            self.expires_in = 7200
        self._token, self._until = token, time.monotonic() + max(60, self.expires_in - TOKEN_MARGIN)
        log.info("access token refreshed (expires_in=%ss)", self.expires_in)
        return token

    def token(self, stale=None):
        """当前的 access token；stale 是刚被钉钉拒了的那个（401）：别的线程已经换过就直接用新的。"""
        with self._lock:
            if self._token and self._token != stale and time.monotonic() < self._until:
                return self._token
            return self._fetch_token()

    def open_connection(self):
        """Stream 第一步：拿 endpoint 和 ticket（90 秒、只能用一次）。返回 (主机, 端口, 带 ticket 的请求路径)。"""
        status, data = self.net.post(f"https://{API_HOST}{OPEN_PATH}", {
            "clientId": self.cfg.client_id, "clientSecret": self.cfg.client_secret,
            "subscriptions": [{"type": "CALLBACK", "topic": BOT_TOPIC}], "ua": UA, "localIp": ""})
        if status != 200:
            raise PlatformError(_err(status, data, "取 Stream 连接失败"), status=status,
                                code=str(data.get("code") or ""), definite=status < 500)
        endpoint, ticket = data.get("endpoint"), data.get("ticket")
        where = check_url(endpoint, "endpoint")
        if where is None:
            raise PlatformError("钉钉给的 Stream 地址不是 wss://*.dingtalk.com:443，不连")
        if not isinstance(ticket, str) or not re.fullmatch(r"[!-~]{1,512}", ticket):
            raise PlatformError("钉钉没有给 ticket")
        host, port, path = where
        return host, port, f"{path}?ticket={urllib.parse.quote(ticket, safe='')}"

    def _openapi(self, path, payload):
        token = self.token()
        status, data = self.net.post(f"https://{API_HOST}{path}", payload,
                                     headers={"x-acs-dingtalk-access-token": token})
        if status == 401:                       # access token 被拒：换一次、重试一次
            token = self.token(stale=token)
            status, data = self.net.post(f"https://{API_HOST}{path}", payload,
                                         headers={"x-acs-dingtalk-access-token": token})
        code = str(data.get("code") or "")
        if status == 429 or "throttl" in code.lower() or "flowcontrol" in code.lower():
            raise PlatformError(_err(status, data, "钉钉限流"), status=status, code=code, throttled=True)
        if status >= 500:
            raise PlatformError(_err(status, data, "钉钉出错"), status=status, code=code, definite=False)
        if status != 200:
            raise PlatformError(_err(status, data, "钉钉拒绝了"), status=status, code=code)
        return data

    @staticmethod
    def _message(text, fmt):
        if fmt == "markdown":
            return "sampleMarkdown", json.dumps({"title": title_of(text), "text": text}, ensure_ascii=False)
        return "sampleText", json.dumps({"content": text}, ensure_ascii=False)

    def send_group(self, chat_id, text, fmt="text"):
        key, param = self._message(text, fmt)
        data = self._openapi(GROUP_SEND_PATH, {"robotCode": self.cfg.robot_code, "openConversationId": chat_id,
                                               "msgKey": key, "msgParam": param})
        if not data.get("processQueryKey"):
            raise PlatformError("钉钉的回包里没有 processQueryKey", status=200, definite=False)
        return {"message_id": str(data["processQueryKey"])[:200]}

    def send_user(self, user_id, text, fmt="text"):
        key, param = self._message(text, fmt)
        data = self._openapi(USER_SEND_PATH, {"robotCode": self.cfg.robot_code, "userIds": [user_id],
                                              "msgKey": key, "msgParam": param})
        if data.get("invalidStaffIdList"):
            raise PlatformError("钉钉说这个用户 ID 不对，或不在应用的可见范围里", status=200)
        if data.get("flowControlledStaffIdList"):
            raise PlatformError("钉钉对这个用户限流", status=200, throttled=True)
        if not data.get("processQueryKey"):
            raise PlatformError("钉钉的回包里没有 processQueryKey", status=200, definite=False)
        return {"message_id": str(data["processQueryKey"])[:200]}

    def send_webhook(self, webhook, text, fmt="text", at=()):
        if fmt == "markdown":
            body = {"msgtype": "markdown", "markdown": {"title": title_of(text), "text": text}}
        else:
            body = {"msgtype": "text", "text": {"content": text}}
        if at:
            body["at"] = {"atUserIds": list(at), "isAtAll": False}
        status, data = self.net.post(webhook, body, kind="webhook")
        try:
            code = int(data.get("errcode") if data.get("errcode") is not None else -1)
        except (TypeError, ValueError):
            code = -1
        if status >= 500:
            raise PlatformError(_err(status, data, "钉钉出错"), status=status, definite=False)
        if code in THROTTLE_CODES or status == 429:
            raise PlatformError(_err(status, data, "钉钉限流"), status=status, code=str(code), throttled=True)
        if status != 200 or code != 0:
            raise PlatformError(_err(status, data, "sessionWebhook 发送失败"), status=status, code=str(code))
        return {}


# === 收 ========================================================================================

def interpret(data):
    """机器人消息（data 是解析好的 dict）→ (去向, 事件, 回复用的信息)。去向是计数用的名字；事件为 None 时不交给 kb-app。"""
    if not isinstance(data, dict):
        return "malformed", None, None
    kind = {"1": "single", "2": "group"}.get(str(data.get("conversationType") or ""))
    if kind is None:
        return "chat_type", None, None
    msg_id, staff, chat_id = data.get("msgId"), data.get("senderStaffId"), data.get("conversationId")
    if not isinstance(msg_id, str) or not MSG_ID.match(msg_id):
        return "malformed", None, None
    if not isinstance(staff, str) or not STAFF_ID.match(staff):
        return "no_staff_id", None, None            # 外部联系人之类：白名单只认企业内的 userId
    sender_corp, bot_corp = data.get("senderCorpId"), data.get("chatbotCorpId")
    if isinstance(sender_corp, str) and isinstance(bot_corp, str) and sender_corp and bot_corp \
            and sender_corp != bot_corp:
        return "other_corp", None, None
    if not isinstance(chat_id, str) or not CID.match(chat_id):
        if kind == "group":
            return "malformed", None, None
        chat_id = ""
    if kind == "group" and data.get("isInAtList") is not True:
        return "not_at", None, None                 # 官方说不会推过来；真来了只计数
    msgtype = data.get("msgtype")
    text = ""
    if msgtype == "text":
        content = data.get("text").get("content") if isinstance(data.get("text"), dict) else None
        text = content if isinstance(content, str) else ""
    elif msgtype == "richText":                     # 图文混排：只取文字
        content = data.get("content") if isinstance(data.get("content"), dict) else {}
        parts = content.get("richText") if isinstance(content.get("richText"), list) else []
        text = "".join(p["text"] for p in parts if isinstance(p, dict) and isinstance(p.get("text"), str))
    text = text.strip()
    event = {"kind": "text" if text else "unsupported", "platform": PLATFORM, "chat_type": kind, "chat_id": chat_id,
             "chat_name": str(data.get("conversationTitle") or "")[:100] if kind == "group" else "",
             "sender_id": staff, "sender_name": str(data.get("senderNick") or "")[:50], "sender_type": 0,
             "msg_key": f"{PLATFORM}:{msg_id}", "text": ""}
    raw = text.encode("utf-8")
    if len(raw) > TEXT_MAX:
        text, event["truncated"] = raw[:TEXT_MAX].decode("utf-8", "ignore"), True
    event["text"] = text
    webhook = data.get("sessionWebhook")
    try:
        expires = int(data.get("sessionWebhookExpiredTime") or 0) / 1000.0
    except (TypeError, ValueError):
        expires = 0.0
    if not (isinstance(webhook, str) and check_url(webhook, "webhook")):
        webhook, expires = "", 0.0
    return ("forwarded" if text else "unsupported"), event, {"webhook": webhook, "webhook_expires": expires}


class EpochMismatch(Exception):
    pass


@dataclass
class _Queued:
    id: int
    chat: str
    size: int
    born: float
    event: dict


class Inbox:
    """内存里的待取队列（和云上协同转接程序的同名类一样）。转接程序崩溃时里面的消息就丢了，明确接受，不落盘。"""

    def __init__(self, clock=time.monotonic, wall=time.time):
        self.clock, self.wall = clock, wall
        self.epoch = secrets.token_hex(8)
        self.counters = {}
        self.last_poll = None
        self._cond = threading.Condition()
        self._items = []
        self._next = 1
        self._bytes = 0
        self._seen = OrderedDict()
        self._hits = {}

    def count(self, name, amount=1):
        with self._cond:
            self.counters[name] = self.counters.get(name, 0) + amount

    def claim(self, key) -> bool:
        """第一次见到这个消息键返回 True。新旧两条连接同时收到同一条时只有一边拿得到（同一把锁里判断、登记）。"""
        now = self.clock()
        with self._cond:
            self._expire(now)
            if key in self._seen:
                self.counters["duplicate"] = self.counters.get("duplicate", 0) + 1
                return False
            self._seen[key] = now
            return True

    def _rate(self, key, limit, now):
        hits = self._hits.setdefault(key, deque())
        while hits and now - hits[0] >= 60:
            hits.popleft()
        if len(hits) >= limit:
            return False
        hits.append(now)
        return True

    def _drop(self, item, reason):
        self._items.remove(item)
        self._bytes -= item.size
        self.counters[reason] = self.counters.get(reason, 0) + 1

    def _expire(self, now):
        for item in [i for i in self._items if now - i.born >= EVENT_TTL]:
            self._drop(item, "expired")
        while self._seen and (len(self._seen) > SEEN_MAX or now - next(iter(self._seen.values())) >= SEEN_TTL):
            self._seen.popitem(last=False)
        for key in [k for k, hits in self._hits.items() if not hits or now - hits[-1] >= 60]:
            del self._hits[key]

    def offer(self, event) -> str:
        """收下一条 claim 过的消息：queued / sender_rate / chat_rate。"""
        now = self.clock()
        chat = f"{event['chat_type']}:{event['chat_id'] or event['sender_id']}"
        with self._cond:
            self._expire(now)
            for key, limit, name in ((f"s:{event['sender_id']}", SENDER_PER_MINUTE, "sender_rate"),
                                     (f"c:{chat}", CHAT_PER_MINUTE, "chat_rate")):
                if not self._rate(key, limit, now):
                    self.counters[name] = self.counters.get(name, 0) + 1
                    return name
            size = len(json.dumps(event, ensure_ascii=False).encode("utf-8"))
            mine = [i for i in self._items if i.chat == chat]
            if len(mine) >= PER_CHAT_MAX:
                self._drop(mine[0], "dropped_chat_full")
            while self._items and (len(self._items) >= QUEUE_MAX or self._bytes + size > QUEUE_BYTES):
                busiest = max({i.chat for i in self._items}, key=lambda c: sum(1 for i in self._items if i.chat == c))
                self._drop(next(i for i in self._items if i.chat == busiest), "dropped_queue_full")
            self._items.append(_Queued(self._next, chat, size, now, event))
            self._next += 1
            self._bytes += size
            self.counters["queued"] = self.counters.get("queued", 0) + 1
            self._cond.notify_all()
            return "queued"

    def fetch(self, epoch, after, wait, limit=FETCH_MAX) -> dict:
        deadline = self.clock() + max(0.0, min(float(wait), WAIT_MAX))
        with self._cond:
            if epoch and epoch != self.epoch:
                raise EpochMismatch(self.epoch)
            if not epoch:
                after = 0                       # 还不知道 epoch 时的编号不作数
            for item in [i for i in self._items if i.id <= after]:     # 确认：kb-app 已经落库的
                self._items.remove(item)
                self._bytes -= item.size
            self.last_poll = self.wall()
            while True:
                self._expire(self.clock())
                ready = [i for i in self._items if i.id > after]
                remaining = deadline - self.clock()
                if ready or remaining <= 0:
                    break
                self._cond.wait(min(remaining, 1.0))
            return {"epoch": self.epoch,
                    "events": [{**i.event, "id": i.id} for i in ready[:max(1, min(int(limit), FETCH_MAX))]]}

    def size(self):
        with self._cond:
            return len(self._items), self._bytes


class Handles:
    """收消息时发给 kb-app 的 handle：后面记着发往哪里（会话、发送人、sessionWebhook），kb-app 只拿得到 handle。"""

    def __init__(self, clock=time.monotonic):
        self.clock = clock
        self._lock = threading.Lock()
        self._items = OrderedDict()

    def issue(self, event, reply=None) -> str:
        handle = secrets.token_urlsafe(18)
        info = {key: event[key] for key in ("chat_type", "chat_id", "sender_id")}
        info.update(reply or {})
        with self._lock:
            self._items[handle] = (self.clock(), info)
            while len(self._items) > HANDLES_MAX:
                self._items.popitem(last=False)
        return handle

    def get(self, handle):
        with self._lock:
            hit = self._items.get(str(handle or ""))
            if hit is None or self.clock() - hit[0] >= HANDLE_TTL:
                return None
            return dict(hit[1])


# === 推送目标 ==================================================================================

class Targets:
    """/etc/doc2sop-dingtalk/targets.yaml：推送目标（名字 → 群的 openConversationId 或企业内 userId）和要屏蔽的发送人。"""

    NAME = re.compile(r"^[^\x00-\x1f\x7f]{1,30}$")

    def __init__(self, path):
        self.path = Path(path)
        self._key = None
        self.targets, self.deny, self.problems = {}, frozenset(), ()

    def load(self):
        try:
            st = self.path.stat()
        except FileNotFoundError:
            self._key, self.targets, self.deny, self.problems = None, {}, frozenset(), ()
            return self
        except OSError as exc:
            self.problems = (f"读不了推送目标文件：{exc.__class__.__name__}",)
            return self
        key = (st.st_mtime_ns, st.st_size)
        if key == self._key:
            return self
        self._key = key
        problems, targets, deny = [], {}, set()
        data = None
        if yaml is None:
            problems.append("缺少 PyYAML（apt install python3-yaml）")
        else:
            try:
                data = yaml.safe_load(self.path.read_text(encoding="utf-8"))
            except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
                problems.append(f"推送目标文件读不了或写错了：{exc.__class__.__name__}")
        data = data or {}
        if not isinstance(data, dict):
            problems.append("推送目标文件最外层要写成「键: 值」")
            data = {}
        for name, spec in (data.get("targets") or {}).items() if isinstance(data.get("targets"), dict) else ():
            name = " ".join(str(name).split())
            spec = spec if isinstance(spec, dict) else {}
            chat_id, user_id = str(spec.get("chat_id") or "").strip(), str(spec.get("user_id") or "").strip()
            if not self.NAME.match(name):
                problems.append("推送目标的名字要是 1–30 个字")
            elif bool(chat_id) == bool(user_id):
                problems.append(f"推送目标「{name}」要写 chat_id 或 user_id 之一")
            elif chat_id and not CID.match(chat_id):
                problems.append(f"推送目标「{name}」的 chat_id 要是 cid 开头的群会话 ID")
            elif user_id and not STAFF_ID.match(user_id):
                problems.append(f"推送目标「{name}」的 user_id 写得不对")
            else:
                targets[name] = ("chat", chat_id) if chat_id else ("user", user_id)
        for entry in data.get("deny_senders") or []:
            if STAFF_ID.match(str(entry).strip()):
                deny.add(str(entry).strip())
        self.targets, self.deny, self.problems = targets, frozenset(deny), tuple(problems)
        if problems:
            log.warning("targets file: %s", "；".join(problems))
        return self


# === 发 ========================================================================================

class TokenBucket:
    def __init__(self, rate, burst, clock=time.monotonic):
        self.rate, self.burst, self.clock = rate, burst, clock
        self._tokens, self._at = float(burst), clock()
        self._lock = threading.Lock()

    def take(self, timeout):
        deadline = self.clock() + timeout
        while True:
            with self._lock:
                now = self.clock()
                self._tokens = min(self.burst, self._tokens + (now - self._at) * self.rate)
                self._at = now
                if self._tokens >= 1:
                    self._tokens -= 1
                    return True
                wait = (1 - self._tokens) / self.rate
            if now + wait > deadline:
                return False
            time.sleep(min(wait, 0.2))


class _Stream:
    """一次流式回答的缓冲状态（按 目的地 + request_id 一个）：waiting →（3 秒）hinted →（done）done。"""

    def __init__(self, born):
        self.lock = threading.Lock()
        self.born = born
        self.phase = "waiting"
        self.first = ""
        self.format = "text"
        self.results = {}                   # seq -> (状态, 回包)
        self.final = None
        self.timer = None


class Outbox:
    """替 kb-app 发消息：回复按 handle、推送按名字；共用一个限速桶；每个会话每分钟最多 CHAT_SEND_PER_MINUTE 条；
    每个推送目标每小时最多 PUSH_PER_HOUR 条。"""

    def __init__(self, platform, targets, clock=time.monotonic, wall=time.time, hint_delay=HINT_DELAY):
        self.platform, self.targets, self.clock, self.wall = platform, targets, clock, wall
        self.hint_delay = hint_delay
        self.bucket = TokenBucket(SEND_RATE, SEND_BURST, clock)
        self.counters = {}
        self._lock = threading.Lock()
        self._streams = OrderedDict()
        self._chat_hits = {}
        self._dead_hooks = OrderedDict()
        self._pushes = {}
        self._held = {}

    def _count(self, name):
        with self._lock:
            self.counters[name] = self.counters.get(name, 0) + 1

    def _chat_ok(self, dest):
        now = self.clock()
        with self._lock:
            for key in [k for k, h in self._chat_hits.items() if not h or now - h[-1] >= 60]:
                del self._chat_hits[key]
            hits = self._chat_hits.setdefault(dest, deque())
            while hits and now - hits[0] >= 60:
                hits.popleft()
            if len(hits) >= CHAT_SEND_PER_MINUTE:
                return False
            hits.append(now)
            return True

    def _send(self, dest, call):
        """(状态, 回包)。200 发出去了；429 确定没发（太快）；502 钉钉明确没收（definite）或结果不明。"""
        if not self._chat_ok(dest):
            self._count("send_chat_limited")
            return 429, {"ok": False, "error": "这个会话一分钟内发得太多，稍后再发", "sent": False}
        if not self.bucket.take(SEND_WAIT):
            self._count("send_throttled")
            return 429, {"ok": False, "error": "发得太快，稍后再发", "sent": False}
        try:
            result = call()
        except PlatformError as exc:
            if exc.throttled:
                self._count("send_throttled")
                return 429, {"ok": False, "error": str(exc), "code": exc.code, "sent": False}
            self._count("send_failed")
            log.warning("send failed: %s", exc)
            return 502, {"ok": False, "error": str(exc), "code": exc.code, "definite": exc.definite, "sent": exc.sent}
        self._count("sent")
        return 200, {"ok": True, **(result or {})}

    @staticmethod
    def _hook_key(webhook):
        return hashlib.sha256(webhook.encode("utf-8")).hexdigest()

    def _hook_usable(self, info):
        webhook = info.get("webhook") or ""
        if not webhook or self.wall() >= float(info.get("webhook_expires") or 0) - WEBHOOK_MARGIN:
            return ""
        with self._lock:
            return "" if self._hook_key(webhook) in self._dead_hooks else webhook

    def _mark_dead(self, webhook):
        with self._lock:
            self._dead_hooks[self._hook_key(webhook)] = self.clock()
            while len(self._dead_hooks) > HANDLES_MAX:
                self._dead_hooks.popitem(last=False)

    def reply(self, info, text, fmt="text", mention=False):
        """回复一条：先用 sessionWebhook（群里 mention 时真 @）；它过期了、或钉钉明确说发不了，就地改走机器人发消息接口。"""
        group = info["chat_type"] != "single"
        dest = f"{info['chat_type']}:{info['chat_id'] or info['sender_id']}"
        webhook = self._hook_usable(info)
        if webhook:
            at = [info["sender_id"]] if mention and group else []
            status, body = self._send(dest, lambda: self.platform.send_webhook(webhook, text, fmt, at))
            if not (status == 502 and body.get("definite")):
                log.info("reply %s:%s via session len=%d → %s", info["chat_type"],
                         tail(info["chat_id"] or info["sender_id"]), len(text), status)
                return status, body
            self._mark_dead(webhook)
            self._count("webhook_fallback")
        if group:
            status, body = self._send(dest, lambda: self.platform.send_group(info["chat_id"], text, fmt))
        else:
            status, body = self._send(dest, lambda: self.platform.send_user(info["sender_id"], text, fmt))
        log.info("reply %s:%s via api len=%d → %s", info["chat_type"], tail(info["chat_id"] or info["sender_id"]),
                 len(text), status)
        return status, body

    # --- 流式：缓冲，每问最多 2 条 ---
    def _stream_state(self, key):
        now = self.clock()
        with self._lock:
            while self._streams:
                old = next(iter(self._streams.values()))
                if len(self._streams) < STREAMS_MAX and now - old.born < STREAM_TTL:
                    break
                self._streams.popitem(last=False)
                if old.timer:
                    old.timer.cancel()
            state = self._streams.get(key)
            if state is None:
                state = self._streams[key] = _Stream(now)
            return state

    def reply_stream(self, info, packet):
        """kb-app 的流式包。中间包只缓存（回 200，kb-app 照常往下走）；done / error 那一包才发最终回答。
        第一包有内容时起一个定时器：hint_delay 秒内 done 没来，就把第一包（「正在查…」）发出去。
        同一个 seq 重发回第一次的结果；进了 done 以后什么都不再发。"""
        state = self._stream_state((info["chat_type"], info["chat_id"], info["sender_id"], packet["request_id"]))
        seq = packet["seq"]
        with state.lock:
            if seq in state.results:
                status, body = state.results[seq]
                return status, {**body, "cached": True}
            if packet["type"] == "delta":
                if state.phase == "waiting" and not state.first and packet["content"].strip():
                    state.first, state.format = packet["content"], packet.get("format") or "text"
                    state.timer = threading.Timer(self.hint_delay, self._hint, (info, state))
                    state.timer.daemon = True
                    state.timer.start()
                state.results[seq] = (200, {"ok": True, "buffered": True})
                return state.results[seq]
            if state.phase == "done":
                state.results[seq] = state.final
                return state.final[0], {**state.final[1], "cached": True}
            if state.timer:
                state.timer.cancel()
            previous, state.phase = state.phase, "done"
            content = packet["content"] if packet["content"].strip() else state.first
            if not content.strip():
                result = (200, {"ok": True, "empty": True})
            else:
                result = self.reply(info, content, packet.get("format") or "text",
                                    mention=info["chat_type"] != "single")
            if result[0] == 429 or (result[0] == 502 and not result[1].get("sent", True)):
                state.phase = previous           # 确定没发出去：同一包原样重发是安全的
                return result
            state.final = result
            state.results[seq] = result
            log.info("reply stream %s:%s req=%s %s → %s", info["chat_type"], tail(info["chat_id"] or info["sender_id"]),
                     tail(packet["request_id"]), "after hint" if previous == "hinted" else "single", result[0])
            return result

    def _hint(self, info, state):
        """hint_delay 秒还没答完：把第一包（回复头 +「🔎 正在查…」）发一条。和 done 抢同一把锁，done 先到就不发。"""
        with state.lock:
            if state.phase != "waiting":
                return
            state.phase = "hinted"
            status, _ = self.reply(info, state.first, state.format, mention=False)
            if status != 200:
                self._count("hint_failed")

    def push(self, name, text, fmt="text"):
        target = self.targets.load().targets.get(name)
        if target is None:
            return 404, {"ok": False, "error": "没有这个推送目标"}
        now = self.clock()
        with self._lock:
            window = self._pushes.setdefault(name, deque())
            while window and now - window[0] >= 3600:
                window.popleft()
            if len(window) >= PUSH_PER_HOUR:    # 告警风暴：不单独发，攒着，窗口空出来时合并成一条
                self._held[name] = self._held.get(name, 0) + 1
                self.counters["push_held"] = self.counters.get("push_held", 0) + 1
                return 202, {"ok": True, "held": True, "pending": self._held[name]}
            window.append(now)
        status, body = self._deliver(target, text, fmt)
        log.info("push %s len=%d → %s", tail(target[1]), len(text), status)
        return status, body

    def _deliver(self, target, text, fmt="text"):
        kind, ident = target
        if kind == "chat":
            return self._send(f"group:{ident}", lambda: self.platform.send_group(ident, text, fmt))
        return self._send(f"single:{ident}", lambda: self.platform.send_user(ident, text, fmt))

    def flush_held(self):
        """攒着的推送：窗口空出来就合并成一条「另有 N 条」。由主循环定时调。"""
        now = self.clock()
        targets = self.targets.load().targets
        with self._lock:
            ready = []
            for name, count in list(self._held.items()):
                window = self._pushes.setdefault(name, deque())
                while window and now - window[0] >= 3600:
                    window.popleft()
                if name not in targets:
                    del self._held[name]
                elif len(window) < PUSH_PER_HOUR:
                    window.append(now)
                    ready.append((name, count))
        for name, count in ready:
            text = f"（过去一小时另有 {count} 条推送因为太多没有单独发，请到网页「SOP → 执行记录」里查看。）"
            status, _ = self._deliver(targets[name], text)
            if status == 200:
                with self._lock:
                    remaining = self._held.get(name, 0) - count
                    if remaining > 0:
                        self._held[name] = remaining
                    else:
                        self._held.pop(name, None)
                log.info("push summary %s: %d held", tail(targets[name][1]), count)


# === Stream 连接 ==============================================================================

class Link:
    """一条 Stream 连接（一个线程）。机器人消息交给 bridge.on_callback 后回 ack；系统 ping 原样带回 opaque；
    disconnect 时通知 bridge 马上另开一条，自己继续收，直到服务端断开（最多 DRAIN_MAX 秒）。"""

    PING_EVERY = 30.0
    DEAD_AFTER = 90.0
    DRAIN_MAX = 20.0
    READ_TICK = 1.0

    def __init__(self, bridge, number):
        self.bridge, self.number = bridge, number
        self.draining = False
        self.healthy = False
        self.closed = threading.Event()
        self.ws = None
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name=f"dingtalk-link-{number}", daemon=True)

    def start(self):
        self._thread.start()
        return self

    def stop(self):
        self._stop.set()
        self._thread.join(timeout=5)

    def _open(self):
        host, port, path = self.bridge.platform.open_connection()
        try:
            sock = self.bridge.net.connect(host, port)
        except PlatformError:
            raise
        except (OSError, ssl.SSLError, ValueError) as exc:
            raise PlatformError(f"Stream 连不上：{exc.__class__.__name__}", definite=False) from None
        try:
            ws = websocket.WebSocket(enable_multithread=True)
            ws.settimeout(HTTP_TIMEOUT)
            # TCP、TLS 都是上面建好的：websocket-client 拿到现成的 socket 就不再查代理、不再包 TLS；不跟重定向
            ws.connect(f"wss://{host}{path}", socket=sock, redirect_limit=0, suppress_origin=True,
                       header={"User-Agent": UA})
        except BaseException:
            sock.close()
            raise
        status = getattr(getattr(ws, "handshake_response", None), "status", 0)
        if status != 101:
            ws.close()
            raise PlatformError(f"Stream 握手返回 HTTP {status}（不跟重定向）")
        ws.settimeout(self.READ_TICK)
        return ws

    def _run(self):
        reason = "closed"
        try:
            try:
                self.ws = self._open()
            except PlatformError as exc:
                self.bridge.link_failed(self, str(exc), auth=exc.definite and 400 <= exc.status < 500)
                return
            except Exception as exc:            # websocket 的报错只记类名：说明里可能带 URL（有 ticket）
                self.bridge.link_failed(self, f"Stream 连不上：{exc.__class__.__name__}")
                return
            self.bridge.link_up(self)
            reason = self._loop()
        finally:
            if self.ws is not None:
                try:
                    self.ws.close(timeout=1)
                except Exception:
                    pass
            self.closed.set()
            if self.ws is not None:
                self.bridge.link_down(self, reason)

    def _loop(self):
        clock = self.bridge.clock
        last_rx = last_ping = clock()
        drain_since = None
        while not self._stop.is_set():
            now = clock()
            if self.draining:
                drain_since = drain_since or now
                if now - drain_since >= self.DRAIN_MAX:
                    return "drained"
            if now - last_rx >= self.DEAD_AFTER:
                return "silent"
            if now - last_ping >= self.PING_EVERY:
                try:
                    self.ws.ping()
                except Exception as exc:
                    return f"ping failed ({exc.__class__.__name__})"
                last_ping = now
            try:
                opcode, frame = self.ws.recv_data_frame(True)
            except websocket.WebSocketTimeoutException:
                continue
            except Exception as exc:
                return f"connection lost ({exc.__class__.__name__})"
            last_rx = clock()
            if opcode == websocket.ABNF.OPCODE_CLOSE:
                return "server closed"
            if opcode not in (websocket.ABNF.OPCODE_TEXT, websocket.ABNF.OPCODE_BINARY):
                continue
            if not self.healthy:
                self.healthy = True
                self.bridge.link_healthy(self)
            try:
                self._frame(frame.data)
            except Exception as exc:            # 一帧怪数据不能让连接挂掉
                self.bridge.warn("frame", f"bad frame: {exc.__class__.__name__}")
        return "stopped"

    def _ack(self, message_id, code=200, message="OK", data='{"response": null}'):
        if message_id:
            self.ws.send(json.dumps({"code": code, "message": message, "data": data,
                                     "headers": {"messageId": message_id, "contentType": "application/json"}}))

    def _frame(self, raw):
        if len(raw) > FRAME_MAX:
            self.bridge.inbox.count("too_large")
            return
        try:
            frame = json.loads(raw)
        except (ValueError, UnicodeDecodeError):
            frame = None
        if not isinstance(frame, dict):
            self.bridge.inbox.count("malformed")
            return
        headers = frame.get("headers") if isinstance(frame.get("headers"), dict) else {}
        message_id = headers.get("messageId") if isinstance(headers.get("messageId"), str) else ""
        topic, kind = headers.get("topic"), frame.get("type")
        if kind == "SYSTEM":
            if topic == "ping":
                data = frame.get("data") if isinstance(frame.get("data"), str) else "{}"
                self._ack(message_id, data=data)
            elif topic == "disconnect":
                self.draining = True
                self.bridge.link_draining(self)
            return
        if kind == "CALLBACK" and topic == BOT_TOPIC:
            try:
                data = json.loads(frame.get("data") or "")
            except (TypeError, ValueError):
                data = None
            self.bridge.on_callback(data)
            self._ack(message_id)
            return
        self.bridge.inbox.count("other_topic")
        self._ack(message_id, code=404, message="not subscribed", data="{}")


# === 转接程序本体 ==============================================================================

class Bridge:
    def __init__(self, cfg, problems=(), clock=time.monotonic, wall=time.time, net=None, tick=1.0,
                 hint_delay=HINT_DELAY):
        self.cfg, self.clock, self.wall, self.tick = cfg, clock, wall, tick
        self.config_problems = tuple(problems)
        self.net = net or Net(tls_context(cfg.ca_file))
        self.platform = Platform(cfg, self.net)
        self.inbox = Inbox(clock, wall)
        self.handles = Handles(clock)
        self.targets = Targets(cfg.targets_file)
        self.outbox = Outbox(self.platform, self.targets, clock, wall, hint_delay)
        self.started_at = wall()
        self._state, self._since, self._problem = ("starting" if cfg.enabled else "disabled"), wall(), ""
        self._lock = threading.Lock()
        self._links = []
        self._serial = 0
        self._attempt = 0
        self._next_at = 0.0
        self._stop = threading.Event()
        self._thread = None
        self._last_warn = {}
        self.reconnects = 0

    # --- 状态 ---
    def set_state(self, state, problem=""):
        with self._lock:
            if state != self._state:
                self._since = self.wall()
            self._state, self._problem = state, problem

    def missing(self):
        """开着却跑不起来的原因（缺包、缺配置）。"""
        out = list(self.config_problems)
        if websocket is None:
            out.append("缺少 python3-websocket（apt install python3-websocket）")
        if yaml is None:
            out.append("缺少 python3-yaml")
        for name, value in (("DINGTALK_CLIENT_ID", self.cfg.client_id),
                            ("DINGTALK_CLIENT_SECRET", self.cfg.client_secret)):
            if not value:
                out.append(f"没配 {name}")
        return out

    def connections(self):
        with self._lock:
            return [link for link in self._links if link.ws is not None and not link.closed.is_set()]

    def status(self) -> dict:
        with self._lock:
            state, since, problem = self._state, self._since, self._problem
        targets = self.targets.load()
        count, size = self.inbox.size()
        problems = list(self.missing() if self.cfg.enabled else self.config_problems)
        if problem:
            problems.append(problem)
        problems += list(targets.problems)
        return {"ok": True, "protocol": list(PROTOCOL), "platform": PLATFORM, "formats": list(FORMATS),
                "enabled": self.cfg.enabled, "state": state, "since": now_iso(since),
                "started_at": now_iso(self.started_at), "tls": True, "diagnose": False,
                "connections": len(self.connections()), "reconnects": self.reconnects, "send": self.cfg.send,
                "robot": tail(self.cfg.robot_code) if self.cfg.robot_code else "", "conflict": False,
                "targets": sorted(targets.targets),
                "target_kinds": {name: kind for name, (kind, _) in sorted(targets.targets.items())},
                "problems": problems, "queue": {"events": count, "bytes": size},
                "kb_app_last_poll": now_iso(self.inbox.last_poll) if self.inbox.last_poll else None,
                "counters": {**self.inbox.counters, **self.outbox.counters}}

    def warn(self, key, message):
        now = self.clock()
        if now - self._last_warn.get(key, -3600) >= 60:
            self._last_warn[key] = now
            log.warning("%s", message)

    def _backoff(self):
        return min(60.0, 2 ** min(self._attempt - 1, 6)) + secrets.randbelow(1000) / 1000

    # --- 连接的回调 ---
    def link_failed(self, link, why, auth=False):
        with self._lock:
            self._attempt += 1
            delay = 600.0 if auth else self._backoff()      # 凭据不对：10 分钟一试
            self._next_at = self.clock() + delay
        self.set_state("problem" if auth else "disconnected", why)
        log.warning("stream #%d failed: %s; retry in %ds", link.number, why, int(delay))

    def link_up(self, link):
        self.set_state("connected")
        log.info("stream #%d connected", link.number)

    def link_healthy(self, link):
        with self._lock:
            self._attempt = 0

    def link_draining(self, link):
        """钉钉说这条连接要断了：马上另开一条（旧的继续收，直到服务端断开）。"""
        with self._lock:
            self._next_at = 0.0
        log.info("stream #%d: server asked to reconnect", link.number)

    def link_down(self, link, reason):
        with self._lock:
            others = [other for other in self._links if other is not link and other.ws is not None
                      and not other.closed.is_set()]
            if not link.draining:
                self._attempt += 1
                self._next_at = self.clock() + self._backoff()
        if not others:
            self.set_state("disconnected", f"连接断开（{reason}）")
        log.info("stream #%d closed: %s", link.number, reason)

    # --- 收 ---
    def on_callback(self, data):
        try:
            outcome, event, reply = interpret(data)
        except Exception as exc:              # 收消息的线程不能因为一条怪消息挂掉
            outcome, event, reply = "malformed", None, None
            self.warn("interpret", f"bad message: {exc.__class__.__name__}")
        if event is None:
            self.inbox.count(outcome)
            return
        if event["sender_id"] in self.targets.load().deny:
            self.inbox.count("denied_sender")
            return
        if not self.inbox.claim(event["msg_key"]):
            return
        self.inbox.count(outcome)
        event["handle"] = self.handles.issue(event, reply)
        event["received_at"] = now_iso(self.wall())
        result = self.inbox.offer(event)
        log.info("message %s:%s from %s kind=%s len=%d → %s", event["chat_type"], tail(event["chat_id"]),
                 tail(event["sender_id"]), event["kind"], len(event["text"]), result)

    # --- 发 ---
    def _can_send(self):
        if not self.cfg.enabled or self.missing():
            return 503, "还没连上钉钉"
        if not self.cfg.send:
            return 403, "发送已关闭（DINGTALK_SEND=off）"
        return 0, ""

    def reply(self, body) -> tuple:
        status, why = self._can_send()
        if status:
            return status, {"ok": False, "error": why}
        info = self.handles.get(body.get("handle"))
        if info is None:
            return 410, {"ok": False, "error": "handle 不存在或已过期（超过 24 小时，或转接程序重启过）"}
        if "stream" in body:
            packet, problem = check_packet(body.get("stream"))
            if problem:
                return 400, {"ok": False, "error": problem}
            return self.outbox.reply_stream(info, packet)
        text, problem = check_text(body.get("text"))
        fmt, bad = check_format(body.get("format"))
        if problem or bad:
            return 400, {"ok": False, "error": problem or bad}
        return self.outbox.reply(info, text, fmt, bool(body.get("mention")))

    def push(self, body) -> tuple:
        status, why = self._can_send()
        if status:
            return status, {"ok": False, "error": why}
        text, problem = check_text(body.get("text"))
        fmt, bad = check_format(body.get("format"))
        if problem or bad:
            return 400, {"ok": False, "error": problem or bad}
        return self.outbox.push(str(body.get("target") or ""), text, fmt)

    # --- 主循环 ---
    def start(self):
        self._thread = threading.Thread(target=self._run, name="dingtalk-bridge", daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=10)
        with self._lock:
            links = list(self._links)
        for link in links:
            link.stop()

    def step(self):
        """主循环的一拍：没有在用的连接（全断了，或者唯一那条在等服务端断开）而且到点了，就开一条新的。"""
        with self._lock:
            self._links = [link for link in self._links if not link.closed.is_set()]
            due = not [link for link in self._links if not link.draining] and self.clock() >= self._next_at
            if due:
                self._serial += 1
                link = Link(self, self._serial)
                self._links.append(link)
                if self._serial > 1:
                    self.reconnects += 1
        if due:
            if self._state != "connected":
                self.set_state("connecting", self._problem)
            link.start()
        if self.cfg.send:
            self.outbox.flush_held()

    def _run(self):
        if not self.cfg.enabled:
            log.info("DINGTALK_ENABLED is off: not connecting")
            return
        while not self._stop.is_set():
            problems = self.missing()
            if problems:
                self.set_state("problem", "；".join(problems))
                self._stop.wait(60)
                continue
            self.step()
            self._stop.wait(self.tick)


def check_text(raw):
    if not isinstance(raw, str) or not raw.strip():
        return "", "text 要是非空字符串"
    if len(raw) > OUT_TEXT_MAX:
        return "", f"text 超过 {OUT_TEXT_MAX} 字"
    if "\x00" in raw:
        return "", "text 里不能有 NUL"
    return raw, ""


def check_format(raw):
    if raw in (None, ""):
        return "text", ""
    if raw not in FORMATS:
        return "", "format 只能是 text 或 markdown"
    return raw, ""


def check_packet(raw):
    if not isinstance(raw, dict):
        return None, "stream 要是对象"
    request_id, seq = str(raw.get("request_id") or ""), raw.get("seq")
    kind, mode, content = raw.get("type"), raw.get("message_type") or "", raw.get("content") or ""
    fmt, bad = check_format(raw.get("format"))
    if not REQUEST_ID.match(request_id):
        return None, "request_id 只能是 1–64 个字母、数字、_、-"
    if not isinstance(seq, int) or isinstance(seq, bool) or not 1 <= seq <= 100000:
        return None, "seq 要是 1–100000 的整数"
    if kind not in STREAM_TYPES or mode not in STREAM_MODES:
        return None, f"type 只能是 {'/'.join(STREAM_TYPES)}，message_type 只能是 append/cover"
    if not isinstance(content, str) or len(content) > OUT_TEXT_MAX or "\x00" in content:
        return None, f"content 要是不超过 {OUT_TEXT_MAX} 字的字符串"
    if bad:
        return None, bad
    return {"request_id": request_id, "seq": seq, "type": kind, "message_type": mode, "content": content,
            "format": fmt}, ""


# === 本地接口 ==================================================================================

class Api(BaseHTTPRequestHandler):
    bridge = None
    token = b""
    timeout = 60
    server_version = "doc2sop-dingtalk"
    sys_version = ""

    def log_message(self, format, *args):    # noqa: A002  不要默认的访问日志
        pass

    def _send(self, status, payload):
        body = json.dumps({k: v for k, v in payload.items() if k != "sent"}, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read(self):
        """先把请求体读掉再回话（不读就关连接，对方可能只收到 RST）。超过 BODY_MAX 回 None。"""
        try:
            length = int(self.headers.get("Content-Length", "") or 0)
        except ValueError:
            length = -1
        if length < 0 or length > BODY_MAX:
            self.close_connection = True
            return None
        return self.rfile.read(length) if length else b""

    def _gate(self, protocol=True):
        supplied = self.headers.get(TOKEN_HEADER, "").encode("utf-8", "replace")
        if not self.token or not hmac.compare_digest(supplied, self.token):
            self._send(401, {"ok": False, "error": "令牌无效"})
            return False
        if protocol:
            try:
                version = int(self.headers.get(PROTOCOL_HEADER, ""))
            except ValueError:
                version = 0
            if not PROTOCOL[0] <= version <= PROTOCOL[1]:
                self._send(409, {"ok": False, "error": "协议版本不兼容", "protocol": list(PROTOCOL)})
                return False
        return True

    def do_GET(self):
        url = urllib.parse.urlsplit(self.path)
        if url.path == "/health":
            if self._gate(protocol=False):
                self._send(200, {"ok": True, "protocol": list(PROTOCOL)})
            return
        if url.path not in ("/status", "/events"):
            return self._send(404, {"ok": False, "error": "Not found"})
        if not self._gate():
            return
        if url.path == "/status":
            return self._send(200, self.bridge.status())
        query = urllib.parse.parse_qs(url.query)
        try:
            after = int((query.get("after") or ["0"])[0])
            wait = float((query.get("wait") or ["0"])[0])
            limit = int((query.get("limit") or [str(FETCH_MAX)])[0])
        except ValueError:
            return self._send(400, {"ok": False, "error": "after、wait、limit 要是数字"})
        try:
            result = self.bridge.inbox.fetch((query.get("epoch") or [""])[0], after, wait, limit)
        except EpochMismatch as exc:
            return self._send(409, {"ok": False, "error": "epoch 变了（转接程序重启过），从 0 重新取",
                                    "epoch": str(exc)})
        self._send(200, {"ok": True, **result})

    def do_POST(self):
        raw = self._read()
        path = urllib.parse.urlsplit(self.path).path
        if path not in ("/reply", "/push"):
            return self._send(404, {"ok": False, "error": "Not found"})
        if not self._gate():
            return
        if raw is None:
            return self._send(413, {"ok": False, "error": f"请求体超过 {BODY_MAX // 1024} KB"})
        try:
            body = json.loads(raw or b"{}")
        except (ValueError, UnicodeDecodeError):
            return self._send(400, {"ok": False, "error": "请求体不是合法的 JSON"})
        if not isinstance(body, dict):
            return self._send(400, {"ok": False, "error": "请求体要是 JSON 对象"})
        status, payload = (self.bridge.reply if path == "/reply" else self.bridge.push)(body)
        self._send(status, payload)


def make_server(bridge, host, port):
    if not ipaddress.ip_address(host).is_loopback:
        raise ValueError("本地接口只能听 127.0.0.1 或 ::1")
    handler = type("BoundApi", (Api,), {"bridge": bridge, "token": bridge.cfg.token.encode("utf-8")})
    server_class = ThreadingHTTPServer
    if ":" in host:
        server_class = type("ThreadingHTTPServer6", (ThreadingHTTPServer,), {"address_family": socket.AF_INET6})
    server = server_class((host, port), handler)
    server.daemon_threads = True
    return server


# === 命令 ======================================================================================

def _setup_logging():
    if not log.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(logging.Formatter("%(levelname)s dingtalk: %(message)s"))
        log.addHandler(handler)
        log.setLevel(logging.INFO)
        log.propagate = False


def _stop(signum, frame):
    raise SystemExit(0)


def serve():
    cfg, problems = load_config()
    if not cfg.token:
        print("错误：环境变量 CHAT_BRIDGE_TOKEN 至少要 32 个字符（kb-app 的 .env 里填同一个值）", file=sys.stderr)
        return 1
    if cfg.listen is None:
        print("错误：DINGTALK_LISTEN 只能是 127.0.0.1:端口 或 [::1]:端口", file=sys.stderr)
        return 1
    bridge = Bridge(cfg, problems)
    server = make_server(bridge, *cfg.listen)
    signal.signal(signal.SIGTERM, _stop)
    log.info("bridge listening on %s:%d; enabled=%s send=%s", cfg.listen[0], cfg.listen[1], cfg.enabled,
             "on" if cfg.send else "off")
    for problem in problems:
        log.warning("config: %s", problem)
    bridge.start()
    try:
        server.serve_forever()
    except (KeyboardInterrupt, SystemExit):
        pass
    finally:
        server.server_close()
        bridge.stop()
        log.info("bridge stopped")
    return 0


def probe_tls(net, host, port) -> str:
    """只做 TLS 握手、看证书，不发 WebSocket 握手（ticket 不用）。"""
    try:
        with net.connect(host, port, timeout=5) as conn:
            cert = conn.getpeercert() or {}
            issuer = dict(item[0] for item in cert.get("issuer", ()))
            return (f"可以：{conn.version()}，签发者 {issuer.get('organizationName') or issuer.get('commonName', '?')}，"
                    f"到期 {cert.get('notAfter', '?')}，主机名校验通过")
    except ssl.SSLCertVerificationError as exc:
        return f"不行：证书校验失败（{exc.verify_message}）"
    except (ssl.SSLError, OSError, PlatformError) as exc:
        return f"不行：{exc.__class__.__name__}"


def check(out=None, env=None, net=None):
    """试连时的只读握手：换 access token → 取一次 Stream 的 endpoint（不连）→ 对 endpoint 的主机只做 TLS 握手。"""
    out = out or sys.stdout
    cfg, problems = load_config(env)
    for problem in problems:
        print(f"配置问题：{problem}", file=out)
    missing = [name for name, value in (("DINGTALK_CLIENT_ID", cfg.client_id),
                                        ("DINGTALK_CLIENT_SECRET", cfg.client_secret)) if not value]
    if missing:
        print(f"没配 {'、'.join(missing)}，没法握手", file=out)
        return 1
    net = net or Net(tls_context(cfg.ca_file))
    platform = Platform(cfg, net)
    try:
        platform.token()
        print(f"换 access token：成功（有效期 {platform.expires_in} 秒）", file=out)
        host, port, _ = platform.open_connection()
        print(f"Stream 连接：钉钉给的地址是 wss://{host}:{port}（ticket 不打印、不用，90 秒后自己作废）", file=out)
    except PlatformError as exc:
        print(f"失败：{exc}", file=out)
        return 1
    print(f"robotCode 末 4 位：{tail(cfg.robot_code)}", file=out)
    result = probe_tls(net, host, port)
    print(f"TLS 探测 {host}:{port}：{result}", file=out)
    return 0 if result.startswith("可以") else 2


def set_credentials(path=ENV_FILE, stdin=None, out=None, interactive=None, now=None):
    """从标准输入读 Client ID、Client Secret（终端上不回显），写进环境文件：原子写入、权限 600；
    改之前的文件留一份 .bak-时间（只留最近这一份：旧密钥不在盘上越积越多）。"""
    stdin, out = stdin or sys.stdin, out or sys.stdout
    interactive = stdin.isatty() if interactive is None else interactive
    if interactive:
        key, secret = getpass.getpass("Client ID: ").strip(), getpass.getpass("Client Secret: ").strip()
    else:
        lines = [line.strip() for line in stdin.read().splitlines() if line.strip()]
        key, secret = (lines + ["", ""])[:2]
    for name, value in (("Client ID", key), ("Client Secret", secret)):
        if not SECRET_VALUE.match(value):
            print(f"错误：{name} 没填，或者含空白、引号、反斜杠", file=out)
            return 1
    target = Path(path)
    lines = []
    backup = None
    if target.exists():
        original = target.read_text(encoding="utf-8")
        lines = [line for line in original.splitlines()
                 if not re.match(r"^\s*DINGTALK_CLIENT_(ID|SECRET)\s*=", line)]
        stamp = (now or datetime.now()).strftime("%Y%m%d%H%M%S")
        for suffix in ("", *(f"-{n}" for n in range(1, 100))):
            backup = target.with_name(f"{target.name}.bak-{stamp}{suffix}")
            try:
                fd = os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                break
            except FileExistsError:
                continue
        else:
            print("错误：备份文件名都被占了", file=out)
            return 1
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(original)
    lines += [f"DINGTALK_CLIENT_ID={key}", f"DINGTALK_CLIENT_SECRET={secret}"]
    temp = target.with_name(f".{target.name}.{secrets.token_hex(4)}.tmp")
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write("\n".join(lines) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, target)
    except BaseException:
        temp.unlink(missing_ok=True)
        raise
    kept = backup.name if backup is not None else ""
    removed = 0
    for old in target.parent.glob(f"{target.name}.bak-*"):
        if old.name != kept:
            old.unlink(missing_ok=True)
            removed += 1
    print(f"已写入 {target}（Client ID 末 4 位 {tail(key)}）。重启转接程序生效：systemctl restart doc2sop-dingtalk",
          file=out)
    if kept:
        print(f"上一版留在 {kept}" + (f"，更早的 {removed} 份备份已删除" if removed else ""), file=out)
    return 0


def read_env_file(path) -> dict:
    """读 systemd 的 EnvironmentFile（KEY=VALUE，# 和 ; 开头是注释，值可以带一对引号），给手工跑 check 用。"""
    out = {}
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line[0] in "#;" or "=" not in line:
            continue
        key, value = (part.strip() for part in line.split("=", 1))
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
            continue
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
            value = value[1:-1]
        out[key] = value
    return out


def main(argv=None):
    parser = argparse.ArgumentParser(description="doc2sop 的钉钉转接程序（只听 127.0.0.1）")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("serve", help="运行（systemd 里用这个）")
    chk = sub.add_parser("check", help="只读握手：换 access token、取 Stream 地址、TLS 探测")
    chk.add_argument("--env-file", help=f"从这个文件读配置（root 手工跑时用 {ENV_FILE}；服务账号自己读不到它）")
    creds = sub.add_parser("set-credentials", help="写入 Client ID、Client Secret")
    creds.add_argument("--env-file", default=ENV_FILE)
    args = parser.parse_args(argv)
    _setup_logging()
    if args.command == "check":
        env = None
        if args.env_file:
            try:
                env = {**os.environ, **read_env_file(args.env_file)}
            except (OSError, UnicodeDecodeError) as exc:
                print(f"错误：读不了 {args.env_file}（{exc.__class__.__name__}），要用 root 跑", file=sys.stderr)
                return 1
        return check(env=env)
    if args.command == "set-credentials":
        return set_credentials(args.env_file)
    return serve()


if __name__ == "__main__":
    sys.exit(main())
