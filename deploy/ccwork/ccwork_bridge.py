#!/usr/bin/env python3
"""云上协同转接程序：doc2sop 和云上协同（浪潮的协同办公软件）之间的搬运工。

它只做三件事，不懂任何策略——谁能用、能查什么都在 kb-app：
    收    用应用机器人的身份连云上协同的 MQTT（必须 TLS）。收到推送先看大小，再解码、解密，丢掉不该收的
          （自己发的、群里没 @ 它的、非文字的、文件传输助手之类的会话），剩下的整理好排队
    交    kb-app 带令牌来长轮询取走（GET /events），落库后在下一次轮询时确认
    发    替 kb-app 发文字和流式消息：回复只能拿收消息时发出的 handle（24 小时内有效），推送只能按
          targets.yaml 里 root 配好的名字——kb-app 拿不到原始的会话 ID 去发
    从不自己回话：未开通、暂停、kb-app 不在，这些话都由 kb-app 查过白名单之后再说

协议（换令牌、读机器人信息、组织路由、MQTT 账号、消息字段号、加解密规则）按开放平台的接口行为自己实现，
没有拷官方开发包（ccwork-sdk/ccwork-chat-sdk-go，没有许可证）的代码。

安全：
    凭据      只从环境变量读（systemd 从 root 600 的 /etc/doc2sop-ccwork.env 读进来），从不打印；平台请求和
              响应的正文、消息内容一律不进日志；会话 ID、用户 ID、MQTT 主题只记末 4 位；paho 自己的日志不开
    MQTT      只连 ssl://，校验证书和主机名，心跳 60 秒；tcp:// 要 CCWORK_ALLOW_PLAINTEXT=diagnose，而且只诊断：
              收、计数，不交给 kb-app、不发任何东西（明文时信封可以被改，白名单就不可靠了）
    平台接口   只接受 https://；不走环境变量里的代理、不跟重定向（令牌在请求头里）
    本地接口   只听 127.0.0.1 / ::1；全部接口都要令牌（X-Chat-Bridge-Token），带协议版本（X-Chat-Bridge-Protocol）
    节制      解密前单条载荷不超过 64 KB；每个发送人每分钟 10 条、每个会话 30 条；队列 200 条 / 1 MB，一个会话
              最多占 50 条；发往平台的调用共用一个限速桶；每个推送目标每小时最多 20 条，多的合并成一条

用法（依赖：python3-paho-mqtt、python3-cryptography、python3-yaml，都从 apt 装）：
    python3 ccwork_bridge.py serve             # systemd 里跑这个
    python3 ccwork_bridge.py check             # 只读握手：换令牌、读机器人信息、查组织路由，对 broker 只做 TLS 握手
    python3 ccwork_bridge.py set-credentials   # 从标准输入读 app-key、app-secret，写进环境文件（root 600）

本地接口（都要令牌；除 /health 外都要协议版本头）：
    GET  /health                           {"ok": true, "protocol": [1, 1]}
    GET  /status                           连接、计数、推送目标的名字、问题；不含密钥，ID 只有末 4 位
    GET  /events?epoch=&after=&wait=        长轮询取消息；after 是 kb-app 已经落库的最后编号，同时算确认；
                                           epoch 对不上回 409，带上新的 epoch
    POST /reply   {"handle", "text", "mention"} 或 {"handle", "stream": {request_id, seq, type, message_type, content}}
    POST /push    {"target": 名字, "text"}
"""
import argparse
import getpass
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
import urllib.error
import urllib.parse
import urllib.request
from collections import OrderedDict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except ImportError:  # 缺包时 serve 照样能起来回 /health，状态里写明
    Cipher = algorithms = modes = None
try:
    import paho.mqtt.client as paho
except ImportError:
    paho = None
try:
    import yaml
except ImportError:
    yaml = None

PROTOCOL = (1, 1)                       # 本地接口支持的协议版本范围
TOKEN_HEADER = "X-Chat-Bridge-Token"
PROTOCOL_HEADER = "X-Chat-Bridge-Protocol"
LISTEN_DEFAULT = "127.0.0.1:8796"
ENV_FILE = "/etc/doc2sop-ccwork.env"
TARGETS_FILE = "/etc/doc2sop-ccwork/targets.yaml"
SAAS_DEFAULT = "https://r.ccwork.com"
APP_VERSION = "4.2.0"                   # 组织路由接口要的客户端版本号
TZ = timezone(timedelta(hours=8))

# --- 平台接口 ------------------------------------------------------------------------------
TOKEN_PATH = "/service/get_inner_token"
ROBOT_PATH = "/cloud/open/getRobotInfo"
ROUTER_PATH = "/api/router/v2.0/OrgRouter"
SEND_CHAT_PATH = "/cloudplus/openplatform/applicationRobotSendMsg"
SEND_USER_PATH = "/cloudplus/openplatform/appbotSendMsgByUserId"
STREAM_CHAT_PATH = "/cloudplus/openplatform/robotSendStream"
STREAM_USER_PATH = "/cloudplus/openplatform/appbotSendStreamMsgByUserId"
SUCCESS = ("", "0000", "OK")
EXPIRED = "0704"
HTTP_TIMEOUT = 10
RESPONSE_MAX = 256 * 1024

# --- 收 ------------------------------------------------------------------------------------
PAYLOAD_MAX = 64 * 1024                 # 解密之前，单条 MQTT 载荷的上限
TEXT_MAX = 8 * 1024                     # 交给 kb-app 的单条正文上限（字节）
KEEPALIVE = 60
QUEUE_MAX, QUEUE_BYTES, PER_CHAT_MAX = 200, 1024 * 1024, 50
EVENT_TTL = 600                         # 秒：kb-app 这么久还没取走就丢掉
SENDER_PER_MINUTE, CHAT_PER_MINUTE = 10, 30
SEEN_TTL, SEEN_MAX = 24 * 3600, 20000   # 去重：QoS 1 可能重发同一条
FETCH_MAX, WAIT_MAX = 50, 25
CONFLICT_SHORT, CONFLICT_WINDOW, CONFLICT_COUNT = 30, 600, 3   # 连上不到 30 秒就被断开，10 分钟里 3 次：疑似互踢
CONFLICT_DELAY, STABLE_SECONDS = 300, 600

# --- 发 ------------------------------------------------------------------------------------
HANDLE_TTL, HANDLES_MAX = 24 * 3600, 5000
OUT_TEXT_MAX = 6000                     # 单条发出去的文字上限（字）
SEND_RATE, SEND_BURST, SEND_WAIT = 5.0, 10, 10.0
PUSH_PER_HOUR = 20
STREAM_CACHE_TTL, STREAM_CACHE_MAX = 600, 2000
REQUEST_ID = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
STREAM_TYPES = ("delta", "done", "error")
STREAM_MODES = ("", "append", "cover")
BODY_MAX = 64 * 1024

log = logging.getLogger("ccwork")


def tail(value) -> str:
    """会话 ID、用户 ID、MQTT 主题在日志和状态里只留末 4 位。"""
    text = str(value or "")
    return "…" + text[-4:] if text else "-"


def now_iso(wall=None) -> str:
    return datetime.fromtimestamp(wall if wall is not None else time.time(), TZ).isoformat(timespec="seconds")


def _clean(text, limit=120) -> str:
    """平台报错里的说明：去掉控制字符、截短。只用在状态和日志里，平台响应的正文本身从不记录。"""
    return re.sub(r"[\x00-\x1f\x7f]+", " ", str(text or ""))[:limit]


# === 配置 ====================================================================================

@dataclass(frozen=True)
class Broker:
    tls: bool
    host: str
    port: int

    def __str__(self):
        return f"{'ssl' if self.tls else 'tcp'}://{self.host}:{self.port}"


def parse_broker(text) -> Broker:
    parts = urllib.parse.urlsplit(text.strip())
    scheme = parts.scheme.lower()
    if scheme in ("ssl", "tls", "mqtts"):
        tls = True
    elif scheme in ("tcp", "mqtt"):
        tls = False
    else:
        raise ValueError("要写成 ssl://主机:端口")
    try:
        port = parts.port
    except ValueError:
        raise ValueError("端口不对") from None
    if not parts.hostname or parts.username or parts.password or parts.path not in ("", "/") or parts.query:
        raise ValueError("要写成 ssl://主机:端口")
    return Broker(tls, parts.hostname, port or (8883 if tls else 1883))


def _https(url) -> bool:
    parts = urllib.parse.urlsplit(url)
    return parts.scheme == "https" and bool(parts.hostname) and not parts.username and not parts.query


@dataclass(frozen=True)
class Config:
    enabled: bool = False
    app_key: str = ""
    app_secret: str = ""
    base_url: str = ""
    saas_host: str = SAAS_DEFAULT
    broker: Broker | None = None
    plaintext: bool = False             # CCWORK_ALLOW_PLAINTEXT=diagnose：允许 tcp://，只诊断
    send: bool = False
    token: str = ""
    listen: tuple = ("127.0.0.1", 8796)
    targets_file: str = TARGETS_FILE
    ca_file: str = ""

    def __repr__(self):                 # 凭据和令牌不出现在任何字符串里
        return (f"Config(enabled={self.enabled}, base_url={self.base_url!r}, broker={str(self.broker or '')!r}, "
                f"plaintext={self.plaintext}, send={self.send}, listen={self.listen})")


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

    base_url = get("CCWORK_BASE_URL").rstrip("/")
    if base_url and not _https(base_url):
        problems.append("CCWORK_BASE_URL 要是 https:// 开头的地址（平台接口带着凭据，不能明文）")
        base_url = ""
    saas = get("CCWORK_SAAS_HOST", SAAS_DEFAULT).rstrip("/")
    if not _https(saas):
        problems.append("CCWORK_SAAS_HOST 要是 https:// 开头的地址")
        saas = ""
    mode = get("CCWORK_ALLOW_PLAINTEXT").lower()
    if mode not in ("", "diagnose"):
        problems.append("CCWORK_ALLOW_PLAINTEXT 只能留空或写 diagnose（只诊断：收、计数，不交给 kb-app、不发）")
    plaintext = mode == "diagnose"
    broker = None
    if get("CCWORK_BROKER"):
        try:
            broker = parse_broker(get("CCWORK_BROKER"))
        except ValueError as exc:
            problems.append(f"CCWORK_BROKER {exc}")
    send = get("CCWORK_SEND", "off").lower()
    if send not in ("on", "off"):
        problems.append("CCWORK_SEND 只能是 on 或 off，按 off 处理")
    crypto = get("CCWORK_CRYPTO", "builtin").lower()
    if crypto != "builtin":
        problems.append("CCWORK_CRYPTO 只支持 builtin（不用厂商的加密程序）")
    token = get("CHAT_BRIDGE_TOKEN")
    if token and (len(token) < 32 or re.search(r"\s", token)):
        problems.append("CHAT_BRIDGE_TOKEN 至少 32 个字符、不能有空白（建议 openssl rand -hex 32）")
        token = ""
    try:
        listen = parse_listen(get("CCWORK_LISTEN", LISTEN_DEFAULT))
    except ValueError:
        problems.append("CCWORK_LISTEN 只能是 127.0.0.1:端口 或 [::1]:端口")
        listen = None
    ca_file = get("CCWORK_CA_FILE")
    if ca_file and not Path(ca_file).is_file():
        problems.append("CCWORK_CA_FILE 指的文件不存在")
        ca_file = ""
    cfg = Config(enabled=get("CCWORK_ENABLED").lower() in ("1", "true", "yes", "on"),
                 app_key=get("CCWORK_APP_KEY"), app_secret=get("CCWORK_APP_SECRET"), base_url=base_url,
                 saas_host=saas, broker=broker, plaintext=plaintext, send=send == "on", token=token,
                 listen=listen, targets_file=get("CCWORK_TARGETS_FILE", TARGETS_FILE), ca_file=ca_file)
    return cfg, problems


def tls_context(ca_file=""):
    """校验证书和主机名的 TLS 上下文；配了 CCWORK_CA_FILE 就只信它（私有 CA、测试），否则用系统根证书。"""
    context = ssl.create_default_context(cafile=ca_file or None)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


# === 加解密 ===================================================================================
# 消息体的加密由 externalType 的两个标志位决定：0x02 是 AES，0x40 是国密 SM4。
# 只有 0x40 时用 SM4；有 0x02、或者两位都没有，都按 AES 解；两位都在时平台按「不加密」处理。
# AES 是 ECB 模式；SM4 是 CBC 模式；都用 PKCS7 填充；密钥就是机器人信息里 DecryptKey 的 UTF-8 字节。
# SM4 的 IV 由密钥本身排出来：密钥第 0、2、4…个字符，接着第 1、3、5…个字符（一共 16 字节）；密钥不是合法的
# UTF-8 时 IV 全 0。这条规则是拿厂商程序的对照数据核出来的（tests/fixtures/ccwork_crypto_vectors.json）：
# 字母数字密钥和随机二进制密钥两种情况都逐字节对上；DecryptKey 是接口返回的字符串，实际只会是前一种。

AES, SM4 = "aes", "sm4"
AES_BIT, SM4_BIT = 0x02, 0x40


class CryptoError(ValueError):
    pass


def cipher_for(external_type):
    aes, sm4 = bool(external_type & AES_BIT), bool(external_type & SM4_BIT)
    if aes and sm4:
        return None
    return SM4 if sm4 else AES


def sm4_iv(key: bytes) -> bytes:
    try:
        text = key.decode("utf-8")
    except UnicodeDecodeError:
        return bytes(16)
    iv = (text[0::2] + text[1::2]).encode("utf-8")
    return iv if len(iv) == 16 else bytes(16)


def _cipher(alg, key):
    if Cipher is None:
        raise CryptoError("缺少 cryptography（apt install python3-cryptography）")
    if alg == AES:
        if len(key) not in (16, 24, 32):
            raise CryptoError(f"AES 密钥要 16、24 或 32 字节，现在是 {len(key)} 字节")
        return Cipher(algorithms.AES(key), modes.ECB())
    if alg == SM4:
        if len(key) != 16:
            raise CryptoError(f"SM4 密钥要 16 字节，现在是 {len(key)} 字节")
        return Cipher(algorithms.SM4(key), modes.CBC(sm4_iv(key)))
    raise CryptoError(f"不认识的算法 {alg}")


def encrypt(alg, data: bytes, key: bytes) -> bytes:
    """只给测试和对照数据用：转接程序自己从不加密。"""
    pad = 16 - len(data) % 16
    worker = _cipher(alg, key).encryptor()
    return worker.update(bytes(data) + bytes([pad]) * pad) + worker.finalize()


def decrypt(alg, data: bytes, key: bytes) -> bytes:
    if not data or len(data) % 16:
        raise CryptoError("密文长度不是 16 字节的整数倍")
    worker = _cipher(alg, key).decryptor()
    plain = worker.update(bytes(data)) + worker.finalize()
    pad = plain[-1]
    if not 1 <= pad <= 16 or plain[-pad:] != bytes([pad]) * pad:
        raise CryptoError("填充不对（密钥或算法不对）")
    return plain[:-pad]


# === protobuf：只解用得到的字段 ================================================================
# 字段号来自开放平台的消息定义：ChatMessage（推送的信封）、ChatUser（发送人）、Text（文字消息）、
# MixedContent（图文混编）、Quote（引用回复）。解码有上限：嵌套层数、字段个数、重复字段个数，长度一律核对。

DEPTH_MAX, FIELDS_MAX, REPEATED_MAX = 4, 4096, 512


class ProtoError(ValueError):
    pass


def _varint(buf, pos):
    value = shift = 0
    for _ in range(10):
        if pos >= len(buf):
            raise ProtoError("varint 截断")
        byte = buf[pos]
        pos += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, pos
        shift += 7
    raise ProtoError("varint 超过 10 字节")


def _fields(buf):
    pos = count = 0
    while pos < len(buf):
        count += 1
        if count > FIELDS_MAX:
            raise ProtoError("字段太多")
        key, pos = _varint(buf, pos)
        number, wire = key >> 3, key & 7
        if not 1 <= number < 1 << 29:
            raise ProtoError("字段号不对")
        if wire == 0:
            value, pos = _varint(buf, pos)
        elif wire in (1, 5):
            size = 8 if wire == 1 else 4
            if pos + size > len(buf):
                raise ProtoError("定长字段截断")
            value, pos = buf[pos:pos + size], pos + size
        elif wire == 2:
            size, pos = _varint(buf, pos)
            if size > len(buf) - pos:
                raise ProtoError("长度超出消息")
            value, pos = buf[pos:pos + size], pos + size
        else:
            raise ProtoError(f"不支持的编码类型 {wire}")
        yield number, wire, value


USER = {1: ("user_id", "str"), 2: ("name", "str"), 4: ("user_type", "int")}
MESSAGE = {1: ("message_type", "int"), 2: ("chat_id", "uint"), 3: ("sender", USER), 5: ("external_type", "int"),
           6: ("msg_id", "uint"), 8: ("content", "bytes"), 11: ("chat_type", "int"), 12: ("chat_name", "str"),
           15: ("msg_uniq_id", "uint")}
TEXT = {1: ("text", "str"), 2: ("at", "str*"), 3: ("at_all", "bool")}
MIXED = {2: ("at", "str*"), 3: ("at_all", "bool")}
QUOTE = {1: ("message", TEXT)}
_WIRE = {"str": 2, "str*": 2, "bytes": 2, "uint": 0, "int": 0, "bool": 0}


def decode(buf, schema, depth=0) -> dict:
    if depth > DEPTH_MAX:
        raise ProtoError("嵌套太深")
    out = {}
    for number, wire, value in _fields(bytes(buf)):
        spec = schema.get(number)
        if spec is None:
            continue
        name, kind = spec
        expected = 2 if isinstance(kind, dict) else _WIRE[kind]
        if wire != expected:
            raise ProtoError(f"字段 {number} 的编码类型不对")
        if isinstance(kind, dict):
            out[name] = decode(value, kind, depth + 1)
        elif kind in ("str", "str*"):
            text = value.decode("utf-8", "replace")
            if kind == "str":
                out[name] = text
            else:
                items = out.setdefault(name, [])
                if len(items) >= REPEATED_MAX:
                    raise ProtoError("重复字段太多")
                items.append(text)
        elif kind == "bytes":
            out[name] = value
        elif kind == "uint":
            out[name] = value
        elif kind == "int":                 # int32：负数按 64 位补码编码，取低 32 位
            value &= 0xFFFFFFFF
            out[name] = value - (1 << 32) if value >= 1 << 31 else value
        else:
            out[name] = bool(value)
    return out


# === 收到一条推送：解码、解密、过滤，整理成交给 kb-app 的消息 ====================================

CHAT_TYPES = {1: "single", 2: "group", 3: "org", 4: "dept"}    # 6 自己、7 文件传输助手、8 聊天归集：不理
MSG_TEXT, MSG_MIXED, MSG_QUOTE, MSG_ORDER = 1, 14, 999, 6666
# 人发的、但我们看不了的内容：图片、文件、小视频、名片、语音、位置、分享、引用图文混编。私聊里收到时告诉对方「只能看文字」；
# 系统通知、指令、流式消息这类不是人发的，一律不理
USER_CONTENT = {2, 3, 4, 5, 6, 8, 10, 1000}


@dataclass(frozen=True, repr=False)
class Robot:
    robot_id: str
    org_id: str
    org_code: str
    password: str                       # MQTT 密码（机器人信息里的 jwtToken）
    key: bytes                          # 解密消息体的密钥（DecryptKey）
    hint: str = ""                      # 机器人信息里的 mqtt 字段（含义待试连确认，只在 check 里看形状）

    @property
    def username(self):
        return f"{self.org_id}_{self.robot_id}"

    @property
    def client_id(self):
        return f"{self.org_id}_{self.robot_id}_sdk"

    @property
    def topic(self):
        return self.username

    def __repr__(self):
        return f"Robot({tail(self.robot_id)}, org={self.org_code})"


def interpret(payload, robot):
    """(去向, 消息)。去向是计数用的名字；只有 text / unsupported / undecryptable 三种会交给 kb-app。"""
    if len(payload) > PAYLOAD_MAX:
        return "too_large", None
    try:
        msg = decode(payload, MESSAGE)
    except ProtoError:
        return "malformed", None
    kind = msg.get("message_type", 0)
    if kind == MSG_ORDER:
        return "order", None
    sender = msg.get("sender") or {}
    if sender.get("user_id") == robot.robot_id:
        return "self", None
    chat_type = CHAT_TYPES.get(msg.get("chat_type", 0))
    if chat_type is None:
        return "chat_type", None
    single = chat_type == "single"
    if kind not in (MSG_TEXT, MSG_MIXED, MSG_QUOTE):
        # 图片、文件、语音……群里看不出 @ 了谁（@ 列表在文字里），只有私聊时告诉对方「只能看文字」
        if single and kind in USER_CONTENT:
            return "unsupported", _event(msg, "unsupported", chat_type)
        return "not_text", None
    content = msg.get("content") or b""
    alg = cipher_for(msg.get("external_type", 0))
    if content and alg:
        try:
            content = decrypt(alg, content, robot.key)
        except CryptoError:
            return (f"decrypt_failed_{alg}", _event(msg, "undecryptable", chat_type) if single else None)
    try:
        if kind == MSG_TEXT:
            body = decode(content, TEXT)
        elif kind == MSG_MIXED:
            body = decode(content, MIXED)
        else:
            body = decode(content, QUOTE).get("message") or {}
    except ProtoError:
        return "malformed", None
    if not single and robot.robot_id not in (body.get("at") or []):
        return "not_at", None                       # 群里没 @ 它（@所有人不算）：当场丢掉，只计数
    if kind != MSG_TEXT:
        return "unsupported", _event(msg, "unsupported", chat_type)
    text = body.get("text") or ""
    event = _event(msg, "text", chat_type)
    raw = text.encode("utf-8")
    if len(raw) > TEXT_MAX:
        text, event["truncated"] = raw[:TEXT_MAX].decode("utf-8", "ignore"), True
    event["text"] = text
    return "forwarded", event


def _event(msg, kind, chat_type):
    sender = msg.get("sender") or {}
    chat_id = str(msg.get("chat_id", 0))
    key = str(msg.get("msg_uniq_id") or f"{chat_id}:{msg.get('msg_id', 0)}")
    return {"kind": kind, "platform": "ccwork", "chat_type": chat_type, "chat_id": chat_id,
            "chat_name": (msg.get("chat_name") or "")[:100], "sender_id": sender.get("user_id") or "",
            "sender_name": (sender.get("name") or "")[:50], "sender_type": sender.get("user_type", 0),
            "msg_key": key, "text": ""}


# === 队列：交给 kb-app 之前 =====================================================================

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
    """内存里的待取队列。转接程序崩溃时里面的消息就丢了——和 MQTT 掉线期间一样，明确接受，不落盘。"""

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
        """收下一条消息：queued / duplicate / sender_rate / chat_rate。"""
        now = self.clock()
        chat = f"{event['chat_type']}:{event['chat_id']}"
        with self._cond:
            self._expire(now)
            if event["msg_key"] in self._seen:
                self.counters["duplicate"] = self.counters.get("duplicate", 0) + 1
                return "duplicate"
            self._seen[event["msg_key"]] = now
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
                # 队列满了：丢占得最多的那个会话里最旧的一条，一个群刷屏挤不掉别的群
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
                after = 0                       # 还不知道 epoch 时的编号不作数：可能是转接程序重启前的
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
    """收消息时发给 kb-app 的 handle：回复只能拿它，拿不到原始会话 ID。24 小时内有效，转接程序重启就作废。"""

    def __init__(self, clock=time.monotonic):
        self.clock = clock
        self._lock = threading.Lock()
        self._items = OrderedDict()

    def issue(self, event) -> str:
        handle = secrets.token_urlsafe(18)
        info = {key: event[key] for key in ("chat_type", "chat_id", "sender_id")}
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


# === 平台接口 ==================================================================================

class PlatformError(Exception):
    """调平台接口失败。definite=False 表示结果不明（超时、断网、5xx）：平台可能已经收到了。"""

    def __init__(self, message, code="", status=0, definite=True):
        super().__init__(message)
        self.code, self.status, self.definite = code, status, definite


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):     # 令牌在请求头里，不能跟着跳走
        return None


class Platform:
    def __init__(self, cfg, context=None, timeout=HTTP_TIMEOUT):
        self.cfg = cfg
        self.timeout = timeout
        self.expires_in = 0
        self._token = ""
        self._lock = threading.Lock()
        self._opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect(),
                                                   urllib.request.HTTPSHandler(context=context or tls_context(cfg.ca_file)))

    def _request(self, url, data, content_type, headers=None):
        try:
            request = urllib.request.Request(url, data=data, method="POST",
                                             headers={"Content-Type": content_type, **(headers or {})})
            with self._opener.open(request, timeout=self.timeout) as response:
                raw = response.read(RESPONSE_MAX + 1)
        except urllib.error.HTTPError as exc:
            status = exc.code
            exc.close()
            raise PlatformError(f"平台返回 HTTP {status}", status=status, definite=status < 500) from None
        except (urllib.error.URLError, OSError, ValueError, http.client.HTTPException) as exc:
            reason = getattr(exc, "reason", exc)
            raise PlatformError(f"连不上平台：{reason.__class__.__name__}", definite=False) from None
        if len(raw) > RESPONSE_MAX:
            raise PlatformError("平台的响应太大")
        try:
            body = json.loads(raw)
        except ValueError:
            raise PlatformError("平台的响应不是 JSON") from None
        if not isinstance(body, dict):
            raise PlatformError("平台的响应不是 JSON 对象")
        return body

    @staticmethod
    def _data(body):
        code = str(body.get("code") if body.get("code") is not None else "")
        if code not in SUCCESS:
            raise PlatformError(f"平台返回 {code}：{_clean(body.get('message'))}", code=code)
        return body.get("data")

    def _fetch_token(self):
        form = urllib.parse.urlencode({"appKey": self.cfg.app_key, "appSecret": self.cfg.app_secret}).encode()
        data = self._data(self._request(self.cfg.base_url + TOKEN_PATH, form, "application/x-www-form-urlencoded"))
        token = (data or {}).get("access_token") if isinstance(data, dict) else None
        if not token or not isinstance(token, str):
            raise PlatformError("换令牌的响应里没有 access_token")
        self._token = token
        try:
            self.expires_in = int((data or {}).get("expires_in") or 0)
        except (TypeError, ValueError):
            self.expires_in = 0
        log.info("access token refreshed (expires_in=%ss)", self.expires_in)
        return token

    def token(self):
        with self._lock:
            return self._token or self._fetch_token()

    def _call(self, path, payload):
        token = self.token()
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        body = self._request(self.cfg.base_url + path, data, "application/json", {"access_token": token})
        if str(body.get("code")) == EXPIRED:
            with self._lock:                    # 别的线程已经换过就不再换
                if self._token == token:
                    self._fetch_token()
                token = self._token
            body = self._request(self.cfg.base_url + path, data, "application/json", {"access_token": token})
        return self._data(body)

    def robot_info(self) -> Robot:
        data = self._call(ROBOT_PATH, {"robotReqTag": "openBotInfoByAppid"})
        if not isinstance(data, dict):
            raise PlatformError("机器人信息的响应不对")
        robot_id = data.get("robotId")
        robot = Robot(robot_id=str(robot_id if robot_id is not None else "").strip(),
                      org_id=str(data.get("orgId") or "").strip(), org_code=str(data.get("orgCode") or "").strip(),
                      password=str(data.get("jwtToken") or ""), key=str(data.get("DecryptKey") or "").encode("utf-8"),
                      hint=str(data.get("mqtt") or ""))
        missing = [name for name, value in (("robotId", robot.robot_id), ("orgId", robot.org_id),
                                            ("jwtToken", robot.password), ("DecryptKey", robot.key)) if not value]
        if missing:
            raise PlatformError(f"机器人信息里缺 {'、'.join(missing)}")
        return robot

    def org_router(self, org_code) -> str:
        body = json.dumps({"orgCode": org_code, "appVersion": APP_VERSION}).encode()
        data = self._data(self._request(self.cfg.saas_host + ROUTER_PATH, body, "application/json",
                                        {"User-Agent": "ccwork"}))
        server = (data or {}).get("mqttServer") if isinstance(data, dict) else None
        if not server or not isinstance(server, str):
            raise PlatformError("组织路由里没有 mqttServer")
        return server.strip()

    @staticmethod
    def _stamp():
        return datetime.now(TZ).strftime("%Y-%m-%d %H:%M:%S.%f +0800 CST")

    def send_text(self, robot, text, chat_id="", user_id="", at=()):
        message = {"message": text}
        payload = {"app_robot_code": robot.robot_id, "timestamp": self._stamp(), "text": message}
        if at:
            payload["at"] = message["at"] = list(at)
        if chat_id:
            payload["chat_id"] = int(chat_id)
            path = SEND_CHAT_PATH
        else:
            payload.update(user_id=user_id, chat_id=0)
            path = SEND_USER_PATH
        data = self._call(path, payload)
        return str((data or {}).get("message_id") or "") if isinstance(data, dict) else ""

    def send_stream(self, robot, packet, chat_id="", user_id=""):
        payload = {"app_robot_code": robot.robot_id, "request_id": packet["request_id"], "seq": packet["seq"],
                   "type": packet["type"], "ts": datetime.now(TZ).isoformat()}
        for key in ("message_type", "content"):
            if packet.get(key):
                payload[key] = packet[key]
        if chat_id:
            payload["chat_id"] = int(chat_id)
            path = STREAM_CHAT_PATH
        else:
            payload["user_id"] = user_id
            path = STREAM_USER_PATH
        self._call(path, payload)


# === 推送目标 ==================================================================================

class Targets:
    """/etc/doc2sop-ccwork/targets.yaml：推送目标（名字 → 群 ID 或用户 ID）和要屏蔽的发送人。改了不用重启。"""

    NAME = re.compile(r"^[^\x00-\x1f\x7f]{1,30}$")
    CHAT_ID = re.compile(r"^[0-9]{1,20}$")
    USER_ID = re.compile(r"^[!-~]{1,64}$")

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
            elif chat_id and not self.CHAT_ID.match(chat_id):
                problems.append(f"推送目标「{name}」的 chat_id 要是数字")
            elif user_id and not self.USER_ID.match(user_id):
                problems.append(f"推送目标「{name}」的 user_id 写得不对")
            else:
                targets[name] = ("chat", chat_id) if chat_id else ("user", user_id)
        for entry in data.get("deny_senders") or []:
            if self.USER_ID.match(str(entry).strip()):
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


class Outbox:
    """替 kb-app 发消息：回复按 handle、推送按名字；共用一个限速桶；每个推送目标每小时最多 PUSH_PER_HOUR 条。"""

    def __init__(self, platform, targets, clock=time.monotonic):
        self.platform, self.targets, self.clock = platform, targets, clock
        self.bucket = TokenBucket(SEND_RATE, SEND_BURST, clock)
        self.counters = {}
        self._lock = threading.Lock()
        self._streams = OrderedDict()
        self._pushes = {}
        self._held = {}

    def _count(self, name):
        with self._lock:
            self.counters[name] = self.counters.get(name, 0) + 1

    def _send(self, call):
        if not self.bucket.take(SEND_WAIT):
            self._count("send_throttled")
            return 429, {"ok": False, "error": "发得太快，稍后再发"}
        try:
            result = call()
        except PlatformError as exc:
            self._count("send_failed")
            log.warning("send failed: %s", exc)
            return 502, {"ok": False, "error": str(exc), "code": exc.code, "definite": exc.definite}
        self._count("sent")
        return 200, {"ok": True, **(result or {})}

    @staticmethod
    def _where(info):
        """回复发到哪：有会话 ID 就按会话发；私聊万一没有会话 ID，按发送人发。"""
        if info["chat_id"] not in ("", "0"):
            return {"chat_id": info["chat_id"]}
        return {"user_id": info["sender_id"]}

    def reply_text(self, robot, info, text, mention):
        at = [info["sender_id"]] if mention and info["chat_type"] != "single" and info["sender_id"] else []
        status, body = self._send(lambda: {"message_id": self.platform.send_text(robot, text, at=at,
                                                                                 **self._where(info))})
        log.info("reply text %s:%s len=%d → %s", info["chat_type"], tail(info["chat_id"]), len(text), status)
        return status, body

    def reply_stream(self, robot, info, packet):
        key = (packet["request_id"], packet["seq"])
        now = self.clock()
        with self._lock:
            while self._streams and (len(self._streams) > STREAM_CACHE_MAX
                                     or now - next(iter(self._streams.values()))[0] >= STREAM_CACHE_TTL):
                self._streams.popitem(last=False)
            hit = self._streams.get(key)
        if hit:                                 # 同一包重发：直接回上次的结果，不再发给平台
            return hit[1], {**hit[2], "cached": True}
        status, body = self._send(lambda: self.platform.send_stream(robot, packet, **self._where(info)))
        if status == 200 or body.get("definite"):
            with self._lock:
                self._streams[key] = (now, status, body)
        if packet["type"] != "delta" or status != 200:
            log.info("reply stream %s:%s req=%s seq=%d %s → %s", info["chat_type"], tail(info["chat_id"]),
                     tail(packet["request_id"]), packet["seq"], packet["type"], status)
        return status, body

    def push(self, robot, name, text):
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
        status, body = self._deliver(robot, target, text)
        log.info("push %s len=%d → %s", tail(target[1]), len(text), status)
        return status, body

    def _deliver(self, robot, target, text):
        kind, ident = target
        return self._send(lambda: {"message_id": self.platform.send_text(
            robot, text, **({"chat_id": ident} if kind == "chat" else {"user_id": ident}))})

    def flush_held(self, robot):
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
            text = (f"（过去一小时另有 {count} 条推送因为太多没有单独发，请到网页「SOP → 执行记录」里查看。）")
            status, _ = self._deliver(robot, targets[name], text)
            if status == 200:
                with self._lock:
                    remaining = self._held.get(name, 0) - count
                    if remaining > 0:
                        self._held[name] = remaining
                    else:
                        self._held.pop(name, None)
                log.info("push summary %s: %d held", tail(targets[name][1]), count)


# === MQTT 连接 =================================================================================

class Link:
    """和 broker 的连接（paho 1.6）。只订阅机器人自己的主题；收到的载荷交给 bridge.on_payload。"""

    def __init__(self, bridge, robot, broker, context=None):
        self.bridge, self.robot, self.broker = bridge, robot, broker
        self.connected_at = None
        self.conflict = False
        self._shorts = deque()
        kwargs = {"callback_api_version": paho.CallbackAPIVersion.VERSION1} if hasattr(paho, "CallbackAPIVersion") else {}
        client = paho.Client(client_id=robot.client_id, clean_session=True, protocol=paho.MQTTv311, **kwargs)
        client.username_pw_set(robot.username, robot.password)
        if broker.tls:
            client.tls_set_context(context or tls_context(bridge.cfg.ca_file))
        client.reconnect_delay_set(min_delay=1, max_delay=60)
        client.on_connect, client.on_disconnect = self._on_connect, self._on_disconnect
        client.on_connect_fail, client.on_message = self._on_connect_fail, self._on_message
        client.on_subscribe = self._on_subscribe
        self.client = client

    def start(self):
        self.client.connect_async(self.broker.host, self.broker.port, keepalive=KEEPALIVE)
        self.client.loop_start()

    def stop(self):
        try:
            self.client.disconnect()
        finally:
            self.client.loop_stop()

    def update_password(self, robot):
        self.robot = robot
        self.client.username_pw_set(robot.username, robot.password)

    def _on_connect(self, client, userdata, flags, rc):
        if rc == 0:
            self.connected_at = self.bridge.clock()
            self.bridge.set_state("connected")
            client.subscribe(self.robot.topic, qos=1)
            log.info("mqtt connected to %s, subscribing %s", self.broker, tail(self.robot.topic))
            return
        reason = {1: "协议版本不被接受", 2: "ClientID 被拒绝", 3: "服务不可用", 4: "用户名或密码不对", 5: "没有权限"}
        self.bridge.set_state("disconnected", f"broker 拒绝连接：{reason.get(rc, rc)}")
        log.warning("mqtt connect refused rc=%s", rc)
        if rc in (4, 5):                        # MQTT 密码（jwtToken）可能过期了：重新读机器人信息
            self.bridge.request_refresh()

    def _on_connect_fail(self, client, userdata):
        self.bridge.set_state("disconnected", "连不上 broker（网络或 TLS 握手失败）")
        log.warning("mqtt connect to %s failed", self.broker)

    def _on_subscribe(self, client, userdata, mid, granted):
        if any(q == 0x80 for q in granted):
            self.bridge.set_state("problem", "订阅被 broker 拒绝")
            log.warning("mqtt subscription refused")

    def _on_disconnect(self, client, userdata, rc):
        now = self.bridge.clock()
        lasted = None if self.connected_at is None else now - self.connected_at
        self.connected_at = None
        if rc == 0:
            return
        self.bridge.set_state("disconnected", f"连接断开（{rc}）")
        log.warning("mqtt disconnected rc=%s after %ss", rc, "-" if lasted is None else int(lasted))
        if lasted is not None and lasted < CONFLICT_SHORT:
            self._shorts.append(now)
            while self._shorts and now - self._shorts[0] >= CONFLICT_WINDOW:
                self._shorts.popleft()
            if len(self._shorts) >= CONFLICT_COUNT and not self.conflict:
                self.conflict = True            # 同一个 ClientID 在别处也连着，两边会互踢：退避
                client.reconnect_delay_set(min_delay=CONFLICT_DELAY, max_delay=CONFLICT_DELAY)
                log.warning("mqtt: kicked %d times in %ds, another client may use the same robot; backing off",
                            len(self._shorts), CONFLICT_WINDOW)

    def settle(self):
        """连接稳定一段时间后，撤掉互踢时加的退避。由主循环定时调。"""
        if self.conflict and self.connected_at is not None and self.bridge.clock() - self.connected_at >= STABLE_SECONDS:
            self.conflict = False
            self._shorts.clear()
            self.client.reconnect_delay_set(min_delay=1, max_delay=60)

    def _on_message(self, client, userdata, message):
        self.bridge.on_payload(message.payload)


# === 转接程序本体 ==============================================================================

class Bridge:
    def __init__(self, cfg, problems=(), clock=time.monotonic, wall=time.time, platform=None, context=None, tick=5.0):
        self.cfg, self.clock, self.wall, self.tick = cfg, clock, wall, tick
        self.config_problems = tuple(problems)
        self.context = context
        self.platform = platform or (Platform(cfg, context) if cfg.base_url else None)
        self.inbox = Inbox(clock, wall)
        self.handles = Handles(clock)
        self.targets = Targets(cfg.targets_file)
        self.outbox = Outbox(self.platform, self.targets, clock)
        self.robot = None
        self.link = None
        self.broker = None
        self.started_at = wall()
        self._state, self._since, self._problem = ("starting" if cfg.enabled else "disabled"), wall(), ""
        self._refresh = threading.Event()
        self._stop = threading.Event()
        self._thread = None
        self._lock = threading.Lock()
        self._last_warn = {}

    # --- 状态 ---
    def set_state(self, state, problem=""):
        with self._lock:
            if state != self._state:
                self._since = self.wall()
            self._state, self._problem = state, problem

    def request_refresh(self):
        self._refresh.set()

    def missing(self):
        """开着却跑不起来的原因（缺包、缺配置）。"""
        out = list(self.config_problems)
        if Cipher is None:
            out.append("缺少 python3-cryptography")
        if paho is None:
            out.append("缺少 python3-paho-mqtt（apt install python3-paho-mqtt）")
        if yaml is None:
            out.append("缺少 python3-yaml")
        for name, value in (("CCWORK_APP_KEY", self.cfg.app_key), ("CCWORK_APP_SECRET", self.cfg.app_secret),
                            ("CCWORK_BASE_URL", self.cfg.base_url), ("CCWORK_SAAS_HOST", self.cfg.saas_host)):
            if not value:
                out.append(f"没配 {name}")
        return out

    def diagnose_only(self):
        return self.broker is not None and not self.broker.tls

    def status(self) -> dict:
        with self._lock:
            state, since, problem = self._state, self._since, self._problem
        targets = self.targets.load()
        count, size = self.inbox.size()
        problems = [p for p in (self.missing() if self.cfg.enabled else list(self.config_problems))]
        if problem:
            problems.append(problem)
        problems += list(targets.problems)
        return {"ok": True, "protocol": list(PROTOCOL), "enabled": self.cfg.enabled, "state": state,
                "since": now_iso(since), "started_at": now_iso(self.started_at),
                "tls": None if self.broker is None else self.broker.tls, "diagnose": self.diagnose_only(),
                "broker": f"{self.broker.host}:{self.broker.port}" if self.broker else "",
                "send": self.cfg.send and not self.diagnose_only(), "robot": tail(self.robot.robot_id) if self.robot else "",
                "conflict": bool(self.link and self.link.conflict), "targets": sorted(targets.targets),
                "problems": problems, "queue": {"events": count, "bytes": size},
                "kb_app_last_poll": now_iso(self.inbox.last_poll) if self.inbox.last_poll else None,
                "counters": {**self.inbox.counters, **self.outbox.counters}}

    # --- 收 ---
    def on_payload(self, payload):
        robot = self.robot
        if robot is None:
            return
        try:
            outcome, event = interpret(payload, robot)
        except Exception as exc:              # 收消息的线程不能因为一条怪消息挂掉
            outcome, event = "malformed", None
            self._warn("interpret", f"bad payload: {exc.__class__.__name__}")
        self.inbox.count(outcome)
        if outcome.startswith("decrypt_failed"):
            self._warn("decrypt", f"decrypt failed ({outcome[15:]})")
        if event is None:
            return
        if event["sender_id"] in self.targets.load().deny:
            self.inbox.count("denied_sender")
            return
        if self.diagnose_only():                # 明文连接只诊断：不交给 kb-app
            self.inbox.count("diagnose_only")
            return
        event["handle"] = self.handles.issue(event)
        event["received_at"] = now_iso(self.wall())
        result = self.inbox.offer(event)
        log.info("message %s:%s from %s kind=%s len=%d → %s", event["chat_type"], tail(event["chat_id"]),
                 tail(event["sender_id"]), event["kind"], len(event["text"]), result)

    def _warn(self, key, message):
        now = self.clock()
        if now - self._last_warn.get(key, -3600) >= 60:
            self._last_warn[key] = now
            log.warning("%s", message)

    # --- 发 ---
    def _can_send(self):
        if not self.cfg.enabled or self.robot is None:
            return 503, "还没连上云上协同"
        if self.diagnose_only():
            return 403, "明文连接只用来诊断，不发任何东西"
        if not self.cfg.send:
            return 403, "发送已关闭（CCWORK_SEND=off）"
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
            return self.outbox.reply_stream(self.robot, info, packet)
        text, problem = check_text(body.get("text"))
        if problem:
            return 400, {"ok": False, "error": problem}
        return self.outbox.reply_text(self.robot, info, text, bool(body.get("mention")))

    def push(self, body) -> tuple:
        status, why = self._can_send()
        if status:
            return status, {"ok": False, "error": why}
        text, problem = check_text(body.get("text"))
        if problem:
            return 400, {"ok": False, "error": problem}
        return self.outbox.push(self.robot, str(body.get("target") or ""), text)

    # --- 主循环 ---
    def start(self):
        self._thread = threading.Thread(target=self._run, name="ccwork-bridge", daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=10)
        if self.link:
            self.link.stop()

    def _connect(self):
        robot = self.platform.robot_info()
        broker = self.cfg.broker
        if broker is None:
            server = self.platform.org_router(robot.org_code)
            broker = parse_broker(f"tcp://{server}")
            if not self.cfg.plaintext:
                raise PlatformError(f"组织路由给的 MQTT 地址 {broker.host}:{broker.port} 是明文；请向厂商要加密端口，"
                                    "配 CCWORK_BROKER=ssl://主机:端口")
        if not broker.tls and not self.cfg.plaintext:
            raise PlatformError("CCWORK_BROKER 是明文地址：要么换成 ssl://，要么设 CCWORK_ALLOW_PLAINTEXT=diagnose 只诊断")
        self.robot, self.broker = robot, broker
        self.link = Link(self, robot, broker, self.context)
        self.set_state("connecting")
        self.link.start()
        log.info("robot %s, broker %s%s", tail(robot.robot_id), broker, "" if broker.tls else "（明文，只诊断）")

    def _run(self):
        if not self.cfg.enabled:
            log.info("CCWORK_ENABLED is off: not connecting")
            return
        backoff = 30
        while not self._stop.is_set():
            if self.link is None:
                problems = self.missing()
                if problems:
                    self.set_state("problem", "；".join(problems))
                    self._stop.wait(60)
                    continue
                try:
                    self._connect()
                    backoff = 30
                except (PlatformError, ValueError) as exc:
                    self.set_state("problem", str(exc))
                    log.warning("start failed: %s; retry in %ss", exc, backoff)
                    self._stop.wait(backoff)
                    backoff = min(backoff * 2, 600)
                    continue
            if self._refresh.is_set():
                self._refresh.clear()
                try:
                    self.robot = self.platform.robot_info()
                    self.link.update_password(self.robot)
                    log.info("robot info refreshed")
                except PlatformError as exc:
                    log.warning("refreshing robot info failed: %s", exc)
            self.link.settle()
            if self.cfg.send and not self.diagnose_only():
                self.outbox.flush_held(self.robot)
            self._stop.wait(self.tick)


def check_text(raw):
    if not isinstance(raw, str) or not raw.strip():
        return "", "text 要是非空字符串"
    if len(raw) > OUT_TEXT_MAX:
        return "", f"text 超过 {OUT_TEXT_MAX} 字"
    if "\x00" in raw:
        return "", "text 里不能有 NUL"
    return raw, ""


def check_packet(raw):
    if not isinstance(raw, dict):
        return None, "stream 要是对象"
    request_id, seq = str(raw.get("request_id") or ""), raw.get("seq")
    kind, mode, content = raw.get("type"), raw.get("message_type") or "", raw.get("content") or ""
    if not REQUEST_ID.match(request_id):
        return None, "request_id 只能是 1–64 个字母、数字、_、-"
    if not isinstance(seq, int) or isinstance(seq, bool) or not 1 <= seq <= 100000:
        return None, "seq 要是 1–100000 的整数"
    if kind not in STREAM_TYPES or mode not in STREAM_MODES:
        return None, f"type 只能是 {'/'.join(STREAM_TYPES)}，message_type 只能是 append/cover"
    if not isinstance(content, str) or len(content) > OUT_TEXT_MAX or "\x00" in content:
        return None, f"content 要是不超过 {OUT_TEXT_MAX} 字的字符串"
    return {"request_id": request_id, "seq": seq, "type": kind, "message_type": mode, "content": content}, ""


# === 本地接口 ==================================================================================

class Api(BaseHTTPRequestHandler):
    bridge = None
    token = b""
    timeout = 60
    server_version = "doc2sop-ccwork"
    sys_version = ""

    def log_message(self, format, *args):    # noqa: A002  不要默认的访问日志（路径里有 handle 之类的东西）
        pass

    def _send(self, status, payload):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
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
        if self.bridge.diagnose_only():
            wait = 0.0                          # 明文只诊断：什么都不交给 kb-app
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
        handler.setFormatter(logging.Formatter("%(levelname)s ccwork: %(message)s"))
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
        print("错误：CCWORK_LISTEN 只能是 127.0.0.1:端口 或 [::1]:端口", file=sys.stderr)
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


HOST_PORT = re.compile(r"^[A-Za-z0-9.-]{1,253}:[0-9]{1,5}$")


def probe_tls(host, port, context, timeout=5.0) -> str:
    """只做 TLS 握手、看证书，不发任何 MQTT 包。"""
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=host) as conn:
                cert = conn.getpeercert() or {}
                subject = dict(item[0] for item in cert.get("subject", ()))
                issuer = dict(item[0] for item in cert.get("issuer", ()))
                return (f"可以：{conn.version()}，证书 CN={subject.get('commonName', '?')}，"
                        f"签发者 {issuer.get('organizationName') or issuer.get('commonName', '?')}，"
                        f"到期 {cert.get('notAfter', '?')}，主机名校验通过")
    except ssl.SSLCertVerificationError as exc:
        return f"不行：证书校验失败（{exc.verify_message}）"
    except ssl.SSLError as exc:
        return f"不行：TLS 握手失败（{exc.reason or exc.__class__.__name__}），这个端口可能不是加密端口"
    except OSError as exc:
        return f"不行：连不上（{exc.__class__.__name__}）"


def check(out=None, env=None, ports=(8883, 443, 8884)):
    """试连第 1 步：只读握手。换令牌 → 读机器人信息 → 查组织路由 → 对 broker 的候选加密端口只做 TLS 握手。"""
    out = out or sys.stdout
    cfg, problems = load_config(env)
    for problem in problems:
        print(f"配置问题：{problem}", file=out)
    missing = [name for name, value in (("CCWORK_APP_KEY", cfg.app_key), ("CCWORK_APP_SECRET", cfg.app_secret),
                                        ("CCWORK_BASE_URL", cfg.base_url), ("CCWORK_SAAS_HOST", cfg.saas_host))
               if not value]
    if missing:
        print(f"没配 {'、'.join(missing)}，没法握手", file=out)
        return 1
    context = tls_context(cfg.ca_file)
    platform = Platform(cfg, context)
    try:
        platform.token()
        print(f"换令牌：成功（有效期 {platform.expires_in or '?'} 秒）", file=out)
        robot = platform.robot_info()
        print(f"机器人：ID {tail(robot.robot_id)}，组织 ID {tail(robot.org_id)}，orgCode {robot.org_code or '?'}，"
              f"DecryptKey {len(robot.key)} 字节", file=out)
        if not robot.hint:
            print("机器人信息里的 mqtt 字段：没有", file=out)
        elif HOST_PORT.match(robot.hint):
            print(f"机器人信息里的 mqtt 字段：{robot.hint}", file=out)
        else:
            print(f"机器人信息里的 mqtt 字段：有，但不像「主机:端口」（{len(robot.hint)} 个字符，不打印内容）", file=out)
        server = platform.org_router(robot.org_code)
        print(f"组织路由给的 MQTT 地址：{server}", file=out)
    except PlatformError as exc:
        print(f"失败：{exc}", file=out)
        return 1
    if cfg.broker:
        candidates = [(cfg.broker.host, cfg.broker.port)]
    else:
        host, _, port = server.rpartition(":")
        candidates = [(host or server, p) for p in dict.fromkeys(list(ports) + ([int(port)] if port.isdigit() else []))]
    print("TLS 探测（只握手，不发 MQTT 登录包）：", file=out)
    good = []
    for host, port in candidates:
        result = probe_tls(host, port, context)
        print(f"  {host}:{port}  {result}", file=out)
        if result.startswith("可以"):
            good.append((host, port))
    if good and not cfg.broker:
        print(f"建议：CCWORK_BROKER=ssl://{good[0][0]}:{good[0][1]}", file=out)
    elif not good:
        print("没有找到可用的加密端口：请向厂商要 MQTT 的 TLS 地址", file=out)
    return 0 if good else 2


SECRET_VALUE = re.compile(r"^[!#-&(-\[\]-~]{1,256}$")    # 可见 ASCII，不含空白、引号、反斜杠


def set_credentials(path=ENV_FILE, stdin=None, out=None, interactive=None, now=None):
    """从标准输入读 app-key、app-secret（终端上不回显），写进环境文件：原子写入、权限 600、旧文件留 .bak-时间。"""
    stdin, out = stdin or sys.stdin, out or sys.stdout
    interactive = stdin.isatty() if interactive is None else interactive
    if interactive:
        key, secret = getpass.getpass("app-key: ").strip(), getpass.getpass("app-secret: ").strip()
    else:
        lines = [line.strip() for line in stdin.read().splitlines() if line.strip()]
        key, secret = (lines + ["", ""])[:2]
    for name, value in (("app-key", key), ("app-secret", secret)):
        if not SECRET_VALUE.match(value):
            print(f"错误：{name} 没填，或者含空白、引号、反斜杠", file=out)
            return 1
    target = Path(path)
    lines = []
    if target.exists():
        original = target.read_text(encoding="utf-8")
        lines = [line for line in original.splitlines() if not re.match(r"^\s*CCWORK_APP_(KEY|SECRET)\s*=", line)]
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
    lines += [f"CCWORK_APP_KEY={key}", f"CCWORK_APP_SECRET={secret}"]
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
    print(f"已写入 {target}（app-key 末 4 位 {tail(key)}）。重启转接程序生效：systemctl restart doc2sop-ccwork", file=out)
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description="doc2sop 的云上协同转接程序（只听 127.0.0.1）")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("serve", help="运行（systemd 里用这个）")
    sub.add_parser("check", help="只读握手：换令牌、读机器人信息、查组织路由、TLS 探测")
    creds = sub.add_parser("set-credentials", help="写入 app-key、app-secret")
    creds.add_argument("--env-file", default=ENV_FILE)
    args = parser.parse_args(argv)
    _setup_logging()
    if args.command == "check":
        return check()
    if args.command == "set-credentials":
        return set_credentials(args.env_file)
    return serve()


if __name__ == "__main__":
    sys.exit(main())
