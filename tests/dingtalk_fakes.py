"""钉钉转接程序测试用的替身：一个假的钉钉（同一个端口上既是 HTTPS 开放平台、sessionWebhook，也是 Stream 的 WebSocket）。

只听 127.0.0.1，证书现生成在临时目录里（借 ccwork_fakes 的临时 CA），证书里写的是钉钉的主机名；转接程序的 Net 换一个
dial，把钉钉的主机名接到这里，TLS 照样按主机名校验。这里的 token、ticket、session 都带 canary 字样，测试结束时
核对它们没进日志。
"""
import base64
import hashlib
import importlib.util
import json
import socket
import ssl
import sys
import threading
import time
import urllib.parse
from pathlib import Path

from tests.ccwork_fakes import make_certs, server_context, wait_for  # noqa: F401  （wait_for 给测试用）

REPO = Path(__file__).resolve().parent.parent
if "dingtalk_bridge" in sys.modules:
    bridge = sys.modules["dingtalk_bridge"]
else:
    _SPEC = importlib.util.spec_from_file_location("dingtalk_bridge", REPO / "deploy" / "dingtalk" / "dingtalk_bridge.py")
    bridge = importlib.util.module_from_spec(_SPEC)
    sys.modules["dingtalk_bridge"] = bridge
    _SPEC.loader.exec_module(bridge)

HOSTS = ("api.dingtalk.com", "oapi.dingtalk.com", "wss-open-connection.dingtalk.com")
CLIENT_ID = "dingclientid9876"
CLIENT_SECRET = "ding-secret-canary-0123456789"
TOKEN = "k" * 40                        # 本地接口的令牌
GROUP = "cidGroupConversationX7Q1=="
STAFF = "staff-alice-58c3"
CORP = "dingcorp0001"
GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def bot_message(n=1, *, text="问题金丝雀 kb-app 内存高怎么办", group=True, at=True, msgtype="text", staff=STAFF,
                chat=GROUP, corp=CORP, webhook=None, expires_in=5400.0, **extra):
    """一条机器人消息（Stream CALLBACK 的 data）。"""
    data = {"conversationType": "2" if group else "1", "conversationId": chat if group else "cidSingleChatY9Z2==",
            "msgId": f"msg-{n}", "senderStaffId": staff, "senderNick": "张三", "senderCorpId": corp,
            "chatbotCorpId": CORP, "robotCode": CLIENT_ID, "isInAtList": at if group else False,
            "conversationTitle": "运维值班群" if group else "", "msgtype": msgtype,
            "sessionWebhook": webhook or f"https://oapi.dingtalk.com/robot/sendBySession?session=sess-canary-{n}",
            "sessionWebhookExpiredTime": int((time.time() + expires_in) * 1000), "createAt": int(time.time() * 1000)}
    if msgtype == "text":
        data["text"] = {"content": " " + text}
    elif msgtype == "richText":
        data["content"] = {"richText": [{"text": text}, {"downloadCode": "img-code"}]}
    elif msgtype == "picture":
        data["content"] = {"downloadCode": "img-code"}
    data.update(extra)
    return data


def callback(data, message_id="mid-1"):
    return {"specVersion": "1.0", "type": "CALLBACK",
            "headers": {"topic": bridge.BOT_TOPIC, "messageId": message_id, "contentType": "application/json",
                        "time": str(int(time.time() * 1000))},
            "data": json.dumps(data, ensure_ascii=False)}


def system(topic, data, message_id="sys-1"):
    return {"specVersion": "1.0", "type": "SYSTEM",
            "headers": {"topic": topic, "messageId": message_id, "contentType": "application/json"},
            "data": json.dumps(data)}


# --- WebSocket 帧 --------------------------------------------------------------------------

def _read_exact(conn, size):
    data = b""
    while len(data) < size:
        chunk = conn.recv(size - len(data))
        if not chunk:
            raise ConnectionError("closed")
        data += chunk
    return data


def encode_frame(opcode, payload=b""):
    head = bytes([0x80 | opcode])
    size = len(payload)
    if size < 126:
        head += bytes([size])
    elif size < 65536:
        head += bytes([126]) + size.to_bytes(2, "big")
    else:
        head += bytes([127]) + size.to_bytes(8, "big")
    return head + payload


def read_frame(conn):
    first, second = _read_exact(conn, 2)
    opcode, size = first & 0x0F, second & 0x7F
    if size == 126:
        size = int.from_bytes(_read_exact(conn, 2), "big")
    elif size == 127:
        size = int.from_bytes(_read_exact(conn, 8), "big")
    mask = _read_exact(conn, 4) if second & 0x80 else b""
    payload = _read_exact(conn, size)
    if mask:
        payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    return opcode, payload


class WsConn:
    """服务端这边的一条 Stream 连接：收到的（已解开的 JSON）放在 received 里。"""

    def __init__(self, conn, ticket):
        self.conn, self.ticket = conn, ticket
        self.received = []
        self.pings = 0
        self.lock = threading.Lock()
        self.open = True

    def send(self, obj):
        data = json.dumps(obj, ensure_ascii=False).encode("utf-8") if not isinstance(obj, bytes) else obj
        with self.lock:
            self.conn.sendall(encode_frame(0x1, data))

    def close(self, graceful=True):
        self.open = False
        try:
            if graceful:
                with self.lock:
                    self.conn.sendall(encode_frame(0x8, (1000).to_bytes(2, "big")))
            self.conn.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.conn.close()

    def acks(self):
        return [m for m in self.received if isinstance(m, dict) and "code" in m]

    def serve(self):
        try:
            while self.open:
                opcode, payload = read_frame(self.conn)
                if opcode == 0x9:
                    self.pings += 1
                    with self.lock:
                        self.conn.sendall(encode_frame(0xA, payload))
                elif opcode == 0x8:
                    with self.lock:
                        self.conn.sendall(encode_frame(0x8, payload[:2]))
                    break
                elif opcode in (0x1, 0x2):
                    try:
                        self.received.append(json.loads(payload))
                    except ValueError:
                        self.received.append(payload)
        except (OSError, ConnectionError, ssl.SSLError, ValueError):
            pass
        finally:
            self.open = False
            try:
                self.conn.close()
            except OSError:
                pass


# --- 假的钉钉 --------------------------------------------------------------------------------

class FakeDingTalk:
    """开放平台（换 token、开 Stream 连接、群发、单聊发）、sessionWebhook 和 Stream 的 WebSocket，都在一个端口上。

    endpoint        开 Stream 连接时给出去的地址
    http_redirect   开 Stream 连接回 302（转接程序不能跟）
    ws_redirect     WebSocket 握手回 302
    expire_next     接下来几次带 token 的请求回 401
    fail_next       接下来几次群发 / 单聊发回的 (状态, JSON)
    webhook_next    接下来几次 sessionWebhook 回的 (状态, JSON)
    user_reply      单聊发的回包（测「200 但部分失败」）
    """

    def __init__(self, context):
        self.context = context
        self.endpoint = "wss://wss-open-connection.dingtalk.com/connect"
        self.http_redirect = self.ws_redirect = False
        self.expire_next = 0
        self.fail_next, self.webhook_next = [], []
        self.user_reply = None
        self.tokens = 0
        self.token = ""
        self.tickets = {}
        self.used_tickets = []
        self.requests = []
        self.conns = []
        self.dialed = []
        self.lock = threading.Lock()
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        self.running = True
        threading.Thread(target=self._accept, daemon=True).start()

    def dial(self, host, port, timeout):
        """给转接程序的 Net 用：钉钉的主机名一律接到这里。"""
        self.dialed.append((host, port))
        return socket.create_connection(("127.0.0.1", self.port), timeout=timeout)

    def _accept(self):
        while self.running:
            try:
                raw, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(raw,), daemon=True).start()

    def _serve(self, raw):
        try:
            conn = self.context.wrap_socket(raw, server_side=True)
        except (OSError, ssl.SSLError):
            raw.close()
            return
        try:
            head = b""
            while b"\r\n\r\n" not in head:
                chunk = conn.recv(4096)
                if not chunk:
                    conn.close()
                    return
                head += chunk
            head, _, rest = head.partition(b"\r\n\r\n")
            lines = head.decode("latin-1").split("\r\n")
            method, target, _ = lines[0].split(" ", 2)
            headers = {k.strip().lower(): v.strip() for k, v in (line.split(":", 1) for line in lines[1:] if ":" in line)}
            if headers.get("upgrade", "").lower() == "websocket":
                return self._websocket(conn, target, headers)
            size = int(headers.get("content-length") or 0)
            body = rest + (_read_exact(conn, size - len(rest)) if size > len(rest) else b"")
            url = urllib.parse.urlsplit(target)
            status, payload, extra = self.handle(method, url.path, urllib.parse.parse_qs(url.query), headers, body)
            data = json.dumps(payload, ensure_ascii=False).encode()
            extra_lines = "".join(f"{k}: {v}\r\n" for k, v in extra.items())
            conn.sendall(f"HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {len(data)}\r\n"
                         f"Connection: close\r\n{extra_lines}\r\n".encode() + data)
            conn.close()
        except (OSError, ConnectionError, ssl.SSLError, ValueError):
            conn.close()

    def _websocket(self, conn, target, headers):
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(target).query)
        ticket = (query.get("ticket") or [""])[0]
        with self.lock:
            born = self.tickets.pop(ticket, None)
            self.used_tickets.append(ticket)
        if self.ws_redirect:
            conn.sendall(b"HTTP/1.1 302 Found\r\nLocation: wss://wss-open-connection.dingtalk.com/stolen\r\n"
                         b"Content-Length: 0\r\n\r\n")
            conn.close()
            return
        if born is None or time.monotonic() - born > 90:
            body = f"bad ticket {ticket}".encode()
            conn.sendall(b"HTTP/1.1 401 Unauthorized\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)
            conn.close()
            return
        accept = base64.b64encode(hashlib.sha1((headers["sec-websocket-key"] + GUID).encode()).digest()).decode()
        conn.sendall(f"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                     f"Sec-WebSocket-Accept: {accept}\r\n\r\n".encode())
        ws = WsConn(conn, ticket)
        with self.lock:
            self.conns.append(ws)
        ws.serve()

    def handle(self, method, path, query, headers, body):
        with self.lock:
            try:
                data = json.loads(body or b"{}")
            except ValueError:
                data = {}
            self.requests.append((path, query, headers, data))
            if path == bridge.TOKEN_PATH:
                if data.get("appKey") != CLIENT_ID or data.get("appSecret") != CLIENT_SECRET:
                    return 400, {"code": "invalidClientIdOrSecret", "message": "无效的 clientId 或 clientSecret"}, {}
                self.tokens += 1
                self.token = f"at-canary-{self.tokens}"
                return 200, {"accessToken": self.token, "expireIn": 7200}, {}
            if path == bridge.OPEN_PATH:
                if self.http_redirect:
                    return 302, {}, {"Location": "https://api.dingtalk.com/stolen"}
                if data.get("clientId") != CLIENT_ID or data.get("clientSecret") != CLIENT_SECRET:
                    return 401, {"code": "Unauthorized", "message": "鉴权失败"}, {}
                ticket = f"tk-canary-{len(self.used_tickets) + len(self.tickets) + 1}"
                self.tickets[ticket] = time.monotonic()
                return 200, {"endpoint": self.endpoint, "ticket": ticket}, {}
            if path.startswith("/robot/sendBySession"):
                if self.webhook_next:
                    status, payload = self.webhook_next.pop(0)
                    return status, payload, {}
                return 200, {"errcode": 0, "errmsg": "ok"}, {}
            if headers.get("x-acs-dingtalk-access-token") != self.token or self.expire_next:
                self.expire_next = max(0, self.expire_next - 1)
                return 401, {"code": "InvalidAuthentication", "message": "token 过期"}, {}
            if self.fail_next:
                status, payload = self.fail_next.pop(0)
                return status, payload, {}
            if path == bridge.GROUP_SEND_PATH:
                return 200, {"processQueryKey": f"pq-{len(self.requests)}"}, {}
            if path == bridge.USER_SEND_PATH:
                return 200, self.user_reply or {"processQueryKey": f"pq-{len(self.requests)}", "invalidStaffIdList": [],
                                                "flowControlledStaffIdList": []}, {}
            return 404, {"code": "notFound"}, {}

    def sent(self, *paths):
        with self.lock:
            return [(path, query, data) for path, query, _, data in self.requests
                    if any(path.startswith(p) for p in paths)]

    def live(self):
        with self.lock:
            return [c for c in self.conns if c.open]

    def close(self):
        self.running = False
        self.sock.close()
        for conn in list(self.conns):
            conn.close(graceful=False)
