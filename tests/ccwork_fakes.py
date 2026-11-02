"""云上协同转接程序测试用的替身：假的 MQTT broker、假的开放平台（HTTPS）、临时 CA、protobuf 编码。

都只听 127.0.0.1，证书现生成在临时目录里（cryptography），不进仓库。消息样本用这里自己的编码函数造，
字段号见 deploy/ccwork/ccwork_bridge.py 里的 MESSAGE / TEXT 等定义。
"""
import importlib.util
import ipaddress
import json
import socket
import ssl
import sys
import threading
import time
import urllib.parse
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

if "ccwork_bridge" in sys.modules:
    bridge = sys.modules["ccwork_bridge"]
else:
    _SPEC = importlib.util.spec_from_file_location("ccwork_bridge", REPO / "deploy" / "ccwork" / "ccwork_bridge.py")
    bridge = importlib.util.module_from_spec(_SPEC)
    sys.modules["ccwork_bridge"] = bridge
    _SPEC.loader.exec_module(bridge)

KEY = b"Wc6AQHJFQiBasKJQ"          # 和真实的 DecryptKey 一样是 16 个字母数字
ROBOT_ID = "98765"
ORG_ID = "org9"
TOKEN = "t" * 40                    # 本地接口的令牌


def wait_for(predicate, timeout=10.0, step=0.02):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(step)
    return predicate()


class Clock:
    """可以拨的时钟：Inbox、Handles、Outbox 的 clock 参数用它。"""

    def __init__(self, start=1000.0):
        self.now = start

    def __call__(self):
        return self.now


# --- protobuf 编码 ------------------------------------------------------------------------

def varint(value):
    value &= (1 << 64) - 1
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def f_bytes(number, data):
    data = data.encode("utf-8") if isinstance(data, str) else bytes(data)
    return varint(number << 3 | 2) + varint(len(data)) + data


def f_int(number, value):
    return varint(number << 3) + varint(value)


def text_body(text, at=(), at_all=False):
    out = f_bytes(1, text) + b"".join(f_bytes(2, a) for a in at)
    return out + (f_int(3, 1) if at_all else b"")


def chat_message(content=b"", *, message_type=1, chat_id=4242, sender="u_alice", sender_name="张三", user_type=0,
                 chat_type=2, external_type=0x02, msg_id=7, uniq=123456789, chat_name="运维值班群", key=KEY,
                 encrypt=True):
    alg = bridge.cipher_for(external_type)
    body = bridge.encrypt(alg, content, key) if (encrypt and alg and content) else content
    user = f_bytes(1, sender) + f_bytes(2, sender_name) + (f_int(4, user_type) if user_type else b"")
    out = f_int(1, message_type) + f_int(2, chat_id) + f_bytes(3, user) + f_int(5, external_type) + f_int(6, msg_id)
    out += f_bytes(8, body) + f_int(11, chat_type) + f_bytes(12, chat_name)
    return out + (f_int(15, uniq) if uniq else b"")


def robot(**kwargs):
    values = {"robot_id": ROBOT_ID, "org_id": ORG_ID, "org_code": "ORG", "password": "jwt-1", "key": KEY}
    values.update(kwargs)
    return bridge.Robot(**values)


# --- 临时 CA 和证书 --------------------------------------------------------------------------

def make_certs(folder, names=("127.0.0.1", "localhost")):
    """测试用的 CA 和服务器证书：(ca.pem, server.pem, server-key.pem)。names 是证书里的主机名（IP 或域名）；
    同一个目录再调一次 leaf_cert 可以用同一个 CA 签别的名字（测主机名校验）。"""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    folder = Path(folder)
    now = datetime.now(timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "doc2sop test CA")])
    ca_cert = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key())
               .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(days=1))
               .not_valid_after(now + timedelta(days=2))
               .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
               .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
                                            data_encipherment=False, key_agreement=False, key_cert_sign=True,
                                            crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
               .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
               .sign(ca_key, hashes.SHA256()))
    pem = serialization.Encoding.PEM
    (folder / "ca.pem").write_bytes(ca_cert.public_bytes(pem))
    (folder / "ca-key.pem").write_bytes(ca_key.private_bytes(pem, serialization.PrivateFormat.PKCS8,
                                                             serialization.NoEncryption()))
    cert, key = leaf_cert(folder, names, "server")
    return folder / "ca.pem", cert, key


def leaf_cert(folder, names, stem):
    """用 folder 里的测试 CA 签一张服务器证书，证书里只有 names 这些主机名：(stem.pem, stem-key.pem)。"""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    folder = Path(folder)
    now = datetime.now(timezone.utc)
    ca_cert = x509.load_pem_x509_certificate((folder / "ca.pem").read_bytes())
    ca_key = serialization.load_pem_private_key((folder / "ca-key.pem").read_bytes(), password=None)
    alt = []
    for name in names:
        try:
            alt.append(x509.IPAddress(ipaddress.ip_address(name)))
        except ValueError:
            alt.append(x509.DNSName(name))
    key = ec.generate_private_key(ec.SECP256R1())
    cert = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, names[0])])).issuer_name(ca_cert.subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=2))
            .add_extension(x509.SubjectAlternativeName(alt), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
            .sign(ca_key, hashes.SHA256()))
    pem = serialization.Encoding.PEM
    (folder / f"{stem}.pem").write_bytes(cert.public_bytes(pem))
    (folder / f"{stem}-key.pem").write_bytes(key.private_bytes(pem, serialization.PrivateFormat.PKCS8,
                                                               serialization.NoEncryption()))
    return folder / f"{stem}.pem", folder / f"{stem}-key.pem"


def server_context(cert, key):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    return context


# --- 假的 MQTT broker（MQTT 3.1.1 里用得到的那几种包） -------------------------------------------

def _read_exact(conn, size):
    data = b""
    while len(data) < size:
        chunk = conn.recv(size - len(data))
        if not chunk:
            raise ConnectionError("closed")
        data += chunk
    return data


def _string(buf, pos):
    size = int.from_bytes(buf[pos:pos + 2], "big")
    return buf[pos + 2:pos + 2 + size], pos + 2 + size


class FakeBroker:
    """refuse(password) 返回 CONNACK 的返回码（默认 0 接受）；kick_after_connect 为真时连上就断开（模拟被别处踢掉）。"""

    def __init__(self, tls=None):
        self.tls = tls
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self.connects, self.subscriptions, self.pubacks = [], [], []
        self.refuse = lambda password: 0
        self.kick_after_connect = False
        self.granted = None
        self.client = None
        self.lock = threading.Lock()
        self.running = True
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self):
        while self.running:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn):
        try:
            if self.tls:
                conn = self.tls.wrap_socket(conn, server_side=True)
            while self.running:
                header = _read_exact(conn, 1)[0]
                length, shift = 0, 0
                while True:
                    byte = _read_exact(conn, 1)[0]
                    length |= (byte & 0x7F) << shift
                    shift += 7
                    if not byte & 0x80:
                        break
                body = _read_exact(conn, length)
                kind = header >> 4
                if kind == 1:
                    if not self._connect(conn, body):
                        return
                elif kind == 8:
                    pid = body[:2]
                    topic, pos = _string(body, 2)
                    self.subscriptions.append((topic.decode(), body[pos]))
                    conn.sendall(bytes([0x90, 3]) + pid + bytes([self.granted if self.granted is not None else body[pos]]))
                elif kind == 4:
                    self.pubacks.append(int.from_bytes(body[:2], "big"))
                elif kind == 12:
                    conn.sendall(b"\xd0\x00")
                elif kind == 14:
                    return
        except (OSError, ConnectionError, ssl.SSLError, IndexError, ValueError):
            return                          # 对方发来的不是 MQTT（比如 TLS 握手）：断开就是
        finally:
            with self.lock:
                if self.client is conn:
                    self.client = None
            conn.close()

    def _connect(self, conn, body):
        _, pos = _string(body, 0)
        level, flags = body[pos], body[pos + 1]
        keepalive = int.from_bytes(body[pos + 2:pos + 4], "big")
        client_id, pos = _string(body, pos + 4)
        username = password = None
        if flags & 0x80:
            username, pos = _string(body, pos)
        if flags & 0x40:
            password, pos = _string(body, pos)
        info = {"client_id": client_id.decode(), "username": username and username.decode(),
                "password": password and password.decode(), "keepalive": keepalive, "clean": bool(flags & 0x02),
                "level": level}
        self.connects.append(info)
        rc = self.refuse(info["password"])
        conn.sendall(bytes([0x20, 2, 0, rc]))
        if rc:
            return False
        if self.kick_after_connect:
            time.sleep(0.05)
            return False
        with self.lock:
            self.client = conn
        return True

    def connected(self):
        with self.lock:
            return self.client is not None

    def publish(self, topic, payload, pid=1, dup=False):
        body = len(topic).to_bytes(2, "big") + topic.encode() + pid.to_bytes(2, "big") + payload
        remaining, size = bytearray(), len(body)
        while True:
            byte, size = size & 0x7F, size >> 7
            remaining.append(byte | (0x80 if size else 0))
            if not size:
                break
        with self.lock:
            self.client.sendall(bytes([0x32 | (0x08 if dup else 0)]) + bytes(remaining) + body)

    def close(self):
        self.running = False
        self.sock.close()
        with self.lock:
            if self.client:
                try:
                    self.client.close()
                except OSError:
                    pass


# --- 假的开放平台（HTTPS） ------------------------------------------------------------------------

class FakePlatform:
    """开放平台的 7 个接口。expire_next：接下来几次带令牌的请求回 0704；fail_next：接下来几次发送回的 HTTP 状态码。"""

    def __init__(self, context, app_key="key-1", app_secret="secret-1", broker="127.0.0.1:1883"):
        self.app_key, self.app_secret, self.broker = app_key, app_secret, broker
        self.tokens = 0
        self.token = ""
        self.jwt_serial = 0
        self.expire_next = 0
        self.fail_next = []
        self.redirect = False
        self.requests = []
        self.lock = threading.Lock()
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, format, *args):    # noqa: A002
                pass

            def do_POST(self):
                body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
                headers = {name.lower(): value for name, value in self.headers.items()}
                status, payload, extra = outer.handle(self.path, headers, body)
                data = json.dumps(payload, ensure_ascii=False).encode()
                self.send_response(status)
                for name, value in extra.items():
                    self.send_header(name, value)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.port = self.server.server_address[1]
        self.url = f"https://127.0.0.1:{self.port}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def handle(self, path, headers, body):
        with self.lock:
            self.requests.append((path, headers, body))
            if path == "/stolen":
                return 200, {"code": "0000"}, {}
            if path == bridge.TOKEN_PATH:
                if self.redirect:
                    return 302, {}, {"Location": f"{self.url}/stolen"}
                form = urllib.parse.parse_qs(body.decode())
                if form.get("appKey") != [self.app_key] or form.get("appSecret") != [self.app_secret]:
                    return 200, {"code": "0101", "message": "appKey 或 appSecret 不对"}, {}
                self.tokens += 1
                self.token = f"access-{self.tokens}"
                return 200, {"code": "0000", "data": {"access_token": self.token, "expires_in": 7200}}, {}
            if path == bridge.ROUTER_PATH:
                return 200, {"code": "0000", "data": {"mqttServer": self.broker}}, {}
            if headers.get("access_token") != self.token or self.expire_next:
                self.expire_next = max(0, self.expire_next - 1)
                return 200, {"code": "0704", "message": "令牌过期"}, {}
            if path == bridge.ROBOT_PATH:
                self.jwt_serial += 1
                return 200, {"code": "0000", "data": {"robotId": int(ROBOT_ID), "orgId": ORG_ID, "orgCode": "ORG",
                                                      "jwtToken": f"jwt-{self.jwt_serial}",
                                                      "DecryptKey": KEY.decode(), "mqtt": ""}}, {}
            if self.fail_next:
                return self.fail_next.pop(0), {"code": "9999", "message": "出错了"}, {}
            data = json.loads(body)
            if path in (bridge.STREAM_CHAT_PATH, bridge.STREAM_USER_PATH):
                return 200, {"code": "0000", "data": {"request_id": data["request_id"], "seq": data["seq"]}}, {}
            return 200, {"code": "0000", "data": {"message_id": f"m-{len(self.requests)}"}}, {}

    def sent(self, *paths):
        with self.lock:
            return [json.loads(body) for path, _, body in self.requests if path in paths]

    def close(self):
        self.server.shutdown()
        self.server.server_close()
