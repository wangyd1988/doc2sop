"""来源地址：谁连的应用、经没经代理、是不是 HTTPS。所有按来源做的判断（只收本机、MCP_CLIENTS、alerts.clients、
限频、审批记录里的 ip=）都用这里算出的地址，不再各自看 TCP 对端。

ClientAddress 是最外层的 ASGI 中间件，改写 scope["client"]（和经可信代理时的 scope["scheme"]），之后的代码照旧读
request.client.host 也是对的；新代码用 address() / is_local() / transport()。uvicorn 自己的 proxy_headers 关着
（app/serve.py），FORWARDED_ALLOW_IPS 不再起作用、有值时拒绝启动。

- 对端在 TRUSTED_PROXIES 里（写错、写 * 或 0.0.0.0/0 时导入就报错，app/serve.py 据此拒绝启动）：X-Forwarded-For
  从右往左跳过可信的项，第一个不可信的就是客户端；X-Forwarded-Proto 只认 http / https，取最右一个（离应用最近的代理
  写的）。登记的代理没带 X-Forwarded-For（只带 Forwarded / X-Real-IP，或者什么都没带——本机对端、Host 是本机的除外），
  或者 X-Forwarded-For 里认不出地址：按「来源不明」处理。
- 配错的识别：对端是回环地址、又不是登记过的代理转来的（不在名单里，或在名单里却没带 X-Forwarded-For），并且
  ① 带了任何转发头，或 ② Host 不是 127.0.0.1、::1、localhost（或者没有 Host）——这种请求多半是本机的反向代理、
  TCP 转发（realm、stunnel……）转进来的公网请求。来源一律记成 UNTRUSTED（不是 IP），「只收本机」、MCP_CLIENTS、
  alerts.clients 都不放行；同时记下来给页面标红。② 只用来发现配错：Host 是客户端写的，经 TCP 转发进来的人可以照写
  127.0.0.1，所以不要用 TCP 转发把公网连接接到应用端口。
- 对端不可信、不是回环、带了转发头（经公司的正向代理出网很常见）：照常用对端地址；对端是私网地址时页面给一条提示
  （如果它其实是你的反向代理，要登记进 TRUSTED_PROXIES）。
"""
import ipaddress
import logging
import os
import threading
import time

log = logging.getLogger("kb")

UNTRUSTED = "untrusted-proxy"       # 来源不明（经没登记的代理转来）时的「地址」：不是 IP，任何按地址放行的名单都不放
PEER_KEY = "doc2sop.peer"           # 原始 TCP 对端
VIA_KEY = "doc2sop.via"             # 经哪个可信代理转来（原始对端）；直连时没有
FORWARD_HEADERS = (b"x-forwarded-for", b"x-forwarded-proto", b"x-forwarded-host", b"x-forwarded-port",
                   b"x-real-ip", b"forwarded")
LOG_GAP = 60                        # 同一类配错，日志每这么多秒最多一行


class ConfigError(ValueError):
    """TRUSTED_PROXIES / FORWARDED_ALLOW_IPS 配得不对：拒绝启动。"""


def parse_trusted(text) -> tuple:
    """TRUSTED_PROXIES → 网段。写错的、* 和 0.0.0.0/0 这种「谁都信」的一律报错：配了就要配对。"""
    networks = []
    for entry in str(text or "").split(","):
        entry = entry.strip()
        if not entry:
            continue
        if entry == "*":
            raise ConfigError("TRUSTED_PROXIES 不能写 *：那样谁都能用 X-Forwarded-For 冒充别的地址（包括本机）。只写反向代理自己的地址")
        try:
            network = ipaddress.ip_network(entry, strict=False)
        except ValueError:
            raise ConfigError(f"TRUSTED_PROXIES 里的 {entry[:80]!r} 不是 IP 地址或网段（不能写主机名）") from None
        if network.prefixlen == 0:
            raise ConfigError(f"TRUSTED_PROXIES 不能写 {entry}：那样谁都能冒充别的地址。只写反向代理自己的地址")
        networks.append(network)
    return tuple(networks)


TRUSTED = parse_trusted(os.environ.get("TRUSTED_PROXIES", ""))


def ip_of(text):
    """文本 → IP 地址（IPv4 映射的 IPv6 地址换成 IPv4）；不是 IP 时 None。"""
    try:
        address = ipaddress.ip_address(str(text or "").strip())
    except ValueError:
        return None
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        return address.ipv4_mapped
    return address


def is_loopback(text) -> bool:
    address = ip_of(text)
    return address is not None and address.is_loopback


def is_trusted(text, networks=None) -> bool:
    networks = TRUSTED if networks is None else networks
    address = ip_of(text)
    return address is not None and any(address in network for network in networks)


def host_name(value) -> str:
    """Host 头 → 主机名（小写、去掉端口；[::1]:8765 → ::1）。认不出时空串。"""
    text = str(value or "").strip().lower()
    if text.startswith("["):
        end = text.find("]")
        return text[1:end] if end > 0 else ""
    if text.count(":") == 1:
        return text.split(":", 1)[0]
    return text


def local_host(value) -> bool:
    """Host 指的是不是本机：localhost（含 *.localhost）或回环地址。经 SSH 隧道、在本机上 curl 的请求都是这样。"""
    name = host_name(value)
    return name == "localhost" or name.endswith(".localhost") or is_loopback(name)


def _forwarded_entry(text):
    """X-Forwarded-For 的一项 → 规范的 IP 文本；带端口、带引号、带方括号的都认；认不出时 None。"""
    text = text.strip().strip('"')
    if text.startswith("["):
        text = text[1:text.find("]")] if "]" in text else ""
    elif text.count(":") == 1:
        text = text.split(":", 1)[0]
    address = ip_of(text)
    return str(address) if address is not None else None


def _client_from(chain, networks):
    """X-Forwarded-For 从右往左：跳过可信代理，第一个不可信的就是客户端。认不出的项 → None（来源不明）。"""
    entries = [part for part in chain.split(",") if part.strip()]
    found = None
    for part in reversed(entries):
        found = _forwarded_entry(part)
        if found is None:
            return None
        if not is_trusted(found, networks):
            return found
    return found      # 全是可信代理：最左边那个就是发起的人


# --- 最近一次配错（页面标红用） ---------------------------------------------------------------

_events = {}            # kind -> {"at", "peer", "why", "count"}
_logged = {}
_events_lock = threading.Lock()


def _note(kind, peer, why):
    now = time.time()
    with _events_lock:
        event = _events.get(kind) or {"count": 0}
        _events[kind] = {"at": now, "peer": str(peer)[:64], "why": why, "count": event["count"] + 1}
        quiet = now - _logged.get(kind, -LOG_GAP) < LOG_GAP
        if not quiet:
            _logged[kind] = now
    if not quiet:
        if kind == "untrusted":
            log.warning("request from %s looks forwarded (%s) but TRUSTED_PROXIES does not list it: "
                        "treated as an unknown outside address", str(peer)[:64], why)
        else:
            log.info("request from private address %s carries forwarding headers (%s); "
                     "if it is your reverse proxy, add it to TRUSTED_PROXIES", str(peer)[:64], why)


def events() -> dict:
    """{"untrusted": {...}, "private": {...}}：最近一次各是什么时候、从哪个对端、为什么、一共几次。"""
    with _events_lock:
        return {kind: dict(event) for kind, event in _events.items()}


def reset_events():
    with _events_lock:
        _events.clear()
        _logged.clear()


# --- 中间件 ---------------------------------------------------------------------------------

def _headers(scope) -> dict:
    found = {}
    for key, value in scope.get("headers") or []:
        key = key.lower()
        if key == b"host" or key in FORWARD_HEADERS:
            found.setdefault(key, []).append(value.decode("latin-1"))
    return found


def _scheme(scope, https: bool) -> str:
    if scope.get("type") == "websocket":
        return "wss" if https else "ws"
    return "https" if https else "http"


def resolve(scope, networks=None) -> None:
    """就地改写 scope：client 换成真实来源（或 UNTRUSTED），经可信代理时 scheme 按 X-Forwarded-Proto。"""
    networks = TRUSTED if networks is None else networks
    client = scope.get("client")
    peer = str(client[0]) if client else ""
    port = client[1] if client else 0
    scope[PEER_KEY] = peer
    headers = _headers(scope)
    forwarded = [key.decode() for key in FORWARD_HEADERS if key in headers]
    trusted = bool(networks) and is_trusted(peer, networks)
    if trusted and b"x-forwarded-for" in headers:
        found = _client_from(",".join(headers[b"x-forwarded-for"]), networks)
        scope[VIA_KEY] = peer
        protos = [p.strip().lower() for p in ",".join(headers.get(b"x-forwarded-proto", [])).split(",") if p.strip()]
        if protos and protos[-1] in ("http", "https"):
            scope["scheme"] = _scheme(scope, protos[-1] == "https")
        if found is None:
            _note("untrusted", peer, "可信代理给的 X-Forwarded-For 里认不出客户端地址")
        scope["client"] = (found or UNTRUSTED, 0)
        return
    if trusted:
        # 登记的代理却没带 X-Forwarded-For：不知道真实客户端是谁。只有本机对端、没带任何转发头、Host 也是本机的
        # （经 SSH 隧道、本机 curl，代理和应用在同一台机器时）才照常算它自己
        host = (headers.get(b"host") or [""])[0]
        if forwarded or not is_loopback(peer) or not local_host(host):
            _note("untrusted", peer, "登记的代理没带 X-Forwarded-For（只认这个头）")
            scope["client"] = (UNTRUSTED, port)
        return
    if is_loopback(peer):
        if forwarded:
            _note("untrusted", peer, "带了 " + "、".join(forwarded))
            scope["client"] = (UNTRUSTED, port)
        elif not local_host((headers.get(b"host") or [""])[0]):
            _note("untrusted", peer, "Host 不是本机地址（%s）" % (host_name((headers.get(b"host") or [""])[0])[:64] or "没有 Host"))
            scope["client"] = (UNTRUSTED, port)
        return
    if forwarded and not trusted:
        address = ip_of(peer)
        if address is not None and address.is_private:
            _note("private", peer, "带了 " + "、".join(forwarded))


class ClientAddress:
    """纯 ASGI 中间件：在一切之前把来源地址算对（见模块说明）。构造参数必须叫 app（老版本 Starlette 用 cls(app=…)）。"""

    def __init__(self, app, networks=None):
        self.app = app
        self.networks = networks

    async def __call__(self, scope, receive, send):
        if scope["type"] in ("http", "websocket"):
            resolve(scope, self.networks)
        await self.app(scope, receive, send)


# --- 给各处用的 -------------------------------------------------------------------------------

def address(request, default="-") -> str:
    """真实来源地址（经 ClientAddress 改写之后的 client）；经没登记的代理转来时是 UNTRUSTED。"""
    client = getattr(request, "client", None)
    return str(client.host) if client and client.host else default


def is_local(request) -> bool:
    """是不是本机来的（经 SSH 隧道、本机 curl）：只有回环地址算。UNTRUSTED、testclient 这类不是 IP 的都不算。"""
    return is_loopback(address(request, ""))


def transport(request) -> dict:
    """这次连接：是不是 HTTPS、真实来源、TCP 对端、经哪个可信代理；加上 TRUSTED_PROXIES 和最近的配错。"""
    scope = request.scope
    return {"https": scope.get("scheme") in ("https", "wss"),
            "client": address(request, ""), "untrusted": address(request, "") == UNTRUSTED,
            "peer": str(scope.get(PEER_KEY, address(request, ""))), "via": str(scope.get(VIA_KEY, "")),
            "trusted_proxies": [str(network) for network in TRUSTED], "events": events()}
