"""自动执行的服务器配置（docs/自动执行.md「服务器上的配置」）。

邮件（SMTP 主机、端口、加密方式、账号、授权码、发件人）、收件组、告警入口的令牌和来源地址、报告链接用的页面地址，
都只写在服务器上的一个文件里（AUTOMATION_FILE，默认 DATA_DIR/automation.yaml）。页面上只看得到收件组的名字和人数，
计划和告警规则也只能从收件组里选名字：如果页面能改收件人，拿到网页密码的人就能把巡检结果定时发到外面去。

改了不用重启：每次用到时看一眼文件的修改时间和大小，变了就重新读。读不了、写错了的部分按「没配」处理，
页面上写明哪里不对——说明里不带任何密钥和收件地址。
"""
import ipaddress
import os
import re
import threading
from dataclasses import dataclass, field
from email.utils import parseaddr
from urllib.parse import urlsplit

import yaml

from app.config import AUTOMATION_FILE, log

SECURITY = ("ssl", "starttls", "none")
DEFAULT_PORTS = {"ssl": 465, "starttls": 587, "none": 25}
TOKEN_MIN = 16              # 告警令牌至少多长：短了容易被猜
GROUP_MAX = 50              # 一个收件组最多几个地址
GROUPS_MAX = 20
NAME_MAX = 30
FILE_MAX = 64 * 1024
TIMEOUT = 20.0
EMAIL = re.compile(r"^[^@\s<>,;\"'()\[\]]+@[^@\s<>,;\"'()\[\]]+\.[^@\s<>,;\"'()\[\]]+$")
CONTROL = re.compile(r"[\x00-\x1f\x7f]")
KNOWN = ("site_url", "mail", "groups", "alerts")


@dataclass(frozen=True)
class Mail:
    host: str
    port: int
    security: str          # ssl（465）/ starttls（587）/ none（不登录的内网中继）
    user: str
    password: str
    sender: str            # From 头，可以带名字：doc2sop 巡检 <bot@example.com>
    sender_addr: str       # 信封发件人
    ca_file: str
    timeout: float


@dataclass(frozen=True)
class Settings:
    path: str
    exists: bool
    mail: Mail | None = None
    groups: dict = field(default_factory=dict)      # 名字 -> (地址, …)
    alert_token: str = ""
    alert_clients: tuple = ()                        # 原样的写法（页面显示）
    alert_networks: tuple = ()                       # 解析出的网段；配了却一项都不对时为空：全拒
    site_url: str = ""
    problems: tuple = ()
    loose: str = ""                                  # 文件权限太宽时的说明


_lock = threading.Lock()
_cache = {"key": None, "value": None}


def reset():
    """忘掉缓存（测试里同一秒内改两次文件、大小又一样时用）。"""
    with _lock:
        _cache.update(key=None, value=None)


def load() -> Settings:
    """此刻的配置。文件没变就用上次读到的；变了重新读，有问题记一行日志（不带密钥）。"""
    path = AUTOMATION_FILE
    try:
        st = path.stat()
    except FileNotFoundError:
        return Settings(path=str(path), exists=False)
    except OSError as exc:
        return Settings(path=str(path), exists=True, problems=(f"读不了这个文件：{exc.__class__.__name__}",))
    key = (st.st_mtime_ns, st.st_size, st.st_mode)
    with _lock:
        if _cache["key"] == key:
            return _cache["value"]
    value = _parse(path, st)
    with _lock:
        _cache.update(key=key, value=value)
    if value.problems or value.loose:
        log.warning("automation config %s: %s", path, "；".join(value.problems + ((value.loose,) if value.loose else ())))
    else:
        log.info("automation config loaded: mail=%s groups=%d alerts=%s", "on" if value.mail else "off",
                 len(value.groups), "on" if value.alert_token else "off")
    return value


def _where(exc) -> str:
    """YAML 写错的位置。不带出错那一行的内容：那一行可能就是授权码。"""
    mark = getattr(exc, "problem_mark", None)
    problem = getattr(exc, "problem", None) or exc.__class__.__name__
    return f"第 {mark.line + 1} 行第 {mark.column + 1} 列：{problem}" if mark is not None else str(problem)


def _parse(path, st) -> Settings:
    problems = []
    loose = ""
    if os.name != "nt" and st.st_mode & 0o077:
        loose = f"文件权限 {oct(st.st_mode & 0o777)[2:]} 太宽：里面有邮箱授权码和告警令牌，请 chmod 600"
    if st.st_size > FILE_MAX:
        return Settings(path=str(path), exists=True, problems=(f"文件超过 {FILE_MAX // 1024} KB，没有读",), loose=loose)
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        return Settings(path=str(path), exists=True, problems=(f"YAML 写错了，{_where(exc)}",), loose=loose)
    except (OSError, UnicodeDecodeError) as exc:
        return Settings(path=str(path), exists=True, problems=(f"读不了这个文件：{exc.__class__.__name__}",), loose=loose)
    data = data or {}
    if not isinstance(data, dict):
        return Settings(path=str(path), exists=True, problems=("最外层要写成「键: 值」",), loose=loose)
    unknown = [str(k) for k in data if k not in KNOWN]
    if unknown:
        problems.append(f"不认识的配置项：{'、'.join(unknown[:5])}（只认 {'、'.join(KNOWN)}）")
    mail = _mail(data.get("mail"), problems)
    groups = _groups(data.get("groups"), problems)
    token, clients, networks = _alerts(data.get("alerts"), problems)
    return Settings(path=str(path), exists=True, mail=mail, groups=groups, alert_token=token, alert_clients=clients,
                    alert_networks=networks, site_url=_site(data.get("site_url"), problems),
                    problems=tuple(problems), loose=loose)


def _text(value) -> str:
    return "" if value is None else str(value).strip()


def _mail(raw, problems):
    if raw in (None, "", {}):
        return None
    if not isinstance(raw, dict):
        problems.append("mail 要写成「键: 值」")
        return None
    host = _text(raw.get("host"))
    if not host or CONTROL.search(host) or any(c in host for c in "/@ "):
        problems.append("mail.host 没填或写得不对（只写主机名，如 smtp.qq.com）")
        return None
    security = _text(raw.get("security")).lower()
    port = raw.get("port")
    if not security:
        security = "ssl" if port in (None, 465, "465") else "starttls"
    if security not in SECURITY:
        problems.append(f"mail.security 只能是 {' / '.join(SECURITY)}")
        return None
    try:
        port = int(port) if port not in (None, "") else DEFAULT_PORTS[security]
    except (TypeError, ValueError):
        port = 0
    if not 1 <= port <= 65535:
        problems.append("mail.port 要是 1–65535 的整数")
        return None
    user, password = _text(raw.get("user")), _text(raw.get("password"))
    if security == "none" and (user or password):
        problems.append("mail.security 是 none（明文连接）时不能填 user、password：账号和授权码不能明文发出去，请用 ssl 或 starttls")
        return None
    if user and not password:
        problems.append("填了 mail.user 却没填 mail.password（邮箱的授权码）")
        return None
    sender = _text(raw.get("from")) or user
    _, addr = parseaddr(sender)
    if not EMAIL.match(addr or "") or CONTROL.search(sender):
        problems.append("mail.from 没填或写得不对：写发件地址，或「名字 <地址>」")
        return None
    try:
        timeout = min(120.0, max(5.0, float(raw.get("timeout") or TIMEOUT)))
    except (TypeError, ValueError):
        timeout = TIMEOUT
    return Mail(host=host, port=port, security=security, user=user, password=password, sender=sender,
                sender_addr=addr, ca_file=_text(raw.get("ca_file")), timeout=timeout)


def _groups(raw, problems) -> dict:
    if raw in (None, "", {}):
        return {}
    if not isinstance(raw, dict):
        problems.append("groups 要写成「组名: [地址, …]」")
        return {}
    out = {}
    for name, addresses in raw.items():
        name = " ".join(str(name).split())
        if not name or len(name) > NAME_MAX or CONTROL.search(name):
            problems.append(f"收件组的名字要是 1–{NAME_MAX} 个字")
            continue
        if isinstance(addresses, str):
            addresses = [a for a in re.split(r"[,;，；\s]+", addresses) if a]
        if not isinstance(addresses, list):
            problems.append(f"收件组「{name}」要写成地址列表")
            continue
        good = list(dict.fromkeys(_text(a) for a in addresses if EMAIL.match(_text(a))))
        bad = len([a for a in addresses if not EMAIL.match(_text(a))])
        if bad:
            problems.append(f"收件组「{name}」里有 {bad} 个地址写得不对，已忽略")
        if len(good) > GROUP_MAX:
            problems.append(f"收件组「{name}」超过 {GROUP_MAX} 个地址，只用前 {GROUP_MAX} 个")
            good = good[:GROUP_MAX]
        if not good:
            problems.append(f"收件组「{name}」没有可用的地址")
            continue
        if len(out) >= GROUPS_MAX:
            problems.append(f"收件组最多 {GROUPS_MAX} 个，后面的没有用")
            break
        out[name] = tuple(good)
    return out


def _alerts(raw, problems):
    if raw in (None, "", {}):
        return "", (), ()
    if not isinstance(raw, dict):
        problems.append("alerts 要写成「键: 值」")
        return "", (), ()
    token = _text(raw.get("token"))
    if token and (len(token) < TOKEN_MIN or CONTROL.search(token) or " " in token):
        problems.append(f"alerts.token 太短或含空白（至少 {TOKEN_MIN} 个字符，建议 openssl rand -hex 32），告警入口没有打开")
        token = ""
    clients = raw.get("clients") or []
    if isinstance(clients, str):
        clients = [c for c in re.split(r"[,\s]+", clients) if c]
    if not isinstance(clients, list):
        problems.append("alerts.clients 要写成列表")
        clients = []
    clients = tuple(_text(c) for c in clients if _text(c))
    networks = []
    for entry in clients:
        try:
            networks.append(ipaddress.ip_network(entry, strict=False))
        except ValueError:
            problems.append(f"alerts.clients 里的「{entry[:60]}」不是 IP 或网段，已忽略")
    if clients and not networks:
        problems.append("alerts.clients 一项都不对：告警入口拒绝所有来源")
    return token, clients, tuple(networks)


def _site(raw, problems) -> str:
    text = _text(raw).rstrip("/")
    if not text:
        return ""
    parts = urlsplit(text)
    if parts.scheme not in ("http", "https") or not parts.netloc or parts.query or parts.fragment or CONTROL.search(text):
        problems.append("site_url 要写成 http(s)://主机[:端口]，如 http://10.0.0.5:8765")
        return ""
    return text


def client_allowed(settings: Settings, host) -> bool:
    """告警入口的 TCP 对端地址在不在 alerts.clients 里；没配时都放行，配了却一项都不对时全拒（和 MCP_CLIENTS 一样）。"""
    if not settings.alert_clients:
        return True
    try:
        address = ipaddress.ip_address(str(host or ""))
    except ValueError:
        return False
    candidates = [address]
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        candidates.append(address.ipv4_mapped)
    return any(a in network for a in candidates for network in settings.alert_networks)


def public() -> dict:
    """页面上看得到的：有没有配、收件组的名字和人数、告警入口开没开、报告链接的地址、哪里写得不对。
    SMTP 主机、账号、授权码、收件地址、告警令牌一概不出现。"""
    s = load()
    return {"file": s.path, "exists": s.exists, "problems": list(s.problems), "loose": s.loose,
            "mail": {"configured": s.mail is not None, "security": s.mail.security if s.mail else ""},
            "groups": [{"name": name, "count": len(addresses)} for name, addresses in s.groups.items()],
            "alerts": {"enabled": bool(s.alert_token), "clients": list(s.alert_clients)},
            "site_url": s.site_url}
