"""自动执行的配置：发件邮箱（SMTP）、收件组、告警入口的令牌和来源地址、报告链接用的页面地址（docs/自动执行.md）。

两个来源，按键合并（automation_page.overlay）：
    服务器上手写的 AUTOMATION_FILE（默认 DATA_DIR/automation.yaml）：照旧有效，写了的键优先，在页面上只读；
    页面上填的（automation_page：DATA_DIR/automation.page.json，授权码和令牌另放 automation.page-secrets.json），
    扩大能力的改动要审批口令（工具服务核对）。
页面上看得到发件服务器、账号、收件组的地址（要改就得看得见）；授权码、告警令牌永远只有状态，没有值。

改了不用重启：每次用到时看一眼三个文件的 inode、修改时间、大小和权限，变了就重新读；应用自己写完直接清掉缓存。
读不了、写错了的部分按「没配」处理，页面上写明哪里不对——说明里不带任何密钥。
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
# 手写文件里写了就以手写为准的键（groups 按组名另算；整个 groups 写坏了时也在这里）
MANAGED = ("site_url", "mail", "groups", "alerts.token", "alerts.clients")


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
    # 下面是合并页面上的设置用的（automation_page.overlay）
    broken: bool = False                             # 手写文件在，却整个读不了：页面上的设置都不生效、也不能改
    server_keys: frozenset = frozenset()             # 手写文件里写了的键（MANAGED 里的）
    server_groups: frozenset = frozenset()           # 手写文件里的组名
    sources: dict = field(default_factory=dict)      # 每一项从哪来：server / page（页面显示）
    mail_problem: str = ""                           # 页面上的发件设置为什么用不了（授权码要重新输入……）
    skipped: tuple = ()                              # 页面上存了、却没生效的条目：({kind, name, reason}, …)
    page: object = None                              # automation_page.PageState


_lock = threading.Lock()
_cache = {"key": None, "value": None}


def reset():
    """忘掉缓存：应用自己写完设置后马上调，下一次 load() 一定重新读。"""
    with _lock:
        _cache.update(key=None, value=None)


def _stamp(path):
    """文件此刻的样子：inode、修改时间、大小、权限。原子替换后 inode 一定变——修改时间只精确到几毫秒，
    间隔很短的两次写、大小又一样时，只看修改时间会读到旧内容。"""
    try:
        st = os.stat(path)
    except FileNotFoundError:
        return None
    except OSError as exc:
        return ("unreadable", exc.__class__.__name__)
    return (st.st_ino, st.st_mtime_ns, st.st_size, st.st_mode)


def load() -> Settings:
    """此刻的配置：手写的 automation.yaml 加上页面上填的（手写的优先）。三个文件都没变就用上次读到的；
    变了重新读，有问题记一行日志（不带密钥）。"""
    from app import automation_page
    path = AUTOMATION_FILE
    key = (_stamp(path), _stamp(automation_page.PAGE_FILE), _stamp(automation_page.SECRETS_FILE))
    with _lock:
        if _cache["key"] == key:
            return _cache["value"]
    value = automation_page.overlay(_hand(path), automation_page.read())
    with _lock:
        _cache.update(key=key, value=value)
    if value.problems or value.loose:
        log.warning("automation config: %s", "；".join(value.problems + ((value.loose,) if value.loose else ())))
    if value.mail or value.groups or value.alert_token or value.site_url:
        log.info("automation config loaded: mail=%s groups=%d alerts=%s", "on" if value.mail else "off",
                 len(value.groups), "on" if value.alert_token else "off")
    return value


def _hand(path) -> Settings:
    """服务器上手写的那个文件。不在就是什么都没写；在却读不了时 broken：页面上的设置一概不生效（宁可不发、入口关着）。"""
    try:
        st = path.stat()
    except FileNotFoundError:
        return Settings(path=str(path), exists=False)
    except OSError as exc:
        return Settings(path=str(path), exists=True, broken=True, problems=(f"读不了这个文件：{exc.__class__.__name__}",))
    return _parse(path, st)


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
    broken = {"path": str(path), "exists": True, "broken": True, "loose": loose}
    if st.st_size > FILE_MAX:
        return Settings(**broken, problems=(f"文件超过 {FILE_MAX // 1024} KB，没有读",))
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        return Settings(**broken, problems=(f"YAML 写错了，{_where(exc)}",))
    except (OSError, UnicodeDecodeError) as exc:
        return Settings(**broken, problems=(f"读不了这个文件：{exc.__class__.__name__}",))
    data = data or {}
    if not isinstance(data, dict):
        return Settings(**broken, problems=("最外层要写成「键: 值」",))
    unknown = [str(k) for k in data if k not in KNOWN]
    if unknown:
        problems.append(f"不认识的配置项：{'、'.join(unknown[:5])}（只认 {'、'.join(KNOWN)}）")
    mail = _mail(data.get("mail"), problems)
    groups = _groups(data.get("groups"), problems)
    token, clients, networks = _alerts(data.get("alerts"), problems)
    keys, names = _defined(data)
    return Settings(path=str(path), exists=True, mail=mail, groups=groups, alert_token=token, alert_clients=clients,
                    alert_networks=networks, site_url=_site(data.get("site_url"), problems),
                    problems=tuple(problems), loose=loose, server_keys=keys, server_groups=names)


def _defined(data):
    """手写文件里写了哪些键、哪些组名：写了就以手写的为准（哪怕写错了、是空的），页面上存的同一项不生效。"""
    keys = {key for key in ("site_url", "mail") if key in data}
    alerts = data.get("alerts")
    if "alerts" in data and not isinstance(alerts, dict):
        keys.update(("alerts.token", "alerts.clients"))       # 写坏了：令牌、来源都算服务器上的
    elif isinstance(alerts, dict):
        keys.update(f"alerts.{name}" for name in ("token", "clients") if name in alerts)
    raw = data.get("groups")
    names = frozenset()
    if isinstance(raw, dict):
        names = frozenset(" ".join(str(name).split()) for name in raw)
    elif "groups" in data and raw not in (None, "", {}):
        keys.add("groups")                                   # groups 整个写坏了：页面上的组都不生效
    return frozenset(keys), names


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
    """摘要：有没有配、收件组的名字和人数、告警入口开没开、报告链接的地址、哪里写得不对（计划、告警规则的表单和顶上的状态用）。
    这里没有发件服务器、账号和收件地址；要看、要改的那份在 automation_page.view()。授权码、告警令牌哪里都没有值。"""
    s = load()
    return {"file": s.path, "exists": s.exists, "problems": list(s.problems), "loose": s.loose,
            "mail": {"configured": s.mail is not None, "security": s.mail.security if s.mail else ""},
            "groups": [{"name": name, "count": len(addresses)} for name, addresses in s.groups.items()],
            "alerts": {"enabled": bool(s.alert_token), "clients": list(s.alert_clients)},
            "site_url": s.site_url}
