"""自动执行的设置在页面上填：发件邮箱（SMTP）、报告链接、收件组、告警入口的令牌和来源地址（docs/自动执行.md「在页面上配置」）。

两个旁路文件，都在 DATA_DIR，0600，只由应用写（同目录的临时文件 + fsync + 原子替换）：
    automation.page.json           不含密钥：site_url、mail（没有授权码）、groups、alerts.clients，键名和 automation.yaml 一一对应。进备份
    automation.page-secrets.json   邮箱授权码（连同它绑定的去向：host、port、security、user）、告警令牌。只写不读，不进备份

和服务器上手写的 automation.yaml 按键合并（overlay）：手写里写了的键以手写为准，在页面上只读；页面上存的同一项不生效，写明原因。
扩大能力的改动要审批口令，由工具服务核对（ops_client.verify_passphrase：只核对，不写任何东西）；缩小能力的不要。

整个写操作在同一把锁里：读当前设置 → 核对版本号 → 查字段、判断扩大还是缩小 → 请工具服务核对口令 → 写文件 → 记一行变更。
应用是单进程（--workers 1），接口在线程池里跑，在锁里等口令核对没问题。版本号只用页面看得到的那份设置算：
授权码、令牌只带状态和设置时间——拿到版本号也没法离线去猜一个弱授权码。
"""
import contextlib
import copy
import dataclasses
import hashlib
import ipaddress
import json
import os
import re
import secrets
import tempfile
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.utils import parseaddr
from pathlib import Path
from urllib.parse import urlsplit

from app import automation_config, graph
from app.agent import ops_client
from app.automation_config import DEFAULT_PORTS, EMAIL, GROUP_MAX, GROUPS_MAX, NAME_MAX, SECURITY, TIMEOUT, TOKEN_MIN, Mail
from app.config import DATA_DIR, log

PAGE_FILE = DATA_DIR / "automation.page.json"
SECRETS_FILE = DATA_DIR / "automation.page-secrets.json"
PAGE_MAX = 64 * 1024
TEXT_MAX = 200              # 账号、发件人、授权码、报告链接、地址最长几个字
HOST_MAX = 253
CLIENTS_MAX = 50
CHANGES_KEEP, CHANGES_SHOWN = 200, 20
KNOWN = ("site_url", "mail", "groups", "alerts")
SECRET_KEYS = ("mail_password", "alert_token")
# 页面填的文本里不许有的：控制字符、C1 控制字符、行分隔符（会伪造日志行、弄乱邮件头）
BAD = re.compile(r"[\x00-\x1f\x7f-\x9f\u2028\u2029]")
URL_BAD = re.compile(r"[\s\\<>\"'`]")
SECURITY_NAMES = {"ssl": "SSL", "starttls": "STARTTLS", "none": "不加密"}
MAIL_LABELS = {"host": "服务器", "port": "端口", "security": "加密方式", "user": "账号", "from": "发件人"}
_write_lock = threading.Lock()      # 整个写操作（读、核对版本号、判断、核对口令、写文件、记变更）都在它里面


class Invalid(ValueError):
    """写得不对（400）：说明里不带授权码；在核对口令之前就拒绝，不消耗口令次数。"""


class Refused(Exception):
    """apply 不做这次改动：status 是给页面的 HTTP 状态码，extra 一起放进回复（used_by、stale……）。"""

    def __init__(self, status, message, **extra):
        super().__init__(message)
        self.status = status
        self.extra = extra


@dataclass(frozen=True)
class PageState:
    """页面上存的设置，读出来、查过的。raw 是 automation.page.json 的原样：重写时保留不认识的、写坏的条目。"""
    exists: bool = False
    broken: str = ""                                 # 整个读不了的原因（不带文件内容）
    raw: dict = field(default_factory=dict)
    site_url: str = ""
    mail: dict | None = None                         # {host, port, security, user, from}
    groups: dict = field(default_factory=dict)       # 名字 -> (地址, …)：写对了的
    clients: tuple = ()                              # 原样（页面显示）；写了却一项都不对时 networks 为空：全拒
    networks: tuple = ()
    skipped: tuple = ()                              # 写坏了、没生效的条目：({kind, name, reason}, …)
    problems: tuple = ()
    secrets_broken: str = ""
    secrets_raw: dict = field(default_factory=dict)
    password: dict | None = None                     # {value, dest: {host, port, security, user}, set_at}
    token: dict | None = None                        # {value, set_at}

    @property
    def anything(self) -> bool:
        return bool(self.site_url or self.mail or self.groups or self.clients or self.password or self.token)


@dataclass
class Plan:
    """一次改动要写什么。page / secrets 是整个文件的新内容（空的就删掉文件），None 表示不动这个文件。"""
    expand: bool
    detail: str                                      # 变更记录：不带授权码、令牌的值
    action: str = ""                                 # 请工具服务核对口令时写进它日志的 action、target
    target: str = ""
    page: dict | None = None
    secrets: dict | None = None
    secrets_first: bool = False
    token: str = ""                                  # 新生成的告警令牌：只回这一次


# --- 字段 ---------------------------------------------------------------------------------

def _text(value, what, limit=TEXT_MAX) -> str:
    if value is None:
        return ""
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        raise Invalid(f"{what}要是文本")
    text = str(value).strip()
    if len(text) > limit:
        raise Invalid(f"{what}最多 {limit} 个字")
    if BAD.search(text):
        raise Invalid(f"{what}里不能有换行之类的控制字符")
    return text


def _ipv6(host) -> bool:
    try:
        return isinstance(ipaddress.ip_address(host), ipaddress.IPv6Address)
    except ValueError:
        return False


def _port(value, security) -> int:
    if value in (None, ""):
        return DEFAULT_PORTS[security]
    if isinstance(value, str) and re.fullmatch(r"\s*\d{1,5}\s*", value):
        value = int(value)
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65535:
        raise Invalid("端口要是 1–65535 的整数")
    return value


def check_site(value) -> str:
    """报告链接：只认 http(s)://主机[:端口][/路径]；不能带账号密码、问号、#。"""
    text = _text(value, "报告链接").rstrip("/")
    if not text:
        return ""
    parts = urlsplit(text)
    try:
        parts.port
    except ValueError:
        parts = None
    if (parts is None or parts.scheme not in ("http", "https") or not parts.hostname or "@" in parts.netloc
            or parts.query or parts.fragment or "?" in text or "#" in text or URL_BAD.search(text)):
        raise Invalid("报告链接要写成 http(s)://主机[:端口]，如 http://127.0.0.1:8765；不能带账号密码、问号和 #")
    return text


def check_mail(raw) -> dict:
    """发件设置（不含授权码）。规则和服务器上的 automation.yaml 一样（automation_config._mail）。"""
    if not isinstance(raw, dict):
        raise Invalid("发件设置要写成「键: 值」")
    host = _text(raw.get("host"), "发件服务器", HOST_MAX)
    if not host or any(c in host for c in "/@ \\") or (":" in host and not _ipv6(host)):
        raise Invalid("发件服务器只写主机名，如 smtp.qq.com（端口单独填）")
    security = _text(raw.get("security"), "加密方式").lower()
    if not security:
        security = "ssl" if raw.get("port") in (None, "", 465, "465") else "starttls"
    if security not in SECURITY:
        raise Invalid("加密方式只能是 SSL、STARTTLS 或不加密")
    port = _port(raw.get("port"), security)
    user = _text(raw.get("user"), "账号")
    sender = _text(raw.get("from"), "发件人") or user
    if security == "none" and user:
        raise Invalid("不加密时不能填账号：账号和授权码不能明文发出去，请用 SSL（465）或 STARTTLS（587）")
    _, address = parseaddr(sender)
    if not EMAIL.match(address or ""):
        raise Invalid("发件人没填或写得不对：写发件地址，或「名字 <地址>」")
    return {"host": host, "port": port, "security": security, "user": user, "from": sender}


def check_name(value) -> str:
    name = " ".join(_text(value, "收件组的名字").split())
    if not name or len(name) > NAME_MAX:
        raise Invalid(f"收件组的名字要是 1–{NAME_MAX} 个字")
    return name


def check_addresses(value, name) -> tuple:
    if isinstance(value, str):
        value = [a for a in re.split(r"[,;，；\s]+", value) if a]
    if not isinstance(value, list):
        raise Invalid(f"收件组「{name}」要写成地址列表")
    out, seen = [], set()
    for number, item in enumerate(value, 1):
        address = item.strip() if isinstance(item, str) else ""
        if not EMAIL.match(address) or len(address) > TEXT_MAX or BAD.search(address):
            shown = f"：{address[:60]}" if address and not BAD.search(address) else ""
            raise Invalid(f"收件组「{name}」的第 {number} 个地址写得不对{shown}")
        if address.lower() not in seen:
            seen.add(address.lower())
            out.append(address)
    if not out:
        raise Invalid(f"收件组「{name}」至少要有一个地址")
    if len(out) > GROUP_MAX:
        raise Invalid(f"一个收件组最多 {GROUP_MAX} 个地址")
    return tuple(out)


def check_clients(value) -> tuple:
    """告警来源地址 → ((原样, 网段), …)。"""
    if isinstance(value, str):
        value = [c for c in re.split(r"[,，;；\s]+", value) if c]
    if not isinstance(value, list):
        raise Invalid("来源地址要写成列表")
    out, seen = [], set()
    for number, item in enumerate(value, 1):
        text = item.strip() if isinstance(item, str) else ""
        try:
            network = ipaddress.ip_network(text, strict=False)
        except ValueError:
            raise Invalid(f"第 {number} 个来源地址不是 IP 或网段（写成 10.0.0.5 或 10.0.0.0/8）") from None
        if network not in seen:
            seen.add(network)
            out.append((text, network))
    if len(out) > CLIENTS_MAX:
        raise Invalid(f"来源地址最多 {CLIENTS_MAX} 项")
    return tuple(out)


def _dest(mail) -> tuple:
    """授权码绑定的去向：发件服务器（不分大小写）、端口、加密方式、账号。任何一项变了，存着的授权码就不再用。"""
    mail = mail if isinstance(mail, dict) else {}
    return (str(mail.get("host") or "").lower(), mail.get("port"), mail.get("security"), mail.get("user"))


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


# --- 读 -----------------------------------------------------------------------------------

def _load(path, secret=False):
    """(内容, 读不了的原因, 在不在, 权限太宽的说明)。原因里只有位置、没有内容：那一行可能就是授权码。"""
    try:
        st = os.stat(path)
    except FileNotFoundError:
        return None, "", False, ""
    except OSError as exc:
        return None, f"读不了（{exc.__class__.__name__}）", True, ""
    loose = ""
    if secret and os.name != "nt" and st.st_mode & 0o077:
        loose = f"{path.name} 的权限 {oct(st.st_mode & 0o777)[2:]} 太宽：里面有授权码和告警令牌，请 chmod 600"
    if st.st_size > PAGE_MAX:
        return None, f"超过 {PAGE_MAX // 1024} KB", True, loose
    try:
        text = Path(path).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        return None, f"读不了（{exc.__class__.__name__}）", True, loose
    try:
        data = json.loads(text) if text.strip() else {}
    except json.JSONDecodeError as exc:
        return None, f"JSON 写错了，第 {exc.lineno} 行第 {exc.colno} 列：{exc.msg}", True, loose
    except (ValueError, RecursionError):
        return None, "JSON 写错了", True, loose
    if not isinstance(data, dict):
        return None, "最外层要是 JSON 对象", True, loose
    return data, "", True, loose


def _entries(raw, problems, skipped) -> dict:
    """automation.page.json 里的每一项：写对了的拿来用，写坏了的跳过并写明原因（手改坏了也照常运行）。"""
    out = {}
    unknown = [str(key)[:30] for key in raw if key not in KNOWN]
    if unknown:
        problems.append(f"{PAGE_FILE.name} 里有不认识的键：{'、'.join(unknown[:5])}（只认 {'、'.join(KNOWN)}），没有用")

    def skip(kind, name, exc):
        skipped.append({"kind": kind, "name": name, "reason": str(exc), "where": "page"})

    if "site_url" in raw:
        try:
            out["site_url"] = check_site(raw["site_url"])
        except Invalid as exc:
            skip("site_url", "报告链接", exc)
    if "mail" in raw:
        try:
            out["mail"] = check_mail(raw["mail"])
        except Invalid as exc:
            skip("mail", "发件设置", exc)
    groups = raw.get("groups")
    if "groups" in raw and not isinstance(groups, dict):
        skip("groups", "收件组", "groups 要写成「组名: [地址, …]」")
    elif isinstance(groups, dict):
        valid = {}
        for key, addresses in groups.items():
            try:
                name = check_name(key)
            except Invalid as exc:
                skip("group", str(key)[:NAME_MAX], exc)
                continue
            if name in valid:
                skip("group", name, "和前面的收件组重名")
                continue
            try:
                valid[name] = check_addresses(addresses, name)
            except Invalid as exc:
                skip("group", name, exc)
        out["groups"] = valid
    alerts = raw.get("alerts")
    if "alerts" in raw and not isinstance(alerts, dict):
        skip("alert_clients", "告警来源地址", "alerts 要写成「键: 值」")
    elif isinstance(alerts, dict) and alerts.get("clients") not in (None, [], ""):
        entries = alerts["clients"] if isinstance(alerts["clients"], list) else [alerts["clients"]]
        texts, networks = [], []
        for item in entries:
            text = str(item).strip()[:60]
            texts.append(text)
            try:
                networks.append(ipaddress.ip_network(text, strict=False))
            except ValueError:
                pass
        if len(networks) < len(texts):
            skip("alert_clients", "告警来源地址", f"有 {len(texts) - len(networks)} 项不是 IP 或网段，没有用"
                 + ("；一项都不对：告警入口拒绝所有来源" if not networks else ""))
        out["clients"], out["networks"] = tuple(texts), tuple(networks)
    return out


def _secrets(raw, problems) -> dict:
    out = {}
    entry = raw.get("mail_password")
    if entry is not None:
        dest = entry.get("dest") if isinstance(entry, dict) else None
        value = entry.get("value") if isinstance(entry, dict) else None
        if (isinstance(value, str) and value and len(value) <= TEXT_MAX and not BAD.search(value)
                and isinstance(dest, dict)):
            out["password"] = {"value": value, "dest": {key: dest.get(key) for key in ("host", "port", "security", "user")},
                               "set_at": str(entry.get("set_at") or "")[:40]}
        else:
            problems.append("存着的授权码那一项写坏了，没有用：要重新输入授权码")
    entry = raw.get("alert_token")
    if entry is not None:
        value = entry.get("value") if isinstance(entry, dict) else None
        if (isinstance(value, str) and TOKEN_MIN <= len(value) <= TEXT_MAX and not BAD.search(value)
                and " " not in value):
            out["token"] = {"value": value, "set_at": str(entry.get("set_at") or "")[:40]}
        else:
            problems.append("存着的告警令牌那一项写坏了，没有用：要重新生成")
    return out


def read() -> PageState:
    """两个旁路文件此刻的内容。读不了、写错了的部分按「没存」处理，原因进 problems / skipped（不带任何密钥）。"""
    raw, broken, exists, _ = _load(PAGE_FILE)
    secrets_raw, secrets_broken, _, loose = _load(SECRETS_FILE, secret=True)
    problems, skipped = [], []
    if broken:
        problems.append(f"页面上存的设置（{PAGE_FILE.name}）读不了：{broken}。页面上填的都没有生效；"
                        "修好或删掉这个文件之前，页面上不能改")
    if secrets_broken:
        problems.append(f"存授权码、告警令牌的文件（{SECRETS_FILE.name}）读不了：{secrets_broken}。"
                        "按没存处理：授权码要重新输入，告警令牌要重新生成")
    if loose:
        problems.append(loose)
    entries = _entries(raw, problems, skipped) if raw else {}
    stored = _secrets(secrets_raw, problems) if secrets_raw else {}
    return PageState(exists=exists, broken=broken, raw=raw or {}, problems=tuple(problems), skipped=tuple(skipped),
                     secrets_broken=secrets_broken, secrets_raw=secrets_raw or {}, **entries, **stored)


# --- 和手写的合并 -----------------------------------------------------------------------------

def _page_mail(page):
    """页面上的发件设置 → Mail；授权码对不上去向（改过服务器、端口、加密方式、账号）就不用，说明为什么用不了。"""
    mail, password = page.mail, ""
    if mail["user"]:
        stored = page.password
        if stored is None:
            return None, ("存授权码的文件读不了：要重新输入授权码" if page.secrets_broken
                          else "要输入授权码：还没输入过，或者改了发件服务器、端口、加密方式、账号以后原来的作废了")
        if _dest(stored["dest"]) != _dest(mail):
            return None, "授权码要重新输入：发件服务器、端口、加密方式或账号改过了"
        password = stored["value"]
    _, address = parseaddr(mail["from"])
    return Mail(host=mail["host"], port=mail["port"], security=mail["security"], user=mail["user"], password=password,
                sender=mail["from"], sender_addr=address, ca_file="", timeout=TIMEOUT), ""


def overlay(hand, page: PageState):
    """手写的 automation.yaml（hand）加上页面上存的（page）：手写里写了的键以手写为准，页面上同一项跳过并写明原因。
    手写文件在却读不了（broken）时，页面上的一概不生效：宁可不发邮件、入口关着，也不拿一半的配置去用。"""
    keys, name = hand.server_keys, Path(hand.path).name
    skipped, problems = list(page.skipped), list(hand.problems) + list(page.problems)
    sources = {"groups": {group: "server" for group in hand.groups}}
    for key in ("site_url", "mail", "alerts.token", "alerts.clients"):
        if key in keys:
            sources[key] = "server"

    def shadow(kind, label, why):
        skipped.append({"kind": kind, "name": label, "reason": why, "where": "page"})

    if hand.broken:
        if page.anything:
            shadow("all", "页面上的设置", f"服务器上的 {name} 读不了：修好或删掉它之前，页面上的设置都不生效")
        return dataclasses.replace(hand, problems=tuple(problems), skipped=tuple(skipped), sources=sources, page=page)
    server = f"服务器上的 {name} 里写了 {{}}，以它为准"
    site_url, mail, mail_problem = hand.site_url, hand.mail, ""
    if "site_url" in keys:
        if page.site_url:
            shadow("site_url", "报告链接", server.format("site_url"))
    elif page.site_url:
        site_url, sources["site_url"] = page.site_url, "page"
    if "mail" in keys:
        if page.mail or page.password:
            shadow("mail", "发件设置", server.format("mail") + "（整段，连同授权码）")
    elif page.mail:
        sources["mail"] = "page"
        mail, mail_problem = _page_mail(page)
    groups = dict(hand.groups)
    for group, addresses in page.groups.items():
        if "groups" in keys:
            shadow("group", group, f"服务器上的 {name} 里 groups 写得不对，以它为准：页面上的收件组都不生效")
        elif group in hand.server_groups:
            shadow("group", group, f"服务器上的 {name} 里有同名的收件组，以它为准")
        elif len(groups) >= GROUPS_MAX:
            shadow("group", group, f"收件组最多 {GROUPS_MAX} 个（服务器上的和页面上的加起来），这一组没有用")
        else:
            groups[group] = addresses
            sources["groups"][group] = "page"
    token = hand.alert_token
    if "alerts.token" in keys:
        if page.token:
            shadow("alert_token", "告警令牌", server.format("alerts.token"))
    elif page.token:
        token, sources["alerts.token"] = page.token["value"], "page"
    clients, networks = hand.alert_clients, hand.alert_networks
    if "alerts.clients" in keys:
        if page.clients:
            shadow("alert_clients", "告警来源地址", server.format("alerts.clients"))
    elif page.clients:
        clients, networks, sources["alerts.clients"] = page.clients, page.networks, "page"
    return dataclasses.replace(hand, site_url=site_url, mail=mail, mail_problem=mail_problem, groups=groups,
                               alert_token=token, alert_clients=clients, alert_networks=networks,
                               problems=tuple(problems), skipped=tuple(skipped), sources=sources, page=page)


# --- 页面看到的 -------------------------------------------------------------------------------

def _mail_view(settings, page) -> dict:
    source = settings.sources.get("mail", "")
    empty = {"host": "", "port": None, "security": "", "user": "", "from": ""}
    if source == "server":
        mail = settings.mail
        values = ({"host": mail.host, "port": mail.port, "security": mail.security, "user": mail.user,
                   "from": mail.sender} if mail else empty)
        state = "server" if mail and mail.user else "none"
        return {"source": "server", "configured": mail is not None, **values,
                "password": {"state": state, "set_at": ""}, "problem": ""}
    if source == "page":
        mail, stored = page.mail, page.password
        if not mail["user"]:
            state = "none"
        elif stored and _dest(stored["dest"]) == _dest(mail):
            state = "set"
        else:
            state = "missing"
        return {"source": "page", "configured": settings.mail is not None, **mail,
                "password": {"state": state, "set_at": stored["set_at"] if state == "set" else ""},
                "problem": settings.mail_problem}
    return {"source": "", "configured": False, **empty, "password": {"state": "none", "set_at": ""}, "problem": ""}


def sections(settings) -> dict:
    """页面上看到的那份设置。地址、账号都在（要改就得看得见）；授权码、令牌只有状态和设置时间，永远没有值。"""
    page = settings.page if isinstance(settings.page, PageState) else PageState()
    sources = settings.sources or {}
    token_source = sources.get("alerts.token", "")
    return {
        "mail": _mail_view(settings, page),
        "site_url": {"source": sources.get("site_url", ""), "value": settings.site_url,
                     "plain": settings.site_url.startswith("http://")},
        "groups": [{"name": name, "addresses": list(addresses), "source": sources.get("groups", {}).get(name, "server")}
                   for name, addresses in settings.groups.items()],
        "alerts": {"enabled": bool(settings.alert_token),
                   "token": {"source": token_source, "state": "set" if settings.alert_token else "none",
                             "set_at": page.token["set_at"] if token_source == "page" and page.token else ""},
                   "clients": {"source": sources.get("alerts.clients", ""), "values": list(settings.alert_clients)}},
        "skipped": list(settings.skipped),
        "problems": list(settings.problems) + ([settings.loose] if settings.loose else []),
        "server": {"file": settings.path, "exists": settings.exists, "broken": settings.broken,
                   "keys": sorted(settings.server_keys), "groups": sorted(settings.server_groups)},
        "page": {"file": str(PAGE_FILE), "exists": page.exists, "broken": page.broken,
                 "secrets_file": str(SECRETS_FILE), "secrets_broken": page.secrets_broken,
                 "groups": sorted(_names(page.raw.get("groups"))), "mail": "mail" in page.raw,
                 "site_url": "site_url" in page.raw, "clients": bool(page.clients),
                 "password": "mail_password" in page.secrets_raw and not page.secrets_broken,
                 "token": "alert_token" in page.secrets_raw and not page.secrets_broken},
    }


def version_of(settings) -> str:
    """版本号：页面看到的那份设置的哈希。只用不含密钥的内容——授权码、令牌在里面只有状态和设置时间。"""
    text = json.dumps(sections(settings), ensure_ascii=False, sort_keys=True, default=str)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def _blocked(settings) -> str:
    if settings.broken:
        return (f"服务器上的 {Path(settings.path).name} 读不了或写坏了：修好或删掉它之前，"
                "页面上的设置都不生效，也不能改")
    page = settings.page
    if isinstance(page, PageState) and page.broken:
        return f"{PAGE_FILE.name} 读不了（{page.broken}）：修好或删掉这个文件之前页面上不能改，免得盖掉手改的内容"
    return ""


def used_by() -> dict:
    """收件组 → 选了它的计划和告警规则（删组之前页面上列出来、请求里带回来核对）。"""
    from app import alerts, playbooks, schedules
    books = {}

    def book(playbook_id):
        if playbook_id not in books:
            item = playbooks.get(playbook_id)
            books[playbook_id] = item["name"] if item else "（SOP 已删除）"
        return books[playbook_id]

    out = {}
    for item in schedules.listing():
        group = (item.get("notify") or {}).get("group")
        if group:
            out.setdefault(group, []).append({"kind": "schedule", "id": item["id"],
                                              "name": f"计划：{book(item['playbook_id'])}，{item['describe']}"})
    for rule in alerts.rules():
        group = (rule.get("notify") or {}).get("group")
        if group:
            label = f"，告警名包含「{rule['name_contains']}」" if rule.get("name_contains") else ""
            out.setdefault(group, []).append({"kind": "rule", "id": rule["id"],
                                              "name": f"告警规则：{book(rule['playbook_id'])}{label}"})
    return out


def changes(limit=CHANGES_SHOWN) -> list:
    with graph.lock:
        rows = graph.db.execute("SELECT at, user, ip, kind, detail FROM automation_changes ORDER BY id DESC LIMIT ?",
                                (limit,)).fetchall()
    return [dict(row) for row in rows]


def view() -> dict:
    """GET /api/automation 里的 settings：设置、版本号、能不能改（不能改的原因）、审批口令的状态、在用各收件组的计划和规则、最近的变更。"""
    settings = automation_config.load()
    out = sections(settings)
    out["version"] = version_of(settings)
    support = ops_client.verify_support()
    reason = support["reason"] or _blocked(settings)
    out["writable"] = {"ok": not reason, "reason": reason}
    out["approval"] = ops_client.approval_status() if support["supported"] else None
    out["used_by"] = used_by()
    out["changes"] = changes()
    out["limits"] = {"groups": GROUPS_MAX, "addresses": GROUP_MAX, "name": NAME_MAX, "clients": CLIENTS_MAX,
                     "text": TEXT_MAX, "ports": DEFAULT_PORTS}
    return out


# --- 写 -----------------------------------------------------------------------------------

def _names(groups) -> set:
    return {" ".join(str(key).split()) for key in groups} if isinstance(groups, dict) else set()


def _group_key(groups, name):
    """name 在原样里是哪个键（原样的组名可能多了空白）。"""
    for key in groups:
        if " ".join(str(key).split()) == name:
            return key
    return None


def _ordered(raw) -> dict:
    out = {key: raw[key] for key in KNOWN if key in raw}
    out.update((key, value) for key, value in raw.items() if key not in out)
    return out


def _page_copy(page) -> dict:
    return copy.deepcopy(page.raw)


def _secrets_copy(page) -> dict:
    return {} if page.secrets_broken else copy.deepcopy(page.secrets_raw)


def _managed(settings, key, what):
    if key in settings.server_keys:
        raise Refused(409, f"{what}写在服务器上的 {Path(settings.path).name} 里（{key}），以它为准：页面上不能改")


def _plan_mail(change, settings, page) -> Plan:
    _managed(settings, "mail", "发件设置")
    new = check_mail(change)
    password = _text(change.get("password"), "授权码")
    if password and not new["user"]:
        raise Invalid("填了授权码却没填账号")
    stored, old = page.password, page.mail
    same = bool(stored) and bool(new["user"]) and _dest(stored["dest"]) == _dest(new)
    if old == new and not password and (same or not stored):
        raise Invalid("没有改动")
    raw, secret = _page_copy(page), _secrets_copy(page)
    raw["mail"] = new
    if password:
        secret["mail_password"] = {"value": password, "dest": {key: new[key] for key in ("host", "port", "security", "user")},
                                   "set_at": _now()}
        note = "授权码已更新"
    elif same:
        secret, note = None, "授权码沿用"
    elif stored:
        secret.pop("mail_password", None)
        note = "原来的授权码作废了，要重新输入" if new["user"] else "不再需要授权码，存着的删掉了"
    else:
        secret, note = None, "还没有输入授权码" if new["user"] else "不需要授权码"
    where = f"{new['host']}:{new['port']}（{SECURITY_NAMES[new['security']]}）"
    if old:
        changed = [label for key, label in MAIL_LABELS.items() if old.get(key) != new[key]]
        detail = f"改发件设置：{where}" + (f"，改了{'、'.join(changed)}" if changed else "") + f"；{note}"
    else:
        detail = f"新设发件设置：{where}；{note}"
    return Plan(expand=True, detail=detail, action="邮件设置", target=f"发件服务器 {new['host']}:{new['port']}",
                page=_ordered(raw), secrets=secret, secrets_first=bool(password))


def _plan_mail_clear(change, settings, page) -> Plan:
    has_secret = "mail_password" in page.secrets_raw and not page.secrets_broken
    if "mail" not in page.raw and not has_secret:
        raise Invalid("页面上没有存发件设置")
    raw = _page_copy(page)
    raw.pop("mail", None)
    secret = None
    if has_secret:
        secret = _secrets_copy(page)
        secret.pop("mail_password", None)
    return Plan(expand=False, detail="清除页面上的发件设置（连同存着的授权码）", page=_ordered(raw), secrets=secret)


def _plan_site(change, settings, page) -> Plan:
    _managed(settings, "site_url", "报告链接")
    value = check_site(change.get("value"))
    if not value:
        raise Invalid("要填报告链接；不要了就点「清空」")
    if value == page.raw.get("site_url"):
        raise Invalid("没有改动")
    raw = _page_copy(page)
    raw["site_url"] = value
    return Plan(expand=True, detail=f"报告链接改成 {value}", action="邮件设置", target=f"报告链接 {value}",
                page=_ordered(raw))


def _plan_site_clear(change, settings, page) -> Plan:
    if "site_url" not in page.raw:
        raise Invalid("页面上没有存报告链接")
    raw = _page_copy(page)
    raw.pop("site_url")
    return Plan(expand=False, detail="清空报告链接：邮件里不再带链接", page=_ordered(raw))


def _plan_group(change, settings, page) -> Plan:
    if "groups" in settings.server_keys:
        raise Refused(409, f"服务器上的 {Path(settings.path).name} 里 groups 写得不对，收件组都以它为准：修好之前页面上不能改")
    name = check_name(change.get("name"))
    if name in settings.server_groups:
        raise Refused(409, f"收件组「{name}」写在服务器上的 {Path(settings.path).name} 里，以它为准：页面上不能改")
    addresses = check_addresses(change.get("addresses"), name)
    raw = _page_copy(page)
    groups = raw.get("groups") if isinstance(raw.get("groups"), dict) else {}
    key, create = _group_key(groups, name), change.get("create") is True
    if create and key is not None:
        raise Invalid(f"已经有叫「{name}」的收件组了")
    if not create and key is None:
        raise Refused(409, f"收件组「{name}」不存在（可能刚被删掉）：刷新后再改", stale=True)
    if create and len(set(settings.server_groups) | _names(groups)) >= GROUPS_MAX:
        raise Invalid(f"收件组最多 {GROUPS_MAX} 个（服务器上的和页面上的加起来）")
    old = page.groups.get(name, ())
    if not create and addresses == tuple(old):
        raise Invalid("没有改动")
    known = {address.lower() for address in old}
    added = [address for address in addresses if address.lower() not in known]
    removed = len(known - {address.lower() for address in addresses})
    if create:
        groups[name] = list(addresses)
        detail = f"新建收件组「{name}」（{len(addresses)} 个地址）"
        target = f"收件组 {name}（新建，{len(addresses)} 个地址）"
    else:
        groups = {(name if k == key else k): (list(addresses) if k == key else v) for k, v in groups.items()}
        parts = ([f"加 {len(added)} 个地址"] if added else []) + ([f"删 {removed} 个"] if removed else [])
        detail = f"收件组「{name}」：{'、'.join(parts) or '调了顺序'}（现在 {len(addresses)} 个）"
        target = f"收件组 {name}（加 {len(added)} 个地址）"
    raw["groups"] = groups
    return Plan(expand=create or bool(added), detail=detail, action="邮件设置", target=target, page=_ordered(raw))


def _confirm(given, current, name):
    """删在用的收件组：请求里带的「选了它的计划和告警规则」要和现在的一样，不一样回 409 和现在的列表，不消耗口令次数。
    现在没有谁在用就不用确认（工具服务的 _page_confirm 同一个做法）。"""
    if not current:
        return
    wanted = sorted(f"{item['kind']}:{item['id']}" for item in current)
    got = None
    if isinstance(given, list):
        got = sorted({f"{item.get('kind')}:{item.get('id')}" if isinstance(item, dict) else str(item) for item in given})
    if got != wanted:
        raise Refused(409, f"还有 {len(current)} 条计划、告警规则选着收件组「{name}」：确认之后再删（和你看到的不一样时请刷新）",
                      used_by=current)


def _plan_group_delete(change, settings, page) -> Plan:
    name = check_name(change.get("name"))
    raw = _page_copy(page)
    groups = raw.get("groups") if isinstance(raw.get("groups"), dict) else {}
    key = _group_key(groups, name)
    if key is None:
        if name in settings.server_groups or "groups" in settings.server_keys:
            raise Refused(409, f"收件组「{name}」写在服务器上的 {Path(settings.path).name} 里：页面上不能删")
        raise Refused(409, f"收件组「{name}」不存在（可能刚被删掉）：刷新后再看", stale=True)
    current = used_by().get(name, []) if settings.sources.get("groups", {}).get(name) == "page" else []
    _confirm(change.get("used_by"), current, name)
    del groups[key]
    if groups:
        raw["groups"] = groups
    else:
        raw.pop("groups", None)
    count = len(page.groups.get(name, ()))
    detail = f"删除收件组「{name}」" + (f"（{count} 个地址）" if count else "")
    if current:
        detail += f"；{len(current)} 条计划、告警规则还选着它，以后这一项发不出邮件"
    return Plan(expand=False, detail=detail, page=_ordered(raw))


def _plan_token(change, settings, page) -> Plan:
    _managed(settings, "alerts.token", "告警令牌")
    token, rotate = secrets.token_hex(32), page.token is not None
    secret = _secrets_copy(page)
    secret["alert_token"] = {"value": token, "set_at": _now()}
    return Plan(expand=True, detail="重新生成告警令牌：旧的立即失效" if rotate else "生成告警令牌：告警入口打开",
                action="告警入口", target="重新生成告警令牌" if rotate else "生成告警令牌", secrets=secret,
                secrets_first=True, token=token)


def _plan_token_delete(change, settings, page) -> Plan:
    if page.secrets_broken or "alert_token" not in page.secrets_raw:
        raise Invalid("页面上没有存告警令牌")
    secret = _secrets_copy(page)
    secret.pop("alert_token")
    detail = ("删除页面上存的告警令牌（服务器上配置的照常有效）" if "alerts.token" in settings.server_keys
              else "删除告警令牌：告警入口回到 404")
    return Plan(expand=False, detail=detail, secrets=secret)


def _plan_clients(change, settings, page) -> Plan:
    entries = check_clients(change.get("clients"))
    texts, networks = [text for text, _ in entries], [network for _, network in entries]
    managed = "alerts.clients" in settings.server_keys
    if managed and (entries or not page.clients):
        _managed(settings, "alerts.clients", "告警来源地址")
    if tuple(texts) == tuple(page.clients):
        raise Invalid("没有改动")
    if managed or not page.clients:
        expand = False                    # 没生效的页面条目；或者原来不限来源，现在加了限制
    elif not entries:
        expand = True                     # 删到一个不剩 = 不限来源
    else:
        expand = any(not any(new.version == old.version and new.subnet_of(old) for old in page.networks)
                     for new in networks)
    raw = _page_copy(page)
    alerts = dict(raw["alerts"]) if isinstance(raw.get("alerts"), dict) else {}
    if entries:
        alerts["clients"] = texts
    else:
        alerts.pop("clients", None)
    if alerts:
        raw["alerts"] = alerts
    else:
        raw.pop("alerts", None)
    shown = "、".join(texts)
    detail = f"告警来源地址改成 {shown}" if entries else "告警来源地址清空：不限来源"
    target = f"来源地址 {shown}" if entries else "来源地址 不限"
    return Plan(expand=expand, detail=detail, action="告警入口", target=target, page=_ordered(raw))


PLANNERS = {"mail": _plan_mail, "mail-clear": _plan_mail_clear, "site-url": _plan_site,
            "site-url-clear": _plan_site_clear, "group": _plan_group, "group-delete": _plan_group_delete,
            "alert-token": _plan_token, "alert-token-delete": _plan_token_delete, "alert-clients": _plan_clients}


def _write(path, data):
    """整个文件换成 data（空的就删掉文件）：同目录的临时文件写完、fsync、0600，再原子替换——写到一半断电，旧文件还在。"""
    if not data:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(path)
        return
    text = json.dumps(data, ensure_ascii=False, indent=2) + "\n"
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise
    if os.name != "nt":
        with contextlib.suppress(OSError):
            directory = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)


def _commit(plan):
    """先写哪个文件都安全：授权码绑定了去向，两个文件对不上时它不会被用到新的去向上。新的密钥先写，删的后删。"""
    steps = [(SECRETS_FILE, plan.secrets), (PAGE_FILE, plan.page)]
    if not plan.secrets_first:
        steps.reverse()
    try:
        for path, data in steps:
            if data is not None:
                _write(path, data)
    finally:
        automation_config.reset()


def _record(kind, detail, user, ip):
    with graph.lock:
        graph.db.execute("INSERT INTO automation_changes (at, user, ip, kind, detail) VALUES (?, ?, ?, ?, ?)",
                         (graph.now_iso(), user, ip, kind, detail))
        graph.db.execute("DELETE FROM automation_changes WHERE id NOT IN"
                         " (SELECT id FROM automation_changes ORDER BY id DESC LIMIT ?)", (CHANGES_KEEP,))
        graph.db.commit()
    log.info("automation settings changed (user=%s ip=%s): %s", user, ip, detail)


def _verify(passphrase, plan, caller):
    """请工具服务核对口令。只有它回 200 且 {"ok": true} 才算通过；别的一律不写：拒绝照原来的状态码，
    老工具服务 403，连不上、超时 503，其余（5xx、回的不对、任何意外）502。"""
    target = BAD.sub(" ", plan.target)[:120]
    try:
        ops_client.verify_passphrase(passphrase, plan.action, target, caller)
    except ops_client.OpsUnavailable as exc:
        status = exc.status
        if status == 404:
            raise Refused(403, ops_client.OLD_SERVICE_VERIFY) from None
        if status in ops_client.VERIFY_REFUSALS:
            raise Refused(status, str(exc), passphrase=status in (400, 403)) from None
        raise Refused(status if status in (502, 503) else 502, str(exc)) from None
    except Exception as exc:
        log.warning("automation settings: verifying the passphrase failed unexpectedly: %s", exc.__class__.__name__)
        raise Refused(502, "核对审批口令时出了意外，不算通过：没有改") from None


def apply(data, caller="", user="", ip="") -> dict:
    """页面上的一次改动：{version, change: {kind, …}, passphrase}。返回新的设置；生成告警令牌时另带 token（只这一次）。
    不改时抛 Refused。顺序固定：能不能写、版本号、字段（都不消耗口令次数）→ 扩大能力的核对口令 → 写文件 → 记变更。"""
    if not isinstance(data, dict):
        raise Refused(400, "请求体必须是 JSON 对象")
    change = data.get("change")
    kind = change.get("kind") if isinstance(change, dict) else None
    if kind not in PLANNERS:
        raise Refused(400, "不认识的改动（change.kind）")
    passphrase = data.get("passphrase")
    with _write_lock:
        support = ops_client.verify_support()
        if support["reason"]:
            raise Refused(403, support["reason"])
        automation_config.reset()
        settings = automation_config.load()
        blocked = _blocked(settings)
        if blocked:
            raise Refused(409, blocked)
        if data.get("version") != version_of(settings):
            raise Refused(409, "设置刚被改过（别的页面，或服务器上的文件）：刷新后再改", stale=True)
        try:
            plan = PLANNERS[kind](change, settings, settings.page)
        except Invalid as exc:
            raise Refused(400, str(exc)) from None
        if plan.expand:
            if not isinstance(passphrase, str) or not passphrase:
                raise Refused(400, "这项改动扩大了能力，要输审批口令", passphrase=True)
            _verify(passphrase, plan, caller)
        try:
            _commit(plan)
        except OSError as exc:
            log.warning("automation settings: writing failed: %s", exc.__class__.__name__)
            raise Refused(500, f"写不进去（{exc.__class__.__name__}）：检查数据目录的空间和权限") from None
        _record(kind, plan.detail, user, ip)
    out = {"settings": view(), "detail": plan.detail}
    if plan.token:
        out["token"] = plan.token
    return out
