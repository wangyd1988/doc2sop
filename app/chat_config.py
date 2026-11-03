"""群聊机器人（云上协同、钉钉）：谁能用、能查什么（docs/正式部署.md「云上协同」「钉钉」）。

写在服务器上的 chat.yaml（CHAT_FILE，默认 DATA_DIR/chat.yaml）里。页面上只看得到名字、开了哪些工具、哪里写得不对，
拿到网页密码的人不能给自己开通群、开数据工具。文件不在 = 谁也没开通。里面没有密钥（推送目标的 ID 在转接程序的
targets.yaml 里），进备份。改了不用重启：每次用到时看一眼修改时间和大小，变了就重新读。

    platform: dingtalk         # 这份白名单是给哪个平台的：ccwork（云上协同，不写就是它）或 dingtalk（钉钉）。
                               # 和 kb-app 连着的转接程序报的平台对不上时，不取消息、不推送：换平台时旧的白名单、
                               # 推送设置不会被另一个平台「继承」（两边的用户 ID 都是普通字符串，推送目标按名字找）
    robot_name: doc2sop        # 群里 @ 它的名字：从问题里去掉「@doc2sop」
    contact: 王某某             # 没开通时告诉对方找谁（可不填）
    unknown_reply: once        # 没开通的群和人 @ 它：once 每个会话 24 小时回一句；silent 不回
    markdown: false            # 云上协同会渲染 Markdown 时改成 true，回答原样发
    paused: false              # true：开通的群和人一问，只回「暂停服务中」，不调模型
    keep_days: 180             # 占位，暂不自动删（以后只按群聊来源清理，不碰网页上的对话）
    limits: {person_per_hour: 20, group_per_hour: 60, execute_per_hour: 6, context_minutes: 30, max_chars: 3000}
    groups:                    # 开通的群（组织、部门会话也写在这里）；键是会话 ID（云上协同是数字，钉钉是 cid 开头的）
      "1234567890123": {name: 运维值班群, tools: [host_disk], categories: [运维], mode: kb, web: false}
    people:                    # 开通私聊的人；键是用户 ID
      "u_abc123": {name: 王某某, tools: [host_uptime]}
    digest:                    # 每周的知识库缺口摘要；不写就不发
      - {target: 王某某, weekday: 1, hour: 9}                              # 发给个人：全部缺口
      - {target: 运维值班群, weekday: 1, hour: 9, group: "1234567890123"}   # 发到群：只汇总这个群自己的问题

每个群、每个人：tools 是能用的数据工具，逐个写名字，默认一个都没有（工具服务以后批准的新工具不会自动进群）；
categories 只查这几个文档分类，不写是全部——知识库、SOP 都按它收窄（来源文档在别的分类里的 SOP 看不到、执行不了，
手工创建的照常）；mode 是 kb（默认）或 smart（要部署本身打开了智能模式）；web 是联网搜索，默认关。
digest 写了 group 时，target 必须就是这个群（kb-app 只知道目标的名字，核对不了），不然这个群的问题会发到别处。

写错时一律往紧里算，页面上列出哪里不对（日志里只记一行，不带 ID 和人名）：
    一个群或一个人的设置    有不认识的键（拼错的可能本来是一条限制，比如 category）、categories 写了却一个能用的都没有、
                            整段写得不对 → 这个群或这个人不开通；tools、mode、web 里写错的那几项不开
    顶层                    有不认识的配置项（可能是拼错的 paused 或 limits）、paused 或 limits 写得不对 → 整个暂停，
                            开通的群和人只收到「暂停服务中」；unknown_reply 写错按 silent；digest 写错的那一项不发
    整个文件                读不了、YAML 写错、太大 → 谁也没开通，也不回「还没有开通」
"""
import os
import re
import threading
from dataclasses import dataclass, field

import yaml

from app.config import CATEGORY_MAX, CHAT_FILE, log

FILE_MAX = 64 * 1024
NAME_MAX = 30
TOOLS_MAX = 50
CATEGORIES_MAX = 20
SCOPES_MAX = 500
DIGEST_MAX = 10
KNOWN = ("robot_name", "contact", "unknown_reply", "markdown", "paused", "keep_days", "limits", "groups", "people",
         "digest")
TOP_KEYS = KNOWN + ("platform",)
PLATFORMS = ("ccwork", "dingtalk")              # 不写 platform 就是 ccwork（云上协同）
PLATFORM_NAMES = {"ccwork": "云上协同", "dingtalk": "钉钉"}
SCOPE_KEYS = ("name", "tools", "categories", "mode", "web")
MODES = ("kb", "smart")
UNKNOWN_REPLIES = ("once", "silent")
# 名字 -> (默认, 最小, 最大)
LIMITS = {"person_per_hour": (20, 1, 1000), "group_per_hour": (60, 1, 5000), "execute_per_hour": (6, 0, 100),
          "context_minutes": (30, 1, 1440), "max_chars": (3000, 500, 5000)}
CHAT_ID = re.compile(r"^[0-9]{1,20}$")          # 和转接程序的 targets.yaml 同一个写法
DINGTALK_CHAT_ID = re.compile(r"^cid[A-Za-z0-9+/=_-]{4,124}$")     # 钉钉群的 openConversationId
GROUP_IDS = {"ccwork": CHAT_ID, "dingtalk": DINGTALK_CHAT_ID}
USER_ID = re.compile(r"^[!-~]{1,64}$")
TOOL_NAME = re.compile(r"^[^\s\x00-\x1f\x7f]{1,80}$")
CONTROL = re.compile(r"[\x00-\x1f\x7f]")


@dataclass(frozen=True)
class Scope:
    """开通的一个群（或组织、部门会话）、一个人：能查什么。"""
    kind: str                       # group / person
    id: str
    name: str
    tools: tuple = ()               # 能用的数据工具，空的就是只查文档
    categories: tuple | None = None  # 只查的文档分类；None 是全部
    mode: str = "kb"
    web: bool = False


@dataclass(frozen=True)
class Digest:
    target: str                     # 转接程序 targets.yaml 里推送目标的名字
    weekday: int = 1                # 1–7：周一到周日
    hour: int = 9
    group: str = ""                 # 只汇总这个群的问题；空的是全部（只能发给个人）


@dataclass(frozen=True)
class Settings:
    path: str
    exists: bool
    platform: str = "ccwork"        # 这份白名单是给哪个平台的；空串：写错了，哪个转接程序都对不上
    robot_name: str = ""
    contact: str = ""
    unknown_reply: str = "once"
    markdown: bool = False
    paused: bool = False
    keep_days: int | None = None
    limits: dict = field(default_factory=lambda: {name: spec[0] for name, spec in LIMITS.items()})
    groups: dict = field(default_factory=dict)      # 会话 ID -> Scope
    people: dict = field(default_factory=dict)      # 用户 ID -> Scope
    digest: tuple = ()
    problems: tuple = ()
    loose: str = ""

    def scope(self, chat_type, chat_id, sender_id) -> Scope | None:
        """这条消息归哪个开通的群或人；没开通是 None。私聊看发送人，群（含组织、部门会话）看会话 ID。"""
        if chat_type == "single":
            return self.people.get(str(sender_id or ""))
        return self.groups.get(str(chat_id or ""))


_lock = threading.Lock()
_cache = {"key": None, "value": None}


def reset():
    """忘掉缓存（测试里同一秒内改两次文件、大小又一样时用）。"""
    with _lock:
        _cache.update(key=None, value=None)


def load() -> Settings:
    """此刻的配置。文件没变就用上次读到的；变了重新读，有问题记一行日志（不带 ID）。"""
    path = CHAT_FILE
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
        log.warning("chat config %s: %s", path, "；".join(value.problems + ((value.loose,) if value.loose else ())))
    else:
        log.info("chat config loaded: groups=%d people=%d paused=%s", len(value.groups), len(value.people),
                 value.paused)
    return value


def _where(exc) -> str:
    mark = getattr(exc, "problem_mark", None)
    problem = getattr(exc, "problem", None) or exc.__class__.__name__
    return f"第 {mark.line + 1} 行第 {mark.column + 1} 列：{problem}" if mark is not None else str(problem)


def _parse(path, st) -> Settings:
    loose = ""
    if os.name != "nt" and st.st_mode & 0o022:
        # 里面没有密钥，但谁能改它谁就能给自己开通群、开数据工具
        loose = f"文件权限 {oct(st.st_mode & 0o777)[2:]} 太宽：别的账号能改它（等于能给自己开通），请 chmod 644 或 600"
    if st.st_size > FILE_MAX:
        return _unreadable(path, f"文件超过 {FILE_MAX // 1024} KB，没有读", loose)
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        return _unreadable(path, f"YAML 写错了，{_where(exc)}", loose)
    except (OSError, UnicodeDecodeError) as exc:
        return _unreadable(path, f"读不了这个文件：{exc.__class__.__name__}", loose)
    data = data or {}
    if not isinstance(data, dict):
        return _unreadable(path, "最外层要写成「键: 值」", loose)
    problems = []
    halt = False                    # 顶层写错：可能是拼错的 paused、limits，按暂停处理
    unknown = [str(k) for k in data if k not in TOP_KEYS]
    if unknown:
        problems.append(f"不认识的配置项：{'、'.join(unknown[:5])}（只认 {'、'.join(KNOWN)}），先按暂停处理")
        halt = True
    platform = _text(data.get("platform")) or "ccwork"
    if platform not in PLATFORMS:
        # 认不出是哪个平台的白名单：哪个转接程序都对不上，不取消息、不推送
        problems.append(f"platform 只能是 {' 或 '.join(PLATFORMS)}（不写就是 ccwork），先按暂停处理")
        platform, halt = "", True
    paused = data.get("paused")
    if paused in (None, ""):
        paused = False
    elif not isinstance(paused, bool):
        problems.append("paused 只能写 true 或 false，先按暂停处理")
        paused = True
    limits, limits_ok = _limits(data.get("limits"), problems)
    if not limits_ok:
        problems.append("limits 写得不对，先按暂停处理")
        halt = True
    unknown_reply = _text(data.get("unknown_reply")) or "once"
    if unknown_reply not in UNKNOWN_REPLIES:
        problems.append("unknown_reply 只能是 once 或 silent，先按 silent（不回）")
        unknown_reply = "silent"
    groups = _scopes(data.get("groups"), "group", problems, platform)
    return Settings(path=str(path), exists=True, platform=platform,
                    robot_name=_name(data.get("robot_name"), "robot_name", problems),
                    contact=_name(data.get("contact"), "contact", problems), unknown_reply=unknown_reply,
                    markdown=_flag(data.get("markdown"), "markdown", problems), paused=paused or halt,
                    keep_days=_keep_days(data.get("keep_days"), problems), limits=limits,
                    groups=groups, people=_scopes(data.get("people"), "person", problems, platform),
                    digest=_digest(data.get("digest"), groups, problems), problems=tuple(problems), loose=loose)


def _unreadable(path, problem, loose) -> Settings:
    """整个文件用不了：谁也没开通，也不回「还没有开通」（之前开通了的群会莫名其妙收到这句）。"""
    return Settings(path=str(path), exists=True, unknown_reply="silent", paused=True,
                    problems=(problem + "，谁也没开通",), loose=loose)


def _text(value) -> str:
    return "" if value is None else " ".join(str(value).split())


def _name(raw, what, problems) -> str:
    text = _text(raw)
    if len(text) > NAME_MAX or CONTROL.search(text):
        problems.append(f"{what} 最多 {NAME_MAX} 个字")
        return ""
    return text


def _flag(raw, what, problems) -> bool:
    if raw in (None, ""):
        return False
    if not isinstance(raw, bool):
        problems.append(f"{what} 只能写 true 或 false")
        return False
    return raw


def _keep_days(raw, problems):
    if raw in (None, ""):
        return None
    if isinstance(raw, bool) or not isinstance(raw, int) or not 1 <= raw <= 3650:
        problems.append("keep_days 要是 1–3650 的整数（目前只是占位，暂不自动删）")
        return None
    return raw


def _limits(raw, problems) -> tuple:
    """(各项限频, 有没有写对)。写错的项先按默认值填上，但调用方会因此整个暂停。"""
    out = {name: spec[0] for name, spec in LIMITS.items()}
    if raw in (None, "", {}):
        return out, True
    if not isinstance(raw, dict):
        problems.append("limits 要写成「名字: 数」")
        return out, False
    ok = True
    for key, value in raw.items():
        spec = LIMITS.get(str(key))
        if spec is None:
            problems.append(f"limits 里不认识 {str(key)[:30]}（只认 {'、'.join(LIMITS)}）")
            ok = False
        elif isinstance(value, bool) or not isinstance(value, int) or not spec[1] <= value <= spec[2]:
            problems.append(f"limits.{key} 要是 {spec[1]}–{spec[2]} 的整数")
            ok = False
        else:
            out[str(key)] = value
    return out, ok


def _scopes(raw, kind, problems, platform="ccwork") -> dict:
    what = "groups" if kind == "group" else "people"
    if raw in (None, "", {}) or not platform:
        return {}
    if not isinstance(raw, dict):
        problems.append(f"{what} 要写成「ID: 设置」")
        return {}
    out = {}
    for key, spec in list(raw.items())[:SCOPES_MAX]:
        ident = str(key).strip()
        pattern = GROUP_IDS.get(platform, CHAT_ID) if kind == "group" else USER_ID
        if isinstance(key, bool) or not pattern.match(ident):
            problems.append(f"{what} 里有一项（…{ident[-4:]}）不像{'会话' if kind == 'group' else '用户'} ID，没有开通")
            continue
        scope = _scope(kind, ident, spec, f"{what}.{ident[-4:]}", problems)
        if scope is not None:
            out[ident] = scope
    if len(raw) > SCOPES_MAX:
        problems.append(f"{what} 最多 {SCOPES_MAX} 个，后面的没有读")
    return out


def _scope(kind, ident, spec, where, problems) -> Scope | None:
    if spec in (None, ""):
        spec = {}
    if not isinstance(spec, dict):
        problems.append(f"{where} 要写成「name: …, tools: […]」，没有开通")
        return None
    extra = [str(k) for k in spec if k not in SCOPE_KEYS]
    if extra:
        # 拼错的键可能本来是一条限制（比如把 categories 写成 category）：猜不出意思就不开通
        problems.append(f"{where} 里不认识 {'、'.join(extra[:3])}（只认 {'、'.join(SCOPE_KEYS)}），没有开通")
        return None
    categories = None
    if "categories" in spec:
        categories = _names(spec.get("categories"), f"{where}.categories", None, CATEGORIES_MAX, problems)
        if not categories:
            # 写了分类却一个能用的都没有（空的、全写错了）：不能当成「全部分类」
            problems.append(f"{where}.categories 写了，可一个能用的分类都没有（不写才是全部分类），没有开通")
            return None
    name = _name(spec.get("name"), f"{where}.name", problems) or (
        f"群…{ident[-4:]}" if kind == "group" else f"用户…{ident[-4:]}")
    tools = _names(spec.get("tools"), f"{where}.tools", TOOL_NAME, TOOLS_MAX, problems)
    mode = _text(spec.get("mode")) or "kb"
    if mode not in MODES:
        problems.append(f"{where}.mode 只能是 kb 或 smart，先按 kb")
        mode = "kb"
    return Scope(kind=kind, id=ident, name=name, tools=tools, categories=categories, mode=mode,
                 web=_flag(spec.get("web"), f"{where}.web", problems))


def _names(raw, where, pattern, limit, problems) -> tuple:
    if raw in (None, ""):
        return ()
    if isinstance(raw, str):
        raw = [raw]
    if not isinstance(raw, list):
        problems.append(f"{where} 要写成列表：[名字, 名字]")
        return ()
    out = []
    for item in raw[:limit]:
        text = _text(item)
        scalar = isinstance(item, (str, int, float)) and not isinstance(item, bool)
        bad = not scalar or not text or CONTROL.search(text) or (pattern.match(text) is None if pattern
                                                                 else len(text) > CATEGORY_MAX)
        if bad:
            problems.append(f"{where} 里有一项写得不对：{text[:30]}")
        elif text not in out:
            out.append(text)
    if len(raw) > limit:
        problems.append(f"{where} 最多 {limit} 项，后面的没有读")
    return tuple(out)


def _digest(raw, groups, problems) -> tuple:
    if raw in (None, "", [], {}):
        return ()
    items = [raw] if isinstance(raw, dict) else raw
    if not isinstance(items, list):
        problems.append("digest 要写成「target: 名字, weekday: 1, hour: 9」或它们的列表")
        return ()
    out = []
    for n, item in enumerate(items[:DIGEST_MAX], 1):
        if not isinstance(item, dict):
            problems.append(f"digest 第 {n} 项要写成「target: 名字, weekday: 1, hour: 9」")
            continue
        target = _name(item.get("target"), f"digest 第 {n} 项的 target", problems)
        weekday, hour = item.get("weekday", 1), item.get("hour", 9)
        group = _text(item.get("group"))
        if not target:
            problems.append(f"digest 第 {n} 项没写 target（推送目标的名字）")
        elif isinstance(weekday, bool) or not isinstance(weekday, int) or not 1 <= weekday <= 7:
            problems.append(f"digest 第 {n} 项的 weekday 要是 1–7（周一到周日）")
        elif isinstance(hour, bool) or not isinstance(hour, int) or not 0 <= hour <= 23:
            problems.append(f"digest 第 {n} 项的 hour 要是 0–23")
        elif group and group not in groups:
            problems.append(f"digest 第 {n} 项的 group 要是 groups 里开通了的群")
        else:
            out.append(Digest(target=target, weekday=weekday, hour=hour, group=group))
    return tuple(out)


def public(settings: Settings | None = None) -> dict:
    """页面上看得到的：开通了哪些群和人、各自能查什么、哪里写得不对。"""
    s = settings or load()

    def view(scope):
        return {"id": scope.id, "name": scope.name, "tools": list(scope.tools),
                "categories": None if scope.categories is None else list(scope.categories),
                "mode": scope.mode, "web": scope.web}

    return {"file": s.path, "exists": s.exists, "problems": list(s.problems), "loose": s.loose,
            "platform": s.platform, "platform_name": PLATFORM_NAMES.get(s.platform, ""),
            "robot_name": s.robot_name, "contact": s.contact, "unknown_reply": s.unknown_reply,
            "markdown": s.markdown, "paused": s.paused, "keep_days": s.keep_days, "limits": dict(s.limits),
            "groups": [view(g) for g in s.groups.values()], "people": [view(p) for p in s.people.values()],
            "digest": [{"target": d.target, "weekday": d.weekday, "hour": d.hour, "group": d.group}
                       for d in s.digest]}
