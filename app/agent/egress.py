"""统一出网规则（docs/工具.md「出网规则」）：web_search 的搜索词、web_fetch 的链接，发出去之前都过这里。

规则全部在代码里执行，不靠提示词。依次检查：

1. 严格模式  WEB_AFTER_DATA=deny：本轮调过数据类工具，这一轮剩下的部分不再联网。默认 screen，只做下面几条。
2. 链接来源  web_fetch 只能读本轮 web_search 结果里的链接、用户本轮消息里给出的链接；模型自己拼的一律拒绝。
             真正去读的是批准过的那个原样的链接，模型换个等价写法也不用它的写法（见 check_url）。
3. 静态拦截  screen()：IP、疑似密钥和令牌、内网域名、邮箱、WEB_SEARCH_BLOCKLIST。搜索词和链接用同一套规则；
             链接解码后再查一遍，路径里用连字符、下划线连起来的标题（slug）不算令牌。
             本轮搜索结果里原样出现过的链接不查「疑似令牌或哈希」（UUID、commit SHA 这类路径很常见）：发出去的就是
             搜索引擎给的原样链接，模型改不了，夹带不了内部数据；其余几条照查。只在用户消息里出现过的链接全套检查。
4. 污点拦截  本轮的污点有两种：
             - 数据类工具调用里声明了 x-entity 的实参值。工具真查了它，说明是内部对象；用户自己提过也算。
             - 数据类工具返回里像资源名的标识符：同时有字母和数字或连字符（web01、payroll-db），
               用户本轮消息里原样出现过的除外。带单位的数量（512MiB、30s）、v1.2 这类版本号、不到 3 个字符的不算。
               按最终给模型看的那一份（压缩、截断之后）收集：模型看得到的都记上。
             出网内容里按词边界出现了污点就拒绝（不分大小写）。只有字母的词（OOMKilled）和纯数字（137）不算污点，
             否则联网就没法用了。搜索结果里的链接也照查。

本轮的状态在 Turn.usage["egress"]，和其他按轮计数一样每轮清零：

    question  用户本轮的消息：污点豁免、取用户给的链接
    urls      用户本轮消息里给出的链接 {canonical(): 原样的链接}
    results   本轮搜索结果里的链接 {canonical(): 原样的链接}；两边都有时读搜索结果给的写法
    taint     {小写的值: "entity" | "output"}
    data      本轮调没调过数据类工具（严格模式）

本轮绑了外网类工具时 loop 才建这份状态（start）；没建时 observe() 什么都不做——不联网的轮次不必收集污点。
"""
import re
from urllib.parse import quote, unquote, urlsplit

from app.config import WEB_AFTER_DATA, WEB_SEARCH_BLOCKLIST, log

STATE = "egress"
QUESTION_CHARS = 20000     # 存进本轮状态的用户消息上限（取链接、污点豁免用）
MAX_URLS = 300             # 本轮可读链接的上限
TAINT_MAX = 5000           # 本轮污点的上限：再多的返回只记 x-entity 实参
SCAN_CHARS = 400_000       # 每次数据类工具返回最多扫多少字
IDENT_MIN, IDENT_MAX = 3, 128


class Refused(ValueError):
    """这次出网不合规则（可能把内部信息带出去）。说明是中文，原样转给模型。

    rule、word 只进日志：哪条规则、命中了什么（疑似密钥、令牌只记开头几个字符），用来看误拦多不多。
    """

    def __init__(self, message, rule="other", word=""):
        super().__init__(message)
        self.rule, self.word = rule, word


# --- 静态拦截 ----------------------------------------------------------------------

TOKEN_LABEL = "疑似令牌或哈希"
# 发出去之前在代码里拦一道：这些内容一旦进了公共搜索引擎、或随链接发到别人的服务器，就收不回来了。
LEAK_PATTERNS = [
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "IP 地址"),
    (re.compile(r"\b(?:sk|tvly|ghp|gho|xox[abp]|AKIA)[-_][A-Za-z0-9_-]{8,}", re.I), "疑似密钥"),
    (re.compile(r"\b[A-Za-z0-9_-]{32,}\b"), TOKEN_LABEL),
    (re.compile(r"\b[\w.-]+\.(?:internal|intranet|local|lan|corp)\b", re.I), "内网域名"),
    (re.compile(r"[\w.+-]+@[\w-]+\.[\w.]+"), "邮箱地址"),
]
_SLUG_WORD = re.compile(r"[a-z]+|[A-Z][a-z]*|[A-Z]+|\d+")


def _slug(run) -> bool:
    """链接里用连字符、下划线连起来的标题（how-to-fix-oomkilled-in-kubernetes），不是令牌。

    至少三段、每段不超过 24 个字符，并且最多一段不像单词（像单词 = 全小写、首字母大写、全大写或纯数字；
    Medium 这类链接末尾带一段十六进制 id）。随机生成的令牌每段都大小写、数字混杂，过不了。
    """
    parts = [part for part in re.split(r"[-_]+", run) if part]
    if len(parts) < 3 or max(len(part) for part in parts) > 24:
        return False
    return sum(1 for part in parts if not _SLUG_WORD.fullmatch(part)) <= 1


def _loggable(label, hit) -> str:
    """命中的内容记日志时：疑似密钥、令牌只留开头几个字符，别的原样。"""
    return f"{hit[:4]}…（{len(hit)} 字符）" if label in ("疑似密钥", TOKEN_LABEL) else hit


def screen(text, *, subject="搜索词", action="上网搜索", blocklist=None, url=False, tokens=True) -> None:
    """静态拦截：含 IP、疑似密钥或令牌、内网域名、邮箱或内部名词（WEB_SEARCH_BLOCKLIST）就抛 Refused。

    url=True（查链接）时，路径里的 slug 不算令牌，其余规则和搜索词完全一样。
    tokens=False 时整条「疑似令牌或哈希」都不查（本轮搜索结果里原样出现过的链接，见 check_url），其余照查。
    """
    for pattern, label in LEAK_PATTERNS:
        if label == TOKEN_LABEL and not tokens:
            continue
        if url and label == TOKEN_LABEL:
            hit = next((m.group() for m in pattern.finditer(text) if not _slug(m.group())), None)
        else:
            found = pattern.search(text)
            hit = found.group() if found else None
        if hit is not None:
            raise Refused(f"{subject}里含有{label}，为防止内部信息外泄，已拒绝{action}",
                          rule=f"static:{label}", word=_loggable(label, hit))
    lowered = text.lower()
    for word in (WEB_SEARCH_BLOCKLIST if blocklist is None else blocklist):
        if word.lower() in lowered:
            raise Refused(f"{subject}里含有内部名词「{word}」，为防止内部信息外泄，已拒绝{action}",
                          rule="static:内部名词", word=word)


def screen_url(url, tokens=True) -> None:
    """链接的静态拦截：原样查一遍，百分号解码后再查一遍（%E5… 编码的内部名词、编码过的令牌也拦得住）。

    tokens=False：不查「疑似令牌或哈希」（本轮搜索结果里原样出现过的链接）。
    """
    for text in dict.fromkeys((url, unquote(url))):
        screen(text, subject="链接", action="读取", url=True, tokens=tokens)


# --- 链接：规范化与来源 -------------------------------------------------------------

_URL = re.compile(r"https?://[^\s<>\"'`，。；：！？、（）【】《》「」『』“”‘’…]+", re.I)
_TRAILING = ".,;:!?'\"]}>"


def ascii_host(host) -> str | None:
    host = str(host or "").strip().lower().rstrip(".")
    if not host:
        return None
    if host.isascii():
        return host
    try:
        return host.encode("idna").decode("ascii")
    except UnicodeError:
        return None


def _normal(text, safe) -> str:
    return quote(unquote(text), safe=safe)


def canonical(url) -> str | None:
    """比对用的链接：不分 http/https，去掉默认端口、#片段和路径末尾的斜杠，主机名小写，百分号编码统一。

    这些差别带不出任何信息；路径和查询串的内容必须一致——要夹带东西，只能塞在那里。不是 http(s) 链接时返回 None。
    """
    try:
        parts = urlsplit(str(url or "").strip())
        port = parts.port
    except ValueError:
        return None
    if parts.scheme.lower() not in ("http", "https"):
        return None
    host = ascii_host(parts.hostname)
    if host is None:
        return None
    netloc = host if port in (None, 80, 443) else f"{host}:{port}"
    path = _normal(parts.path, "/:@!$&'()*+,;=-._~").rstrip("/")
    query = _normal(parts.query, "/?:@!$&'()*+,;=-._~")
    return netloc + path + (f"?{query}" if query else "")


def find_urls(text) -> list:
    """用户消息里给出的 http(s) 链接：原样（去掉句末标点），按出现顺序去重。"""
    out = []
    for match in _URL.finditer(str(text or "")):
        url = match.group().rstrip(_TRAILING)
        # 「（见 https://x/y）」这种：多出来的右括号不是链接的一部分；Foo_(bar) 这种成对的括号保留
        while url.endswith(")") and url.count("(") < url.count(")"):
            url = url[:-1].rstrip(_TRAILING)
        if canonical(url) and url not in out:
            out.append(url)
    return out


# --- 本轮状态 -----------------------------------------------------------------------

def _allow(state, field, urls) -> None:
    """urls 记进 state[field]，形如 {canonical: 原样的链接}：比对按 canonical，真正去读的是原样的那个（见 check_url）。"""
    allowed = state.get(field)
    if not isinstance(allowed, dict):
        allowed = state[field] = {}
    for url in urls:
        key = canonical(url)
        if key and key not in allowed and len(allowed) < MAX_URLS:
            allowed[key] = str(url).strip()


def start(question) -> dict:
    """一轮开始时的出网状态（loop.run 在本轮绑了外网类工具时建）。"""
    state = {"question": str(question or "")[:QUESTION_CHARS], "urls": {}, "results": {}, "taint": {}, "data": False}
    _allow(state, "urls", find_urls(state["question"]))
    return state


def _state(turn) -> dict:
    state = turn.usage.get(STATE)
    if not isinstance(state, dict):
        state = turn.usage[STATE] = start("")
    return state


def allow_urls(turn, urls) -> None:
    """web_search 拿到结果后：这些链接本轮可以读（记下搜索引擎给的原样写法，读的时候发它）。"""
    _allow(_state(turn), "results", urls)


_TOKEN = re.compile(r"[A-Za-z0-9._-]+")
_LETTER = re.compile(r"[A-Za-z]")
_DIGIT_OR_DASH = re.compile(r"[0-9-]")
# 带单位的数量：512MiB、1.5Gi、100m、30s、10ms、2h……是读数，不是名字
_MEASURE = re.compile(r"\d+(?:\.\d+)?(?:[KMGTPEkmgtpe]i?[Bb]?(?:ps)?|[Bb](?:ps)?|ms|us|ns|s|m|h|d|w|y|min|sec|hrs?)")
_VERSION = re.compile(r"[vV]\d+(?:\.\d+)*")


def resource_like(token) -> bool:
    """像资源名的标识符：同时有字母和数字或连字符（web01、payroll-db、a1b2c3d4e5f6）。

    只有字母的词（OOMKilled）、纯数字（137）、带单位的数量（512MiB）、v1.2 这类版本号、不到 3 个字符的都不算。
    """
    return (IDENT_MIN <= len(token) <= IDENT_MAX and _LETTER.search(token) is not None
            and _DIGIT_OR_DASH.search(token) is not None
            and not _MEASURE.fullmatch(token) and not _VERSION.fullmatch(token))


def identifiers(text) -> list:
    """一段返回里像资源名的标识符，按出现顺序去重。db01.prod.example.com 这种还拆出 db01。"""
    out = {}
    for match in _TOKEN.finditer(str(text or "")[:SCAN_CHARS]):
        token = match.group().strip("._-")
        for candidate in [token] + (token.split(".") if "." in token else []):
            candidate = candidate.strip("_-")
            if resource_like(candidate):
                out.setdefault(candidate, None)
    return list(out)


def _inner(char) -> bool:
    return char.isascii() and (char.isalnum() or char == "_")


def mentioned(value, text) -> bool:
    """value 按词边界出现在 text 里（不分大小写）：前后不能紧挨着英文字母、数字或下划线。

    连字符、点、斜杠、中文都算边界：payroll-db 出现在「payroll-db-backup」「/payroll-db/」「查payroll-db」里都算。
    """
    value, text = str(value).lower(), str(text or "").lower()
    if not value:
        return False
    start = text.find(value)
    while start != -1:
        end = start + len(value)
        if (start == 0 or not _inner(text[start - 1])) and (end == len(text) or not _inner(text[end])):
            return True
        start = text.find(value, start + 1)
    return False


def _entities(state, schema, args) -> None:
    """x-entity 实参记成污点：工具真查了它，说明是内部对象；用户自己提过也算。"""
    taint = state.setdefault("taint", {})
    properties = schema.get("properties") if isinstance(schema, dict) else None
    properties = properties if isinstance(properties, dict) else {}
    for key, value in (args if isinstance(args, dict) else {}).items():
        prop = properties.get(key)
        if isinstance(prop, dict) and prop.get("x-entity") and isinstance(value, str) and value.strip():
            taint[value.strip().lower()] = "entity"


def expect(turn, schema, args) -> None:
    """一批调用执行之前（loop 的 tools 节点）：先登记这批里的数据类调用——x-entity 实参记成污点，本轮算调过数据类工具。

    模型会在同一条回复里并行发出搜索和数据类调用，搜索排在前面先执行时，也要看得到同批的这些污点；
    WEB_AFTER_DATA=deny 时同批的外网调用也就不放行了。返回里的标识符照旧在执行后由 observe 收集。
    """
    state = turn.usage.get(STATE)
    if not isinstance(state, dict):
        return
    state["data"] = True
    _entities(state, schema, args)


def observe(turn, schema, args, shown) -> None:
    """一次数据类工具调用之后（loop 的 tools 节点）：记下本轮调过数据类工具，收集污点。

    shown 是这次调用最终给模型看的内容（压缩、截断之后）：模型看得到的标识符都要记上，看不到的它也带不出去。
    x-entity 实参不管返回是什么都记（执行前 expect 已经记过一遍）。本轮没建出网状态（没绑外网类工具）时什么都不做。
    污点多到 TAINT_MAX 还装不下时，本轮剩下的部分不再联网——宁可不搜，也不漏记。
    """
    state = turn.usage.get(STATE)
    if not isinstance(state, dict):
        return
    state["data"] = True
    _entities(state, schema, args)
    taint = state["taint"]
    question = state.get("question") or ""
    for ident in identifiers(shown):
        key = ident.lower()
        if key in taint or mentioned(ident, question):
            continue
        if len(taint) >= TAINT_MAX:
            log.warning("egress taint is full (%d), going offline for the rest of this turn", TAINT_MAX)
            state["overflow"] = True
            break
        taint[key] = "output"


def poison(turn) -> None:
    """收集污点出了错：本轮剩下的部分一律不联网（宁可不搜，也不冒外泄的险）。"""
    state = _state(turn)
    state["data"] = True
    state["broken"] = True


# --- 检查 ---------------------------------------------------------------------------

def _gate(state, action) -> None:
    if state.get("broken"):
        raise Refused(f"出网检查出错，本轮不再{action}；请基于已有信息作答", rule="broken")
    if state.get("overflow"):
        raise Refused(f"本轮查到的数据太多，出网检查顾不过来，这一轮不再{action}；请基于已有信息作答", rule="overflow")
    if WEB_AFTER_DATA == "deny" and state.get("data"):
        raise Refused(f"本轮已经查过内部数据，按出网设置（WEB_AFTER_DATA=deny）这一轮不再{action}；请基于已有信息作答",
                      rule="strict")


def _check_taint(state, texts, subject, action, hint="") -> None:
    taint = state.get("taint") or {}
    # 长的先查：payroll-db-01 和 payroll-db 都是污点时，报更完整的那个
    for value in sorted(taint, key=len, reverse=True):
        if any(mentioned(value, text) for text in texts):
            what = "本轮查过的内部对象" if taint[value] == "entity" else "本轮数据里出现过的标识符"
            raise Refused(f"{subject}里含有{what}「{value}」，为防止内部信息外泄，已拒绝{action}{hint}",
                          rule=f"taint:{taint[value]}", word=value)


def check_query(turn, query) -> None:
    """web_search 的搜索词发出去之前：严格模式、静态拦截、污点拦截。不合规则抛 Refused。"""
    state = _state(turn)
    _gate(state, "上网搜索")
    screen(query)
    _check_taint(state, [query], "搜索词", "上网搜索", "；去掉它、只用公开的通用词再搜")


def check_url(turn, url) -> str:
    """web_fetch 的链接发出去之前：严格模式、链接来源、静态拦截、污点拦截。不合规则抛 Refused。

    返回真正要去读的链接：本轮批准过的那个原样的链接，而不是模型传来的写法。等价的写法（http/https、默认端口、
    百分号编码、末尾斜杠）对比对没有区别，对方服务器却看得出来——模型挑写法就能一位一位地往外带信息，所以不用它的。
    本轮搜索结果里有的，发搜索引擎给的原样链接，不查「疑似令牌或哈希」：链接是搜索引擎给的，模型改不了，夹带不了
    内部数据（要往外带只能走搜索词，搜索词照旧检查）。只在用户消息里出现过的，全套检查。
    这里只管「链接里的内容能不能发出去」；链接指向哪里（内网、回环、云元数据……）由 web_fetch 防 SSRF 的那一层管。
    """
    state = _state(turn)
    _gate(state, "联网")
    key = canonical(url)
    if key is None:
        raise Refused("链接无效：要以 http:// 或 https:// 开头", rule="invalid", word=str(url)[:200])
    results, given = state.get("results"), state.get("urls")
    if isinstance(results, dict) and key in results:
        approved, from_search = results[key], True
    elif isinstance(given, dict) and key in given:
        approved, from_search = given[key], False
    else:
        raise Refused("只能读取本轮搜索结果里的链接或用户本轮消息里给出的链接，这个链接两者都不是；"
                      "请原样使用搜索结果里的链接，不要自己拼接或改写", rule="source", word=str(url)[:200])
    screen_url(approved, tokens=not from_search)
    _check_taint(state, [approved, unquote(approved)], "链接", "读取")
    return approved
