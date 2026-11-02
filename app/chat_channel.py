"""云上协同的聊天线程（docs/正式部署.md「云上协同」）：从转接程序取消息、查白名单、按命令或问题处理、流式回复。

一条消息的路径：

    长轮询（chat_bridge.events）→ 查白名单（chat.yaml）→ 没开通的只记 ID 和次数、24 小时回一句；
    开通的连同正文写进收件表（落库之后下一次轮询才确认）→ 暂停、限频、排队 → 命令或问题 → 回复 → 收件表记完成、清掉正文

问题和「执行」SOP 走和网页同一个问答核心（main.start_chat_turn / turn_events，由 chat_api.install 注入）：
渠道记 chat，只绑这个群开通的数据工具，只查开通的文档分类。事件流一定在这里关掉（提前结束也关），收尾才在本线程照常执行。

每个人在每个群一条对话（私聊每人一条），30 分钟没说话或回「新话题」就另开；接着用之前核对对话的最后一条消息还是我们记下的那条，
对不上（网页上有人续过、上一轮没答完）就另开。回答至多一次：重启时处理到一半的记成中断，回一句「请再问一次」，不重跑。
"""
import re
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import datetime, timedelta, timezone

from app import chat_config, chat_format, chat_push, chat_store, conversations, graph, runs, settings
from app.agent import registry, sop_tools, web_search
from app.chat_bridge import BridgeError, EpochChanged
from app.config import BOT_NAME, log, why
from app.rag.lexical import tokenize

WORKERS = 2                 # 同时答几个问题（和自动执行的 2 个分开算）
QUEUE_MAX = 10              # 再多排几个
POLL_WAIT = 25.0
BACKOFF = (2, 5, 15, 30, 60)
ASK_TIMEOUT = 180.0         # 一次回答大约等多久（只在两个事件之间看；模型单次调用最长 120 秒、失败重试一次，
EXECUTE_TIMEOUT = 600.0     # 最坏会超出一两分钟）；到了就放弃，回「没答出来」。按 SOP 执行要调好几次工具，等得久些
NOTICE_GAP = 600            # 「太频繁」「上一个还在答」「暂停服务中」：每人 10 分钟最多回一次
QUEUE_GAP = 300             # 「排队太多」：每个会话 5 分钟最多一次
DAILY_GAP = 86400           # 「只能看文字」「解不开」：每个会话一天一次
TEXT_OUT_MAX = 5900         # 转接程序收的单条上限是 6000 字
CANDIDATES_MAX = 3
LEXICAL_MIN = 0.25
VERDICTS = {"误报": "false_alarm", "阈值不对": "wrong_threshold", "漏了一步": "missing_step", "结论对": "correct"}
CHAT_TYPES = ("single", "group", "org", "dept")
KINDS = ("text", "unsupported", "undecryptable")

_HELP = re.compile(r"^(?:帮助|help|\?|？|使用说明|怎么用)$", re.IGNORECASE)
_NEW = re.compile(r"^(?:新话题|重新开始)$")
_MORE = re.compile(r"^全文$")
_UNHELPFUL = re.compile(r"^没答好(?:[\s：:，,]+(.*))?$", re.DOTALL)
_VERDICT = re.compile(r"^(误报|阈值不对|漏了一步|结论对)(?:[\s：:，,]+(.*))?$", re.DOTALL)
_EXECUTE = re.compile(r"^执行(?:\s*$|(\d{1,2})(?:\s+(.*))?$|\s+(.+)$)", re.DOTALL)
_PARAM = re.compile(r"^([^\s=＝:：，,；;（）()]+)\s*[=＝:：]\s*(.+)$")
_PAREN = re.compile(r"[（(]([^（）()]*)[）)]\s*$")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


def tail(value) -> str:
    """日志里的会话 ID、用户 ID 只留末 4 位。"""
    text = str(value or "")
    return "…" + text[-4:] if text else "-"


def parse_execute(rest) -> dict:
    """「执行」后面的部分 → {selector: 编号或 SOP 名, pairs: [(参数, 值)], bad: [看不懂的]}。

    认「执行 2 host=gateway-b」「执行 磁盘巡检 host：a，port：22」，也认网页的写法「执行 SOP《磁盘巡检》（host：a）」。"""
    rest = str(rest or "").strip()
    pairs, bad, selector, seen = [], [], [], False
    inner = ""
    paren = _PAREN.search(rest)
    if paren:
        inner, rest = paren.group(1), rest[:paren.start()].strip()
    for token in rest.split():
        for part in re.split(r"[，,；;]", token):
            if not part:
                continue
            found = _PARAM.match(part)
            if found:
                pairs.append((found.group(1), found.group(2)))
                seen = True
            elif seen:
                bad.append(part)
            else:
                selector.append(part)
    for part in re.split(r"[，,；;\s]+", inner):
        if part:
            found = _PARAM.match(part)
            if found:
                pairs.append((found.group(1), found.group(2)))
            else:
                bad.append(part)
    return {"selector": " ".join(selector), "pairs": pairs, "bad": bad}


def parse_command(text) -> tuple:
    """(命令, 参数)。整条消息就是命令时才算；不是命令时是 ("ask", None)。"""
    text = str(text or "").strip()
    if _HELP.match(text):
        return "help", None
    if _NEW.match(text):
        return "new", None
    if _MORE.match(text):
        return "more", None
    found = _UNHELPFUL.match(text)
    if found:
        return "unhelpful", (found.group(1) or "").strip()
    found = _VERDICT.match(text)
    if found:
        return "verdict", (found.group(1), (found.group(2) or "").strip())
    found = _EXECUTE.match(text)
    if found:
        number, more, rest = found.groups()
        return "execute", parse_execute(f"{number} {more or ''}" if number else rest or "")
    return "ask", None


def check_params(pairs, bad, blanks) -> tuple:
    """按 SOP 的定义核对参数：({参数: 值}, 说明)。不认识的、重复的直接拒；留空的参数全部给齐之前绝不开始执行。"""
    if bad:
        return {}, f"看不懂这几项：{'、'.join(bad[:3])}。参数要写成 名字=值"
    out = {}
    for key, value in pairs:
        if key not in blanks:
            return {}, (f"这个 SOP 没有参数 {key}" + (f"，要填的是：{'、'.join(blanks)}" if blanks else "，它不需要参数"))
        if key in out:
            return {}, f"参数 {key} 写了两次"
        value = value.strip()
        if not value or len(value) > 200 or _CONTROL.search(value):
            return {}, f"参数 {key} 的值不对（最多 200 个字）"
        out[key] = value
    missing = [key for key in blanks if key not in out]
    if missing:
        return {}, f"这个 SOP 需要：{'、'.join(missing)}"
    return out, ""


def clean_event(raw) -> dict | None:
    """转接程序给的消息 → 统一格式；缺字段、类型不对的返回 None（只计数，不处理）。"""
    if not isinstance(raw, dict):
        return None

    def text(key, limit):
        value = raw.get(key)
        return value[:limit] if isinstance(value, str) else ""

    event = {"id": raw.get("id") if isinstance(raw.get("id"), int) else 0, "handle": text("handle", 200),
             "kind": text("kind", 20), "platform": text("platform", 20) or "ccwork",
             "chat_type": text("chat_type", 10), "chat_id": text("chat_id", 64), "chat_name": text("chat_name", 100),
             "sender_id": text("sender_id", 64), "sender_name": text("sender_name", 50),
             "msg_key": text("msg_key", 200), "text": text("text", 20000), "truncated": raw.get("truncated") is True,
             "received_at": text("received_at", 40)}
    if (not event["handle"] or not event["msg_key"] or not event["sender_id"] or event["kind"] not in KINDS
            or event["chat_type"] not in CHAT_TYPES or (event["chat_type"] != "single" and not event["chat_id"])):
        return None
    return event


def person_key(event) -> tuple:
    return (event["platform"], event["chat_type"], event["chat_id"], event["sender_id"])


def chat_key(event) -> tuple:
    return (event["platform"], event["chat_type"], event["chat_id"] if event["chat_type"] != "single"
            else event["sender_id"])


def _tokens(text) -> set:
    return {token for token in tokenize(str(text or "")) if len(token) > 1}


def _dice(a, b) -> float:
    return 2 * len(a & b) / (len(a) + len(b)) if a and b else 0.0


def _titles() -> dict:
    try:
        return {name: (entry.get("title") or name) for name, entry in registry.data_tools().items()}
    except Exception:
        return {}


def visible_books(scope) -> list:
    """这个群、这个人看得到的启用的 SOP。限定了文档分类时，来源文档在别的分类里的去掉，手工创建的照常可见
    （和对外令牌同一个规矩：sop_tools.visible）；没限定时就是全部启用的。"""
    return sop_tools.visible(registry.Turn(categories=scope.categories))


def _reason(failure) -> str:
    text = str(failure or "")
    if "超时" in text or "Timeout" in text or "timed out" in text:
        return "模型超时"
    if text.startswith("检索失败"):
        return "知识库检索出错"
    return "出错了"


# --- 流式回复 ---------------------------------------------------------------------------------

class Streamer:
    """一次回答的流式包，在自己的线程里发，不拖慢读事件流。

    每包都是 cover，带到目前为止的全文：丢一包下一包就补上。第一包马上发（「🔎 正在查知识库…」）；之后只在新增了
    至少 MIN_NEW 个字或状态变了时才发，间隔前 15 秒 1.5 秒、到 60 秒 3 秒、再往后 6 秒；一次回答最多 MAX_PACKETS 包，
    最后留两包：正文加出处（delta），再一包 done。

    seq 只在转接程序回成功（或回同一包的缓存）后才往上加。结果不明（超时、断网、平台 5xx）时同一个 seq、同样的内容
    重发，最多 RETRIES 次；还不行就不再发（state=uncertain），免得整段答案出现两遍。平台明确拒了的（state=rejected），
    由调用方在最后换成普通文字发一次；handle 过期、发送关着这类发不了的（state=stopped），什么都不再发。
    """
    PACES = ((15.0, 1.5), (60.0, 3.0), (None, 6.0))
    MIN_NEW = 20
    MAX_PACKETS = 40
    RETRIES = 3
    RETRY_WAIT = (1.0, 2.0, 4.0)
    FINISH_WAIT = 90.0

    def __init__(self, bridge, handle, render, status=chat_format.STATUS_SEARCH, clock=time.monotonic,
                 sleep=time.sleep):
        self.bridge, self.handle, self.render = bridge, handle, render
        self.clock, self.sleep = clock, sleep
        self.request_id = uuid.uuid4().hex
        self.seq = 1
        self.sent = 0
        self.state = "ok"
        self.error = None
        self._text, self._status = "", status
        self._sent_len, self._sent_status = 0, None
        self._final = None
        self._cond = threading.Condition()
        self._thread = threading.Thread(target=self._run, name="chat-stream", daemon=True)

    def start(self):
        self._thread.start()
        return self

    def update(self, text=None, status=None):
        with self._cond:
            if text is not None:
                self._text = text
            if status is not None:
                self._status = status
            self._cond.notify_all()

    def finish(self, final) -> bool:
        """发最后两包，等发完（最多 FINISH_WAIT 秒）。返回最后一包有没有确认发出去。"""
        with self._cond:
            self._final = final
            self._cond.notify_all()
        self._thread.join(self.FINISH_WAIT)
        return self.state == "ok" and not self._thread.is_alive()

    @property
    def stopped(self) -> bool:
        return self.state == "stopped"

    def _pace(self, elapsed) -> float:
        for until, gap in self.PACES:
            if until is None or elapsed < until:
                return gap
        return self.PACES[-1][1]

    def _next(self, started, last):
        """等到该发下一包：返回 ("final", 全文) 或 ("delta", (正文, 状态))。"""
        with self._cond:
            while True:
                if self._final is not None:
                    return "final", self._final
                now = self.clock()
                gap = self._pace(now - started)
                due = last is None or now - last >= gap
                changed = self._status != self._sent_status or len(self._text) - self._sent_len >= self.MIN_NEW
                if self.state == "ok" and due and changed and self.sent < self.MAX_PACKETS - 2:
                    return "delta", (self._text, self._status)
                wait = gap - (now - last) if last is not None and not due else 1.0
                self._cond.wait(max(0.02, min(wait, 1.0)))

    def _run(self):
        started, last = self.clock(), None
        try:
            while True:
                kind, payload = self._next(started, last)
                if kind == "final":
                    if self.state == "ok" and self._send(payload[:TEXT_OUT_MAX], "delta"):
                        self._send(payload[:TEXT_OUT_MAX], "done")
                    return
                text, status = payload
                self._send(self.render(text, status)[:TEXT_OUT_MAX], "delta")
                self._sent_len, self._sent_status = len(text), status
                last = self.clock()
        except Exception:
            log.warning("chat stream crashed", exc_info=True)
            self.state = "stopped"

    def _send(self, content, kind) -> bool:
        packet = {"request_id": self.request_id, "seq": self.seq, "type": kind, "message_type": "cover",
                  "content": content}
        for attempt in range(self.RETRIES + 1):
            try:
                self.bridge.reply_stream(self.handle, packet)
            except BridgeError as exc:
                if exc.retryable and attempt < self.RETRIES:
                    self.sleep(self.RETRY_WAIT[min(attempt, len(self.RETRY_WAIT) - 1)])
                    continue
                self.error = exc
                self.state = "uncertain" if exc.retryable else "rejected" if exc.rejected else "stopped"
                return False
            self.seq += 1
            self.sent += 1
            return True
        return False


# --- 聊天线程 ---------------------------------------------------------------------------------

class Channel:
    """一个后台线程长轮询转接程序；问题和「执行」交给 WORKERS 个工作线程，命令和提示语交给一个快线程。"""

    def __init__(self, bridge, start_turn, turn_events, *, clock=time.monotonic):
        self.bridge, self.start_turn, self.turn_events = bridge, start_turn, turn_events
        self.clock = clock
        self._pool = ThreadPoolExecutor(WORKERS, thread_name_prefix="chat")
        self._quick = ThreadPoolExecutor(1, thread_name_prefix="chat-quick")
        self._lock = threading.Lock()
        self._inflight = 0
        self._busy = set()
        self._hits = {}
        self._notices = {}
        self._stop = threading.Event()
        self._thread = None
        self._maintained = None
        self.counters = {}
        self.link = {"state": "starting", "since": chat_store.now_iso(), "error": "", "last_poll": None}

    # --- 起停 ---
    def start(self):
        chat_store.ensure()
        resume, interrupted = chat_store.inbox_recover()
        for event in interrupted:
            self._quick.submit(self._say, event, "刚才服务重启，这个问题没答完，请再问一次。")
        for event in resume:
            self._route(event)
        self.maintain()
        self._thread = threading.Thread(target=self._poll, name="chat-poll", daemon=True)
        self._thread.start()
        log.info("chat: started (resumed %d, interrupted %d)", len(resume), len(interrupted))

    def maintain(self, now=None):
        """每天一次（启动时、之后轮询线程里顺带）：清掉处理完的收件记录（只留几天，够去重用）、30 天没动静的「没开通」记录。"""
        day = (now or datetime.now(timezone.utc)).date()
        if self._maintained == day:
            return
        self._maintained = day          # 先记下：出错了也是明天再试，不在每一轮轮询里反复报
        try:
            inbox, unknown = chat_store.inbox_prune(now=now), chat_store.unknown_prune(now=now)
        except Exception:
            log.warning("chat: daily cleanup failed", exc_info=True)
            return
        if inbox or unknown:
            log.info("chat: daily cleanup removed %d inbox record(s) and %d unknown chat(s)", inbox, unknown)

    def stop(self, timeout=5.0):
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout)
        self._pool.shutdown(wait=False, cancel_futures=True)
        self._quick.shutdown(wait=False, cancel_futures=True)

    def wait_idle(self, timeout=10.0) -> bool:
        """测试用：等工作线程和快线程手上的都做完。"""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self._lock:
                inflight = self._inflight
            if inflight == 0:
                self._quick.submit(lambda: None).result(timeout=max(0.1, deadline - time.monotonic()))
                with self._lock:
                    if self._inflight == 0:
                        return True
            time.sleep(0.02)
        return False

    def status(self) -> dict:
        with self._lock:
            return {**self.link, "inflight": self._inflight, "counters": dict(self.counters)}

    def _count(self, name):
        with self._lock:
            self.counters[name] = self.counters.get(name, 0) + 1

    def _link(self, state, error=""):
        with self._lock:
            if self.link["state"] != state:
                self.link.update(state=state, since=chat_store.now_iso())
            self.link["error"] = error
            if state == "ok":
                self.link["last_poll"] = chat_store.now_iso()

    # --- 取消息 ---
    def _poll(self):
        epoch = chat_store.state_get("epoch")
        after = int(chat_store.state_get("after", "0") or 0)
        failures = 0
        while not self._stop.is_set():
            self.maintain()
            try:
                epoch_now, events = self.bridge.events(epoch, after, POLL_WAIT)
            except EpochChanged as exc:
                log.info("chat: bridge restarted, fetching from the beginning")
                epoch, after = exc.epoch, 0
                chat_store.state_set("epoch", epoch)
                chat_store.state_set("after", 0)
                continue
            except BridgeError as exc:
                failures += 1
                self._link("unreachable", str(exc))
                if failures in (1, 10) or failures % 60 == 0:
                    log.warning("chat: bridge unreachable (%d): %s", failures, exc)
                self._stop.wait(BACKOFF[min(failures, len(BACKOFF)) - 1])
                continue
            except Exception:
                failures += 1
                log.warning("chat: polling failed", exc_info=True)
                self._stop.wait(BACKOFF[min(failures, len(BACKOFF)) - 1])
                continue
            failures = 0
            self._link("ok")
            if epoch_now and epoch_now != epoch:
                epoch = epoch_now
                chat_store.state_set("epoch", epoch)
            for raw in events:
                try:
                    self.receive(raw)
                except Exception:
                    log.warning("chat: handling a message failed", exc_info=True)
                if isinstance(raw, dict) and isinstance(raw.get("id"), int):
                    after = max(after, raw["id"])
            chat_store.state_set("after", after)       # 落库之后才确认：下一次轮询带上它
            try:
                chat_push.maybe_digest()
            except Exception:
                log.warning("chat: weekly digest failed", exc_info=True)

    def receive(self, raw):
        """一条消息：先查白名单。没开通的只记 ID 和次数（不记内容），开通的落库后再分派。"""
        event = clean_event(raw)
        if event is None:
            self._count("malformed")
            return
        cfg = chat_config.load()
        scope = cfg.scope(event["chat_type"], event["chat_id"], event["sender_id"])
        if scope is None:
            self._count("refused")
            due = chat_store.unknown_record(event)
            log.info("chat %s %s:%s from %s → refused (not enabled)", event["platform"], event["chat_type"],
                     tail(event["chat_id"]), tail(event["sender_id"]))
            if due and cfg.unknown_reply == "once":
                where = "这个群" if event["chat_type"] != "single" else "私聊"
                text = f"{where}还没有开通 {BOT_NAME}" + (f"，需要的话请联系 {cfg.contact}" if cfg.contact else "") + "。"
                self._quick.submit(self._say, event, text)
            return
        if not chat_store.inbox_add(event):
            self._count("duplicate")
            return
        self._route(event)

    def _notice_due(self, key, gap) -> bool:
        now = self.clock()
        with self._lock:
            last = self._notices.get(key)
            if last is not None and now - last < gap:
                return False
            self._notices[key] = now
            if len(self._notices) > 5000:
                self._notices = {k: v for k, v in self._notices.items() if now - v < DAILY_GAP}
            return True

    def _allow(self, key, limit, window=3600.0) -> bool:
        """滑动窗口限频：没到上限就记一次、返回 True。"""
        now = self.clock()
        with self._lock:
            hits = [t for t in self._hits.get(key, []) if now - t < window]
            if len(hits) >= limit:
                self._hits[key] = hits
                return False
            hits.append(now)
            self._hits[key] = hits
            return True

    def _quick_job(self, key, fn, *args):
        """命令、提示语：在快线程里做，做完收件表记完成。"""
        def job():
            try:
                chat_store.inbox_set(key, "processing")
                fn(*args)
            except Exception:
                log.warning("chat: command failed", exc_info=True)
            finally:
                chat_store.inbox_set(key, "done")
        self._quick.submit(job)

    def _drop(self, key, event, notice_key, gap, text):
        """不处理这条：到了间隔就回一句提示，收件表记完成。"""
        if self._notice_due(notice_key, gap):
            self._quick_job(key, self._say, event, text)
        else:
            chat_store.inbox_set(key, "done")

    def _route(self, event):
        """开通了的消息：暂停、类型、同一个人还有没答完的、命令、限频、排队，按顺序看。"""
        key = event["msg_key"]
        cfg = chat_config.load()
        scope = cfg.scope(event["chat_type"], event["chat_id"], event["sender_id"])
        if scope is None:
            chat_store.inbox_set(key, "done")
            return
        person, where = person_key(event), chat_key(event)
        if cfg.paused:
            return self._drop(key, event, ("paused", person), NOTICE_GAP,
                              f"{BOT_NAME} 暂停服务中，请稍后再问" + (f"，或联系 {cfg.contact}" if cfg.contact else "") + "。")
        if event["kind"] == "unsupported":
            return self._drop(key, event, ("unsupported", where), DAILY_GAP,
                              "目前只能看文字消息：图片、文件、图文混排、引用回复还看不了，请把问题打成文字再发。")
        if event["kind"] == "undecryptable":
            return self._drop(key, event, ("undecryptable", where), DAILY_GAP,
                              "这条消息解不开（加密方式不认识），请换成普通文字再发一次。")
        with self._lock:
            busy = person in self._busy
        if busy:
            return self._drop(key, event, ("busy", person), NOTICE_GAP, "上一个问题还在回答，答完再问。")
        text = chat_format.strip_mention(event["text"], cfg.robot_name)
        command, arg = parse_command(text)
        if command not in ("ask", "execute"):
            return self._quick_job(key, self._command, event, scope, command, arg)
        if not text:
            return self._quick_job(key, self._say, event, f"请在 @ {cfg.robot_name or BOT_NAME} 之后写上问题；回「帮助」看能问什么。")
        if not self._allow(("person", person), cfg.limits["person_per_hour"]):
            return self._drop(key, event, ("limited", person), NOTICE_GAP,
                              f"你这一小时问得太多了（最多 {cfg.limits['person_per_hour']} 个），请稍后再问。")
        if event["chat_type"] != "single" and not self._allow(("group", where), cfg.limits["group_per_hour"]):
            return self._drop(key, event, ("group_limited", where), NOTICE_GAP,
                              f"这里这一小时问得太多了（最多 {cfg.limits['group_per_hour']} 个），请稍后再问。")
        with self._lock:
            full = self._inflight >= WORKERS + QUEUE_MAX
            if not full:
                self._inflight += 1
                self._busy.add(person)
        if full:
            return self._drop(key, event, ("queue", where), QUEUE_GAP, "排队的问题太多了，请过几分钟再问。")
        self._pool.submit(self._work, key, event, person, text, command, arg)

    def _work(self, key, event, person, text, command, arg):
        try:
            chat_store.inbox_set(key, "processing")
            cfg = chat_config.load()
            scope = cfg.scope(event["chat_type"], event["chat_id"], event["sender_id"])
            if scope is not None:
                if command == "execute":
                    self._execute(event, cfg, scope, arg, text)
                else:
                    self._answer(event, cfg, scope, text)
        except Exception:
            log.warning("chat: answering failed", exc_info=True)
        finally:
            chat_store.inbox_set(key, "done")
            with self._lock:
                self._inflight -= 1
                self._busy.discard(person)

    # --- 回话 ---
    def _say(self, event, text, mention=False):
        """普通文字回复。群里第一行写明在回谁。发不出去只记日志。"""
        if event["chat_type"] != "single" and not mention:
            asked = chat_format.strip_mention(event["text"], chat_config.load().robot_name)
            text = chat_format.reply_head(event["sender_name"], asked) + "\n" + text
        try:
            self.bridge.reply_text(event["handle"], text[:TEXT_OUT_MAX], mention)
            return True
        except BridgeError as exc:
            log.info("chat reply %s:%s → failed (%s)", event["chat_type"], tail(event["chat_id"]), exc)
            return False

    # --- 回答 ---
    def _continue(self, event, cfg):
        """能接着用的那条对话（chat_threads 的一行）；不能接着用的关掉，返回 None。"""
        thread = chat_store.thread_current(event["platform"], event["chat_type"], event["chat_id"],
                                           event["sender_id"])
        if thread is None:
            return None
        fresh = (datetime.now(timezone.utc) - timedelta(minutes=cfg.limits["context_minutes"])).isoformat(
            timespec="seconds")
        conversation_id = thread.get("conversation_id")
        usable = (thread["updated_at"] >= fresh and conversation_id and conversations.exists(conversation_id)
                  and thread.get("last_message_id") is not None
                  and chat_store.last_message_id(conversation_id) == thread["last_message_id"])
        if not usable:
            chat_store.thread_close(thread["id"])
            return None
        return thread

    def _candidates(self, answer, question, scope) -> list:
        """回答末尾列的「相关 SOP」：回答里《》提到的、这里看得到的、每一步工具都开通了的，再按字面相似补到最多 3 个。"""
        if not scope.tools:
            return []
        try:
            live = set(registry.sop_tools())
        except Exception:
            return []
        usable = [p for p in visible_books(scope)
                  if p["steps"] and all(s["tool"] in scope.tools and s["tool"] in live for s in p["steps"])]
        picked = []
        for name in re.findall(r"《([^》]{1,60})》", str(answer or "")):
            for book in usable:
                if book["name"] == name and book not in picked:
                    picked.append(book)
        asked = _tokens(question)
        ranked = sorted(((_dice(asked, _tokens(f"{b['name']} {b['trigger']}")), b) for b in usable if b not in picked),
                        key=lambda pair: -pair[0])
        picked += [book for score, book in ranked if score >= LEXICAL_MIN]
        return picked[:CANDIDATES_MAX]

    def _answer(self, event, cfg, scope, question, playbook=None, asked=None):
        """一次回答（或一次按 SOP 执行）：流式发到群里，结束后补出处、SOP 候选或执行结论。asked 是这个人原本写的话。"""
        group = event["chat_type"] != "single"
        if not settings.configured():
            self._say(event, "管理员还没有配置模型，暂时答不了。")
            return
        thread = self._continue(event, cfg)
        head = chat_format.reply_head(event["sender_name"], asked or question) if group else ""
        limit = cfg.limits["max_chars"]

        def render(text, status):
            shown, rest = chat_format.truncate(chat_format.plain(text, cfg.markdown), limit)
            return "\n".join(part for part in (head, shown + ("\n……" if rest else ""), status) if part)

        titles = _titles()
        streamer = Streamer(self.bridge, event["handle"], render).start()
        started = self.clock()
        kind = "execute" if playbook else "ask"
        who = event["sender_name"] or tail(event["sender_id"])
        answer, failure, completed, turn, thread_id = "", None, False, None, None
        hits, extra, tools_used = [], [], 0
        try:
            turn = self.start_turn(question, thread["conversation_id"] if thread else None,
                                   title=f"云上协同·{scope.name}：{question}",
                                   mode="kb" if playbook else scope.mode, web=scope.web and not playbook,
                                   playbook_id=playbook["id"] if playbook else None, tools=scope.tools,
                                   categories=scope.categories, note=chat_format.CHAT_RULES,
                                   run_note=f"云上协同·{scope.name}·{who}" if playbook else "")
        except Exception as exc:
            log.warning("chat: could not start the turn", exc_info=True)
            failure = f"开始回答时出错：{why(exc)}"
        if turn is not None:
            if thread is not None and thread["conversation_id"] == turn.conversation_id:
                thread_id = thread["id"]
            else:
                thread_id = chat_store.thread_open(event, scope.name, turn.conversation_id)
            chat_store.turn_add(thread_id, turn.conversation_id, turn.execution_id, turn.run_id, kind)
            deadline = started + (EXECUTE_TIMEOUT if playbook else ASK_TIMEOUT)
            try:
                # 一定在这里关掉事件流（提前结束也关）：收尾（图谱、执行记录、删空对话、根 run）才在本线程照常执行
                with closing(self.turn_events(turn)) as events:
                    for item in events:
                        if "delta" in item:
                            answer += item["delta"]
                            streamer.update(answer, "")
                        elif "tool_call" in item:
                            tools_used += 1
                            status = chat_format.status_for(item["tool_call"], titles)
                            if status:
                                streamer.update(status=status)
                        elif "sources" in item:
                            hits = list(item["sources"] or [])
                        elif "kb_sources" in item or "web_sources" in item:
                            extra += list(item.get("kb_sources") or item.get("web_sources") or [])
                        elif "error" in item:
                            failure = item["error"]
                        if self.clock() > deadline:
                            failure = "超时"
                            break
                        if streamer.stopped or self._stop.is_set():
                            failure = failure or "发不出去"
                            break
                    else:
                        completed = True
            except Exception as exc:
                log.warning("chat: answer stream failed", exc_info=True)
                failure = f"回答时出错：{why(exc)}"
        answered = completed and bool(answer.strip())
        run = runs.get(turn.run_id) if turn is not None and turn.run_id else None
        picked = [] if playbook or not answered else self._candidates(answer, question, scope)
        if answered:
            tail_lines = ["（回答中途出错，可能不完整）" if failure else "",
                          chat_format.sources_line(answer, hits + extra)]
            if playbook:
                tail_lines += chat_format.run_lines(run, chat_push.site_url())
            else:
                tail_lines.append(chat_format.candidates_line([b["name"] for b in picked]))
            final, remainder = chat_format.compose(head, chat_format.plain(answer, cfg.markdown), tail_lines, limit)
        else:
            final, remainder = "\n".join(p for p in (head, f"这次没答出来（{_reason(failure)}），请稍后再问。") if p), ""
        delivered = streamer.finish(final)
        if streamer.state == "rejected":
            # 平台明确拒了流式消息：换成普通文字发一次，这时真 @ 提问人
            delivered = self._say(event, final, mention=group)
        if thread_id is not None:
            if answered:
                chat_store.thread_update(thread_id, last_message_id=chat_store.last_message_id(turn.conversation_id),
                                         last_execution_id=turn.execution_id, last_run_id=turn.run_id,
                                         candidates=[b["id"] for b in picked], remainder=remainder)
            elif not conversations.exists(turn.conversation_id):
                chat_store.thread_close(thread_id)
        outcome = "answered" if answered else "failed"
        where = scope.name if scope.kind == "group" else "私聊"        # 群名是 chat.yaml 里起的；人名不进日志
        log.info("chat %s %s user=%s len=%d → %s %.1fs %s tools=%d packets=%d%s%s", event["platform"], where,
                 tail(event["sender_id"]), len(question), outcome, self.clock() - started,
                 "execute" if playbook else scope.mode, tools_used, streamer.sent,
                 "" if delivered else f" delivery={streamer.state}", f" failure={failure}" if failure else "")

    # --- 命令 ---
    def _command(self, event, scope, command, arg):
        cfg = chat_config.load()
        thread = chat_store.thread_current(event["platform"], event["chat_type"], event["chat_id"],
                                           event["sender_id"])
        if command == "help":
            text = chat_format.help_text(scope, _titles(), group=event["chat_type"] != "single",
                                         web=scope.web and web_search.enabled(), contact=cfg.contact)
        elif command == "new":
            if thread is not None:
                chat_store.thread_close(thread["id"])
            text = "好的，接下来是新话题，不接之前的上文。"
        elif command == "more":
            return self._more(event, cfg, thread)
        elif command == "unhelpful":
            execution = thread.get("last_execution_id") if thread else None
            if not execution:
                text = "还没有可以评价的回答。"
            else:
                graph.record_feedback(execution, "unhelpful", arg[:300])
                text = "已记下：上一条回答没答好。管理员会在「知识库缺口」里看到它，据此补文档。"
        else:
            word, note = arg
            run_id = thread.get("last_run_id") if thread else None
            if not run_id or thread.get("last_execution_id") != run_id:
                text = f"「{word}」只对你上一次的 SOP 执行有效；你上一条不是 SOP 执行。"
            else:
                graph.record_feedback(run_id, VERDICTS[word], note[:300])
                text = f"已记下：{word}。"
        self._say(event, text)

    def _more(self, event, cfg, thread):
        rest = (thread or {}).get("remainder") or ""
        if not rest:
            self._say(event, "没有没发完的部分。")
            return
        parts, left = chat_format.pieces(rest, cfg.limits["max_chars"], 3)
        for part in parts:
            if not self._say(event, part):
                return
        if left:
            title = conversations_title(thread.get("conversation_id"))
            self._say(event, "还有一部分太长没发，完整内容在网页「对话」里" + (f"，标题：{title}" if title else "") + "。")
        chat_store.thread_update(thread["id"], remainder="")

    def _resolve(self, selector, thread, scope) -> tuple:
        """「执行」后面写的是哪个 SOP：("one", SOP) / ("pick", [SOP…]) / ("none", 说明) / ("question", None)。

        只在这里看得到的 SOP 里找（限定了文档分类时，来源文档在别的分类里的不算）。
        写的是名字却一个都对不上时当成普通问题（「执行 SOP 时报错怎么办」这种）。"""
        enabled = visible_books(scope)
        by_id = {book["id"]: book for book in enabled}
        offered = [i for i in ((thread or {}).get("candidates") or []) if i in by_id]
        if not selector:
            if len(offered) == 1:
                return "one", by_id[offered[0]]
            if offered:
                return "pick", [by_id[i] for i in offered]
            return "none", "先问一个问题，回答末尾会列出相关 SOP；也可以直接回「执行 SOP 名」。"
        if selector.isdigit():
            n = int(selector)
            ids = (thread or {}).get("candidates") or []
            if 1 <= n <= len(ids) and ids[n - 1] in by_id:
                return "one", by_id[ids[n - 1]]
            return "none", "没有这个编号：编号是上一条回答末尾「相关 SOP」里的。"
        name = re.sub(r"^SOP\s*", "", selector, flags=re.IGNORECASE).strip().strip("《》").strip()
        exact = [book for book in enabled if book["name"] == name]
        if exact:
            return "one", exact[0]
        near = [book for book in enabled if name and name in book["name"]]
        if len(near) == 1:
            return "one", near[0]
        if near:
            return "pick", near[:5]
        return "question", None

    def _execute(self, event, cfg, scope, spec, text):
        thread = chat_store.thread_current(event["platform"], event["chat_type"], event["chat_id"],
                                           event["sender_id"])
        found, book = self._resolve(spec["selector"], thread, scope)
        if found == "question":
            return self._answer(event, cfg, scope, text)
        if not scope.tools:
            return self._say(event, "这里没有开通查实际数据，SOP 要在开通了数据工具的群或私聊里执行。")
        if cfg.limits["execute_per_hour"] == 0:
            return self._say(event, "这里没有开通执行 SOP。")
        if found == "none":
            return self._say(event, book)
        if found == "pick":
            if thread is None:
                thread_id = chat_store.thread_open(event, scope.name, None)
            else:
                thread_id = thread["id"]
            chat_store.thread_update(thread_id, candidates=[b["id"] for b in book])
            listed = "　".join(f"{n}. {b['name']}" for n, b in enumerate(book, 1))
            return self._say(event, f"有几个 SOP 对得上：{listed}——回「执行 1」这样的编号选一个。")
        missing = sorted({s["tool"] for s in book["steps"] if s["tool"] not in scope.tools})
        if missing:
            return self._say(event, f"SOP《{book['name']}》要用的工具 {'、'.join(missing)} 在这里没有开通，执行不了。")
        from app import autorun
        problem = autorun.precheck(book)
        if problem:
            return self._say(event, f"执行不了：{problem}")
        blanks = [key for key, _ in sop_tools.blanks(book)]
        params, problem = check_params(spec["pairs"], spec["bad"], blanks)
        if problem:
            example = " ".join(f"{key}=…" for key in blanks)
            hint = f"。请回：执行 {spec['selector'] or ''} {example}".replace("  ", " ") if blanks else ""
            return self._say(event, problem + hint)
        if runs.busy(book["id"]):
            return self._say(event, f"SOP《{book['name']}》上一次还没跑完，等它跑完再执行。")
        if not self._allow(("execute", chat_key(event)), cfg.limits["execute_per_hour"]):
            return self._say(event, f"这里一小时最多执行 {cfg.limits['execute_per_hour']} 次 SOP，请稍后再试。")
        question = f"执行 SOP《{book['name']}》" + (
            "（" + "，".join(f"{key}：{value}" for key, value in params.items()) + "）" if params else "")
        self._answer(event, cfg, scope, question, playbook=book, asked=text)


def conversations_title(conversation_id) -> str:
    if not conversation_id:
        return ""
    with conversations.lock:
        row = conversations.db.execute("SELECT title FROM conversations WHERE id = ?", (conversation_id,)).fetchone()
    return row[0] if row else ""
