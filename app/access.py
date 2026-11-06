"""对外接入：外部智能体（MCP 客户端）的令牌、调用审计和限流。

过渡期（统一登录之前）每个客户端一枚令牌，在管理页「对外接入」签发：

    - 库里只存哈希（sha256），明文只在签发时显示一次。可以吊销、可以设过期时间。
    - 范围三种：knowledge（知识库，可以只开放某几个文档分类）、sop（SOP 工具和提示词）、data（宿主机标了 export 的数据工具）。
      签出的范围不能超过页面本来就能看到的：分类必须是知识库里现有的。
    - 每个 HTTP 请求都现查库：吊销、过期立刻生效。

审计：每次工具 / 提示词调用记一行：客户端、名字、参数、返回大小、耗时、成败、对应的图谱执行；保留 MCP_AUDIT_DAYS 天。
页面上清除审计（全部、N 天以前、某枚令牌的）要审批口令，每次清除都在 access_changes 里留一条「谁、什么时候、从哪里、清了多少条」。
限流：按令牌限制每分钟的调用次数（工具和提示词，默认 MCP_RATE_PER_MINUTE）和单次返回大小（默认 MCP_MAX_RESULT_CHARS）；
HTTP 请求另有一个宽松的总上限（调用次数的 10 倍），挡住失控的客户端。限流计数在进程内存里（应用只跑一个 worker）。

总开关：MCP_ENABLED（.env）是上限；它打开时，页面上还有一个开关（mcp_state 表的 switch 行，没有这行就是开）。
关着时 /mcp 一律 403，令牌的管理照常。关不要口令，重新打开要审批口令（工具服务核对）。宿主机上的逃生口：
    docker exec kb-app python -m app.access open        # 等同于有宿主机 root：不要口令

操作记录（access_changes）：开关、删令牌、清审计、分类改动带来的令牌白名单改动，只增不删，页面上没有删除接口。
"""
import hashlib
import json
import re
import secrets
import sqlite3
import sys
import threading
import time
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from app.config import DATA_DIR, MCP_AUDIT_DAYS, MCP_MAX_RESULT_CHARS, MCP_RATE_PER_MINUTE

SCOPES = ("knowledge", "sop", "data")
PREFIX = "d2s_"
NAME_MAX = 40
EXPIRES_DAYS_MAX = 3650
RATE_RANGE = (1, 10000)
RESULT_RANGE = (1000, 200000)
ARGS_CHARS = 2000            # 审计里参数最多记多少字
TOUCH_SECONDS = 60           # last_used_at 最多每分钟写一次
REQUESTS_PER_CALL = 10       # HTTP 请求的总上限 = 调用上限 × 这个数

db = sqlite3.connect(DATA_DIR / "access.db", check_same_thread=False)
db.row_factory = sqlite3.Row
db.execute("PRAGMA journal_mode=WAL")
db.executescript("""
CREATE TABLE IF NOT EXISTS mcp_tokens (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  scopes TEXT NOT NULL,
  categories TEXT,
  rate_per_minute INTEGER,
  max_result_chars INTEGER,
  created_at TEXT NOT NULL,
  expires_at TEXT,
  revoked_at TEXT,
  last_used_at TEXT
);
CREATE TABLE IF NOT EXISTS mcp_calls (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  at TEXT NOT NULL,
  token_id TEXT NOT NULL,
  client TEXT NOT NULL,
  kind TEXT NOT NULL,
  name TEXT NOT NULL,
  args TEXT NOT NULL DEFAULT '{}',
  result_chars INTEGER NOT NULL DEFAULT 0,
  duration_ms INTEGER NOT NULL DEFAULT 0,
  ok INTEGER NOT NULL DEFAULT 1,
  error TEXT NOT NULL DEFAULT '',
  execution_id TEXT,
  session TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS mcp_calls_by_token ON mcp_calls(token_id, at);
CREATE INDEX IF NOT EXISTS mcp_calls_by_time ON mcp_calls(at);
CREATE TABLE IF NOT EXISTS mcp_state (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  at TEXT NOT NULL,
  user TEXT NOT NULL DEFAULT '',
  ip TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS access_changes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  at TEXT NOT NULL,
  user TEXT NOT NULL DEFAULT '',
  ip TEXT NOT NULL DEFAULT '',
  kind TEXT NOT NULL,
  detail TEXT NOT NULL DEFAULT '',
  count INTEGER
);
""")


def _migrate(conn):
    """后加的列补上（老库的旧行取默认值）。via：调用从哪条路来，'' 是外部客户端，'page' 是管理页「测一下」「试调」
    在进程内转给 /mcp 的（app/mcp_probe.py）。回滚到老镜像时，老代码 SELECT * 多一列无害、INSERT 写明了列名，不受影响。"""
    if "via" not in {row[1] for row in conn.execute("PRAGMA table_info(mcp_calls)")}:
        conn.execute("ALTER TABLE mcp_calls ADD COLUMN via TEXT NOT NULL DEFAULT ''")
    conn.commit()


_migrate(db)
lock = threading.Lock()
VIAS = ("", "page")


class AccessError(ValueError):
    """签发参数不合法，附带可以直接给页面看的原因。"""


@dataclass(frozen=True)
class Client:
    """一枚有效令牌代表的外部客户端。"""
    id: str
    name: str
    scopes: frozenset
    categories: frozenset | None        # None = 全部分类
    rate_per_minute: int
    max_result_chars: int

    def can(self, scope) -> bool:
        return scope in self.scopes


def _now():
    return datetime.now(timezone.utc)


def _iso(moment):
    return moment.isoformat(timespec="seconds")


def _hash(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _bounded(value, low, high, what):
    if value in (None, ""):
        return None
    try:
        number = int(value)
    except (TypeError, ValueError):
        raise AccessError(f"{what}要是整数") from None
    if not low <= number <= high:
        raise AccessError(f"{what}要在 {low}–{high} 之间")
    return number


def issue(name, scopes, categories=None, expires_days=None, rate_per_minute=None, max_result_chars=None,
          known_categories=None):
    """签发一枚令牌：返回 (令牌信息, 明文)。明文只有这一次，库里只存哈希。

    categories 为 None 是全部分类（包括以后新增的）；给了列表就是白名单，必须是 known_categories 里有的。
    known_categories 也可以是函数：在库锁里现取（分类改名、删除拿着同一把锁，签出来的白名单不会写上刚删掉的分类）。
    只有 data 范围时分类没有意义，存成全部。
    """
    name = " ".join(str(name or "").split())[:NAME_MAX]
    if not name:
        raise AccessError("要给令牌起个名字，比如「张三的 Claude Code」")
    scopes = sorted({str(s) for s in (scopes or [])})
    if not scopes:
        raise AccessError("至少选一个范围：知识库、SOP、数据工具")
    unknown = [s for s in scopes if s not in SCOPES]
    if unknown:
        raise AccessError(f"不认识的范围：{'、'.join(unknown)}；只能是 {'、'.join(SCOPES)}")
    if categories is not None and not {"knowledge", "sop"} & set(scopes):
        categories = None

    def check_known():
        if categories is None or known_categories is None:
            return
        known = set(known_categories() if callable(known_categories) else known_categories)
        missing = [c for c in categories if c not in known]
        if missing:
            raise AccessError(f"知识库里没有这些分类：{'、'.join(missing)}")

    if categories is not None:
        categories = sorted({" ".join(str(c).split()) for c in categories if str(c).strip()})
        if not categories:
            raise AccessError("限定分类时至少选一个分类；不想限定就选「全部分类」")
        check_known()
    days = _bounded(expires_days, 1, EXPIRES_DAYS_MAX, "有效天数")
    rate = _bounded(rate_per_minute, *RATE_RANGE, "每分钟调用次数")
    chars = _bounded(max_result_chars, *RESULT_RANGE, "单次返回字数")
    token_id = secrets.token_hex(6)
    plain = f"{PREFIX}{token_id}_{secrets.token_urlsafe(32)}"
    now = _now()
    with lock:
        if callable(known_categories):
            check_known()
        db.execute("INSERT INTO mcp_tokens (id, name, token_hash, scopes, categories, rate_per_minute,"
                   " max_result_chars, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                   (token_id, name, _hash(plain), json.dumps(scopes),
                    None if categories is None else json.dumps(categories, ensure_ascii=False),
                    rate, chars, _iso(now), _iso(now + timedelta(days=days)) if days else None))
        db.commit()
    return get(token_id), plain


def _status(row, now=None):
    if row["revoked_at"]:
        return "revoked"
    if row["expires_at"] and datetime.fromisoformat(row["expires_at"]) <= (now or _now()):
        return "expired"
    return "active"


def _view(row):
    categories = json.loads(row["categories"]) if row["categories"] else None
    return {"id": row["id"], "name": row["name"], "scopes": json.loads(row["scopes"]), "categories": categories,
            "rate_per_minute": row["rate_per_minute"] or MCP_RATE_PER_MINUTE,
            "max_result_chars": row["max_result_chars"] or MCP_MAX_RESULT_CHARS,
            "created_at": row["created_at"], "expires_at": row["expires_at"], "revoked_at": row["revoked_at"],
            "last_used_at": row["last_used_at"], "status": _status(row)}


def get(token_id):
    with lock:
        row = db.execute("SELECT * FROM mcp_tokens WHERE id = ?", (token_id,)).fetchone()
    return _view(row) if row else None


def list_tokens():
    with lock:
        rows = db.execute("SELECT * FROM mcp_tokens ORDER BY created_at DESC").fetchall()
    return [_view(row) for row in rows]


def revoke(token_id) -> bool:
    """吊销：下一个请求就是 401。返回是否真的改了（已吊销的不再改）。"""
    with lock:
        cur = db.execute("UPDATE mcp_tokens SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL",
                         (_iso(_now()), token_id))
        db.commit()
    _limiter.forget(token_id)
    return cur.rowcount > 0


def remove(token_id, user="", ip="") -> dict:
    """删掉一枚令牌的记录：只有已吊销或已过期的能删，还在用的先吊销。它的调用记录不动（记录里本来就存着令牌名）。
    返回删掉的令牌；不存在抛 LookupError，还有效抛 AccessError。删除和留痕在同一个事务里。"""
    with lock:
        row = db.execute("SELECT * FROM mcp_tokens WHERE id = ?", (str(token_id),)).fetchone()
        if row is None:
            raise LookupError("令牌不存在")
        if _status(row) == "active":
            raise AccessError("这枚令牌还有效：先吊销，再删除")
        view = _view(row)
        db.execute("DELETE FROM mcp_tokens WHERE id = ?", (row["id"],))
        _change(db, "token-delete", f"删除了令牌「{clean(row['name'])}」（{row['id']}，{_STATE_TEXT[view['status']]}）",
                None, user, ip)
        db.commit()
    _limiter.forget(row["id"])
    return view


_STATE_TEXT = {"revoked": "已吊销", "expired": "已过期", "active": "有效"}


# --- 总开关、操作记录 ------------------------------------------------------------------

_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f\u2028\u2029]")
SWITCH = "switch"
CHANGES_SHOWN = 50


def clean(text, limit=120) -> str:
    """进操作记录、日志的外部文字（令牌名、分类名）：控制字符换成空格，截长。"""
    return _CONTROL.sub(" ", str(text or ""))[:limit]


def _change(conn, kind, detail, count, user, ip):
    """记一条操作记录（调用方持有 lock、负责 commit：和改动本身在同一个事务里）。只增不删。"""
    conn.execute("INSERT INTO access_changes (at, user, ip, kind, detail, count) VALUES (?, ?, ?, ?, ?, ?)",
                 (_iso(_now()), clean(user, 60), clean(ip, 64), kind, clean(detail, 500), count))


def switch_state() -> dict:
    """页面开关：on 和最近一次改它的时间、人、来源。没改过就是开（升级后行为不变）。"""
    with lock:
        row = db.execute("SELECT * FROM mcp_state WHERE key = ?", (SWITCH,)).fetchone()
    if row is None:
        return {"on": True, "at": None, "user": "", "ip": ""}
    return {"on": row["value"] != "off", "at": row["at"], "user": row["user"], "ip": row["ip"]}


def is_open() -> bool:
    """/mcp 每个请求现查：关着就挡在令牌之前。"""
    with lock:
        row = db.execute("SELECT value FROM mcp_state WHERE key = ?", (SWITCH,)).fetchone()
    return row is None or row["value"] != "off"


def set_switch(on: bool, user="", ip="") -> bool:
    """改开关并留痕；返回是否真的变了（已经是这个状态时什么都不写）。打开要不要口令由调用方把关。"""
    value = "on" if on else "off"
    with lock:
        row = db.execute("SELECT value FROM mcp_state WHERE key = ?", (SWITCH,)).fetchone()
        current = "on" if row is None or row["value"] != "off" else "off"
        if current == value:
            return False
        db.execute("INSERT INTO mcp_state (key, value, at, user, ip) VALUES (?, ?, ?, ?, ?)"
                   " ON CONFLICT(key) DO UPDATE SET value = excluded.value, at = excluded.at,"
                   " user = excluded.user, ip = excluded.ip",
                   (SWITCH, value, _iso(_now()), clean(user, 60), clean(ip, 64)))
        _change(db, "switch-on" if on else "switch-off", "打开了对外接入" if on else "关闭了对外接入", None, user, ip)
        db.commit()
    return True


def list_changes(limit=CHANGES_SHOWN):
    with lock:
        rows = db.execute("SELECT * FROM access_changes ORDER BY id DESC LIMIT ?", (int(limit),)).fetchall()
    return [dict(row) for row in rows]


def set_categories(updates, detail, user="", ip=""):
    """分类改名、合并、删除时同步令牌的白名单：{令牌 id: 新的分类列表}。调用方持有 lock（和改文档分类在同一把锁里）。"""
    for token_id, categories in updates.items():
        db.execute("UPDATE mcp_tokens SET categories = ? WHERE id = ?",
                   (json.dumps(sorted(categories), ensure_ascii=False), token_id))
    if updates:
        _change(db, "token-categories", detail, len(updates), user, ip)
    db.commit()


_touched = {}


def verify(token):
    """令牌 → Client；无效、吊销、过期都返回 None。每个请求都现查库，吊销立刻生效。"""
    token = str(token or "").strip()
    if not token.startswith(PREFIX) or len(token) > 200:
        return None
    with lock:
        row = db.execute("SELECT * FROM mcp_tokens WHERE token_hash = ?", (_hash(token),)).fetchone()
        if row is None or _status(row) != "active":
            return None
        now = time.monotonic()
        if now - _touched.get(row["id"], -TOUCH_SECONDS) >= TOUCH_SECONDS:
            _touched[row["id"]] = now
            db.execute("UPDATE mcp_tokens SET last_used_at = ? WHERE id = ?", (_iso(_now()), row["id"]))
            db.commit()
    categories = json.loads(row["categories"]) if row["categories"] else None
    return Client(id=row["id"], name=row["name"], scopes=frozenset(json.loads(row["scopes"])),
                  categories=None if categories is None else frozenset(categories),
                  rate_per_minute=row["rate_per_minute"] or MCP_RATE_PER_MINUTE,
                  max_result_chars=row["max_result_chars"] or MCP_MAX_RESULT_CHARS)


def describe(token):
    """管理页「测一下」用：明文令牌 → 令牌信息（含状态：有效、已吊销、已过期），库里没有时 None。
    只读：不更新最近使用，不算限流。/mcp 本身不用它——对外只回一个 401，不告诉人令牌是吊销了还是不存在。"""
    token = str(token or "").strip()
    if not token.startswith(PREFIX) or len(token) > 200:
        return None
    with lock:
        row = db.execute("SELECT * FROM mcp_tokens WHERE token_hash = ?", (_hash(token),)).fetchone()
    return _view(row) if row else None


# --- 审计 ---------------------------------------------------------------------------

_pruned = {"at": 0.0}


def record_call(client, kind, name, args, result_chars, duration_ms, ok, error="", execution_id=None, session="",
                via=""):
    """记一次对外调用。参数截到 ARGS_CHARS 字；每天顺手清一次超过保留期的记录。via 见 VIAS。"""
    text = json.dumps(args if isinstance(args, dict) else {}, ensure_ascii=False, default=str)
    if len(text) > ARGS_CHARS:
        text = text[:ARGS_CHARS] + "…"
    with lock:
        db.execute("INSERT INTO mcp_calls (at, token_id, client, kind, name, args, result_chars, duration_ms, ok,"
                   " error, execution_id, session, via) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                   (_iso(_now()), client.id, client.name, kind, str(name)[:120], text, int(result_chars or 0),
                    max(0, int(duration_ms or 0)), 1 if ok else 0, str(error or "")[:300], execution_id,
                    str(session or "")[:64], via if via in VIAS else ""))
        if time.monotonic() - _pruned["at"] > 86400:
            _pruned["at"] = time.monotonic()
            cutoff = _iso(_now() - timedelta(days=MCP_AUDIT_DAYS))
            db.execute("DELETE FROM mcp_calls WHERE at < ?", (cutoff,))
        db.commit()


def recent_calls(limit=50, token_id=None):
    query, params = "SELECT * FROM mcp_calls", []
    if token_id:
        query += " WHERE token_id = ?"
        params.append(token_id)
    with lock:
        rows = db.execute(query + " ORDER BY id DESC LIMIT ?", params + [int(limit)]).fetchall()
    return [{**dict(row), "ok": bool(row["ok"]), "args": json.loads(row["args"]) if row["args"].endswith("}")
             else row["args"]} for row in rows]


def count_calls() -> int:
    with lock:
        return db.execute("SELECT COUNT(*) FROM mcp_calls").fetchone()[0]


PURGE_SCOPES = ("all", "before", "token")
_TOKEN_ID = re.compile(r"^[0-9a-f]{1,32}$")


@dataclass(frozen=True)
class Purge:
    """一次清除的范围：where 子句、参数、给人看的说明（进留痕和工具服务日志的 target）。"""
    scope: str
    where: str
    params: tuple
    text: str


def purge_plan(data) -> Purge:
    """页面请求 → 清除范围。不合法抛 AccessError：在核对口令之前，不消耗口令次数。"""
    data = data if isinstance(data, dict) else {}
    scope = data.get("scope")
    if scope not in PURGE_SCOPES:
        raise AccessError("范围只能是：全部（all）、N 天以前（before）、某枚令牌的（token）")
    if scope == "all":
        return Purge("all", "", (), "全部调用记录")
    if scope == "before":
        days = data.get("days")
        if isinstance(days, bool) or not isinstance(days, int) or not 1 <= days <= EXPIRES_DAYS_MAX:
            raise AccessError(f"天数要是 1–{EXPIRES_DAYS_MAX} 的整数")
        return Purge("before", " WHERE at < ?", (_iso(_now() - timedelta(days=days)),), f"{days} 天以前的调用记录")
    token_id = data.get("token_id")
    if not isinstance(token_id, str) or not _TOKEN_ID.match(token_id):
        raise AccessError("要选一枚令牌")
    with lock:
        row = db.execute("SELECT name FROM mcp_tokens WHERE id = ?", (token_id,)).fetchone() or \
            db.execute("SELECT client AS name FROM mcp_calls WHERE token_id = ? ORDER BY id DESC LIMIT 1",
                       (token_id,)).fetchone()
    name = f"「{clean(row['name'], 40)}」" if row else ""
    return Purge("token", " WHERE token_id = ?", (token_id,), f"令牌{name}（{token_id}）的调用记录")


def purge(plan: Purge, user="", ip="") -> int:
    """按范围删调用记录，同一个事务里记一条留痕（谁、什么时候、从哪里、清了多少条）。口令由调用方先核对。"""
    with lock:
        count = db.execute("DELETE FROM mcp_calls" + plan.where, plan.params).rowcount
        _change(db, "calls-purge", f"清除了{plan.text}", count, user, ip)
        db.commit()
    return count


# --- 限流 ---------------------------------------------------------------------------

class Limiter:
    """按令牌的滑动窗口（60 秒）：工具 / 提示词调用一个，HTTP 请求一个。"""

    def __init__(self, window=60.0):
        self.window = window
        self._hits = {}
        self._lock = threading.Lock()

    def _allow(self, key, limit, now=None):
        now = time.monotonic() if now is None else now
        with self._lock:
            hits = self._hits.setdefault(key, deque())
            while hits and now - hits[0] >= self.window:
                hits.popleft()
            if len(hits) >= limit:
                return False
            hits.append(now)
            return True

    def allow_call(self, client, now=None) -> bool:
        return self._allow(("call", client.id), client.rate_per_minute, now)

    def allow_request(self, client, now=None) -> bool:
        return self._allow(("http", client.id), client.rate_per_minute * REQUESTS_PER_CALL, now)

    def forget(self, token_id):
        with self._lock:
            for key in [k for k in self._hits if k[1] == token_id]:
                del self._hits[key]


_limiter = Limiter()


def allow_call(client) -> bool:
    return _limiter.allow_call(client)


def allow_request(client) -> bool:
    return _limiter.allow_request(client)


def _cli(argv) -> int:
    """宿主机上的逃生口：python -m app.access open | status。open 不要口令——能进容器就等于有宿主机 root。
    关只在页面上关（关的同时要断开正在连着的会话，只有运行中的应用做得到）。"""
    command = argv[0] if argv else "status"
    if command == "status":
        state = switch_state()
        print(f"对外接入（页面开关）：{'开' if state['on'] else '关'}"
              + (f"，{state['at']} 由 {state['user'] or '-'}（{state['ip'] or '-'}）改的" if state["at"] else "，没改过"))
        return 0
    if command == "open":
        changed = set_switch(True, user="cli", ip="host")
        print(("已打开" if changed else "本来就开着") + "：运行中的应用每个 /mcp 请求都现查，不用重启")
        return 0
    print("用法：python -m app.access open | status", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(_cli(sys.argv[1:]))
