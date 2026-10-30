"""对外接入：外部智能体（MCP 客户端）的令牌、调用审计和限流。

过渡期（统一登录之前）每个客户端一枚令牌，在管理页「对外接入」签发：

    - 库里只存哈希（sha256），明文只在签发时显示一次。可以吊销、可以设过期时间。
    - 范围三种：knowledge（知识库，可以只开放某几个文档分类）、sop（SOP 工具和提示词）、data（宿主机标了 export 的数据工具）。
      签出的范围不能超过页面本来就能看到的：分类必须是知识库里现有的。
    - 每个 HTTP 请求都现查库：吊销、过期立刻生效。

审计：每次工具 / 提示词调用记一行：客户端、名字、参数、返回大小、耗时、成败、对应的图谱执行；保留 MCP_AUDIT_DAYS 天。
限流：按令牌限制每分钟的调用次数（工具和提示词，默认 MCP_RATE_PER_MINUTE）和单次返回大小（默认 MCP_MAX_RESULT_CHARS）；
HTTP 请求另有一个宽松的总上限（调用次数的 10 倍），挡住失控的客户端。限流计数在进程内存里（应用只跑一个 worker）。
"""
import hashlib
import json
import secrets
import sqlite3
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
""")
db.commit()
lock = threading.Lock()


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
    if categories is not None:
        categories = sorted({" ".join(str(c).split()) for c in categories if str(c).strip()})
        if not categories:
            raise AccessError("限定分类时至少选一个分类；不想限定就选「全部分类」")
        if known_categories is not None:
            missing = [c for c in categories if c not in set(known_categories)]
            if missing:
                raise AccessError(f"知识库里没有这些分类：{'、'.join(missing)}")
    days = _bounded(expires_days, 1, EXPIRES_DAYS_MAX, "有效天数")
    rate = _bounded(rate_per_minute, *RATE_RANGE, "每分钟调用次数")
    chars = _bounded(max_result_chars, *RESULT_RANGE, "单次返回字数")
    token_id = secrets.token_hex(6)
    plain = f"{PREFIX}{token_id}_{secrets.token_urlsafe(32)}"
    now = _now()
    with lock:
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


# --- 审计 ---------------------------------------------------------------------------

_pruned = {"at": 0.0}


def record_call(client, kind, name, args, result_chars, duration_ms, ok, error="", execution_id=None, session=""):
    """记一次对外调用。参数截到 ARGS_CHARS 字；每天顺手清一次超过保留期的记录。"""
    text = json.dumps(args if isinstance(args, dict) else {}, ensure_ascii=False, default=str)
    if len(text) > ARGS_CHARS:
        text = text[:ARGS_CHARS] + "…"
    with lock:
        db.execute("INSERT INTO mcp_calls (at, token_id, client, kind, name, args, result_chars, duration_ms, ok,"
                   " error, execution_id, session) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                   (_iso(_now()), client.id, client.name, kind, str(name)[:120], text, int(result_chars or 0),
                    max(0, int(duration_ms or 0)), 1 if ok else 0, str(error or "")[:300], execution_id,
                    str(session or "")[:64]))
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
