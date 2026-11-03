"""云上协同在 chat.db 里的几张表（和对话共用一个连接、一把锁）。功能打开后才建：开关空着时库结构和以前一样。

    chat_threads    一条对话一行：平台、会话类型和 ID、发送人 → 对应的对话，最后一条消息、最后一次执行，给出的 SOP 候选，
                    没发完的部分。每个人在每个群一条，私聊每人一条；30 分钟没说话或回「新话题」就另起一行
    chat_turns      这条对话里的每一次执行（以后按群聊来源清理时，只删这里记着的，绝不碰网页上的对话）
    chat_inbox      收件表：消息键 → 消息和处理状态（已收到 / 处理中 / 完成 / 中断 / 过期），处理完清掉正文
    chat_unknown    没开通的群和人 @ 过它：只记 ID、名字、次数和时间，不记内容
    chat_notify     计划、告警规则推到哪个目标（旁表：不动计划和规则自己的表，旧版本编辑、删除都碰不到它）；
                    platform 记保存时是哪个平台的转接程序，换了平台就不推（不会推到另一个平台里同名的目标）
    chat_push_log   每次推送的结果
    chat_state      长轮询的 epoch、编号这类小状态

不往现有的表加列：回滚到没有这个功能的旧镜像时，旧代码照常运行，这几张表留着无害。
"""
import json
from datetime import datetime, timedelta, timezone

from app import conversations

INBOX_TTL_MINUTES = 10          # 重启后多久以内的消息还接着处理
INBOX_KEEP_DAYS = 7             # 处理完的收件记录（正文已清掉）留几天：只为去重，转接程序那边超过 10 分钟的消息就丢了
UNKNOWN_KEEP_DAYS = 30
PUSH_LOG_KEEP = 2000


def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _db():
    return conversations.db


def ensure():
    """建表（幂等）。功能打开时 chat_api.install 调一次。"""
    with conversations.lock:
        _db().executescript("""
CREATE TABLE IF NOT EXISTS chat_threads (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  platform TEXT NOT NULL,
  chat_type TEXT NOT NULL,
  chat_id TEXT NOT NULL,
  chat_name TEXT NOT NULL DEFAULT '',
  sender_id TEXT NOT NULL,
  sender_name TEXT NOT NULL DEFAULT '',
  scope_name TEXT NOT NULL DEFAULT '',
  conversation_id TEXT,
  last_message_id INTEGER,
  last_execution_id TEXT,
  last_run_id TEXT,
  candidates TEXT NOT NULL DEFAULT '[]',
  remainder TEXT NOT NULL DEFAULT '',
  closed INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS chat_threads_by_who ON chat_threads(platform, chat_type, chat_id, sender_id, closed);
CREATE INDEX IF NOT EXISTS chat_threads_by_conversation ON chat_threads(conversation_id);
CREATE TABLE IF NOT EXISTS chat_turns (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  thread_id INTEGER NOT NULL,
  conversation_id TEXT,
  execution_id TEXT,
  run_id TEXT,
  kind TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS chat_turns_by_thread ON chat_turns(thread_id);
CREATE TABLE IF NOT EXISTS chat_inbox (
  msg_key TEXT PRIMARY KEY,
  platform TEXT NOT NULL,
  event TEXT NOT NULL,
  status TEXT NOT NULL,
  received_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS chat_inbox_by_status ON chat_inbox(status, received_at);
CREATE TABLE IF NOT EXISTS chat_unknown (
  platform TEXT NOT NULL,
  chat_type TEXT NOT NULL,
  ident TEXT NOT NULL,
  chat_name TEXT NOT NULL DEFAULT '',
  sender_id TEXT NOT NULL DEFAULT '',
  sender_name TEXT NOT NULL DEFAULT '',
  count INTEGER NOT NULL DEFAULT 0,
  first_at TEXT NOT NULL,
  last_at TEXT NOT NULL,
  replied_at TEXT,
  PRIMARY KEY (platform, chat_type, ident)
);
CREATE TABLE IF NOT EXISTS chat_notify (
  source_kind TEXT NOT NULL,
  source_id TEXT NOT NULL,
  target TEXT NOT NULL,
  send_when TEXT NOT NULL,
  send_repeat TEXT NOT NULL,
  state TEXT NOT NULL DEFAULT '{}',
  updated_at TEXT NOT NULL,
  platform TEXT NOT NULL DEFAULT 'ccwork',
  PRIMARY KEY (source_kind, source_id)
);
CREATE TABLE IF NOT EXISTS chat_push_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  kind TEXT NOT NULL,
  run_id TEXT,
  target TEXT NOT NULL,
  status TEXT NOT NULL,
  detail TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  platform TEXT NOT NULL DEFAULT 'ccwork'
);
CREATE INDEX IF NOT EXISTS chat_push_log_by_run ON chat_push_log(run_id);
CREATE TABLE IF NOT EXISTS chat_state (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
""")
        # 早先建的库（11-03 之前）这两张表没有 platform：补上，原有的行都是云上协同的
        for table in ("chat_notify", "chat_push_log"):
            columns = {row[1] for row in _db().execute(f"PRAGMA table_info({table})")}
            if "platform" not in columns:
                _db().execute(f"ALTER TABLE {table} ADD COLUMN platform TEXT NOT NULL DEFAULT 'ccwork'")
        _db().commit()


# --- 小状态 ---------------------------------------------------------------------------------

def state_get(key, default="") -> str:
    with conversations.lock:
        row = _db().execute("SELECT value FROM chat_state WHERE key = ?", (key,)).fetchone()
    return row[0] if row else default


def state_set(key, value):
    with conversations.lock:
        _db().execute("INSERT INTO chat_state (key, value) VALUES (?, ?)"
                      " ON CONFLICT(key) DO UPDATE SET value = excluded.value", (key, str(value)))
        _db().commit()


# --- 收件表 ---------------------------------------------------------------------------------

def inbox_add(event) -> bool:
    """落库：新消息返回 True；同一个消息键见过了（QoS 1 重发、转接程序重启后重取）返回 False。"""
    stamp = now_iso()
    with conversations.lock:
        cur = _db().execute("INSERT OR IGNORE INTO chat_inbox (msg_key, platform, event, status, received_at,"
                            " updated_at) VALUES (?, ?, ?, 'received', ?, ?)",
                            (event["msg_key"], event.get("platform", ""), json.dumps(event, ensure_ascii=False),
                             stamp, stamp))
        _db().commit()
    return cur.rowcount == 1


def inbox_get(msg_key) -> dict | None:
    with conversations.lock:
        row = _db().execute("SELECT * FROM chat_inbox WHERE msg_key = ?", (msg_key,)).fetchone()
    if row is None:
        return None
    return {"msg_key": row["msg_key"], "status": row["status"], "received_at": row["received_at"],
            "event": json.loads(row["event"])}


def inbox_set(msg_key, status):
    """改处理状态。完成、中断、过期的清掉正文：问题原文只在处理期间留着（对话里另有一份）。"""
    with conversations.lock:
        if status in ("done", "interrupted", "expired"):
            row = _db().execute("SELECT event FROM chat_inbox WHERE msg_key = ?", (msg_key,)).fetchone()
            event = json.loads(row["event"]) if row else {}
            event["text"] = ""
            _db().execute("UPDATE chat_inbox SET status = ?, event = ?, updated_at = ? WHERE msg_key = ?",
                          (status, json.dumps(event, ensure_ascii=False), now_iso(), msg_key))
        else:
            _db().execute("UPDATE chat_inbox SET status = ?, updated_at = ? WHERE msg_key = ?",
                          (status, now_iso(), msg_key))
        _db().commit()


def inbox_recover(now=None) -> tuple:
    """启动时：(还要接着处理的「已收到」, 答到一半被打断的「处理中」)，都是消息本身，只算 INBOX_TTL_MINUTES 以内的。

    处理中的一律改成中断（回答和 SOP 执行至多一次，不会因为重启把同一个 SOP 跑两遍）；更早的改成过期，不再回话。"""
    now = now or datetime.now(timezone.utc)
    fresh = (now - timedelta(minutes=INBOX_TTL_MINUTES)).isoformat(timespec="seconds")
    with conversations.lock:
        rows = _db().execute("SELECT msg_key, status, received_at, event FROM chat_inbox"
                             " WHERE status IN ('received', 'processing') ORDER BY received_at").fetchall()
    resume, interrupted = [], []
    for row in rows:
        recent = row["received_at"] >= fresh
        if row["status"] == "processing":
            inbox_set(row["msg_key"], "interrupted")
            if recent:
                interrupted.append(json.loads(row["event"]))
        elif recent:
            resume.append(json.loads(row["event"]))
        else:
            inbox_set(row["msg_key"], "expired")
    return resume, interrupted


def inbox_prune(days=INBOX_KEEP_DAYS, now=None) -> int:
    """处理完的收件记录（正文早已清掉）只留几天，够去重用。聊天线程启动时和之后每天一次。"""
    cutoff = ((now or datetime.now(timezone.utc)) - timedelta(days=days)).isoformat(timespec="seconds")
    with conversations.lock:
        cur = _db().execute("DELETE FROM chat_inbox WHERE status IN ('done', 'interrupted', 'expired')"
                            " AND received_at < ?", (cutoff,))
        _db().commit()
    return cur.rowcount


# --- 对话对应 -------------------------------------------------------------------------------

def _thread(row) -> dict:
    out = dict(row)
    try:
        out["candidates"] = json.loads(out.get("candidates") or "[]")
    except ValueError:
        out["candidates"] = []
    return out


def thread_current(platform, chat_type, chat_id, sender_id) -> dict | None:
    with conversations.lock:
        row = _db().execute("SELECT * FROM chat_threads WHERE platform = ? AND chat_type = ? AND chat_id = ?"
                            " AND sender_id = ? AND closed = 0 ORDER BY id DESC LIMIT 1",
                            (platform, chat_type, chat_id, sender_id)).fetchone()
    return _thread(row) if row else None


def thread_open(event, scope_name, conversation_id) -> int:
    """这个人在这个会话里开一条新对话（之前开着的那条关掉）。"""
    stamp = now_iso()
    who = (event.get("platform", ""), event["chat_type"], event["chat_id"], event["sender_id"])
    with conversations.lock:
        _db().execute("UPDATE chat_threads SET closed = 1, updated_at = ? WHERE platform = ? AND chat_type = ?"
                      " AND chat_id = ? AND sender_id = ? AND closed = 0", (stamp, *who))
        cur = _db().execute(
            "INSERT INTO chat_threads (platform, chat_type, chat_id, chat_name, sender_id, sender_name, scope_name,"
            " conversation_id, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (who[0], who[1], who[2], event.get("chat_name", "")[:100], who[3], event.get("sender_name", "")[:50],
             scope_name, conversation_id, stamp, stamp))
        _db().commit()
    return cur.lastrowid


def thread_update(thread_id, **fields):
    allowed = ("last_message_id", "last_execution_id", "last_run_id", "candidates", "remainder", "closed",
               "chat_name", "sender_name")
    sets, args = [], []
    for key, value in fields.items():
        if key not in allowed:
            raise ValueError(key)
        sets.append(f"{key} = ?")
        args.append(json.dumps(value, ensure_ascii=False) if key == "candidates" else value)
    sets.append("updated_at = ?")
    args.append(now_iso())
    with conversations.lock:
        _db().execute(f"UPDATE chat_threads SET {', '.join(sets)} WHERE id = ?", (*args, thread_id))
        _db().commit()


def thread_close(thread_id):
    thread_update(thread_id, closed=1)


def close_conversation(conversation_id) -> int:
    """网页上删了群聊的对话：关掉对应的那一行，那个人下一次问另开一条。行本身留着（以后清理按它找来源）。"""
    with conversations.lock:
        cur = _db().execute("UPDATE chat_threads SET closed = 1, updated_at = ? WHERE conversation_id = ?",
                            (now_iso(), conversation_id))
        _db().commit()
    return cur.rowcount


def turn_add(thread_id, conversation_id, execution_id, run_id, kind):
    with conversations.lock:
        _db().execute("INSERT INTO chat_turns (thread_id, conversation_id, execution_id, run_id, kind, created_at)"
                      " VALUES (?, ?, ?, ?, ?, ?)", (thread_id, conversation_id, execution_id, run_id, kind, now_iso()))
        _db().commit()


def last_message_id(conversation_id):
    """这条对话现在的最后一条消息：和 chat_threads 里记下的对不上，说明有人在别处续过（或上一轮没答完）。"""
    with conversations.lock:
        row = _db().execute("SELECT MAX(id) FROM messages WHERE conversation_id = ?", (conversation_id,)).fetchone()
    return row[0] if row else None


def conversations_of_chat(chat_id) -> set:
    """一个群（含组织、部门会话）里所有人的对话：每周摘要按群汇总时只看这些。"""
    with conversations.lock:
        rows = _db().execute("SELECT DISTINCT conversation_id FROM chat_threads WHERE chat_id = ? AND chat_type != 'single'"
                             " AND conversation_id IS NOT NULL", (str(chat_id),)).fetchall()
    return {row[0] for row in rows}


def owns(conversation_id) -> bool:
    with conversations.lock:
        row = _db().execute("SELECT 1 FROM chat_threads WHERE conversation_id = ? LIMIT 1",
                            (conversation_id,)).fetchone()
    return row is not None


def source_of(conversation_id) -> dict | None:
    with conversations.lock:
        row = _db().execute("SELECT platform, chat_type, chat_name, scope_name, sender_name FROM chat_threads"
                            " WHERE conversation_id = ? ORDER BY id DESC LIMIT 1", (conversation_id,)).fetchone()
    return _source(row) if row else None


def _source(row) -> dict:
    return {"platform": row["platform"], "chat_type": row["chat_type"],
            "chat_name": row["scope_name"] or row["chat_name"], "sender_name": row["sender_name"]}


def list_conversations(source="", limit=100) -> list:
    """对话列表（和 conversations.list_conversations 同样的字段），群聊的多一个 source；source=web / chat 时只列那一种。"""
    clause = ""
    if source == "web":
        clause = ("WHERE c.id NOT IN (SELECT conversation_id FROM chat_threads WHERE conversation_id IS NOT NULL)")
    elif source == "chat":
        clause = "WHERE c.id IN (SELECT conversation_id FROM chat_threads WHERE conversation_id IS NOT NULL)"
    with conversations.lock:
        rows = _db().execute(
            "SELECT c.id, c.title, c.updated_at, COUNT(m.id) AS messages"
            f" FROM conversations c LEFT JOIN messages m ON m.conversation_id = c.id {clause}"
            " GROUP BY c.id ORDER BY c.updated_at DESC LIMIT ?", (limit,)).fetchall()
        items = [dict(row) for row in rows]
        ids = [item["id"] for item in items]
        sources = {}
        if ids:
            for row in _db().execute(
                    "SELECT t.conversation_id, t.platform, t.chat_type, t.chat_name, t.scope_name, t.sender_name"
                    f" FROM chat_threads t WHERE t.conversation_id IN ({','.join('?' * len(ids))})"
                    " ORDER BY t.id", ids).fetchall():
                sources[row["conversation_id"]] = _source(row)
    for item in items:
        if item["id"] in sources:
            item["source"] = sources[item["id"]]
    return items


# --- 没开通的 --------------------------------------------------------------------------------

def unknown_record(event, now=None) -> bool:
    """记一笔（不记内容）。返回这次要不要回「还没有开通」：每个会话 24 小时最多一次。"""
    now = now or datetime.now(timezone.utc)
    stamp = now.isoformat(timespec="seconds")
    ident = event["sender_id"] if event["chat_type"] == "single" else event["chat_id"]
    key = (event.get("platform", ""), event["chat_type"], ident)
    with conversations.lock:
        row = _db().execute("SELECT replied_at FROM chat_unknown WHERE platform = ? AND chat_type = ? AND ident = ?",
                            key).fetchone()
        if row is None:
            _db().execute("INSERT INTO chat_unknown (platform, chat_type, ident, chat_name, sender_id, sender_name,"
                          " count, first_at, last_at) VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)",
                          (*key, event.get("chat_name", "")[:100], event["sender_id"],
                           event.get("sender_name", "")[:50], stamp, stamp))
        else:
            _db().execute("UPDATE chat_unknown SET count = count + 1, last_at = ?, chat_name = ?, sender_id = ?,"
                          " sender_name = ? WHERE platform = ? AND chat_type = ? AND ident = ?",
                          (stamp, event.get("chat_name", "")[:100], event["sender_id"],
                           event.get("sender_name", "")[:50], *key))
        replied = row["replied_at"] if row is not None else None
        due = replied is None or replied < (now - timedelta(hours=24)).isoformat(timespec="seconds")
        if due:
            _db().execute("UPDATE chat_unknown SET replied_at = ? WHERE platform = ? AND chat_type = ? AND ident = ?",
                          (stamp, *key))
        _db().commit()
    return due


def unknown_prune(now=None) -> int:
    """30 天没动静的「没开通」记录删掉（聊天线程每天一次；页面列出来之前也清一遍）。"""
    cutoff = ((now or datetime.now(timezone.utc)) - timedelta(days=UNKNOWN_KEEP_DAYS)).isoformat(timespec="seconds")
    with conversations.lock:
        cur = _db().execute("DELETE FROM chat_unknown WHERE last_at < ?", (cutoff,))
        _db().commit()
    return cur.rowcount


def unknown_list(limit=50, now=None) -> list:
    unknown_prune(now)
    with conversations.lock:
        rows = _db().execute("SELECT * FROM chat_unknown ORDER BY last_at DESC LIMIT ?", (limit,)).fetchall()
    return [{k: row[k] for k in ("platform", "chat_type", "ident", "chat_name", "sender_id", "sender_name", "count",
                                 "first_at", "last_at")} for row in rows]


# --- 推送设置和结果 ----------------------------------------------------------------------------

def notify_get(kind, source_id) -> dict | None:
    with conversations.lock:
        row = _db().execute("SELECT * FROM chat_notify WHERE source_kind = ? AND source_id = ?",
                            (kind, source_id)).fetchone()
    if row is None:
        return None
    try:
        state = json.loads(row["state"] or "{}")
    except ValueError:
        state = {}
    return {"kind": row["source_kind"], "id": row["source_id"], "target": row["target"], "when": row["send_when"],
            "repeat": row["send_repeat"], "state": state if isinstance(state, dict) else {},
            "updated_at": row["updated_at"], "platform": row["platform"]}


def notify_all() -> list:
    with conversations.lock:
        rows = _db().execute("SELECT source_kind, source_id FROM chat_notify ORDER BY updated_at DESC").fetchall()
    return [notify_get(row["source_kind"], row["source_id"]) for row in rows]


def notify_set(kind, source_id, target, when, repeat, platform="ccwork"):
    """改设置。目标（或平台）换了，之前「已经提醒过」的状态不再作数（新目标还没收到过）。
    platform 是保存时转接程序的平台：换了平台以后，这条设置不会推到另一个平台里同名的目标。"""
    current = notify_get(kind, source_id)
    state = current["state"] if current and current["target"] == target and current["platform"] == platform else {}
    with conversations.lock:
        _db().execute("INSERT INTO chat_notify (source_kind, source_id, target, send_when, send_repeat, state,"
                      " updated_at, platform) VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(source_kind, source_id)"
                      " DO UPDATE SET target = excluded.target, send_when = excluded.send_when,"
                      " send_repeat = excluded.send_repeat, state = excluded.state, updated_at = excluded.updated_at,"
                      " platform = excluded.platform",
                      (kind, source_id, target, when, repeat, json.dumps(state, ensure_ascii=False), now_iso(),
                       platform))
        _db().commit()


def notify_delete(kind, source_id):
    with conversations.lock:
        _db().execute("DELETE FROM chat_notify WHERE source_kind = ? AND source_id = ?", (kind, source_id))
        _db().commit()


def notify_state(kind, source_id, state):
    with conversations.lock:
        _db().execute("UPDATE chat_notify SET state = ? WHERE source_kind = ? AND source_id = ?",
                      (json.dumps(state, ensure_ascii=False), kind, source_id))
        _db().commit()


def push_log(kind, target, status, detail="", run_id=None, platform="ccwork"):
    with conversations.lock:
        _db().execute("INSERT INTO chat_push_log (kind, run_id, target, status, detail, created_at, platform)"
                      " VALUES (?, ?, ?, ?, ?, ?, ?)",
                      (kind, run_id, target, status, str(detail)[:300], now_iso(), platform))
        _db().execute("DELETE FROM chat_push_log WHERE id <= (SELECT MAX(id) FROM chat_push_log) - ?",
                      (PUSH_LOG_KEEP,))
        _db().commit()


def push_recent(limit=20, run_ids=None) -> list:
    with conversations.lock:
        if run_ids is not None:
            ids = list(run_ids)
            if not ids:
                return []
            rows = _db().execute(f"SELECT * FROM chat_push_log WHERE run_id IN ({','.join('?' * len(ids))})"
                                 " ORDER BY id DESC", ids).fetchall()
        else:
            rows = _db().execute("SELECT * FROM chat_push_log ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return [dict(row) for row in rows]
