"""Multi-turn memory.

Conversations live in SQLite next to the vector store: a few hundred rows do not
justify another service, and keeping them on disk means history survives a
restart and follows the user across devices.
"""
import json
import sqlite3
import threading
import uuid
from datetime import datetime, timezone

from app.config import CHAT_DB_PATH, HISTORY_MESSAGES

db = sqlite3.connect(CHAT_DB_PATH, check_same_thread=False)
db.row_factory = sqlite3.Row
db.execute("PRAGMA journal_mode=WAL")
db.executescript("""
CREATE TABLE IF NOT EXISTS conversations (
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  conversation_id TEXT NOT NULL,
  role TEXT NOT NULL,
  content TEXT NOT NULL,
  sources TEXT,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS messages_by_conversation ON messages(conversation_id, id);
""")
# 老库没有这些列；加列失败说明已经有了。mode 是这一轮的回答模式（kb / smart），老消息是空的（当时只有知识库模式）。
# 老代码按列名读写，不认识的列留空，回滚到旧镜像不受影响。
for column in ("model TEXT", "tools TEXT", "mode TEXT"):
    try:
        db.execute(f"ALTER TABLE messages ADD COLUMN {column}")
    except sqlite3.OperationalError:
        pass
db.commit()
lock = threading.Lock()


def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def exists(conversation_id: str) -> bool:
    with lock:
        row = db.execute("SELECT 1 FROM conversations WHERE id = ?",
                         (conversation_id,)).fetchone()
    return row is not None


def create(title: str) -> dict:
    conversation = {"id": uuid.uuid4().hex, "title": title[:40] or "新对话",
                    "updated_at": now_iso()}
    with lock:
        db.execute(
            "INSERT INTO conversations (id, title, created_at, updated_at) VALUES (?, ?, ?, ?)",
            (conversation["id"], conversation["title"],
             conversation["updated_at"], conversation["updated_at"]))
        db.commit()
    return conversation


def add_message(conversation_id: str, role: str, content: str, sources=None, model=None, tools=None, mode=None):
    """写一条消息，返回它的 id——图谱里的执行记录靠它指回这条回答。mode 是这一轮的回答模式（kb / smart）。"""
    timestamp = now_iso()
    with lock:
        cur = db.execute(
            "INSERT INTO messages (conversation_id, role, content, sources, model, tools, mode, created_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (conversation_id, role, content,
             json.dumps(sources, ensure_ascii=False) if sources else None, model,
             json.dumps(tools, ensure_ascii=False) if tools else None, mode, timestamp))
        db.execute("UPDATE conversations SET updated_at = ? WHERE id = ?",
                   (timestamp, conversation_id))
        db.commit()
        return cur.lastrowid


def recent_history(conversation_id: str):
    """Return the last few (role, content) pairs, oldest first."""
    with lock:
        rows = db.execute(
            "SELECT role, content FROM messages WHERE conversation_id = ?"
            " ORDER BY id DESC LIMIT ?", (conversation_id, HISTORY_MESSAGES)).fetchall()
    return [(row["role"], row["content"]) for row in reversed(rows)]


def modes_used(conversation_id: str) -> list:
    """这个对话里回答用过哪些模式（加 mode 列之前的老消息按知识库模式算）。"""
    with lock:
        rows = db.execute("SELECT DISTINCT COALESCE(mode, 'kb') AS mode FROM messages"
                          " WHERE conversation_id = ? AND role = 'assistant'", (conversation_id,)).fetchall()
    return sorted(row["mode"] for row in rows)


def list_conversations(limit: int = 100):
    with lock:
        rows = db.execute(
            "SELECT c.id, c.title, c.updated_at, COUNT(m.id) AS messages"
            " FROM conversations c LEFT JOIN messages m ON m.conversation_id = c.id"
            " GROUP BY c.id ORDER BY c.updated_at DESC LIMIT ?", (limit,)).fetchall()
    return [dict(row) for row in rows]


def messages_of(conversation_id: str):
    with lock:
        rows = db.execute(
            "SELECT id, role, content, sources, model, tools, mode FROM messages WHERE conversation_id = ?"
            " ORDER BY id", (conversation_id,)).fetchall()
    return [{"id": row["id"], "role": row["role"], "content": row["content"], "model": row["model"],
             "sources": json.loads(row["sources"]) if row["sources"] else [],
             "tools": json.loads(row["tools"]) if row["tools"] else [],
             # 加这一列之前的老消息是空的：那时只有知识库模式
             "mode": row["mode"] or "kb"}
            for row in rows]


def delete(conversation_id: str):
    with lock:
        db.execute("DELETE FROM messages WHERE conversation_id = ?", (conversation_id,))
        db.execute("DELETE FROM conversations WHERE id = ?", (conversation_id,))
        db.commit()
