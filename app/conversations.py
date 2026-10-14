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


def add_message(conversation_id: str, role: str, content: str, sources=None):
    timestamp = now_iso()
    with lock:
        db.execute(
            "INSERT INTO messages (conversation_id, role, content, sources, created_at)"
            " VALUES (?, ?, ?, ?, ?)",
            (conversation_id, role, content,
             json.dumps(sources, ensure_ascii=False) if sources else None, timestamp))
        db.execute("UPDATE conversations SET updated_at = ? WHERE id = ?",
                   (timestamp, conversation_id))
        db.commit()


def recent_history(conversation_id: str):
    """Return the last few (role, content) pairs, oldest first."""
    with lock:
        rows = db.execute(
            "SELECT role, content FROM messages WHERE conversation_id = ?"
            " ORDER BY id DESC LIMIT ?", (conversation_id, HISTORY_MESSAGES)).fetchall()
    return [(row["role"], row["content"]) for row in reversed(rows)]


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
            "SELECT role, content, sources FROM messages WHERE conversation_id = ?"
            " ORDER BY id", (conversation_id,)).fetchall()
    return [{"role": row["role"], "content": row["content"],
             "sources": json.loads(row["sources"]) if row["sources"] else []}
            for row in rows]


def delete(conversation_id: str):
    with lock:
        db.execute("DELETE FROM messages WHERE conversation_id = ?", (conversation_id,))
        db.execute("DELETE FROM conversations WHERE id = ?", (conversation_id,))
        db.commit()
