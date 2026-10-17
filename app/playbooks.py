"""SOP：把文档里"按步骤查看、核对"的经验，变成对已有工具的有序调用。

不限于故障排查——日常巡检、上线前检查、上线后验收都是 SOP。

三层分工：

    知识库（文档）   人写的经验：应该怎么做、正常值是什么
    SOP（标准作业流程）从文档里抽出的做法：按什么顺序调哪些工具、每步看什么
    工具（tool）     宿主机上审过的执行原语，是唯一能动系统的东西

SOP 本身不带任何执行能力。一个步骤如果引用了不存在的工具，写入时就会被拒绝，
所以"自动生成 SOP"不会凭空多出新的执行权限——这是它和"自动生成工具"的本质区别。

（代码里沿用 playbook 作为标识符，对外统一叫「SOP」。）
"""
import json
import sqlite3
import threading
import uuid
from datetime import datetime, timezone

from app.config import DATA_DIR

NAME_MAX = 60
TRIGGER_MAX = 200
STEP_MAX = 20

db = sqlite3.connect(DATA_DIR / "playbooks.db", check_same_thread=False)
db.row_factory = sqlite3.Row
db.execute("PRAGMA journal_mode=WAL")
db.execute("PRAGMA foreign_keys=ON")
db.executescript("""
CREATE TABLE IF NOT EXISTS playbooks (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  trigger TEXT NOT NULL DEFAULT '',
  source TEXT NOT NULL DEFAULT '',
  enabled INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS steps (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  playbook_id TEXT NOT NULL REFERENCES playbooks(id) ON DELETE CASCADE,
  position INTEGER NOT NULL,
  tool TEXT NOT NULL,
  args TEXT NOT NULL DEFAULT '{}',
  checkpoint TEXT NOT NULL DEFAULT '',
  UNIQUE (playbook_id, position)
);
CREATE INDEX IF NOT EXISTS steps_by_playbook ON steps(playbook_id, position);
""")
db.commit()
lock = threading.Lock()


class InvalidPlaybook(ValueError):
    """SOP 内容不合法，附带可直接展示给用户的原因。"""


def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def validate(name, trigger, steps, known_tools):
    """校验并归一化。known_tools 为当前真实可用的工具名集合。"""
    name = (name or "").strip()[:NAME_MAX]
    if not name:
        raise InvalidPlaybook("SOP 名称不能为空")
    trigger = (trigger or "").strip()[:TRIGGER_MAX]

    if not isinstance(steps, list) or not steps:
        raise InvalidPlaybook("至少需要一个步骤")
    if len(steps) > STEP_MAX:
        raise InvalidPlaybook(f"步骤最多 {STEP_MAX} 个")

    cleaned = []
    for index, step in enumerate(steps, 1):
        if not isinstance(step, dict):
            raise InvalidPlaybook(f"第 {index} 步格式不正确")
        tool = str(step.get("tool") or "").strip()
        # 这一行是 SOP 不会扩权的根本原因：只能引用已存在的工具。
        if tool not in known_tools:
            raise InvalidPlaybook(
                f"第 {index} 步引用了不存在的工具「{tool}」；"
                f"当前可用：{'、'.join(sorted(known_tools)) or '无'}")
        args = step.get("args") or {}
        if not isinstance(args, dict):
            raise InvalidPlaybook(f"第 {index} 步的参数必须是对象")
        cleaned.append({"tool": tool, "args": args,
                        "checkpoint": str(step.get("checkpoint") or "").strip()[:300]})
    return name, trigger, cleaned


def save(playbook_id, name, trigger, steps, known_tools, source="", enabled=True):
    """新建或整体覆盖一个 SOP。"""
    name, trigger, cleaned = validate(name, trigger, steps, known_tools)
    timestamp = now_iso()
    with lock:
        if playbook_id and db.execute("SELECT 1 FROM playbooks WHERE id = ?",
                                      (playbook_id,)).fetchone():
            db.execute("UPDATE playbooks SET name=?, trigger=?, enabled=?, updated_at=?"
                       " WHERE id=?",
                       (name, trigger, 1 if enabled else 0, timestamp, playbook_id))
            db.execute("DELETE FROM steps WHERE playbook_id = ?", (playbook_id,))
        else:
            playbook_id = playbook_id or uuid.uuid4().hex
            db.execute("INSERT INTO playbooks (id, name, trigger, source, enabled,"
                       " created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                       (playbook_id, name, trigger, source, 1 if enabled else 0,
                        timestamp, timestamp))
        for position, step in enumerate(cleaned, 1):
            db.execute("INSERT INTO steps (playbook_id, position, tool, args, checkpoint)"
                       " VALUES (?, ?, ?, ?, ?)",
                       (playbook_id, position, step["tool"],
                        json.dumps(step["args"], ensure_ascii=False), step["checkpoint"]))
        db.commit()
    return playbook_id


def _rows_to_playbook(row, steps):
    return {"id": row["id"], "name": row["name"], "trigger": row["trigger"],
            "source": row["source"], "enabled": bool(row["enabled"]),
            "updated_at": row["updated_at"],
            "steps": [{"tool": s["tool"], "args": json.loads(s["args"]),
                       "checkpoint": s["checkpoint"]} for s in steps]}


def get(playbook_id):
    with lock:
        row = db.execute("SELECT * FROM playbooks WHERE id = ?", (playbook_id,)).fetchone()
        if not row:
            return None
        steps = db.execute("SELECT * FROM steps WHERE playbook_id = ? ORDER BY position",
                           (playbook_id,)).fetchall()
    return _rows_to_playbook(row, steps)


def list_all(only_enabled=False):
    with lock:
        query = "SELECT * FROM playbooks"
        if only_enabled:
            query += " WHERE enabled = 1"
        rows = db.execute(query + " ORDER BY updated_at DESC").fetchall()
        steps = db.execute("SELECT * FROM steps ORDER BY playbook_id, position").fetchall()
    grouped = {}
    for step in steps:
        grouped.setdefault(step["playbook_id"], []).append(step)
    return [_rows_to_playbook(row, grouped.get(row["id"], [])) for row in rows]


def delete(playbook_id):
    with lock:
        db.execute("DELETE FROM steps WHERE playbook_id = ?", (playbook_id,))
        db.execute("DELETE FROM playbooks WHERE id = ?", (playbook_id,))
        db.commit()


def set_enabled(playbook_id, enabled):
    with lock:
        db.execute("UPDATE playbooks SET enabled = ?, updated_at = ? WHERE id = ?",
                   (1 if enabled else 0, now_iso(), playbook_id))
        db.commit()


def delete_by_source(source):
    """文档被删除时，连带清掉由它抽取出来的 SOP。"""
    with lock:
        ids = [r["id"] for r in db.execute(
            "SELECT id FROM playbooks WHERE source = ?", (source,)).fetchall()]
        for playbook_id in ids:
            db.execute("DELETE FROM steps WHERE playbook_id = ?", (playbook_id,))
        db.execute("DELETE FROM playbooks WHERE source = ?", (source,))
        db.commit()
    return len(ids)


def as_prompt(known_tools):
    """把启用的 SOP 压成一段紧凑文本，供模型判断是否套用。

    只列出步骤引用的工具当前仍然可用的 SOP——工具没了的 SOP 照着做必然失败。
    """
    usable = []
    for playbook in list_all(only_enabled=True):
        if all(step["tool"] in known_tools for step in playbook["steps"]):
            usable.append(playbook)
    if not usable:
        return ""

    lines = []
    for playbook in usable:
        lines.append(f"SOP《{playbook['name']}》")
        if playbook["trigger"]:
            lines.append(f"  适用：{playbook['trigger']}")
        for index, step in enumerate(playbook["steps"], 1):
            args = "，".join(f"{k}={v}" for k, v in step["args"].items() if v)
            detail = f"  {index}. 调用 {step['tool']}"
            if args:
                detail += f"（{args}）"
            if step["checkpoint"]:
                detail += f" → 检查：{step['checkpoint']}"
            lines.append(detail)
    return "\n".join(lines)
