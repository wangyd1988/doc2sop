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

from app import graph
from app.config import DATA_DIR, log

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
# 老库没有 evidence 列（抽取时记录「文档里哪句话对应这一步」，方便人工核对）
try:
    db.execute("ALTER TABLE steps ADD COLUMN evidence TEXT NOT NULL DEFAULT ''")
except sqlite3.OperationalError:
    pass
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
                        "checkpoint": str(step.get("checkpoint") or "").strip()[:300],
                        "evidence": str(step.get("evidence") or "").strip()[:300]})
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
            db.execute("INSERT INTO steps (playbook_id, position, tool, args, checkpoint, evidence)"
                       " VALUES (?, ?, ?, ?, ?, ?)",
                       (playbook_id, position, step["tool"],
                        json.dumps(step["args"], ensure_ascii=False), step["checkpoint"],
                        step["evidence"]))
        db.commit()
        # 覆盖时来源沿用库里的那份（接口不改来源），播种要用实际存下的值
        stored_source = db.execute("SELECT source FROM playbooks WHERE id = ?",
                                   (playbook_id,)).fetchone()["source"]
    _seed(playbook_id, name, stored_source, cleaned)
    return playbook_id


def _seed(playbook_id, name, source, steps):
    """把这个 SOP 查什么、来自哪篇文档、用了哪些阈值播进图谱。播种失败不影响 SOP 本身。"""
    try:
        graph.seed_playbook(playbook_id, name, source, steps)
    except Exception:
        log.warning("failed to seed graph for playbook %s", playbook_id, exc_info=True)


def _unseed(playbook_ids):
    for playbook_id in playbook_ids:
        try:
            graph.retract_source(f"sop:{playbook_id}")
        except Exception:
            log.warning("failed to retract graph facts for playbook %s", playbook_id, exc_info=True)


def _rows_to_playbook(row, steps):
    return {"id": row["id"], "name": row["name"], "trigger": row["trigger"],
            "source": row["source"], "enabled": bool(row["enabled"]),
            "updated_at": row["updated_at"],
            "steps": [{"tool": s["tool"], "args": json.loads(s["args"]),
                       "checkpoint": s["checkpoint"],
                       "evidence": s["evidence"] if "evidence" in s.keys() else ""} for s in steps]}


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


def sources():
    """来源文档 -> (启用数, 总数)，供面板画折叠分组；不加载步骤。"""
    with lock:
        rows = db.execute("SELECT source, SUM(enabled) AS live, COUNT(*) AS total"
                          " FROM playbooks GROUP BY source").fetchall()
    out = [{"name": r["source"] or "手工创建", "live": int(r["live"] or 0), "total": r["total"]} for r in rows]
    return sorted(out, key=lambda g: (g["name"] == "手工创建", g["name"]))


def search(q="", source="", offset=0, limit=30):
    """一页 SOP。q 为空且 source 为空时返回空页——面板默认只画分组。"""
    q = (q or "").strip()
    if not q and not source:
        return [], 0
    with lock:
        if q:
            # 名称/触发/来源 在主表匹配；工具名/检查点/原句 在步骤表匹配。每个词都要命中。
            where, args = [], []
            for term in q.lower().split():
                like = f"%{term}%"
                where.append("(lower(p.name) LIKE ? OR lower(p.trigger) LIKE ? OR lower(p.source) LIKE ?"
                             " OR EXISTS (SELECT 1 FROM steps s WHERE s.playbook_id = p.id AND"
                             " (lower(s.tool) LIKE ? OR lower(s.checkpoint) LIKE ? OR lower(s.evidence) LIKE ?)))")
                args += [like] * 6
            clause = " AND ".join(where)
        else:
            clause, args = "(p.source = ? OR (? = '手工创建' AND p.source = ''))", [source, source]
        total = db.execute(f"SELECT COUNT(*) FROM playbooks p WHERE {clause}", args).fetchone()[0]
        rows = db.execute(f"SELECT * FROM playbooks p WHERE {clause} ORDER BY updated_at DESC LIMIT ? OFFSET ?",
                          args + [limit, offset]).fetchall()
        ids = [r["id"] for r in rows]
        steps = db.execute(f"SELECT * FROM steps WHERE playbook_id IN ({','.join('?' * len(ids)) or 'NULL'})"
                           " ORDER BY playbook_id, position", ids).fetchall() if ids else []
    grouped = {}
    for step in steps:
        grouped.setdefault(step["playbook_id"], []).append(step)
    return [_rows_to_playbook(row, grouped.get(row["id"], [])) for row in rows], total


def referenced_tools(only_enabled=True):
    """启用的 SOP 引用到的工具名集合——这些工具不论问题是什么都要绑给模型。"""
    with lock:
        query = "SELECT DISTINCT s.tool FROM steps s JOIN playbooks p ON p.id = s.playbook_id"
        if only_enabled:
            query += " WHERE p.enabled = 1"
        return {r["tool"] for r in db.execute(query).fetchall()}


def delete(playbook_id):
    with lock:
        db.execute("DELETE FROM steps WHERE playbook_id = ?", (playbook_id,))
        db.execute("DELETE FROM playbooks WHERE id = ?", (playbook_id,))
        db.commit()
    _unseed([playbook_id])


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
    _unseed(ids)
    return len(ids)


def usable(known_tools):
    """启用、且步骤引用的工具此刻都可用的 SOP——工具没了的 SOP 照着做必然失败。"""
    return [p for p in list_all(only_enabled=True) if all(step["tool"] in known_tools for step in p["steps"])]


def short_names(items):
    """SOP id → 英文短名（sop-前 8 位），给 sop_get、MCP 提示词和 SKILL.md 的目录名用。

    中文名不能当函数名、目录名；id 稳定（场景包的 SOP id 由包名和 SOP 名算出），短名也就稳定。
    前 8 位撞上了就加长到不撞为止。
    """
    def clean(playbook_id):
        return "".join(c for c in str(playbook_id).lower() if c.isascii() and c.isalnum()) or "x"

    ids = sorted({p["id"] for p in items})
    out = {}
    for playbook_id in ids:
        key, size = clean(playbook_id), 8
        while size < len(key) and any(clean(other).startswith(key[:size]) for other in ids if other != playbook_id):
            size += 4
        out[playbook_id] = "sop-" + key[:size]
    return out


def as_prompt(known_tools, brief=False):
    """把启用的 SOP 压成一段紧凑文本，供模型判断是否套用。

    只列出步骤引用的工具当前仍然可用的 SOP——工具没了的 SOP 照着做必然失败。
    brief=True（SOP 太多时）只列名称、短名和适用场景，步骤让模型用 sop_get 现取。
    """
    usable_ = usable(known_tools)
    if not usable_:
        return ""

    lines = []
    if brief:
        names = short_names(usable_)
        for playbook in usable_:
            lines.append(f"SOP《{playbook['name']}》（{names[playbook['id']]}，{len(playbook['steps'])} 步）"
                         + (f"：适用 {playbook['trigger']}" if playbook["trigger"] else ""))
        return "\n".join(lines)
    for playbook in usable_:
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
