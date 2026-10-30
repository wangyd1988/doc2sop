"""组织运行图谱：工具查到的、文档里写的、人纠正过的，都落在这里。

产品原来是一条单向流：文档 → SOP → 工具。工具每次查到的真实数据、人对一次回答的
判断，答完就丢了——下次还得从头查、从头判断。这个模块把它们留下来，并让 SOP 和
文档从「源头」变成图谱的「生成物」：

    输入    工具返回（tool）、文档（doc）、人工纠正（human）、SOP 本身（sop）
    图谱    实体（容器、命名空间、工具、SOP、文档、阈值…）+ 带出处的事实
    输出    长出新 SOP、调阈值、改文档的提议，由人批准后才落到 SOP / 文档上

两条铁律：
  1. 每条事实、每个提议都必须指回出处（某次工具调用、某篇文档、某条反馈）。
     查不到出处的东西不进图谱——否则它和模型的一句猜测没有区别。
  2. 事实只追加不覆盖。同一主语同一谓语的多条记录就是它的时间线；撤回也只改状态。

用 SQLite，不引入图数据库：几张表加索引对这个规模绰绰有余，备份也只是多一个文件。
第一期不用模型抽实体，只在三处零成本播种：保存 SOP、调用工具、人工反馈。
"""
import json
import re
import sqlite3
import threading
import uuid
from datetime import datetime, timedelta, timezone

from app.agent import registry
from app.config import DATA_DIR

OUTCOMES = ("ok", "anomaly", "failed", "unknown")
VERDICTS = ("correct", "false_alarm", "wrong_threshold", "missing_step")
PROPOSAL_KINDS = ("new_sop", "extend_sop", "adjust_threshold", "update_doc", "retire_sop")
# SOP 的这些来源值不是文档名，保存时不为它们建 doc 实体
NON_DOC_SOURCES = ("", "手工创建", "从实践沉淀")

db = sqlite3.connect(DATA_DIR / "graph.db", check_same_thread=False)
db.row_factory = sqlite3.Row
db.execute("PRAGMA journal_mode=WAL")
db.execute("PRAGMA foreign_keys=ON")
db.executescript("""
CREATE TABLE IF NOT EXISTS executions (
  id TEXT PRIMARY KEY,
  conversation_id TEXT NOT NULL,
  message_id INTEGER,
  playbook_id TEXT,
  question TEXT NOT NULL,
  outcome TEXT NOT NULL DEFAULT 'unknown',
  started_at TEXT NOT NULL,
  finished_at TEXT
);
CREATE INDEX IF NOT EXISTS executions_by_conversation ON executions(conversation_id, started_at);
CREATE INDEX IF NOT EXISTS executions_by_playbook ON executions(playbook_id, started_at);

CREATE TABLE IF NOT EXISTS tool_calls (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  execution_id TEXT NOT NULL REFERENCES executions(id) ON DELETE CASCADE,
  seq INTEGER NOT NULL,
  tool TEXT NOT NULL,
  args TEXT NOT NULL DEFAULT '{}',
  output_full TEXT NOT NULL DEFAULT '',
  ok INTEGER NOT NULL DEFAULT 1,
  duration_ms INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  UNIQUE (execution_id, seq)
);

CREATE TABLE IF NOT EXISTS entities (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  kind TEXT NOT NULL,
  name TEXT NOT NULL,
  attrs TEXT NOT NULL DEFAULT '{}',
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL,
  UNIQUE (kind, name)
);

CREATE TABLE IF NOT EXISTS facts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  subject INTEGER NOT NULL REFERENCES entities(id),
  predicate TEXT NOT NULL,
  object_entity INTEGER REFERENCES entities(id),
  object_value TEXT,
  source_kind TEXT NOT NULL,
  source_ref TEXT NOT NULL,
  observed_at TEXT NOT NULL,
  confidence REAL NOT NULL DEFAULT 1.0,
  status TEXT NOT NULL DEFAULT 'active',
  CHECK (object_entity IS NOT NULL OR object_value IS NOT NULL),
  CHECK (source_ref <> '')
);
CREATE INDEX IF NOT EXISTS facts_by_subject ON facts(subject, predicate, observed_at);
CREATE INDEX IF NOT EXISTS facts_by_source ON facts(source_ref);

CREATE TABLE IF NOT EXISTS proposals (
  id TEXT PRIMARY KEY,
  kind TEXT NOT NULL,
  payload TEXT NOT NULL,
  evidence_refs TEXT NOT NULL,
  execution_id TEXT REFERENCES executions(id) ON DELETE SET NULL,
  signature TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'pending',
  created_at TEXT NOT NULL,
  decided_at TEXT,
  decided_by TEXT,
  CHECK (evidence_refs <> '' AND evidence_refs <> '[]')
);
CREATE INDEX IF NOT EXISTS proposals_by_status ON proposals(status, created_at);
CREATE INDEX IF NOT EXISTS proposals_by_execution ON proposals(execution_id);

CREATE TABLE IF NOT EXISTS feedback (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  execution_id TEXT NOT NULL REFERENCES executions(id) ON DELETE CASCADE,
  verdict TEXT NOT NULL,
  note TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL
);
""")
db.commit()
CHANNELS = ("web", "mcp")


def _migrate(conn):
    """老库的 executions 没有 channel 列（这次执行来自页面还是对外 MCP）：补上，老数据都算 web。"""
    try:
        conn.execute("ALTER TABLE executions ADD COLUMN channel TEXT NOT NULL DEFAULT 'web'")
    except sqlite3.OperationalError:
        pass
    conn.commit()


_migrate(db)
lock = threading.Lock()


class UnknownExecution(LookupError):
    """引用了不存在的执行记录。"""


def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# --- 实体与事实 --------------------------------------------------------------

def _touch(kind, name, attrs=None, replace=None):
    """实体存在就刷新 last_seen，不存在就建；返回 id。

    attrs 只补不改（列表取并集），replace 里的键总是覆盖——前者记「第一次是怎么见到它的」，
    后者是会变的展示信息（如 SOP 改名）。调用方持锁。
    """
    timestamp = now_iso()
    row = db.execute("SELECT id, attrs FROM entities WHERE kind = ? AND name = ?",
                     (kind, name)).fetchone()
    if row is None:
        merged = {**(attrs or {}), **(replace or {})}
        cur = db.execute("INSERT INTO entities (kind, name, attrs, first_seen, last_seen)"
                         " VALUES (?, ?, ?, ?, ?)",
                         (kind, name, json.dumps(merged, ensure_ascii=False), timestamp, timestamp))
        return cur.lastrowid
    merged = json.loads(row["attrs"] or "{}")
    for key, value in (attrs or {}).items():
        if isinstance(value, list):
            merged[key] = sorted(set(merged.get(key) or []) | set(value))
        else:
            merged.setdefault(key, value)
    merged.update(replace or {})
    db.execute("UPDATE entities SET last_seen = ?, attrs = ? WHERE id = ?",
               (timestamp, json.dumps(merged, ensure_ascii=False), row["id"]))
    return row["id"]


def _fact(subject, predicate, source_kind, source_ref, object_entity=None, object_value=None,
          confidence=1.0):
    """写一条事实（调用方持锁）。没有出处的一律拒绝——这是图谱可信的前提。"""
    if not source_ref:
        raise ValueError("fact 必须有 source_ref")
    if object_entity is None and object_value is None:
        raise ValueError("fact 必须有宾语")
    cur = db.execute(
        "INSERT INTO facts (subject, predicate, object_entity, object_value, source_kind,"
        " source_ref, observed_at, confidence) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (subject, predicate, object_entity,
         None if object_value is None else str(object_value),
         source_kind, source_ref, now_iso(), float(confidence)))
    return cur.lastrowid


def _retract(source_ref):
    cur = db.execute("UPDATE facts SET status = 'retracted' WHERE source_ref = ? AND status = 'active'",
                     (source_ref,))
    return cur.rowcount


def add_fact(subject, predicate, source_kind, source_ref, obj=None, value=None, confidence=1.0):
    """subject / obj 都是 (kind, name)；宾语要么是实体 obj，要么是字面量 value。"""
    with lock:
        subject_id = _touch(*subject)
        object_id = _touch(*obj) if obj else None
        fact_id = _fact(subject_id, predicate, source_kind, source_ref,
                        object_entity=object_id, object_value=value, confidence=confidence)
        db.commit()
    return fact_id


def retract_source(source_ref):
    """把某个出处播下的事实全部撤回。只改状态，不删行——时间线要留着。"""
    with lock:
        count = _retract(source_ref)
        db.commit()
    return count


def entity(kind, name):
    with lock:
        row = db.execute("SELECT * FROM entities WHERE kind = ? AND name = ?", (kind, name)).fetchone()
    if row is None:
        return None
    return {**dict(row), "attrs": json.loads(row["attrs"] or "{}")}


def facts_of(kind, name, predicate=None, include_retracted=False):
    """某个实体为主语的事实，按观察时间排序；宾语解析成 (kind, name) 或字面量。"""
    query = ("SELECT f.*, o.kind AS object_kind, o.name AS object_name FROM facts f"
             " JOIN entities s ON s.id = f.subject"
             " LEFT JOIN entities o ON o.id = f.object_entity"
             " WHERE s.kind = ? AND s.name = ?")
    args = [kind, name]
    if predicate:
        query += " AND f.predicate = ?"
        args.append(predicate)
    if not include_retracted:
        query += " AND f.status = 'active'"
    with lock:
        rows = db.execute(query + " ORDER BY f.observed_at, f.id", args).fetchall()
    return [{"id": r["id"], "predicate": r["predicate"],
             "object": (r["object_kind"], r["object_name"]) if r["object_entity"] else None,
             "value": r["object_value"], "source_kind": r["source_kind"],
             "source_ref": r["source_ref"], "observed_at": r["observed_at"],
             "confidence": r["confidence"], "status": r["status"]} for r in rows]


# --- 执行与工具调用 ----------------------------------------------------------

def start_execution(conversation_id, question, playbook_id=None, channel="web"):
    """一次 Agent 轮次（或「▶ 执行」发起的一次 SOP 执行）开始。对外 MCP 的一个会话也是一条执行（channel=mcp）。"""
    if channel not in CHANNELS:
        raise ValueError(f"channel 只能是 {'、'.join(CHANNELS)} 之一")
    execution_id = uuid.uuid4().hex
    with lock:
        db.execute("INSERT INTO executions (id, conversation_id, playbook_id, question, started_at, channel)"
                   " VALUES (?, ?, ?, ?, ?, ?)",
                   (execution_id, conversation_id, playbook_id or None, question, now_iso(), channel))
        db.commit()
    return execution_id


def _entities(args, schema):
    """实参里哪些是对象名：(参数名, 值, 实体类型, 属性)。只看工具声明的 x-entity，不猜。

    老写法的参数由工具服务（或应用侧兜底）按参数名和预置正则推出 x-entity，规则见 registry.entity_of；
    预置正则名在 x-pattern 里，照旧记进属性。K8s 对象另记它是哪类资源（同一次调用里的 resource 实参）。
    主机（x-entity: host，工具服务给命令型工具加的 target）的实参可以是 @组名：那是一组主机，记成 host_group。
    """
    properties = (schema or {}).get("properties") if isinstance(schema, dict) else None
    if not isinstance(properties, dict):
        return
    for key, value in args.items():
        prop = properties.get(key)
        kind = prop.get("x-entity") if isinstance(prop, dict) else None
        if not kind or not isinstance(kind, str) or not isinstance(value, str) or not value.strip():
            continue
        value = value.strip()
        attrs = {"param": key}
        if prop.get("x-pattern"):
            attrs["pattern"] = prop["x-pattern"]
        if kind == "k8s_object" and args.get("resource"):
            attrs["resources"] = [str(args["resource"])]
        if kind == "host" and value.startswith("@"):
            kind, value = "host_group", value[1:]
            if not value:
                continue
        yield key, value, kind, attrs


def record_tool_call(execution_id, tool, args, output, ok, duration_ms, params=None, schema=None):
    """记下一次工具调用的完整返回（对外展示的是预览，这里是全文）。

    零成本播种：工具本身成为实体；调用成功时，工具声明了 x-entity 的实参也成为实体并刷新
    last_seen——失败的调用不播种，否则一个打错的容器名就会变成一个「实体」。
    schema 是工具契约里的 inputSchema；只给老写法的 params 时按同一规则推一份。
    事实的出处都是这次调用本身（tool_call:<id>）。
    """
    args = args if isinstance(args, dict) else {}
    if schema is None and params:
        try:
            schema = registry.schema_from_params(params)
        except Exception:
            schema = None
    timestamp = now_iso()
    with lock:
        seq = db.execute("SELECT COALESCE(MAX(seq), 0) + 1 FROM tool_calls WHERE execution_id = ?",
                         (execution_id,)).fetchone()[0]
        cur = db.execute(
            "INSERT INTO tool_calls (execution_id, seq, tool, args, output_full, ok, duration_ms,"
            " created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (execution_id, seq, tool, json.dumps(args, ensure_ascii=False), str(output or ""),
             1 if ok else 0, max(0, int(duration_ms or 0)), timestamp))
        call_id = cur.lastrowid
        ref = f"tool_call:{call_id}"
        tool_entity = _touch("tool", tool)
        _fact(_touch("execution", execution_id), "called", "tool", ref, object_entity=tool_entity)
        if ok:
            for _key, value, kind, attrs in _entities(args, schema):
                subject = _touch(kind, value, attrs)
                _fact(subject, "checked_by", "tool", ref, object_entity=tool_entity)
        db.commit()
    return call_id


def _outcome(answer, failed, calls):
    """一轮的结论质量。规则写死在这里，便于单测钉住；后续可换成以人工反馈为准。

    calls 是 [(tool, ok)]。只数「算观察到系统」的类别（数据类）；联网搜索这类不算，
    没调过数据类工具的轮次是 unknown，不是 ok——什么都没看到，谈不上正常。
    """
    observed = [ok for tool, ok in calls if registry.observes_system(tool)]
    text = (answer or "").strip()
    if failed or not text:
        return "failed"
    if not observed:
        return "unknown"
    if not any(observed):
        return "failed"
    if "❌" in text or "⚠" in text:
        return "anomaly"
    return "ok"


def finish_execution(execution_id, answer, failed=False, message_id=None):
    """回答结束时收口：算 outcome，回填结束时间和对应的助手消息 id。

    对外 MCP 的会话没有页面上那种一问一答、轨迹也不完整：不算结论质量（一直是 unknown），
    结束时间记的是最近一次调用的时间。
    """
    with lock:
        row = db.execute("SELECT channel FROM executions WHERE id = ?", (execution_id,)).fetchone()
        rows = db.execute("SELECT tool, ok FROM tool_calls WHERE execution_id = ? ORDER BY seq",
                          (execution_id,)).fetchall()
        outcome = ("unknown" if row is not None and row["channel"] == "mcp"
                   else _outcome(answer, failed, [(r["tool"], bool(r["ok"])) for r in rows]))
        db.execute("UPDATE executions SET outcome = ?, finished_at = ?,"
                   " message_id = COALESCE(?, message_id) WHERE id = ?",
                   (outcome, now_iso(), message_id, execution_id))
        db.commit()
    return outcome


def _call_row(row):
    return {"id": row["id"], "seq": row["seq"], "tool": row["tool"],
            "args": json.loads(row["args"] or "{}"), "output": row["output_full"],
            "ok": bool(row["ok"]), "duration_ms": row["duration_ms"], "created_at": row["created_at"]}


def execution(execution_id):
    with lock:
        row = db.execute("SELECT * FROM executions WHERE id = ?", (execution_id,)).fetchone()
        if row is None:
            return None
        calls = db.execute("SELECT * FROM tool_calls WHERE execution_id = ? ORDER BY seq",
                           (execution_id,)).fetchall()
    return {**dict(row), "tool_calls": [_call_row(c) for c in calls]}


def tool_calls_by_ids(ids):
    """id -> 调用记录。提议的证据是 tool_call:<id>，页面展示时要换成参数和返回。"""
    ids = [int(i) for i in ids]
    if not ids:
        return {}
    with lock:
        rows = db.execute(f"SELECT * FROM tool_calls WHERE id IN ({','.join('?' * len(ids))})",
                          ids).fetchall()
    return {r["id"]: _call_row(r) for r in rows}


def executions_by_message(conversation_id):
    """message_id -> 执行摘要。回放时给每条助手消息挂上它的执行身份。"""
    with lock:
        rows = db.execute("SELECT id, message_id, outcome, playbook_id FROM executions"
                          " WHERE conversation_id = ? AND message_id IS NOT NULL",
                          (conversation_id,)).fetchall()
    return {r["message_id"]: {"execution_id": r["id"], "outcome": r["outcome"],
                              "playbook_id": r["playbook_id"]} for r in rows}


# --- SOP 播种 ----------------------------------------------------------------

# 阈值只认两种写法：数字带单位（80%、512MB、30 秒），或跟在比较词后面（超过 3、>= 5）。
# 裸数字不算——退出码、年份、端口号都长那样。数字前不能紧贴字母数字，免得 k8s 里的 8s 中招。
_UNIT = r"%|GB|MB|KB|ms|G|M|s|秒|分钟|小时|天|次"
THRESHOLD_UNIT = re.compile(rf"(?<![A-Za-z0-9.])(\d+(?:\.\d+)?)\s*({_UNIT})(?![A-Za-z])")
THRESHOLD_CMP = re.compile(
    rf"(?:超过|大于|高于|低于|小于|少于|不超过|不低于|不少于|达到|>=|<=|≥|≤|>|<)\s*"
    rf"(\d+(?:\.\d+)?)\s*({_UNIT})?(?![A-Za-z0-9])")


def thresholds(text):
    """检查点文字里能可靠认定为阈值的数字，去重后按出现顺序返回，如 ["80%", "3"]。"""
    hits = []
    for regex in (THRESHOLD_UNIT, THRESHOLD_CMP):
        for match in regex.finditer(text or ""):
            hits.append((match.start(1), match.group(1) + (match.group(2) or "")))
    return list(dict.fromkeys(value for _, value in sorted(hits)))


def seed_playbook(playbook_id, name, source, steps):
    """保存 SOP 时的零成本播种（由 playbooks.save 调用）。

    三类事实的出处都是这条 SOP 记录本身（sop:<id>）——「来自哪篇文档」也是 SOP 记录
    上写的，文档只是宾语。SOP 的保存语义是整体覆盖，所以先撤回它之前播下的事实，再按
    新步骤重写；撤回只改状态，之前的版本仍能在时间线上看到。
    """
    ref = f"sop:{playbook_id}"
    with lock:
        _retract(ref)
        sop = _touch("sop", playbook_id, replace={"name": name})
        for tool in dict.fromkeys(step["tool"] for step in steps):
            _fact(sop, "checks", "sop", ref, object_entity=_touch("tool", tool))
        if source not in NON_DOC_SOURCES:
            _fact(sop, "defined_in", "sop", ref, object_entity=_touch("doc", source))
        for step in steps:
            checkpoint = str(step.get("checkpoint") or "")
            for value in thresholds(checkpoint):
                threshold = _touch("threshold", f"{step['tool']}:{value}",
                                   {"value": value, "text": checkpoint[:300]})
                _fact(sop, "threshold", "sop", ref, object_entity=threshold)
        db.commit()


# --- 人工反馈 ----------------------------------------------------------------

def record_feedback(execution_id, verdict, note=""):
    """人对一次回答的判断。写成 human 来源的事实：执行本身被这样评价；按 SOP 执行的，SOP 也记一笔。"""
    if verdict not in VERDICTS:
        raise ValueError(f"verdict 只能是 {'、'.join(VERDICTS)} 之一")
    with lock:
        row = db.execute("SELECT playbook_id FROM executions WHERE id = ?", (execution_id,)).fetchone()
        if row is None:
            raise UnknownExecution(execution_id)
        cur = db.execute("INSERT INTO feedback (execution_id, verdict, note, created_at)"
                         " VALUES (?, ?, ?, ?)",
                         (execution_id, verdict, (note or "").strip()[:300], now_iso()))
        feedback_id = cur.lastrowid
        ref = f"feedback:{feedback_id}"
        _fact(_touch("execution", execution_id), "judged", "human", ref, object_value=verdict)
        if row["playbook_id"]:
            _fact(_touch("sop", row["playbook_id"]), "judged", "human", ref, object_value=verdict)
        db.commit()
    return feedback_id


# --- 提议 --------------------------------------------------------------------

def add_proposal(kind, payload, evidence_refs, execution_id=None, signature=""):
    """图谱对外提的建议。没有证据的提议和没有出处的事实一样，不收。"""
    if kind not in PROPOSAL_KINDS:
        raise ValueError(f"未知的提议类型 {kind}")
    refs = [str(r).strip() for r in (evidence_refs or []) if str(r).strip()]
    if not refs:
        raise ValueError("proposal 必须有 evidence_refs")
    proposal_id = uuid.uuid4().hex
    with lock:
        db.execute("INSERT INTO proposals (id, kind, payload, evidence_refs, execution_id, signature,"
                   " created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                   (proposal_id, kind, json.dumps(payload or {}, ensure_ascii=False),
                    json.dumps(refs, ensure_ascii=False), execution_id, signature or "", now_iso()))
        db.commit()
    return proposal_id


def _proposal_row(row):
    return {**dict(row), "payload": json.loads(row["payload"] or "{}"),
            "evidence_refs": json.loads(row["evidence_refs"] or "[]")}


def get_proposal(proposal_id):
    with lock:
        row = db.execute("SELECT * FROM proposals WHERE id = ?", (proposal_id,)).fetchone()
    return _proposal_row(row) if row else None


def list_proposals(status=None, execution_id=None, limit=50):
    where, args = [], []
    if status:
        where.append("status = ?")
        args.append(status)
    if execution_id:
        where.append("execution_id = ?")
        args.append(execution_id)
    clause = (" WHERE " + " AND ".join(where)) if where else ""
    with lock:
        rows = db.execute(f"SELECT * FROM proposals{clause} ORDER BY created_at DESC LIMIT ?",
                          args + [limit]).fetchall()
    return [_proposal_row(r) for r in rows]


def decide_proposal(proposal_id, status, decided_by="web"):
    """批准或驳回一条待定提议。返回是否真的改了（已决定过的不再改）。"""
    if status not in ("approved", "rejected"):
        raise ValueError("status 只能是 approved / rejected")
    with lock:
        cur = db.execute("UPDATE proposals SET status = ?, decided_at = ?, decided_by = ?"
                         " WHERE id = ? AND status = 'pending'",
                         (status, now_iso(), decided_by, proposal_id))
        db.commit()
    return cur.rowcount > 0


def count_proposals_since(since_iso):
    with lock:
        return db.execute("SELECT COUNT(*) FROM proposals WHERE created_at >= ?",
                          (since_iso,)).fetchone()[0]


def count_proposals(status="pending"):
    with lock:
        return db.execute("SELECT COUNT(*) FROM proposals WHERE status = ?", (status,)).fetchone()[0]


def pending_by_execution(execution_ids):
    """execution_id -> 待确认提议。回放一段对话时一次查完，给每条回答补画卡片。"""
    ids = [i for i in execution_ids if i]
    if not ids:
        return {}
    with lock:
        rows = db.execute(f"SELECT * FROM proposals WHERE status = 'pending' AND execution_id IN"
                          f" ({','.join('?' * len(ids))}) ORDER BY created_at", ids).fetchall()
    return {r["execution_id"]: _proposal_row(r) for r in rows}


def recently_rejected(signature, days):
    """同一个工具序列签名在 days 天内被人忽略过——不要再提同一件事。"""
    if not signature:
        return False
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat(timespec="seconds")
    with lock:
        row = db.execute("SELECT 1 FROM proposals WHERE signature = ? AND status = 'rejected'"
                         " AND decided_at >= ? LIMIT 1", (signature, cutoff)).fetchone()
    return row is not None
