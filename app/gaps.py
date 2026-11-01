"""知识库缺口看板（docs/自动执行.md「知识库缺口看板」）：大家常问、文档里没写的问题，归成一组一组、按次数排。

线索都来自应用自己的记录，不调模型就能找出来：
    no_citation     知识库模式的回答没有引用任何知识库片段
    kb_missing      回答明说知识库里没有（联网补上了的也算：网上有，文档里没有）
    smart_general   智能模式里调过 kb_search，最后却没引用、靠 💡 通用知识回答的
    feedback        有人工反馈的回答：对话里的「👎 没答好」，执行记录上的「误报」「阈值不对」「漏了一步」
不算缺口的：打招呼、闲聊、问它是谁，问知识库里有什么，「继续」这类确认语，查实际数据的（调过数据工具），按 SOP 执行的，
天气、新闻这类实时信息。

归类：先按字面（字的二元组）粗分，不调模型，马上出结果；向量模型可用时，后台每次最多补算 EMBED_BATCH 个问题的向量，
两边都有向量的按余弦相似度判断——要调模型的放到后台、限量。

忽略：这类问题不需要文档，整组标成忽略，以后相似的新问题也自动忽略。对话删了的，里面的问题不再列出。
"""
import json
import math
import re
import threading
import time

from app import conversations, graph, runs, settings
from app.agent import modes, registry
from app.config import log, why
from app.rag.embedding import embed_documents
from app.rag.lexical import tokenize
from app.rag.retrieval import CONTINUATION, is_overview

KINDS = {"no_citation": "没有引用知识库", "kb_missing": "回答说知识库里没有", "smart_general": "智能模式靠通用知识回答",
         "feedback": "有人工反馈"}
SCAN_BATCH = 2000
LEXICAL = 0.5               # 字面相似（Dice 系数）到这个数算一组
COSINE = 0.85               # 向量余弦相似度到这个数算一组
MEMBERS_COMPARED = 8        # 新问题和一组里最多几个问题比
EMBED_BATCH, EMBED_EVERY, EMBED_BACKOFF = 32, 600, 1800
SAMPLES = 5
KEYS_MAX = 500
NEGATIVE = ("false_alarm", "wrong_threshold", "missing_step", "unhelpful")

SMALL_TALK = re.compile(r"^(?:你好|您好|嗨|哈喽|hi|hello|hey|早上好|上午好|中午好|下午好|晚上好|在吗|在不在|谢谢|多谢|感谢|"
                        r"辛苦了|thanks?|thx|好的|好|嗯+|哦+|ok|okay|收到|明白|了解|知道了|再见|拜拜|bye)"
                        r"[\s!！。.~～,，呀啊哈]*$", re.IGNORECASE)
IDENTITY = re.compile(r"你是谁|你叫什么|你能做什么|你会什么|你可以做什么|你有什么功能|介绍一下你自己|怎么用你")
REALTIME = re.compile(r"天气|气温|下雨|下雪|新闻|热搜|股价|股票|汇率|油价|金价|比分|现在几点|今天几号|今天星期")
KB_MISSING = re.compile(r"知识库(?:里|中)?(?:没有|未|并未|暂无|找不到|没找到|查不到|未能找到|未收录)"
                        r"|没有(?:检索|查|找)到(?:相关|任何)|文档(?:里|中)(?:没有|未)")
CITATION = re.compile(r"\[(\d{1,2})\]")
STOP = {"怎么", "什么", "如何", "多少", "哪些", "哪个", "是否", "可以", "需要", "一下", "请问", "是不", "不是", "怎样",
        "为什", "么样", "有没", "没有", "能不", "不能", "知道", "告诉", "帮我", "我们", "你们", "一个", "这个", "那个",
        "的话", "现在", "应该", "么办", "怎么办", "吗", "呢", "的", "了", "么"}


# --- 认出缺口 -------------------------------------------------------------------------

def _sentence(text, match) -> str:
    start = max(text.rfind("。", 0, match.start()), text.rfind("\n", 0, match.start())) + 1
    end_candidates = [i for i in (text.find("。", match.end()), text.find("\n", match.end())) if i >= 0]
    end = min(end_candidates) if end_candidates else len(text)
    return " ".join(text[start:end + 1].split())[:120]


def classify(question, answer, tools, mode):
    """一问一答是不是缺口：(种类, 说明)；不是返回 None。"""
    q = " ".join(str(question or "").split())
    if len(q) < 2 or SMALL_TALK.match(q) or IDENTITY.search(q) or is_overview(q) or REALTIME.search(q):
        return None
    if len(q) <= 12 and CONTINUATION.match(q):
        return None
    if q.startswith("执行 SOP《"):
        return None
    used = [str(t.get("tool") or "") for t in tools or [] if isinstance(t, dict)]
    if any(name and registry.category_of(name) == "data" for name in used):
        return None
    text = str(answer or "")
    cited = bool(CITATION.search(text))
    missing = KB_MISSING.search(text)
    if mode == "smart":
        if "kb_search" not in used:
            return None
        if not cited and modes.uses_general(text):
            return "smart_general", "智能模式查过知识库，最后靠通用知识回答"
        if not cited and missing:
            return "kb_missing", _sentence(text, missing)
        return None
    if missing:
        return "kb_missing", _sentence(text, missing)
    if not cited:
        return "no_citation", "回答没有引用知识库"
    return None


def _state(key, default="0") -> str:
    with graph.lock:
        row = graph.db.execute("SELECT value FROM app_state WHERE key = ?", (key,)).fetchone()
    return row[0] if row else default


def _set_state(key, value):
    with graph.lock:
        graph.db.execute("INSERT INTO app_state (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                         (key, str(value)))
        graph.db.commit()


def _upsert(key, question, kind, detail, asked_at, conversation_id=None, message_id=None, run_id=None, ignores=None):
    with graph.lock:
        row = graph.db.execute("SELECT kinds FROM kb_gaps WHERE key = ?", (key,)).fetchone()
        if row:
            kinds = ",".join(dict.fromkeys([k for k in row[0].split(",") if k] + [kind]))
            graph.db.execute("UPDATE kb_gaps SET kinds = ?, detail = CASE WHEN detail = '' THEN ? ELSE detail END"
                             " WHERE key = ?", (kinds, detail, key))
        else:
            status = "ignored" if ignores and _ignored({"tokens": _tokens(question), "vector": None}, ignores) else "open"
            graph.db.execute("INSERT INTO kb_gaps (key, conversation_id, message_id, run_id, question, kinds, detail,"
                             " asked_at, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                             (key, conversation_id, message_id, run_id, question[:500], kind, detail[:300], asked_at,
                              status))
        graph.db.commit()


def scan(limit=SCAN_BATCH) -> int:
    """接着上次扫到的地方往下扫：新的回答、新的人工反馈。返回这次找出的条数。"""
    found = 0
    ignores = _ignores()
    cursor = int(_state("gaps.message_cursor"))
    rows = conversations.answers_after(cursor, limit)
    for row in rows:
        hit = classify(row["question"], row["answer"], row["tools"], row["mode"])
        if hit:
            _upsert(f"msg:{row['id']}", " ".join(row["question"].split()), hit[0], hit[1], row["created_at"],
                    conversation_id=row["conversation_id"], message_id=row["id"], ignores=ignores)
            found += 1
    if rows:
        _set_state("gaps.message_cursor", rows[-1]["id"])
    cursor = int(_state("gaps.feedback_cursor"))
    with graph.lock:
        feedback = graph.db.execute(
            "SELECT f.id, f.verdict, f.note, f.created_at, e.id AS execution_id, e.message_id, e.conversation_id,"
            " e.question, e.playbook_id FROM feedback f JOIN executions e ON e.id = f.execution_id"
            " WHERE f.id > ? ORDER BY f.id LIMIT ?", (cursor, limit)).fetchall()
    for row in feedback:
        if row["verdict"] not in NEGATIVE:
            continue
        label = runs.FEEDBACK_NAMES.get(row["verdict"], row["verdict"])
        detail = f"人工反馈：{label}" + (f"（{row['note']}）" if row["note"] else "")
        if row["message_id"] is not None and not str(row["conversation_id"]).startswith(("auto:", "mcp:")):
            _upsert(f"msg:{row['message_id']}", " ".join(str(row["question"]).split()), "feedback", detail,
                    row["created_at"], conversation_id=row["conversation_id"], message_id=row["message_id"],
                    ignores=ignores)
            found += 1
            continue
        run = runs.get(row["execution_id"])
        if run:
            question = row["note"] or f"SOP《{run['playbook_name']}》的执行：{label}"
            _upsert(f"run:{row['execution_id']}", question, "feedback", detail, row["created_at"],
                    run_id=row["execution_id"], ignores=ignores)
            found += 1
    if feedback:
        _set_state("gaps.feedback_cursor", feedback[-1]["id"])
    return found


# --- 归类 -----------------------------------------------------------------------------

def _tokens(text) -> frozenset:
    return frozenset(t for t in tokenize(text) if t not in STOP)


def _vector(raw):
    try:
        values = json.loads(raw) if raw else None
    except ValueError:
        return None
    return values if isinstance(values, list) and values else None


def _cosine(a, b) -> float:
    dot = sum(x * y for x, y in zip(a, b))
    norm = math.sqrt(sum(x * x for x in a)) * math.sqrt(sum(y * y for y in b))
    return dot / norm if norm else 0.0


def similar(a, b) -> bool:
    """两个问题算不算一类：都有向量时看余弦相似度，否则看字面（字的二元组）重合得多不多。"""
    if a["vector"] and b["vector"] and len(a["vector"]) == len(b["vector"]):
        return _cosine(a["vector"], b["vector"]) >= COSINE
    if not a["tokens"] or not b["tokens"]:
        return False
    return 2 * len(a["tokens"] & b["tokens"]) / (len(a["tokens"]) + len(b["tokens"])) >= LEXICAL


def _ignores() -> list:
    with graph.lock:
        rows = graph.db.execute("SELECT question, vector FROM kb_gap_ignores").fetchall()
    return [{"tokens": _tokens(r["question"]), "vector": _vector(r["vector"])} for r in rows]


def _ignored(item, ignores) -> bool:
    return any(similar(item, pattern) for pattern in ignores)


def cluster(items) -> list:
    """贪心归组：按时间从新到旧，每个问题并进第一个足够像的组，没有就自成一组。"""
    groups = []
    for item in items:
        home = next((g for g in groups if any(similar(item, m) for m in g["members"][:MEMBERS_COMPARED])), None)
        if home is None:
            groups.append({"members": [item]})
        else:
            home["members"].append(item)
    out = []
    for group in groups:
        members = group["members"]
        latest = members[0]
        kinds = {}
        for member in members:
            for kind in member["kinds"].split(","):
                if kind:
                    kinds[kind] = kinds.get(kind, 0) + 1
        out.append({"id": latest["key"], "count": len(members), "last_at": latest["asked_at"],
                    "example": latest["question"], "detail": latest["detail"],
                    "link": ({"conversation_id": latest["conversation_id"], "message_id": latest["message_id"]}
                             if latest["conversation_id"] else {"run_id": latest["run_id"]}),
                    "kinds": kinds, "questions": list(dict.fromkeys(m["question"] for m in members))[:SAMPLES],
                    "keys": [m["key"] for m in members][:KEYS_MAX]})
    return sorted(out, key=lambda g: (g["count"], g["last_at"]), reverse=True)


def _open_items() -> list:
    with graph.lock:
        rows = graph.db.execute("SELECT * FROM kb_gaps WHERE status = 'open' ORDER BY asked_at DESC").fetchall()
    return [{**dict(r), "tokens": _tokens(r["question"]), "vector": _vector(r["vector"])} for r in rows]


def _purge(items) -> list:
    """对话删了、执行记录删了的不再列，也从表里删掉。"""
    alive = conversations.existing(i["conversation_id"] for i in items if i["conversation_id"])
    gone = [i["key"] for i in items if (i["conversation_id"] and i["conversation_id"] not in alive)
            or (i["run_id"] and not i["conversation_id"] and runs.get(i["run_id"]) is None)]
    if gone:
        with graph.lock:
            for start in range(0, len(gone), 500):
                chunk = gone[start:start + 500]
                graph.db.execute(f"DELETE FROM kb_gaps WHERE key IN ({','.join('?' * len(chunk))})", chunk)
            graph.db.commit()
    return [i for i in items if i["key"] not in set(gone)]


def board(limit=None, embed=True) -> dict:
    """看板：扫新记录，去掉删了的、和忽略过的相似的，归组排序。embed=True 时后台限量补算向量。"""
    scan()
    items = _purge(_open_items())
    ignores = _ignores()
    hidden = [i["key"] for i in items if _ignored(i, ignores)]
    if hidden:
        _set_status(hidden, "ignored")
        items = [i for i in items if i["key"] not in set(hidden)]
    groups = cluster(items)
    if embed and any(i["vector"] is None for i in items):
        _maybe_embed()
    with graph.lock:
        ignored = graph.db.execute("SELECT COUNT(*) FROM kb_gaps WHERE status = 'ignored'").fetchone()[0]
    return {"groups": groups[:limit] if limit else groups, "total": len(groups), "questions": len(items),
            "ignored": ignored, "kinds": KINDS,
            "grouping": "vector" if items and all(i["vector"] for i in items) else
                        "mixed" if any(i["vector"] for i in items) else "lexical"}


def _set_status(keys, status):
    keys = list(keys)
    with graph.lock:
        for start in range(0, len(keys), 500):
            chunk = keys[start:start + 500]
            graph.db.execute(f"UPDATE kb_gaps SET status = ? WHERE key IN ({','.join('?' * len(chunk))})",
                             [status] + chunk)
        graph.db.commit()


def ignore(keys) -> int:
    """忽略一组：这些问题标成忽略，再记下几句代表性的问题，以后相似的新问题也自动忽略。"""
    keys = [str(k) for k in keys or [] if str(k).strip()][:KEYS_MAX]
    if not keys:
        return 0
    with graph.lock:
        rows = graph.db.execute(f"SELECT question, vector FROM kb_gaps WHERE key IN ({','.join('?' * len(keys))})"
                                " ORDER BY asked_at DESC", keys).fetchall()
    _set_status(keys, "ignored")
    seen, stamp = set(), graph.now_iso()
    with graph.lock:
        for row in rows:
            if row["question"] in seen or len(seen) >= SAMPLES:
                continue
            seen.add(row["question"])
            graph.db.execute("INSERT INTO kb_gap_ignores (question, vector, created_at) VALUES (?, ?, ?)",
                             (row["question"], row["vector"], stamp))
        graph.db.commit()
    log.info("knowledge gaps: ignored a group of %d question(s)", len(rows))
    return len(rows)


# --- 后台补算向量（限量）-----------------------------------------------------------------

_embed = {"running": False, "next": 0.0}
_embed_lock = threading.Lock()


def _maybe_embed():
    if not settings.configured():
        return
    with _embed_lock:
        if _embed["running"] or time.monotonic() < _embed["next"]:
            return
        _embed["running"] = True
    threading.Thread(target=embed_batch, name="gap-vectors", daemon=True).start()


def embed_batch() -> int:
    """给最多 EMBED_BATCH 个还没有向量的问题（和忽略过的问题）补算向量。失败了半小时后再试。"""
    done, wait = 0, EMBED_EVERY
    try:
        with graph.lock:
            rows = graph.db.execute("SELECT key, question FROM kb_gaps WHERE vector IS NULL AND status = 'open'"
                                    " ORDER BY asked_at DESC LIMIT ?", (EMBED_BATCH,)).fetchall()
            patterns = graph.db.execute("SELECT id, question FROM kb_gap_ignores WHERE vector IS NULL LIMIT ?",
                                        (EMBED_BATCH,)).fetchall()
        texts = [r["question"] for r in rows] + [p["question"] for p in patterns]
        if texts:
            vectors = embed_documents(texts)
            packed = [json.dumps([round(float(x), 5) for x in v]) for v in vectors]
            with graph.lock:
                for row, vector in zip(rows, packed):
                    graph.db.execute("UPDATE kb_gaps SET vector = ? WHERE key = ?", (vector, row["key"]))
                for pattern, vector in zip(patterns, packed[len(rows):]):
                    graph.db.execute("UPDATE kb_gap_ignores SET vector = ? WHERE id = ?", (vector, pattern["id"]))
                graph.db.commit()
            done = len(texts)
            log.info("knowledge gaps: embedded %d question(s)", done)
    except Exception as exc:
        wait = EMBED_BACKOFF
        log.info("knowledge gaps: embedding skipped (%s), retry in %d min", why(exc), EMBED_BACKOFF // 60)
    finally:
        with _embed_lock:
            _embed.update(running=False, next=time.monotonic() + wait)
    return done
