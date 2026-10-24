"""HTTP API and web UI."""
import contextvars
import hashlib
import json
import queue
import re
import secrets
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Literal

from fastapi import Depends, FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, StreamingResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel, Field

from app import catalog, conversations, graph, jobs, models, packs, playbooks, settings
from app.agent import grow
from app.agent import loop as agent_loop
from app.agent import ops_client, web_search
from app.agent.extract import extract as extract_playbooks
from app.config import (AGENT_MODE, ALLOWED_SUFFIXES, CATEGORY_MAX, BOT_NAME,
                        FILES_DIR, IMAGE_SUFFIXES, MAX_FILE_BYTES, WEB_PASSWORD, WEB_USER,
                        log)
from app.ingest.extract import ExtractionError, extract_pages
from app.ingest.vision import ImageCollector
from app.rag import store
from app.rag.answer import build_messages, rewrite_question, stream_answer, suggest_category
from app.rag.chunking import chunk_pages
from app.rag.embedding import EmbeddingError, embed_documents
from app.rag.retrieval import as_context, catalog_context, is_continuation, is_overview, retrieve
from app.tracing import finish_root_run, start_root_run, traced_under

FILES_DIR.mkdir(parents=True, exist_ok=True)
WEB_DIR = Path(__file__).parent / "web"

security = HTTPBasic()


def require_auth(credentials: HTTPBasicCredentials = Depends(security)):
    user_ok = secrets.compare_digest(credentials.username.encode(), WEB_USER.encode())
    pass_ok = secrets.compare_digest(credentials.password.encode(), WEB_PASSWORD.encode())
    if not (user_ok and pass_ok):
        raise HTTPException(status_code=401, detail="Unauthorized",
                            headers={"WWW-Authenticate": "Basic"})


# Auth guards every route, including the UI itself.
app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None,
              dependencies=[Depends(require_auth)])


def safe_name(filename: str) -> str:
    name = Path(filename or "").name.strip()
    name = re.sub(r'[\\/:*?"<>|\x00-\x1f]', "_", name)
    if not name or name.startswith("."):
        raise HTTPException(400, "文件名无效")
    if Path(name).suffix.lower() not in ALLOWED_SUFFIXES:
        raise HTTPException(400, "只支持 .md / .txt / .pdf / .docx / .pptx 和常见图片文件")
    return name[:200]


@app.get("/", response_class=HTMLResponse)
def index():
    return (WEB_DIR / "index.html").read_text(encoding="utf-8")


@app.get("/manage", response_class=HTMLResponse)
def manage_page():
    """独立管理页：同一个前端，按路径切换到全屏的 工具 / SOP / 文档 管理布局。"""
    return (WEB_DIR / "index.html").read_text(encoding="utf-8")


# --- Documents ---------------------------------------------------------------

def usable_tools() -> dict:
    """宿主机当前对外提供的工具：名字 -> 说明。

    工具定义只在宿主机那一份配置里维护，应用侧不再留第二份清单，
    否则两边迟早对不上（界面显示 6 个、模型实际拿到 5 个就是这么来的）。
    """
    if AGENT_MODE == "off":
        return {}
    return {name: (meta.get("desc", "") if isinstance(meta, dict) else str(meta))
            for name, meta in ops_client.available_tools().items()}


def tool_specs() -> dict:
    """工具名 -> {desc, params}。SOP 抽取要把参数名告诉模型，args 才填得对。"""
    if AGENT_MODE == "off":
        return {}
    return {name: {"desc": meta.get("desc", ""), "params": meta.get("params") or {}}
            for name, meta in ops_client.available_tools().items() if isinstance(meta, dict)}


@app.get("/api/documents")
def documents():
    tools = usable_tools()
    return {"documents": store.list_documents(), "categories": store.all_categories(),
            "chat_model": settings.get("chat_model"), "bot_name": BOT_NAME,
            "configured": settings.configured(),
            "tools": sorted(tools),
            "web_search": AGENT_MODE != "off" and web_search.enabled(),
            "sop_growth": AGENT_MODE != "off" and grow.enabled(),
            "playbooks": len(playbooks.list_all(only_enabled=True)),
            # 欢迎页：已导入场景包的示例问题当 chips；自动导入进行中时引导卡显示进度
            "examples": packs.examples(),
            "packs": packs.progress()}


@app.post("/api/documents")
def upload(file: UploadFile = File(...), category: str = Form(""), background: str = Form("")):
    name = safe_name(file.filename)
    data = file.file.read(MAX_FILE_BYTES + 1)
    if len(data) > MAX_FILE_BYTES:
        raise HTTPException(413, f"文件超过 {MAX_FILE_BYTES // 1024 // 1024}MB")
    if not data:
        raise HTTPException(400, "文件为空")
    if background in ("1", "true", "yes"):
        return {"job": jobs.submit(name, lambda report: ingest(name, data, category, report))}
    return ingest(name, data, category)


@app.get("/api/jobs/{job_id}")
def job_status(job_id: str):
    job = jobs.get(job_id)
    if not job:
        raise HTTPException(404, "任务不存在或已过期")
    return job


def ingest(name: str, data: bytes, category: str = "", report=lambda stage: None):
    """Parse, chunk, embed and store one file. Shared by uploads and saved web notes.

    `report(stage)` is called as the work progresses so a background job can show it.
    """
    digest = hashlib.sha256(data).hexdigest()

    report("解析文件")
    images = ImageCollector()
    try:
        pages = extract_pages(name, data, images)
    except ExtractionError as exc:
        raise HTTPException(400, str(exc))
    if images.images:
        report(f"识别图片 0/{len(images.images)}")
        images.on_progress = lambda done, total: report(f"识别图片 {done}/{total}")
    images.describe_all()
    if Path(name).suffix.lower() in IMAGE_SUFFIXES and images.failed:
        raise HTTPException(502, "图片识别失败，可能是图片内容无法解析或模型暂时不可用，请稍后重试")

    # Splice recognised image text back into the position it occupied.
    pages = [(page, images.fill(text)) for page, text in pages]
    probe = "\n".join(text for _, text in pages)[:1000]
    report("判断分类")
    chosen = category.strip()[:CATEGORY_MAX] or suggest_category(
        name, probe, store.all_categories())

    ids, texts, metas = chunk_pages(name, pages, digest, chosen)
    if not texts:
        raise HTTPException(400, "没有提取到文字或有用的图片内容（扫描件请确认图片清晰度）")

    report(f"向量化 {len(texts)} 个片段")
    try:
        vectors = embed_documents(texts)
    except EmbeddingError as exc:
        raise HTTPException(502, f"向量化失败：{exc}（向量服务可能不可达）")

    report("写入知识库")
    store.replace_document(ids, texts, vectors, metas, name)
    (FILES_DIR / name).write_bytes(data)
    return {"source": name, "chunks": len(texts), "images": images.stats(),
            "category": chosen}


# --- Saving web answers ------------------------------------------------------
#
# 知识库答不了、联网搜到了之后，由人确认再存进知识库，下次就不用再搜。
# 只能由用户在页面上点按钮触发，模型自己不能往知识库里写东西——
# 否则一次被网页内容带偏的回答就会变成"团队知识"，以后每次都被当成权威引用。

WEB_NOTE_CATEGORY = "网络补充"
CITE_KB = re.compile(r"\[(\d{1,2})\]")
# 回答开头那句「知识库里没有找到……以下来自网络搜索」，存进知识库后就成了错误信息。
WEB_PREAMBLE = re.compile(r"^\s*(?:\*\*)?知识库(?:里|中)没有[^\n]*\n+")


class WebNoteSource(BaseModel):
    index: str = Field(pattern=r"^W\d{1,2}$")
    location: str = Field(default="", max_length=200)
    url: str = Field(pattern=r"^https?://", max_length=500)


class WebNote(BaseModel):
    title: str = Field(min_length=1, max_length=60)
    question: str = Field(min_length=1, max_length=2000)
    answer: str = Field(min_length=1, max_length=20000)
    sources: list[WebNoteSource] = Field(min_length=1, max_length=20)


def web_note_markdown(note: WebNote, saved_by: str, today: str) -> str:
    # 知识库片段的 [1][2] 指向的是别的文档，存进来就成了悬空引用，去掉；网络来源 [W1] 保留并列出链接。
    answer = WEB_PREAMBLE.sub("", CITE_KB.sub("", note.answer)).strip()
    refs = "\n".join(f"- [{s.index}] {s.location or s.url} — {s.url}" for s in note.sources)
    return (f"# {note.title}\n\n"
            f"> 来源：网络搜索，{today} 由 {saved_by} 确认后存入知识库。"
            f"网络内容可能随时间变化，引用时请注意时效，必要时打开原链接核对。\n\n"
            f"## 问题\n\n{note.question.strip()}\n\n"
            f"## 答案\n\n{answer}\n\n"
            f"## 参考来源\n\n{refs}\n")


@app.post("/api/web-notes")
def save_web_note(note: WebNote):
    """把一条联网得到的回答存成知识库文档（Markdown），走和上传完全相同的入库流程。"""
    today = datetime.now(timezone(timedelta(hours=8))).strftime("%Y-%m-%d")
    name = safe_name(f"{WEB_NOTE_CATEGORY}-{note.title.strip()}.md")
    data = web_note_markdown(note, WEB_USER, today).encode("utf-8")
    result = ingest(name, data, WEB_NOTE_CATEGORY)
    log.info("saved web note %s (%d chunks)", name, result["chunks"])
    return result


class CategoryUpdate(BaseModel):
    category: str = Field(min_length=1, max_length=CATEGORY_MAX)


@app.patch("/api/documents/{name}/category")
def set_category(name: str, payload: CategoryUpdate):
    name = safe_name(name)
    category = payload.category.strip()[:CATEGORY_MAX]
    if not category:
        raise HTTPException(400, "分类名不能为空")
    if not store.set_category(name, category):
        raise HTTPException(404, "文档不存在")
    return {"source": name, "category": category}


@app.get("/api/documents/{name}/download")
def download_document(name: str):
    if not name or name.startswith(".") or any(c in name for c in "/\\\x00"):
        raise HTTPException(404, "原文件不存在")
    path = FILES_DIR / name
    # Reject symlinks and anything resolving outside the upload directory.
    if path.is_symlink() or path.resolve().parent != FILES_DIR.resolve() or not path.is_file():
        raise HTTPException(404, "原文件不存在或已被删除")
    return FileResponse(path, filename=name, media_type="application/octet-stream",
                        headers={"Cache-Control": "private, no-store",
                                 "X-Content-Type-Options": "nosniff"})


@app.delete("/api/documents/{name}")
def delete_document(name: str):
    name = safe_name(name)
    store.delete_document(name)
    (FILES_DIR / name).unlink(missing_ok=True)
    # 文档没了，从它抽出来的 SOP 也一并清掉，避免留下孤儿流程。
    removed = playbooks.delete_by_source(name)
    return {"deleted": name, "playbooks_removed": removed}


# --- Playbooks ---------------------------------------------------------------

class PlaybookStep(BaseModel):
    tool: str = Field(min_length=1, max_length=60)
    args: dict = Field(default_factory=dict)
    checkpoint: str = Field(default="", max_length=300)
    # 抽取时记录的文档原句，供人核对；手工建的 SOP 可以为空
    evidence: str = Field(default="", max_length=300)


class PlaybookBody(BaseModel):
    name: str = Field(min_length=1, max_length=playbooks.NAME_MAX)
    trigger: str = Field(default="", max_length=playbooks.TRIGGER_MAX)
    steps: list[PlaybookStep] = Field(min_length=1, max_length=playbooks.STEP_MAX)
    enabled: bool = True


@app.get("/api/playbooks")
def list_playbooks(q: str = "", source: str = "", offset: int = 0, limit: int = catalog.PAGE,
                   everything: bool = False):
    """SOP 面板数据：分组（来源文档）+ 一页条目。

    默认只回分组；带 source 回该来源的一页；带 q 回搜索结果的一页。`everything=1` 回全部（编辑器等少量场景）。
    """
    tools = usable_tools()
    offset, limit = catalog.clamp(offset, limit)
    if everything:
        items, total = playbooks.list_all(), None
    else:
        items, total = playbooks.search(q, source, offset, limit)
    for item in items:
        # 工具被下线后，依赖它的 SOP 要在界面上标出来，而不是静默失效。
        item["missing_tools"] = sorted({s["tool"] for s in item["steps"]
                                        if s["tool"] not in tools})
    groups = playbooks.sources()
    # 分组计数里的「生效」要扣掉引用了不可用工具的；这需要看步骤，只对启用的算一次
    live_by_source = {}
    for p in playbooks.list_all(only_enabled=True):
        if all(s["tool"] in tools for s in p["steps"]):
            key = p["source"] or "手工创建"
            live_by_source[key] = live_by_source.get(key, 0) + 1
    for g in groups:
        g["live"] = live_by_source.get(g["name"], 0)
    count = sum(g["total"] for g in groups)
    # 面板标题的「来源：文档 x / 实践 y」——文档抽取、从实践沉淀、手工三类各多少
    origins = {"doc": 0, "practice": 0, "manual": 0}
    for g in groups:
        key = ("practice" if g["name"] == grow.SOURCE else "manual" if g["name"] == "手工创建" else "doc")
        origins[key] += g["total"]
    return {"playbooks": items, "tools": tools, "groups": groups,
            "total": count if total is None else total, "offset": offset, "limit": limit,
            "count": count, "live": sum(live_by_source.values()),
            "origins": origins, "pending": graph.count_proposals("pending")}


@app.get("/api/playbooks/{playbook_id}")
def get_playbook(playbook_id: str):
    item = playbooks.get(playbook_id)
    if not item:
        raise HTTPException(404, "SOP 不存在")
    tools = usable_tools()
    item["missing_tools"] = sorted({s["tool"] for s in item["steps"] if s["tool"] not in tools})
    return item


@app.post("/api/playbooks")
def create_playbook(body: PlaybookBody):
    try:
        playbook_id = playbooks.save(
            None, body.name, body.trigger,
            [s.model_dump() for s in body.steps], set(usable_tools()),
            source="手工创建", enabled=body.enabled)
    except playbooks.InvalidPlaybook as exc:
        raise HTTPException(400, str(exc))
    return playbooks.get(playbook_id)


@app.put("/api/playbooks/{playbook_id}")
def update_playbook(playbook_id: str, body: PlaybookBody):
    existing = playbooks.get(playbook_id)
    if not existing:
        raise HTTPException(404, "SOP 不存在")
    try:
        playbooks.save(playbook_id, body.name, body.trigger,
                       [s.model_dump() for s in body.steps], set(usable_tools()),
                       source=existing["source"], enabled=body.enabled)
    except playbooks.InvalidPlaybook as exc:
        raise HTTPException(400, str(exc))
    return playbooks.get(playbook_id)


@app.delete("/api/playbooks/{playbook_id}")
def remove_playbook(playbook_id: str):
    playbooks.delete(playbook_id)
    return {"deleted": playbook_id}


class ExtractBody(BaseModel):
    source: str = Field(min_length=1, max_length=200)


@app.post("/api/playbooks/extract")
def extract_from_document(body: ExtractBody):
    """从已入库的文档里抽取候选 SOP，返回但不直接保存，由用户确认。"""
    if not settings.configured():
        raise HTTPException(503, settings.NOT_CONFIGURED)
    name = safe_name(body.source)
    tools = usable_tools()
    if not tools:
        raise HTTPException(400, "当前没有可用的工具，无法编排 SOP")

    chunks = store.collection.get(where={"source": name}, include=["documents"])
    if not chunks["documents"]:
        raise HTTPException(404, "文档不存在")
    # Chroma 不保证返回顺序；按入库序号排回原文顺序，否则截断后可能只剩目录和声明页
    def _position(pair):
        tail = pair[0].rsplit(":", 1)[-1]
        return int(tail) if tail.isdigit() else 0
    ordered = sorted(zip(chunks["ids"], chunks["documents"]), key=_position)
    text = "\n".join(doc for _, doc in ordered[:30])

    specs = tool_specs()
    candidates, note = extract_playbooks(
        name, text, {n: specs.get(n) or {"desc": d, "params": {}} for n, d in tools.items()})
    saved = []
    for item in candidates:
        try:
            playbook_id = playbooks.save(None, item["name"], item["trigger"],
                                         item["steps"], set(tools),
                                         source=name, enabled=False)
        except playbooks.InvalidPlaybook as exc:
            log.info("discarded extracted playbook from %s: %s", name, exc)
            continue
        saved.append(playbooks.get(playbook_id))
    # 抽取结果默认停用，确认无误后再启用，避免自动生成的流程直接上线。
    return {"source": name, "extracted": saved, "note": note}


# --- Scenario packs -----------------------------------------------------------
#
# 场景包 = 文档 + 工具定义 + SOP 的目录（docs/场景包.md）。这里只能导入文档和 SOP；
# 工具定义由宿主机（或演示 sidecar）include，应用永远不往宿主机送工具。

@app.get("/api/packs")
def list_packs():
    return packs.overview(set(usable_tools()))


@app.post("/api/packs/{pack_id}/import")
def import_pack(pack_id: str, force: bool = False):
    """同步导入一个包（文档入库 + SOP 入库），幂等；force=1 重导同版本。"""
    try:
        result = packs.import_pack(pack_id, ingest, set(usable_tools()), force=force)
    except packs.PackWaiting as exc:
        raise HTTPException(409, str(exc))
    except packs.PackError as exc:
        raise HTTPException(400, str(exc))
    return {"pack": pack_id, **result}


@app.get("/api/packs/export")
def export_pack_sops(source: str = ""):
    """按 sops.json 的格式导出库里的 SOP：现场长出来、核对过的 SOP 就这样放进场景包。"""
    return {"sops": packs.export_sops(source)}


# --- Proposals: SOP grown from practice ---------------------------------------
#
# 一次自由排查结束后，后台可能提出「把这次沉淀为 SOP」。提议只是一条待确认记录，
# 批准时才真正写成 SOP——仍然经过 playbooks.validate，默认停用，和文档抽取同一条线。

def proposal_view(proposal):
    """给页面看的提议：payload 展开，证据换成对应那次调用的参数与返回预览。"""
    payload = proposal["payload"]
    ids = [int(ref.split(":", 1)[1]) for ref in proposal["evidence_refs"] if ref.startswith("tool_call:")]
    calls = graph.tool_calls_by_ids(ids)
    evidence = []
    for index, call_id in enumerate(ids, 1):
        call = calls.get(call_id)
        if call:
            # 序号按运维工具调用的先后排，和模型写的「第 n 次调用」一致
            evidence.append({"n": index, "tool": call["tool"], "args": call["args"], "ok": call["ok"],
                             "preview": call["output"][:300]})
    return {"id": proposal["id"], "kind": proposal["kind"], "status": proposal["status"],
            "created_at": proposal["created_at"], "execution_id": proposal["execution_id"],
            "name": payload.get("name", ""), "trigger": payload.get("trigger", ""),
            "steps": payload.get("steps", []), "summary": payload.get("summary", {}),
            "target": payload.get("target"), "evidence": evidence}


@app.get("/api/proposals")
def list_proposals(execution_id: str = "", status: str = "pending"):
    items = graph.list_proposals(status=status or None, execution_id=execution_id or None)
    return {"proposals": [proposal_view(p) for p in items], "pending": graph.count_proposals("pending")}


def _pending_proposal(proposal_id):
    proposal = graph.get_proposal(proposal_id)
    if not proposal:
        raise HTTPException(404, "提议不存在")
    if proposal["status"] != "pending":
        raise HTTPException(409, "这条提议已经处理过了")
    return proposal


@app.post("/api/proposals/{proposal_id}/approve")
def approve_proposal(proposal_id: str):
    """批准：新建 SOP（来源「从实践沉淀」、默认停用），或把多出的步骤补到目标 SOP 末尾。"""
    proposal = _pending_proposal(proposal_id)
    payload, tools = proposal["payload"], set(usable_tools())
    try:
        if proposal["kind"] == "extend_sop":
            target = playbooks.get((payload.get("target") or {}).get("id", ""))
            if not target:
                raise HTTPException(404, "目标 SOP 已不存在")
            have = {s["tool"] for s in target["steps"]}
            merged = target["steps"] + [s for s in payload["steps"] if s["tool"] not in have]
            playbook_id = playbooks.save(target["id"], target["name"], target["trigger"], merged,
                                         tools, enabled=target["enabled"])
        elif proposal["kind"] == "new_sop":
            playbook_id = playbooks.save(None, payload["name"], payload.get("trigger", ""),
                                         payload["steps"], tools, source=grow.SOURCE, enabled=False)
        else:
            raise HTTPException(400, "这类提议还不能自动执行")
    except playbooks.InvalidPlaybook as exc:
        raise HTTPException(400, str(exc))
    graph.decide_proposal(proposal_id, "approved")
    return {"proposal": proposal_id, "playbook": playbooks.get(playbook_id)}


@app.post("/api/proposals/{proposal_id}/reject")
def reject_proposal(proposal_id: str):
    _pending_proposal(proposal_id)
    graph.decide_proposal(proposal_id, "rejected")
    return {"proposal": proposal_id, "status": "rejected"}


# --- Tools -------------------------------------------------------------------
#
# 页面能改工具的哪些部分，是一条安全边界：
#   启停、改描述  -> 直接生效（都不改变实际执行的命令）
#   新增工具      -> 只能提交申请，由人在宿主机上批准后才写入配置
# 命令模板永远只在宿主机那份手写配置里定义，这个接口碰不到。

class ToolOverride(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    enabled: bool | None = None
    desc: str | None = Field(default=None, max_length=300)
    label: str | None = Field(default=None, max_length=40)
    reset: bool = False


class ToolProposal(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    label: str = Field(default="", max_length=40)
    desc: str = Field(min_length=1, max_length=300)
    # 命令型：binary + argv；脚本型：script；接口型：http（三选一，具体校验在宿主机侧）
    binary: str = Field(default="", max_length=40)
    argv: list[str] = Field(default_factory=list, max_length=20)
    script: str = Field(default="", max_length=80)
    http: dict | None = None
    params: dict = Field(default_factory=dict)


@app.get("/api/tools")
def tools_overview(q: str = "", group: str = "", offset: int = 0, limit: int = catalog.PAGE):
    """工具面板数据：分组 + 一页条目。默认只回分组；带 group 或 q 才回条目。"""
    detail = ops_client.describe_tools()
    page = catalog.page_tools(detail.get("tools", {}), q, group, offset, limit)
    return {**page, "pending": detail.get("pending", 0),
            "mcp_servers": detail.get("mcp_servers", {}),
            "error": detail.get("error", ""), "agent_mode": AGENT_MODE}


@app.get("/api/tools/scripts")
def tools_scripts():
    return ops_client.list_scripts()


@app.post("/api/tools/override")
def tools_override(body: ToolOverride):
    if (body.enabled is None and body.desc is None
            and body.label is None and not body.reset):
        raise HTTPException(status_code=400, detail="没有要修改的字段")
    try:
        tool = ops_client.override(body.name, enabled_flag=body.enabled,
                                   desc=body.desc, label=body.label,
                                   reset=body.reset)
    except ops_client.OpsUnavailable as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"tool": tool}


@app.get("/api/tools/pending")
def tools_pending():
    return {"pending": ops_client.list_pending()}


@app.post("/api/tools/propose")
def tools_propose(body: ToolProposal):
    """提交新工具申请。申请不会生效，要在宿主机上批准。"""
    tool = body.model_dump()
    kind = "script" if tool.get("script") else "http" if tool.get("http") else "command"
    keep = {"script": ("script",), "http": ("http",), "command": ("binary", "argv")}[kind]
    for field in ("binary", "argv", "script", "http"):
        if field not in keep:
            tool.pop(field, None)
    try:
        result = ops_client.propose(tool, author=WEB_USER)
    except ops_client.OpsUnavailable as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    log.info("tool proposal queued: %s", body.name)
    return result


# --- Conversations -----------------------------------------------------------

@app.get("/api/conversations")
def list_conversations():
    return {"conversations": conversations.list_conversations()}


@app.get("/api/conversations/{conversation_id}")
def conversation_messages(conversation_id: str):
    if not conversations.exists(conversation_id):
        raise HTTPException(404, "对话不存在")
    messages = conversations.messages_of(conversation_id)
    # 助手消息挂上图谱里的执行身份，页面回放后仍能对这条回答打反馈；还没处理的沉淀提议也一起带回
    runs = graph.executions_by_message(conversation_id)
    pending = graph.pending_by_execution([run["execution_id"] for run in runs.values()])
    for message in messages:
        run = runs.get(message["id"])
        if run:
            message["execution_id"] = run["execution_id"]
            if run["execution_id"] in pending:
                message["proposal"] = proposal_view(pending[run["execution_id"]])
    return {"id": conversation_id, "messages": messages}


@app.delete("/api/conversations/{conversation_id}")
def delete_conversation(conversation_id: str):
    conversations.delete(conversation_id)
    agent_loop.forget(conversation_id)  # Agent 的完整记忆也一起删掉
    return {"deleted": conversation_id}


class FeedbackBody(BaseModel):
    execution_id: str = Field(min_length=1, max_length=64)
    verdict: Literal["correct", "false_alarm", "wrong_threshold", "missing_step"]
    note: str = Field(default="", max_length=300)


@app.post("/api/feedback")
def give_feedback(body: FeedbackBody):
    """人对一次回答/执行的判断，作为 human 来源的事实进图谱。"""
    try:
        feedback_id = graph.record_feedback(body.execution_id, body.verdict, body.note)
    except graph.UnknownExecution:
        raise HTTPException(404, "执行记录不存在")
    return {"id": feedback_id, "execution_id": body.execution_id, "verdict": body.verdict}


# --- Model settings ----------------------------------------------------------
#
# 网关地址、key 和模型名可以在管理页改。这是数据面设置：决定数据发给谁，不决定执行什么。
# 工具凭据（OPS_SECRET_* / OPS_TOKEN）不在这里，永远只在宿主机。

class SettingsBody(BaseModel):
    llm_base_url: str = Field(min_length=1, max_length=300, pattern=r"^https?://")
    llm_api_key: str = Field(default="", max_length=500)   # 留空 = 不改
    chat_model: str = Field(min_length=1, max_length=120)
    embed_model: str = Field(min_length=1, max_length=120)
    vision_models: list[str] = Field(default_factory=list, max_length=5)
    # 向量模型单独的地址 / key（没有网关时用）；留空 = 与对话模型相同
    embed_base_url: str = Field(default="", max_length=300, pattern=r"^(https?://.*)?$")
    embed_api_key: str = Field(default="", max_length=500)
    # 重排模型（网关上的 rerank 模型名），留空关闭
    rerank_model: str = Field(default="", max_length=120)
    # 换向量模型必须同时重建索引；页面要显式确认
    reindex: bool = False


@app.get("/api/settings")
def get_settings():
    return {**settings.public(), "docs": len(store.list_documents()), "index_dim": store.dimension(),
            "reindex_job": _reindex_job, "web_search": web_search.enabled(),
            "configured": settings.configured()}


@app.post("/api/settings/test")
def test_settings(body: SettingsBody):
    result = settings.test(body.llm_base_url, body.llm_api_key, body.chat_model, body.embed_model,
                           body.embed_base_url, body.embed_api_key, body.rerank_model)
    dim = store.dimension()
    if result.get("embed_dim") and dim and result["embed_dim"] != dim:
        result["dim_mismatch"] = f"当前索引是 {dim} 维，新向量模型是 {result['embed_dim']} 维，保存后必须重建索引"
    return result


_reindex_job: str | None = None


def reindex_all(report):
    """Re-embed every stored file with the current embedding model."""
    docs = store.list_documents()
    categories = {d["source"]: d["category"] for d in docs}
    files = sorted(p for p in FILES_DIR.iterdir() if p.is_file() and not p.name.startswith("."))
    report(f"清空旧索引（{len(docs)} 个文档）")
    store.reset_collection()
    done, failed = 0, []
    for i, path in enumerate(files, 1):
        report(f"重建索引 {i}/{len(files)}：{path.name}")
        try:
            ingest(path.name, path.read_bytes(), categories.get(path.name, ""))
            done += 1
        except HTTPException as exc:
            failed.append(f"{path.name}（{exc.detail}）")
        except Exception as exc:
            failed.append(f"{path.name}（{exc.__class__.__name__}）")
    return {"rebuilt": done, "failed": failed, "total": len(files)}


@app.put("/api/settings")
def put_settings(body: SettingsBody):
    global _reindex_job
    before = settings.current()
    if not body.llm_api_key and not before["llm_api_key"]:
        raise HTTPException(400, "首次配置必须填写 API Key")
    embed_changed = body.embed_model.strip() != before["embed_model"]
    url_changed = body.llm_base_url.strip().rstrip("/") != before["llm_base_url"].rstrip("/")
    # 清空向量地址 = 回到和对话同一处，也算换了地址
    if body.embed_base_url.strip().rstrip("/") != (before["embed_base_url"] or "").rstrip("/"):
        url_changed = True
    docs = len(store.list_documents())
    if embed_changed and docs and not body.reindex:
        raise HTTPException(409, f"换向量模型会让现有 {docs} 个文档的索引失效，请勾选「同时重建索引」再保存")
    settings.save(body.model_dump(exclude={"reindex"}))
    models._cache.update(at=0.0, models=[])
    # 模型刚配好：演示场景包不用等下一轮退避，马上开始导入
    packs.poke()
    result = {"saved": True, **settings.public()}
    if (embed_changed or (url_changed and body.reindex)) and docs:
        _reindex_job = jobs.submit("重建索引", lambda report: reindex_all(report))
        result["reindex_job"] = _reindex_job
    return result


@app.post("/api/settings/reindex")
def start_reindex():
    global _reindex_job
    if _reindex_job and (job := jobs.get(_reindex_job)) and job["status"] in ("queued", "running"):
        return {"reindex_job": _reindex_job}
    _reindex_job = jobs.submit("重建索引", lambda report: reindex_all(report))
    return {"reindex_job": _reindex_job}


@app.delete("/api/settings")
def reset_settings():
    settings.reset()
    models._cache.update(at=0.0, models=[])
    return settings.public()


# --- Ask ---------------------------------------------------------------------

@app.get("/api/models")
def list_models():
    """Chat models this deployment's key may call, default first."""
    return {"models": models.available(), "default": settings.get("chat_model")}


class Question(BaseModel):
    question: str = Field(min_length=1, max_length=2000)
    conversation_id: str | None = Field(default=None, max_length=64)
    # 联网搜索。页面上的「🌐 联网」开关默认开、每次请求显式传值；程序直接调 API 时默认关（不该默认外发任何东西）。
    # 服务端没配置搜索时这个值不起作用。
    web: bool = False
    # 页面选的模型；必须在网关返回的可用列表里，留空用默认。
    model: str | None = Field(default=None, max_length=120)
    # 「▶ 执行」发起的提问带上 SOP 的 id：这一轮在图谱里就记为一次 SOP 执行，而不只是一次提问。
    playbook_id: str | None = Field(default=None, max_length=64)


@app.post("/api/retrieve")
def retrieve_only(body: Question):
    """只检索不生成：用来核对混合召回（向量 + 关键词）的效果。"""
    return {"hits": retrieve(body.question.strip())}


def _with_stages(fn, *args):
    """在工作线程里跑 fn，把它经 progress 回调报告的阶段实时吐成 NDJSON 行；fn 的返回值作为生成器返回值。

    检索要几秒到几十秒，这期间要给页面发阶段事件，在生成器里同步调它就发不出去。
    contextvars 复制一份带进线程，LangSmith 的父 run 才跟得上。
    """
    box = queue.Queue()
    ctx = contextvars.copy_context()

    def work():
        try:
            box.put(("done", ctx.run(fn, *args, progress=lambda stage: box.put(("stage", stage)))))
        except BaseException as exc:
            box.put(("error", exc))

    threading.Thread(target=work, daemon=True, name="retrieve").start()
    while True:
        kind, payload = box.get()
        if kind == "stage":
            yield json.dumps({"stage": payload}, ensure_ascii=False) + "\n"
        elif kind == "done":
            return payload
        else:
            raise payload


@app.post("/api/ask")
def ask(payload: Question):
    if not settings.configured():
        raise HTTPException(503, settings.NOT_CONFIGURED)
    question = payload.question.strip()
    conversation_id = payload.conversation_id
    if conversation_id and not conversations.exists(conversation_id):
        raise HTTPException(404, "对话不存在，请新建对话")
    try:
        model_name = models.resolve(payload.model)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    if payload.playbook_id and not playbooks.get(payload.playbook_id):
        raise HTTPException(404, "SOP 不存在")

    history = conversations.recent_history(conversation_id) if conversation_id else []
    # Create the conversation first so the trace carries its real id from the very first turn.
    started_new = conversation_id is None
    conversation = ({"id": conversation_id} if conversation_id
                    else conversations.create(question))
    conversation_id = conversation["id"]

    root = start_root_run(question, conversation_id)
    overview = is_overview(question)
    continuation = is_continuation(question, history)
    # Tools are opt-in and degrade gracefully: no ops endpoint and no web search means plain RAG.
    allow_web = AGENT_MODE != "off" and payload.web and web_search.enabled()
    use_agent = AGENT_MODE != "off" and (ops_client.enabled() or allow_web)
    # 图谱里的这一轮：工具的完整返回、最终结论质量、人工反馈都挂在它下面
    execution_id = graph.start_execution(conversation_id, question, payload.playbook_id)

    def stream():
        """NDJSON: conversation, stage…, sources, stage, tool activity, thinking, then answer fragments.

        检索放在流里做：首行先发出去，等待期间页面能看到「改写 → 检索 → 重排 → 思考」在推进，
        而不是对着一个转圈等十几秒。代价是检索失败不能再回 502，只能作为 error 事件发出。
        """
        answer, failure, tool_calls, web_hits, message_id = "", None, [], [], None
        search_query, hits = question, []
        started = time.monotonic()
        retrieved_at = first_token_at = None

        def line(**event):
            return json.dumps(event, ensure_ascii=False) + "\n"

        try:
            yield line(conversation=conversation, model=model_name, execution_id=execution_id)
            try:
                with traced_under(root):
                    # 「知识库里有什么」答案来自文档目录；「继续」是在回应上一轮——两者都不用检索
                    if not (overview or continuation):
                        if history:
                            yield line(stage="rewrite")
                        search_query = rewrite_question(question, history)
                        hits = yield from _with_stages(retrieve, search_query)
            except Exception as exc:
                failure = f"检索失败：{exc.__class__.__name__}"
                yield line(error=failure)
                return
            retrieved_at = time.monotonic()
            yield line(sources=hits)
            conversations.add_message(conversation_id, "user", question)
            context = (catalog_context() if overview
                       else "（本轮是对上一轮的确认，没有重新检索；沿用上一轮的知识库依据和编号）" if continuation
                       else as_context(hits))
            yield line(stage="think")

            if use_agent:
                # The agent decides for itself whether the live environment is
                # needed; events stream out as they happen so the UI can show it.
                try:
                    with traced_under(root):
                        for kind, payload in agent_loop.run(question, context, history,
                                                            allow_web=allow_web,
                                                            thread_id=conversation_id,
                                                            model=model_name,
                                                            execution_id=execution_id):
                            if kind == "delta":
                                answer += payload
                                first_token_at = first_token_at or time.monotonic()
                            elif kind == "error":
                                failure = payload
                            elif kind == "tool_call":
                                tool_calls.append({"tool": payload["tool"], "args": payload.get("args") or {}})
                            elif kind == "tool_result" and tool_calls:
                                # 结果按顺序贴回最近一个还没有结果的调用，回放时能一起看到
                                for call in reversed(tool_calls):
                                    if "preview" not in call:
                                        call.update(preview=payload.get("preview", ""),
                                                    lines=payload.get("lines", 0))
                                        break
                            elif kind == "web_sources":
                                web_hits.extend(payload)
                            yield json.dumps({kind: payload}, ensure_ascii=False) + "\n"
                except Exception as exc:
                    failure = f"工具调用流程失败：{exc.__class__.__name__}"
                    yield line(error=failure)
            else:
                messages = build_messages(question, context, history)
                try:
                    # Re-attach to the root run: this body runs after the response returned.
                    with traced_under(root):
                        for kind, fragment in stream_answer(messages, model=model_name):
                            if kind == "delta":
                                answer += fragment
                                first_token_at = first_token_at or time.monotonic()
                            yield json.dumps({kind: fragment}, ensure_ascii=False) + "\n"
                except Exception as exc:
                    failure = f"大模型调用失败：{exc.__class__.__name__}"
                    yield line(error=failure)

            if answer.strip():
                message_id = conversations.add_message(conversation_id, "assistant", answer,
                                                       hits + web_hits, model=model_name,
                                                       tools=tool_calls)
        finally:
            try:
                graph.finish_execution(execution_id, answer, failed=failure is not None,
                                       message_id=message_id)
                # 自由排查用了工具并答完了：后台看看值不值得沉淀为 SOP，不占这个请求
                if use_agent and message_id is not None and any(c["tool"] != web_search.TOOL_NAME
                                                                 for c in tool_calls):
                    grow.schedule(execution_id, answer, tool_specs)
            except Exception:
                log.warning("failed to finish execution %s", execution_id, exc_info=True)
            # 新对话这一轮什么都没答出来（检索或模型失败）：不在历史里留一个空对话。页面按同一规则忘掉它的 id。
            if started_new and message_id is None:
                conversations.delete(conversation_id)
            now = time.monotonic()
            log.info("ask %s: retrieve=%s first_token=%s total=%.1fs tools=%d model=%s%s",
                     conversation_id[:8],
                     f"{retrieved_at - started:.1f}s" if retrieved_at else "-",
                     f"{first_token_at - started:.1f}s" if first_token_at else "-",
                     now - started, len(tool_calls), model_name,
                     f" failure={failure}" if failure else "")
            finish_root_run(root, outputs={"answer": answer, "search_query": search_query,
                                           "sources": len(hits), "web_sources": len(web_hits),
                                           "model": model_name,
                                           "tools_used": [c["tool"] for c in tool_calls]},
                            error=failure)

    return StreamingResponse(stream(), media_type="application/x-ndjson")


# 演示场景包：DEMO_PACKS 非空时，模型一配好就在后台把文档和 SOP 导进来（docs/场景包.md）。
packs.start_autoimport(ingest, lambda: set(usable_tools()))
