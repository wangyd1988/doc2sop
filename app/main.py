"""HTTP API and web UI."""
import hashlib
import json
import re
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import Depends, FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, StreamingResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel, Field

from app import conversations, playbooks
from app.agent import loop as agent_loop
from app.agent import ops_client, web_search
from app.agent.extract import extract as extract_playbooks
from app.config import (AGENT_MODE, ALLOWED_SUFFIXES, CATEGORY_MAX, CHAT_MODEL, BOT_NAME,
                        FILES_DIR, IMAGE_SUFFIXES, MAX_FILE_BYTES, WEB_PASSWORD, WEB_USER,
                        log)
from app.ingest.extract import ExtractionError, extract_pages
from app.ingest.vision import ImageCollector
from app.rag import store
from app.rag.answer import build_messages, rewrite_question, stream_answer, suggest_category
from app.rag.chunking import chunk_pages
from app.rag.embedding import EmbeddingError, embed_documents
from app.rag.retrieval import as_context, retrieve
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


@app.get("/api/documents")
def documents():
    tools = usable_tools()
    return {"documents": store.list_documents(), "categories": store.all_categories(),
            "chat_model": CHAT_MODEL, "bot_name": BOT_NAME,
            "tools": sorted(tools),
            "web_search": AGENT_MODE != "off" and web_search.enabled(),
            "playbooks": len(playbooks.list_all(only_enabled=True))}


@app.post("/api/documents")
def upload(file: UploadFile = File(...), category: str = Form("")):
    name = safe_name(file.filename)
    data = file.file.read(MAX_FILE_BYTES + 1)
    if len(data) > MAX_FILE_BYTES:
        raise HTTPException(413, f"文件超过 {MAX_FILE_BYTES // 1024 // 1024}MB")
    if not data:
        raise HTTPException(400, "文件为空")
    return ingest(name, data, category)


def ingest(name: str, data: bytes, category: str = ""):
    """Parse, chunk, embed and store one file. Shared by uploads and saved web notes."""
    digest = hashlib.sha256(data).hexdigest()

    images = ImageCollector()
    try:
        pages = extract_pages(name, data, images)
    except ExtractionError as exc:
        raise HTTPException(400, str(exc))
    images.describe_all()
    if Path(name).suffix.lower() in IMAGE_SUFFIXES and images.failed:
        raise HTTPException(502, "图片识别失败，可能是图片内容无法解析或模型暂时不可用，请稍后重试")

    # Splice recognised image text back into the position it occupied.
    pages = [(page, images.fill(text)) for page, text in pages]
    probe = "\n".join(text for _, text in pages)[:1000]
    chosen = category.strip()[:CATEGORY_MAX] or suggest_category(
        name, probe, store.all_categories())

    ids, texts, metas = chunk_pages(name, pages, digest, chosen)
    if not texts:
        raise HTTPException(400, "没有提取到文字或有用的图片内容（扫描件请确认图片清晰度）")

    try:
        vectors = embed_documents(texts)
    except EmbeddingError as exc:
        raise HTTPException(502, f"向量化失败：{exc}（向量服务可能不可达）")

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
    # 文档没了，从它抽出来的技能也一并清掉，避免留下孤儿流程。
    removed = playbooks.delete_by_source(name)
    return {"deleted": name, "playbooks_removed": removed}


# --- Playbooks ---------------------------------------------------------------

class PlaybookStep(BaseModel):
    tool: str = Field(min_length=1, max_length=60)
    args: dict = Field(default_factory=dict)
    checkpoint: str = Field(default="", max_length=300)


class PlaybookBody(BaseModel):
    name: str = Field(min_length=1, max_length=playbooks.NAME_MAX)
    trigger: str = Field(default="", max_length=playbooks.TRIGGER_MAX)
    steps: list[PlaybookStep] = Field(min_length=1, max_length=playbooks.STEP_MAX)
    enabled: bool = True


@app.get("/api/playbooks")
def list_playbooks():
    tools = usable_tools()
    items = playbooks.list_all()
    for item in items:
        # 工具被下线后，依赖它的技能要在界面上标出来，而不是静默失效。
        item["missing_tools"] = sorted({s["tool"] for s in item["steps"]
                                        if s["tool"] not in tools})
    return {"playbooks": items, "tools": tools}


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
        raise HTTPException(404, "技能不存在")
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
    """从已入库的文档里抽取候选技能，返回但不直接保存，由用户确认。"""
    name = safe_name(body.source)
    tools = usable_tools()
    if not tools:
        raise HTTPException(400, "当前没有可用的工具，无法编排技能")

    chunks = store.collection.get(where={"source": name}, include=["documents"])
    if not chunks["documents"]:
        raise HTTPException(404, "文档不存在")
    text = "\n".join(chunks["documents"][:30])

    candidates, note = extract_playbooks(name, text, tools)
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


# --- Tools -------------------------------------------------------------------
#
# 页面能改工具的哪些部分，是一条安全边界：
#   启停、改描述  -> 直接生效（都不改变实际执行的命令）
#   新增工具      -> 只能提交申请，由人在宿主机上批准后才写入配置
# 命令模板永远只在宿主机那份手写配置里定义，这个接口碰不到。

class ToolOverride(BaseModel):
    name: str = Field(min_length=1, max_length=60)
    enabled: bool | None = None
    desc: str | None = Field(default=None, max_length=300)
    label: str | None = Field(default=None, max_length=40)
    reset: bool = False


class ToolProposal(BaseModel):
    name: str = Field(min_length=1, max_length=40)
    label: str = Field(default="", max_length=40)
    desc: str = Field(min_length=1, max_length=300)
    # 命令型：binary + argv；脚本型：script；接口型：http（三选一，具体校验在宿主机侧）
    binary: str = Field(default="", max_length=40)
    argv: list[str] = Field(default_factory=list, max_length=20)
    script: str = Field(default="", max_length=80)
    http: dict | None = None
    params: dict = Field(default_factory=dict)


@app.get("/api/tools")
def tools_overview():
    detail = ops_client.describe_tools()
    return {"tools": detail.get("tools", {}), "pending": detail.get("pending", 0),
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
    return {"id": conversation_id, "messages": conversations.messages_of(conversation_id)}


@app.delete("/api/conversations/{conversation_id}")
def delete_conversation(conversation_id: str):
    conversations.delete(conversation_id)
    agent_loop.forget(conversation_id)  # Agent 的完整记忆也一起删掉
    return {"deleted": conversation_id}


# --- Ask ---------------------------------------------------------------------

class Question(BaseModel):
    question: str = Field(min_length=1, max_length=2000)
    conversation_id: str | None = Field(default=None, max_length=64)
    # 页面上的「🌐 联网」开关；服务端没配置搜索时这个值不起作用。
    web: bool = True


@app.post("/api/ask")
def ask(payload: Question):
    question = payload.question.strip()
    conversation_id = payload.conversation_id
    if conversation_id and not conversations.exists(conversation_id):
        raise HTTPException(404, "对话不存在，请新建对话")

    history = conversations.recent_history(conversation_id) if conversation_id else []
    # Create the conversation first so the trace carries its real id from the very first turn.
    started_new = conversation_id is None
    conversation = ({"id": conversation_id} if conversation_id
                    else conversations.create(question))
    conversation_id = conversation["id"]

    root = start_root_run(question, conversation_id)
    try:
        with traced_under(root):
            search_query = rewrite_question(question, history)
            hits = retrieve(search_query)
    except Exception as exc:
        finish_root_run(root, error=f"检索失败：{exc.__class__.__name__}")
        if started_new:
            conversations.delete(conversation_id)
        raise HTTPException(502, f"检索失败：{exc.__class__.__name__}")

    # Tools are opt-in and degrade gracefully: no ops endpoint and no web search means plain RAG.
    allow_web = AGENT_MODE != "off" and payload.web and web_search.enabled()
    use_agent = AGENT_MODE != "off" and (ops_client.enabled() or allow_web)

    conversations.add_message(conversation_id, "user", question)

    def stream():
        """NDJSON: conversation, sources, tool activity, then answer fragments."""
        answer, failure, tool_calls, web_hits = "", None, [], []
        try:
            yield json.dumps({"conversation": conversation}, ensure_ascii=False) + "\n"
            yield json.dumps({"sources": hits}, ensure_ascii=False) + "\n"
            context = as_context(hits)

            if use_agent:
                # The agent decides for itself whether the live environment is
                # needed; events stream out as they happen so the UI can show it.
                try:
                    with traced_under(root):
                        for kind, payload in agent_loop.run(question, context, history,
                                                            allow_web=allow_web,
                                                            thread_id=conversation_id):
                            if kind == "delta":
                                answer += payload
                            elif kind == "error":
                                failure = payload
                            elif kind == "tool_call":
                                tool_calls.append(payload)
                            elif kind == "web_sources":
                                web_hits.extend(payload)
                            yield json.dumps({kind: payload}, ensure_ascii=False) + "\n"
                except Exception as exc:
                    failure = f"工具调用流程失败：{exc.__class__.__name__}"
                    yield json.dumps({"error": failure}, ensure_ascii=False) + "\n"
            else:
                messages = build_messages(question, context, history)
                try:
                    # Re-attach to the root run: this body runs after the response returned.
                    with traced_under(root):
                        for fragment in stream_answer(messages):
                            answer += fragment
                            yield json.dumps({"delta": fragment}, ensure_ascii=False) + "\n"
                except Exception as exc:
                    failure = f"大模型调用失败：{exc.__class__.__name__}"
                    yield json.dumps({"error": failure}, ensure_ascii=False) + "\n"

            if answer.strip():
                conversations.add_message(conversation_id, "assistant", answer, hits + web_hits)
        finally:
            finish_root_run(root, outputs={"answer": answer, "search_query": search_query,
                                           "sources": len(hits), "web_sources": len(web_hits),
                                           "tools_used": [c["tool"] for c in tool_calls]},
                            error=failure)

    return StreamingResponse(stream(), media_type="application/x-ndjson")
