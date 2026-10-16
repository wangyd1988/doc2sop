"""HTTP API and web UI."""
import hashlib
import json
import re
import secrets
from pathlib import Path

from fastapi import Depends, FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, StreamingResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel, Field

from app import conversations
from app.agent import loop as agent_loop
from app.agent import ops_client
from app.config import (AGENT_MODE, ALLOWED_SUFFIXES, CATEGORY_MAX, CHAT_MODEL, BOT_NAME,
                        FILES_DIR, IMAGE_SUFFIXES, MAX_FILE_BYTES, WEB_PASSWORD, WEB_USER)
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

@app.get("/api/documents")
def documents():
    return {"documents": store.list_documents(), "categories": store.all_categories(),
            "chat_model": CHAT_MODEL, "bot_name": BOT_NAME,
            "tools": sorted(ops_client.available_tools()) if AGENT_MODE != "off" else []}


@app.post("/api/documents")
def upload(file: UploadFile = File(...), category: str = Form("")):
    name = safe_name(file.filename)
    data = file.file.read(MAX_FILE_BYTES + 1)
    if len(data) > MAX_FILE_BYTES:
        raise HTTPException(413, f"文件超过 {MAX_FILE_BYTES // 1024 // 1024}MB")
    if not data:
        raise HTTPException(400, "文件为空")
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
    return {"deleted": name}


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
    return {"deleted": conversation_id}


# --- Ask ---------------------------------------------------------------------

class Question(BaseModel):
    question: str = Field(min_length=1, max_length=2000)
    conversation_id: str | None = Field(default=None, max_length=64)


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

    # Tools are opt-in and degrade gracefully: no ops endpoint means plain RAG.
    use_agent = AGENT_MODE != "off" and ops_client.enabled()

    conversations.add_message(conversation_id, "user", question)

    def stream():
        """NDJSON: conversation, sources, tool activity, then answer fragments."""
        answer, failure, tool_calls = "", None, []
        try:
            yield json.dumps({"conversation": conversation}, ensure_ascii=False) + "\n"
            yield json.dumps({"sources": hits}, ensure_ascii=False) + "\n"
            context = as_context(hits)

            if use_agent:
                # The agent decides for itself whether the live environment is
                # needed; events stream out as they happen so the UI can show it.
                try:
                    with traced_under(root):
                        for kind, payload in agent_loop.run(question, context, history):
                            if kind == "delta":
                                answer += payload
                            elif kind == "error":
                                failure = payload
                            elif kind == "tool_call":
                                tool_calls.append(payload)
                            yield json.dumps({kind: payload}, ensure_ascii=False) + "\n"
                except Exception as exc:
                    failure = f"排障流程失败：{exc.__class__.__name__}"
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
                conversations.add_message(conversation_id, "assistant", answer, hits)
        finally:
            finish_root_run(root, outputs={"answer": answer, "search_query": search_query,
                                           "sources": len(hits),
                                           "tools_used": [c["tool"] for c in tool_calls]},
                            error=failure)

    return StreamingResponse(stream(), media_type="application/x-ndjson")
