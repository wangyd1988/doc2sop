"""Environment-driven configuration for the knowledge base service."""
import logging
import os
from pathlib import Path

# --- Model gateway (LiteLLM) -------------------------------------------------
# Every model call goes through one OpenAI-compatible gateway, so switching
# providers never touches application code.
LLM_BASE_URL = os.environ["LLM_BASE_URL"]
LLM_API_KEY = os.environ["LLM_API_KEY"]
CHAT_MODEL = os.environ.get("CHAT_MODEL", "kb-chat")
EMBED_MODEL = os.environ.get("EMBED_MODEL", "kb-embedding")
# 没有网关、向量模型在另一个厂商时填这两个；留空则和对话模型同一地址同一 key。
EMBED_BASE_URL = os.environ.get("EMBED_BASE_URL", "").strip()
EMBED_API_KEY = os.environ.get("EMBED_API_KEY", "").strip()
VISION_MODELS = [m.strip() for m in
                 os.environ.get("VISION_MODELS", "kb-vision").split(",") if m.strip()]
# Some providers do not really stop thinking for reasoning_effort="none" — they just merge the
# reasoning into the answer text. Leave this empty unless a model is verified to honour it.
REASONING_EFFORT = os.environ.get("REASONING_EFFORT", "").strip()

# --- Web ---------------------------------------------------------------------
WEB_USER = os.environ["WEB_USER"]
WEB_PASSWORD = os.environ["WEB_PASSWORD"]
PORT = int(os.environ.get("PORT", "8765"))
BOT_NAME = os.environ.get("BOT_NAME", "小知")

# --- Storage -----------------------------------------------------------------
DATA_DIR = Path(os.environ.get("DATA_DIR", "/data"))
FILES_DIR = DATA_DIR / "files"
CHROMA_DIR = DATA_DIR / "chroma"
CHAT_DB_PATH = DATA_DIR / "chat.db"
VISION_CACHE_PATH = DATA_DIR / "vision_cache.json"

# --- Ingestion ---------------------------------------------------------------
MAX_FILE_BYTES = int(os.environ.get("MAX_FILE_MB", "50")) * 1024 * 1024
IMAGE_SUFFIXES = {".png", ".jpg", ".jpeg", ".webp", ".bmp", ".gif"}
ALLOWED_SUFFIXES = {".md", ".markdown", ".txt", ".pdf", ".docx", ".pptx"} | IMAGE_SUFFIXES
CHUNK_SIZE = int(os.environ.get("CHUNK_SIZE", "400"))
CHUNK_OVERLAP = int(os.environ.get("CHUNK_OVERLAP", "50"))
DEFAULT_CATEGORY = "未分类"
CATEGORY_MAX = 12

# --- Vision OCR --------------------------------------------------------------
# Caps keep a single upload from exhausting a 2 GB host or the model budget.
MAX_IMAGES_PER_FILE = int(os.environ.get("MAX_IMAGES_PER_FILE", "40"))
MIN_IMAGE_SIDE = 100
MIN_IMAGE_AREA = 40000
MAX_IMAGE_SIDE = 1600
VISION_WORKERS = int(os.environ.get("VISION_WORKERS", "3"))

# --- Retrieval ---------------------------------------------------------------
TOP_K = int(os.environ.get("TOP_K", "8"))
# Drop clearly unrelated chunks so greetings and chit-chat are not answered with noise.
MIN_SCORE = float(os.environ.get("MIN_SCORE", "0.25"))
HISTORY_MESSAGES = int(os.environ.get("HISTORY_MESSAGES", "8"))
HISTORY_CHARS = 1200

# --- Observability -----------------------------------------------------------
# Only build LangSmith runs when tracing is on; RunTree would otherwise still call out.
TRACING = os.environ.get("LANGSMITH_TRACING", "").strip().lower() in ("true", "1", "yes")

# --- Read-only ops tools -----------------------------------------------------
# The agent reaches the host only through this endpoint, which enforces an
# allowlist of read-only commands. Leave OPS_URL empty to disable tools entirely.
OPS_URL = os.environ.get("OPS_URL", "").strip()
OPS_TOKEN = os.environ.get("OPS_TOKEN", "").strip()
AGENT_MODE = os.environ.get("AGENT_MODE", "auto").strip().lower()

# --- Web search (through the gateway) ----------------------------------------
# Name of a LiteLLM search tool (config.yaml `search_tools`). Empty disables web
# search. Going through the gateway means it also works on intranets that can
# only reach the gateway, and the search provider's keys never leave it.
WEB_SEARCH_TOOL = os.environ.get("WEB_SEARCH_TOOL", "").strip()
WEB_SEARCH_MAX_RESULTS = int(os.environ.get("WEB_SEARCH_MAX_RESULTS", "5"))
# Internal names that must never be sent to a public search engine, comma separated.
WEB_SEARCH_BLOCKLIST = [w.strip() for w in
                        os.environ.get("WEB_SEARCH_BLOCKLIST", "").split(",") if w.strip()]

log = logging.getLogger("kb")


def why(exc: Exception) -> str:
    """Readable failure reason: the exception type plus its original message."""
    message = str(exc).strip().replace("\n", " ")
    return f"{exc.__class__.__name__}：{message[:160]}" if message else exc.__class__.__name__
