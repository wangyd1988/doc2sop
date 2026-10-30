"""Environment-driven configuration for the knowledge base service."""
import logging
import os
from pathlib import Path

# --- Model endpoints ---------------------------------------------------------
# All model calls go through OpenAI-compatible endpoints: one gateway for everything,
# or separate vendors for chat and embeddings. These may be left empty: the app then
# starts in "unconfigured" mode and the management page walks the user through setup.
LLM_BASE_URL = os.environ.get("LLM_BASE_URL", "").strip()
LLM_API_KEY = os.environ.get("LLM_API_KEY", "").strip()
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
# 助手自称，也是页面标题与顶栏品牌；团队想给它起自己的名字就设 BOT_NAME。
BOT_NAME = os.environ.get("BOT_NAME", "").strip() or "doc2sop"

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
# Cross-encoder rerank through the gateway (LiteLLM /rerank). Empty = off.
# A base-size cross-encoder costs ~0.3 s per passage on 2 vCPUs, so only the top
# few fused candidates are rescored; the rest keep their fused order.
RERANK_MODEL = os.environ.get("RERANK_MODEL", "").strip()
RERANK_CANDIDATES = int(os.environ.get("RERANK_CANDIDATES", "8"))
RERANK_TIMEOUT = float(os.environ.get("RERANK_TIMEOUT", "10"))
# 向量模型请求超时（秒）。不设的话 OpenAI 客户端默认 600 s 还重试两次，向量服务一悬挂，一次提问能卡 20 分钟。
# 查询只有一条短文本，超时后检索降级为只用关键词召回；入库每个请求最多 16 段（clients.py 的 chunk_size），
# 自托管的 CPU 向量服务要跑几秒到几十秒，所以单独给一个宽松得多的上限。
EMBED_TIMEOUT = float(os.environ.get("EMBED_TIMEOUT", "15"))
EMBED_INGEST_TIMEOUT = float(os.environ.get("EMBED_INGEST_TIMEOUT", "120"))
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

# --- Knowledge tools and plan (docs/工具.md「知识类工具」) -------------------------
# KB_TOOLS 打开后模型能自己补查知识库（kb_search / kb_read / kb_catalog）；没有工具服务、也没开联网的部署
# 也会因此走 Agent 分支。KB_RETRIEVAL_MODE 只在 KB_TOOLS 打开时起作用：
#   prefetch  代码先检索一次、片段放进提示词，不够时模型补查（默认）
#   forced    不预检索，第一轮强制模型调 kb_search；模型不支持指定 tool_choice 时退回 prefetch
#   agentic   不预检索，查不查由模型决定
_TRUE = ("true", "1", "yes")
KB_TOOLS = os.environ.get("KB_TOOLS", "").strip().lower() in _TRUE
RETRIEVAL_MODES = ("prefetch", "forced", "agentic")
KB_RETRIEVAL_MODE = os.environ.get("KB_RETRIEVAL_MODE", "prefetch").strip().lower()
# 待办清单工具 plan：长 SOP 不漏步，「▶ 执行」时按 SOP 步骤预填
PLAN_TOOL = os.environ.get("PLAN_TOOL", "").strip().lower() in _TRUE
# 评测按请求覆盖检索模式（eval/run_eval.py --mode）要带的令牌。留空时应用启动时生成一个，
# 写在 DATA_DIR/eval_token（权限 600），只有能登录宿主机的人读得到。
EVAL_TOKEN = os.environ.get("EVAL_TOKEN", "").strip()
# 联网搜索得到、人确认后存回知识库的文档归在这个分类；知识类工具给模型看时标「来自网络，未核实」
WEB_NOTE_CATEGORY = "网络补充"

# --- Web search (through the gateway) ----------------------------------------
# Name of a LiteLLM search tool (config.yaml `search_tools`). Empty disables web
# search. Going through the gateway means it also works on intranets that can
# only reach the gateway, and the search provider's keys never leave it.
WEB_SEARCH_TOOL = os.environ.get("WEB_SEARCH_TOOL", "").strip()
WEB_SEARCH_MAX_RESULTS = int(os.environ.get("WEB_SEARCH_MAX_RESULTS", "5"))
# Internal names that must never be sent to a public search engine, comma separated.
WEB_SEARCH_BLOCKLIST = [w.strip() for w in
                        os.environ.get("WEB_SEARCH_BLOCKLIST", "").split(",") if w.strip()]

# --- 读网页与出网规则（docs/工具.md「出网规则」）-----------------------------------
# WEB_FETCH 打开后，允许联网的轮次多一个 web_fetch：读本轮搜索结果或用户给的链接的正文。默认关。
WEB_FETCH = os.environ.get("WEB_FETCH", "").strip().lower() in _TRUE
# web_fetch 的出口代理：http://主机:端口（可带账号密码）。留空直连。经代理时 DNS 仍在本机解析、
# CONNECT 到校验过的 IP，防 SSRF 的规则不变。
WEB_FETCH_PROXY = os.environ.get("WEB_FETCH_PROXY", "").strip()
# 一轮里调过数据类工具之后还能不能联网：screen（默认）照常联网，搜索词和链接过静态拦截与污点拦截；
# deny 这一轮剩下的部分不再联网。
WEB_AFTER_DATA_MODES = ("screen", "deny")
WEB_AFTER_DATA = os.environ.get("WEB_AFTER_DATA", "screen").strip().lower()

# --- Growing SOPs from practice -----------------------------------------------
# After a free-form investigation that used several tools and reached a conclusion,
# the agent may propose turning it into an SOP (saved disabled, pending human review).
AUTO_SOP_PROPOSALS = os.environ.get("AUTO_SOP_PROPOSALS", "true").strip().lower() in ("true", "1", "yes")
SOP_PROPOSALS_PER_DAY = int(os.environ.get("SOP_PROPOSALS_PER_DAY", "10"))
# 启用的 SOP 超过这么多个，项目 Agent 的提示词里只放名称和适用场景，步骤由模型用 sop_get 现取；不到时和以前一样整段放进去
SOP_PROMPT_MAX = int(os.environ.get("SOP_PROMPT_MAX", "30"))

# --- 对外 MCP 出口（docs/工具.md「对外 MCP 出口」）-----------------------------------
# 打开后应用多一个 /mcp：外部智能体（Claude Code、Copilot、Cursor…）凭管理页「对外接入」签发的令牌查知识库、
# 按 SOP 排查、调宿主机标了 export 的只读数据工具。关着时 /mcp 不存在，应用行为和以前完全一样。
MCP_ENABLED = os.environ.get("MCP_ENABLED", "").strip().lower() in _TRUE
# 每枚令牌每分钟最多调用几次工具 / 提示词、单次返回最多多少字；签发时可以单独设，留空用这两个默认值
MCP_RATE_PER_MINUTE = int(os.environ.get("MCP_RATE_PER_MINUTE", "60"))
MCP_MAX_RESULT_CHARS = int(os.environ.get("MCP_MAX_RESULT_CHARS", "20000"))
# 只接受这些 Host（逗号分隔，如 kb.example.com,10.0.0.5:8765）；留空不检查 Host——/mcp 只认令牌，
# 令牌不是浏览器会自动带上的凭据，DNS 重绑定拿它没办法。反向代理后面想再加一道，就把对外域名填上。
# 注意 Host 头由客户端随便写：这只防 DNS 重绑定，不是访问控制；限制谁能连用下面的 MCP_CLIENTS
MCP_ALLOWED_HOSTS = [h.strip() for h in os.environ.get("MCP_ALLOWED_HOSTS", "").split(",") if h.strip()]
# 只接受这些来源的 /mcp 连接：TCP 对端地址，逗号分隔的 IP 或网段（如 127.0.0.1,::1 或 10.0.0.0/8）；留空不检查。
# 只经 SSH 隧道用时填 127.0.0.1,::1——隧道进来的连接对端是本机，公网来的不是。认令牌之前先查，不在名单里一律 403
MCP_CLIENTS = [c.strip() for c in os.environ.get("MCP_CLIENTS", "").split(",") if c.strip()]
# 多久检查一次工具、文档、SOP 有没有变化（变了就给连着的客户端发 list_changed）
MCP_WATCH_SECONDS = float(os.environ.get("MCP_WATCH_SECONDS", "30"))
# 对外调用审计记录保留多少天
MCP_AUDIT_DAYS = int(os.environ.get("MCP_AUDIT_DAYS", "180"))

# --- Scenario packs ----------------------------------------------------------
# 场景包 = 文档 + 工具定义 + SOP 的目录（docs/场景包.md）。镜像里 app/ 和 packs/ 是兄弟目录，
# 源码检出时也是，所以默认值两边都对。
PACKS_DIR = Path(os.environ.get("PACKS_DIR", "") or Path(__file__).resolve().parent.parent / "packs")
# 模型配好、工具在线后自动导入的包 id，逗号分隔；留空不自动导入（接口手动导入不受影响）。
DEMO_PACKS = [p.strip() for p in os.environ.get("DEMO_PACKS", "").split(",") if p.strip()]

log = logging.getLogger("kb")
# uvicorn 只配置自己的 logger，不配 root；不挂这个 handler，下面所有 log.info（检索计时、
# 「rerank skipped」这类诊断）都会被静默丢掉，docker logs 里只剩 WARNING。
if not log.handlers:
    _handler = logging.StreamHandler()
    _handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s kb: %(message)s"))
    log.addHandler(_handler)
    log.setLevel(logging.INFO)
    log.propagate = False

if KB_RETRIEVAL_MODE not in RETRIEVAL_MODES:
    log.warning("KB_RETRIEVAL_MODE=%s is not one of %s, using prefetch", KB_RETRIEVAL_MODE, "/".join(RETRIEVAL_MODES))
    KB_RETRIEVAL_MODE = "prefetch"

if WEB_AFTER_DATA not in WEB_AFTER_DATA_MODES:
    log.warning("WEB_AFTER_DATA=%s is not one of %s, using screen", WEB_AFTER_DATA, "/".join(WEB_AFTER_DATA_MODES))
    WEB_AFTER_DATA = "screen"


def why(exc: Exception) -> str:
    """Readable failure reason: the exception type plus its original message."""
    message = str(exc).strip().replace("\n", " ")
    return f"{exc.__class__.__name__}：{message[:160]}" if message else exc.__class__.__name__
