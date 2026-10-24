"""Model clients. Everything talks to one OpenAI-compatible gateway.

Clients are module globals so tests can patch them, but they are rebuilt by
`reload()` whenever the settings page saves — callers must therefore reference
them as `clients.llm`, not `from app.clients import llm`.
"""
from langchain_openai import ChatOpenAI, OpenAIEmbeddings

from app import settings
from app.config import EMBED_INGEST_TIMEOUT, EMBED_TIMEOUT, REASONING_EFFORT


def chat_model(**overrides) -> ChatOpenAI:
    """Build a chat client; reasoning_effort is only sent when explicitly configured."""
    cur = settings.current()
    kwargs = {"model": cur["chat_model"], "base_url": cur["llm_base_url"], "api_key": cur["llm_api_key"],
              "temperature": 0}
    if REASONING_EFFORT:
        kwargs["reasoning_effort"] = REASONING_EFFORT
    kwargs.update(overrides)
    return ChatOpenAI(**kwargs)


llm = rewriter = embeddings = embeddings_bulk = None
vision_llms: list = []
vision_names: list = []


def reload():
    global llm, rewriter, embeddings, embeddings_bulk, vision_llms, vision_names
    cur = settings.current()
    if not settings.configured():
        # 还没配置：客户端留空，调用方按「未配置」处理，而不是去连一个不存在的地址
        llm = rewriter = embeddings = embeddings_bulk = None
        vision_llms, vision_names = [], []
        return
    # Answer generation: long timeout, one retry.
    llm = chat_model(timeout=120, max_retries=1)
    # Query rewriting and auto-categorising: short, cheap, fail fast.
    rewriter = chat_model(timeout=30, max_retries=0, max_tokens=120)
    # Vision models are tried in order; the first one that answers wins.
    vision_names = list(cur["vision_models"])
    vision_llms = [ChatOpenAI(model=name, base_url=cur["llm_base_url"], api_key=cur["llm_api_key"],
                              temperature=0, timeout=90, max_retries=0, max_tokens=1500)
                   for name in vision_names]
    e_url, e_key = settings.embed_endpoint(cur)

    def embedder(timeout):
        return OpenAIEmbeddings(
            model=cur["embed_model"], base_url=e_url, api_key=e_key,
            request_timeout=timeout, max_retries=1,
            # The self-hosted embedding server accepts raw strings only, not token-id arrays.
            check_embedding_ctx_length=False,
            # It also caps each request at 16 inputs.
            chunk_size=16)

    # 查询一条短文本，等不起就降级成关键词召回；入库一批 16 段在 CPU 向量服务上要慢得多，上限单独给
    embeddings = embedder(EMBED_TIMEOUT)
    embeddings_bulk = embedder(EMBED_INGEST_TIMEOUT)


reload()
