"""Model clients. Everything talks to one OpenAI-compatible gateway.

Clients are module globals so tests can patch them, but they are rebuilt by
`reload()` whenever the settings page saves — callers must therefore reference
them as `clients.llm`, not `from app.clients import llm`.
"""
from langchain_openai import ChatOpenAI, OpenAIEmbeddings

from app import settings
from app.config import REASONING_EFFORT


def chat_model(**overrides) -> ChatOpenAI:
    """Build a chat client; reasoning_effort is only sent when explicitly configured."""
    cur = settings.current()
    kwargs = {"model": cur["chat_model"], "base_url": cur["llm_base_url"], "api_key": cur["llm_api_key"],
              "temperature": 0}
    if REASONING_EFFORT:
        kwargs["reasoning_effort"] = REASONING_EFFORT
    kwargs.update(overrides)
    return ChatOpenAI(**kwargs)


llm = rewriter = embeddings = None
vision_llms: list = []
vision_names: list = []


def reload():
    global llm, rewriter, embeddings, vision_llms, vision_names
    cur = settings.current()
    # Answer generation: long timeout, one retry.
    llm = chat_model(timeout=120, max_retries=1)
    # Query rewriting and auto-categorising: short, cheap, fail fast.
    rewriter = chat_model(timeout=30, max_retries=0, max_tokens=120)
    # Vision models are tried in order; the first one that answers wins.
    vision_names = list(cur["vision_models"])
    vision_llms = [ChatOpenAI(model=name, base_url=cur["llm_base_url"], api_key=cur["llm_api_key"],
                              temperature=0, timeout=90, max_retries=0, max_tokens=1500)
                   for name in vision_names]
    embeddings = OpenAIEmbeddings(
        model=cur["embed_model"], base_url=cur["llm_base_url"], api_key=cur["llm_api_key"],
        # The self-hosted embedding server accepts raw strings only, not token-id arrays.
        check_embedding_ctx_length=False,
        # It also caps each request at 16 inputs.
        chunk_size=16)


reload()
