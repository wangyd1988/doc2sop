"""Model clients. Everything talks to one OpenAI-compatible gateway."""
from langchain_openai import ChatOpenAI, OpenAIEmbeddings

from app.config import (CHAT_MODEL, EMBED_MODEL, LLM_API_KEY, LLM_BASE_URL,
                        REASONING_EFFORT, VISION_MODELS)


def chat_model(**overrides) -> ChatOpenAI:
    """Build a chat client; reasoning_effort is only sent when explicitly configured."""
    kwargs = {"model": CHAT_MODEL, "base_url": LLM_BASE_URL, "api_key": LLM_API_KEY,
              "temperature": 0}
    if REASONING_EFFORT:
        kwargs["reasoning_effort"] = REASONING_EFFORT
    kwargs.update(overrides)
    return ChatOpenAI(**kwargs)


# Answer generation: long timeout, one retry.
llm = chat_model(timeout=120, max_retries=1)
# Query rewriting and auto-categorising: short, cheap, fail fast.
rewriter = chat_model(timeout=30, max_retries=0, max_tokens=120)

# Vision models are tried in order; the first one that answers wins.
vision_llms = [ChatOpenAI(model=name, base_url=LLM_BASE_URL, api_key=LLM_API_KEY,
                          temperature=0, timeout=90, max_retries=0, max_tokens=1500)
               for name in VISION_MODELS]

embeddings = OpenAIEmbeddings(
    model=EMBED_MODEL,
    base_url=LLM_BASE_URL,
    api_key=LLM_API_KEY,
    # The self-hosted embedding server accepts raw strings only, not token-id arrays.
    check_embedding_ctx_length=False,
    # It also caps each request at 16 inputs.
    chunk_size=16,
)
