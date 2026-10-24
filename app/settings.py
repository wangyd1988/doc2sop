"""Model connection settings, editable from the management page.

The `.env` values are the bootstrap defaults; anything saved here overrides them
and takes effect immediately (clients are rebuilt), no restart needed.

What this is and is not:
  - It decides *which gateway and which models* receive the data this app
    already sends out (questions, chunks, images). That is a product setting.
  - It is NOT the tool credential boundary. `OPS_SECRET_*` and the ops token stay
    on the host and are never exposed here — those decide what gets *executed*.

The API key is write-only: GET returns a masked tail, never the key itself.
The file is written with 0600.
"""
import json
import os
import threading
import urllib.request

from app import config
from app.config import DATA_DIR, log, why

PATH = DATA_DIR / "settings.json"
FIELDS = ("llm_base_url", "llm_api_key", "chat_model", "embed_model", "vision_models",
          "embed_base_url", "embed_api_key", "rerank_model")
SECRETS = ("llm_api_key", "embed_api_key")
_lock = threading.Lock()
_overrides: dict = {}
version = 0


def _env_defaults() -> dict:
    return {"llm_base_url": config.LLM_BASE_URL, "llm_api_key": config.LLM_API_KEY,
            "chat_model": config.CHAT_MODEL, "embed_model": config.EMBED_MODEL,
            "vision_models": list(config.VISION_MODELS),
            # 向量模型可以在另一个地址（没有网关、对话和向量来自不同厂商时）；空 = 和对话模型同一处
            "embed_base_url": config.EMBED_BASE_URL, "embed_api_key": config.EMBED_API_KEY,
            "rerank_model": config.RERANK_MODEL}


def _load():
    global _overrides
    try:
        data = json.loads(PATH.read_text(encoding="utf-8"))
        _overrides = {k: v for k, v in data.items() if k in FIELDS and v not in (None, "", [])}
    except FileNotFoundError:
        _overrides = {}
    except ValueError:
        log.warning("settings.json unreadable, ignoring it")
        _overrides = {}


_load()


def current() -> dict:
    """Effective settings: env defaults with page overrides applied."""
    with _lock:
        merged = _env_defaults()
        merged.update(_overrides)
        return merged


def get(name: str):
    return current()[name]


def configured() -> bool:
    """Can we talk to a model at all? False until an address and a key exist (env or page)."""
    cur = current()
    return bool(cur["llm_base_url"] and cur["llm_api_key"])


NOT_CONFIGURED = "还没有配置模型：请到 管理 → 模型设置 填写对话模型和向量模型的地址与 key"


def embed_endpoint(cur: dict | None = None) -> tuple[str, str]:
    """(base_url, api_key) for embeddings: the dedicated endpoint if one is set, else the chat one.

    The dedicated key only applies together with a dedicated address — same host, same key.
    """
    cur = cur or current()
    if cur["embed_base_url"]:
        return cur["embed_base_url"], cur["embed_api_key"] or cur["llm_api_key"]
    return cur["llm_base_url"], cur["llm_api_key"]


def mask(key: str) -> str:
    key = key or ""
    return ("•" * 8 + key[-4:]) if len(key) >= 8 else ("•" * len(key) if key else "")


def public() -> dict:
    """What the page may see: everything except the keys, plus where each value comes from."""
    cur = current()
    with _lock:
        src = {k: ("page" if k in _overrides else "env") for k in FIELDS}
    return {"llm_base_url": cur["llm_base_url"], "llm_api_key_masked": mask(cur["llm_api_key"]),
            "chat_model": cur["chat_model"], "embed_model": cur["embed_model"],
            "vision_models": cur["vision_models"],
            "embed_base_url": cur["embed_base_url"], "embed_api_key_masked": mask(cur["embed_api_key"]),
            "rerank_model": cur["rerank_model"],
            "source": src}


def save(updates: dict):
    """Persist overrides. An empty key means 'keep the existing one'."""
    global version
    clean = {}
    for k in FIELDS:
        if k not in updates:
            continue
        v = updates[k]
        if k == "vision_models":
            v = [s.strip() for s in (v if isinstance(v, list) else str(v).split(",")) if s.strip()]
        elif isinstance(v, str):
            v = v.strip()
        if k in SECRETS and not v:
            continue
        clean[k] = v
    with _lock:
        env = _env_defaults()
        for k, v in clean.items():
            # 和 .env 一样的值不算覆盖，这样「来源」标签才准确
            if v in ("", []) or v == env.get(k):
                _overrides.pop(k, None)
            else:
                _overrides[k] = v
        PATH.parent.mkdir(parents=True, exist_ok=True)
        tmp = PATH.with_suffix(".tmp")
        tmp.write_text(json.dumps(_overrides, ensure_ascii=False, indent=2), encoding="utf-8")
        os.chmod(tmp, 0o600)
        os.replace(tmp, PATH)
        version += 1
    log.info("model settings saved: %s", ", ".join(sorted(clean)) or "nothing")
    from app import clients
    clients.reload()


def reset():
    """Drop every page override and go back to .env."""
    global version
    with _lock:
        _overrides.clear()
        PATH.unlink(missing_ok=True)
        version += 1
    from app import clients
    clients.reload()


def _models_url(base: str) -> str:
    base = base.rstrip("/")
    return base + "/models" if base.endswith("/v1") else base + "/v1/models"


def test(base_url: str, api_key: str, chat_model: str, embed_model: str,
         embed_base_url: str = "", embed_api_key: str = "", rerank_model: str = "") -> dict:
    """Try the endpoints with these values before saving. Never raises."""
    out = {"ok": False, "models": [], "chat": None, "embed": None, "embed_dim": None, "errors": [],
           "separate_embed": bool(embed_base_url), "rerank": None}
    cur = current()
    api_key = api_key or cur["llm_api_key"]
    if not api_key:
        out["errors"].append("请填写 API Key")
        return out
    e_url = embed_base_url or base_url
    e_key = embed_api_key or (cur["embed_api_key"] if embed_base_url else "") or api_key
    try:
        req = urllib.request.Request(_models_url(base_url), headers={"Authorization": f"Bearer {api_key}"})
        with urllib.request.urlopen(req, timeout=8) as r:
            out["models"] = sorted(str(m.get("id", "")) for m in json.load(r).get("data", []) if m.get("id"))
    except Exception as exc:
        # 很多直连厂商没有 /models；只记一句，不算失败，对话调用成功才算通
        out["models_note"] = f"列不出模型（{why(exc)}），不影响使用；模型名手动填写"
    from langchain_openai import ChatOpenAI, OpenAIEmbeddings
    try:
        reply = ChatOpenAI(model=chat_model, base_url=base_url, api_key=api_key, timeout=45,
                           max_retries=0, max_tokens=60, temperature=0).invoke("只回复 OK")
        # 推理型模型可能把 token 花在思考上，正文为空；能返回就算通了
        out["chat"] = (reply.content or "").strip()[:20] or "可调用"
    except Exception as exc:
        out["errors"].append(f"对话模型 {chat_model} 调用失败：{why(exc)}")
    try:
        # 「测试连接」是人在页面上等着的：不设超时会沿用客户端默认的 600 s × 重试，一挂就是半小时
        vec = OpenAIEmbeddings(model=embed_model, base_url=e_url, api_key=e_key,
                               request_timeout=config.EMBED_TIMEOUT, max_retries=0,
                               check_embedding_ctx_length=False, chunk_size=16).embed_query("测试")
        out["embed"] = "ok"
        out["embed_dim"] = len(vec)
    except Exception as exc:
        out["errors"].append(f"向量模型 {embed_model}（{e_url}）调用失败：{why(exc)}")
    if rerank_model:
        try:
            base = base_url.rstrip("/")
            base = base[:-3] if base.endswith("/v1") else base
            req = urllib.request.Request(
                base + "/v1/rerank",
                json.dumps({"model": rerank_model, "query": "测试", "documents": ["相关", "无关"]}).encode(),
                {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=20) as r:
                results = json.load(r).get("results", [])
            out["rerank"] = "ok" if results else "无结果"
            if not results:
                out["errors"].append(f"重排模型 {rerank_model} 返回为空")
        except Exception as exc:
            out["errors"].append(f"重排模型 {rerank_model} 调用失败：{why(exc)}")
    out["ok"] = not out["errors"]
    return out
