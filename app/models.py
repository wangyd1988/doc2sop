"""Which chat models the user may pick from.

The list comes from the gateway's /v1/models with the app's own key, so it is
exactly the set this key is allowed to call. Nothing else is configurable from
the page: the gateway address and key stay in the host's .env, because a page
that can rewrite them is a page that can leak every document to any address.
"""
import json
import threading
import time
import urllib.request

from app import settings
from app.config import log, why

CACHE_SECONDS = 60
_cache = {"at": 0.0, "models": []}
_lock = threading.Lock()


def _fetch() -> list:
    """Raw model ids from the gateway. Network only; filtering happens in `available`."""
    cur = settings.current()
    base = cur["llm_base_url"].rstrip("/")
    url = base + "/models" if base.endswith("/v1") else base + "/v1/models"
    request = urllib.request.Request(url, headers={"Authorization": f"Bearer {cur['llm_api_key']}"})
    with urllib.request.urlopen(request, timeout=8) as response:
        data = json.load(response)
    return [str(item.get("id", "")) for item in data.get("data", []) if item.get("id")]


def _chat_only(names) -> list:
    # 只藏向量模型：它不能聊天。多模态模型（OCR 用的那几个）同时也是聊天模型，保留。
    cur = settings.current()
    hidden = {cur["embed_model"]} - {cur["chat_model"]}
    return sorted({n for n in names if n and n not in hidden})


def available(force: bool = False) -> list:
    """Chat model names, default first. Falls back to the default alone on failure."""
    with _lock:
        fresh = time.time() - _cache["at"] < CACHE_SECONDS
        if force or not fresh or not _cache["models"]:
            try:
                _cache["models"] = _chat_only(_fetch())
            except Exception as exc:
                log.info("model list unavailable: %s", why(exc))
                _cache["models"] = _cache["models"] or []
            _cache["at"] = time.time()
        models = list(_cache["models"])
    default = settings.get("chat_model")
    if default in models:
        models.remove(default)
    return [default] + models


def resolve(requested: str | None) -> str:
    """Turn a page request into a model name we are allowed to call, or raise ValueError."""
    requested = (requested or "").strip()
    default = settings.get("chat_model")
    if not requested or requested == default:
        return default
    if requested in available():
        return requested
    # 列表可能过期（网关刚加了模型），刷新一次再判断。
    if requested in available(force=True):
        return requested
    raise ValueError(f"模型「{requested}」不在这把 key 可用的列表里，请在网关上确认授权")
