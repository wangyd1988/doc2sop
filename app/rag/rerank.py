"""Rerank: a cross-encoder re-scores the candidates retrieval already found.

Vector search and BM25 each look at the query and the passage separately; a
cross-encoder reads them together and is much better at "is this passage really
about that question". It is slow per pair, so it only sees the top few fused
candidates (RERANK_CANDIDATES), and the whole step is best-effort: any failure
or timeout falls back to the fused order so answering never depends on it.

Goes through the same gateway as every other model call (LiteLLM `/rerank`,
Cohere-compatible). Empty RERANK_MODEL disables it.
"""
import json
import urllib.request

from langsmith import traceable

from app import settings
from app.config import RERANK_CANDIDATES, RERANK_TIMEOUT, log, why


def enabled() -> bool:
    return bool(settings.get("rerank_model")) and settings.configured()


def _endpoint() -> str:
    base = settings.get("llm_base_url").rstrip("/")
    base = base[:-3] if base.endswith("/v1") else base
    return base + "/v1/rerank"


def _post(url, payload):
    """Isolated so tests can replace the network."""
    request = urllib.request.Request(
        url, json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        {"Authorization": f"Bearer {settings.get('llm_api_key')}", "Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=RERANK_TIMEOUT) as response:
        return json.load(response)


@traceable(name="重排", run_type="retriever")
def rerank(question: str, hits: list, keep: int) -> list:
    """Return `hits` re-ordered by cross-encoder score, trimmed to `keep`.

    Only the first RERANK_CANDIDATES hits are scored; the rest are dropped (they
    were already the weakest by fused rank). Each kept hit gains `rerank` (the raw
    score) and `match` is left as-is. On any failure the input order is returned.
    """
    if not enabled() or len(hits) <= 1:
        return hits[:keep]
    pool = hits[:RERANK_CANDIDATES]
    try:
        data = _post(_endpoint(), {"model": settings.get("rerank_model"), "query": question,
                                   "documents": [h["text"] for h in pool], "top_n": len(pool)})
        scored = [(float(r["relevance_score"]), int(r["index"])) for r in data.get("results", [])]
    except Exception as exc:
        log.info("rerank skipped: %s", why(exc))
        return hits[:keep]
    if len(scored) != len(pool):
        log.info("rerank returned %d scores for %d docs, ignoring", len(scored), len(pool))
        return hits[:keep]
    scored.sort(key=lambda s: -s[0])
    out = []
    for score, i in scored[:keep]:
        hit = dict(pool[i])
        hit["rerank"] = round(score, 3)
        out.append(hit)
    for n, hit in enumerate(out, 1):
        hit["index"] = n
    return out
