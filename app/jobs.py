"""Background jobs for slow uploads.

A PDF full of screenshots can take a minute to OCR; holding the HTTP request open
that long trips proxies and leaves the user staring at a spinner with no idea
what is happening. Instead the upload returns a job id straight away, the work
runs in a small thread pool, and the page polls for the current stage.

Jobs are in-memory on purpose: there is one process, and a job that outlives a
restart is not worth resuming (the user just uploads again).
"""
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor

from fastapi import HTTPException

from app.config import log

WORKERS = 2          # ingestion is model-bound; more threads would just queue on the gateway
KEEP_SECONDS = 3600  # finished jobs linger for an hour so a slow poll still finds them

_pool = ThreadPoolExecutor(max_workers=WORKERS, thread_name_prefix="ingest")
_lock = threading.Lock()
_jobs: dict = {}


def submit(name: str, work) -> str:
    """Queue `work(report)`; `report(stage)` updates the visible progress."""
    job_id = uuid.uuid4().hex
    with _lock:
        _jobs[job_id] = {"id": job_id, "name": name, "status": "queued", "stage": "排队中",
                         "result": None, "detail": None, "started": time.time()}
        _sweep()

    def report(stage: str):
        with _lock:
            job = _jobs.get(job_id)
            if job:
                job["stage"] = stage

    def run():
        with _lock:
            _jobs[job_id]["status"] = "running"
        try:
            result = work(report)
            with _lock:
                _jobs[job_id].update(status="done", stage="完成", result=result)
        except HTTPException as exc:
            with _lock:
                _jobs[job_id].update(status="error", stage="失败", detail=str(exc.detail))
        except Exception as exc:
            log.warning("background ingest failed for %s", name, exc_info=True)
            with _lock:
                _jobs[job_id].update(status="error", stage="失败",
                                     detail=f"入库失败：{exc.__class__.__name__}")

    _pool.submit(run)
    return job_id


def get(job_id: str):
    with _lock:
        job = _jobs.get(job_id)
        return dict(job) if job else None


def _sweep():
    cutoff = time.time() - KEEP_SECONDS
    for job_id in [j for j, job in _jobs.items()
                   if job["status"] in ("done", "error") and job["started"] < cutoff]:
        del _jobs[job_id]
