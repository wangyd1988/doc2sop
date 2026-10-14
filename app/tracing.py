"""LangSmith helpers.

The answer endpoint streams, so the generator body runs *after* the response object
is returned — often on another thread. A root run is therefore created by hand and
kept open until the stream finishes, and nested runs are re-attached to it.
"""
from contextlib import contextmanager

from langsmith.run_helpers import tracing_context
from langsmith.run_trees import RunTree

from app.config import CHAT_MODEL, TOP_K, TRACING, log


def start_root_run(question: str, conversation_id):
    """Open a LangSmith run that stays alive across the streamed response."""
    if not TRACING:
        return None
    try:
        root = RunTree(name="知识库问答", run_type="chain",
                       inputs={"question": question},
                       # RunTree silently drops a bare metadata= kwarg; it must go inside extra.
                       extra={"metadata": {"conversation_id": conversation_id,
                                           "chat_model": CHAT_MODEL, "top_k": TOP_K}})
        root.post()
        return root
    except Exception as exc:
        log.info("langsmith root run not started: %s", exc.__class__.__name__)
        return None


def finish_root_run(root, outputs=None, error=None):
    if root is None:
        return
    try:
        root.end(outputs=outputs, error=error)
        root.patch()
    except Exception as exc:
        log.info("langsmith root run not closed: %s", exc.__class__.__name__)


@contextmanager
def traced_under(root):
    """Attach nested runs to the root, even from the streaming worker thread."""
    if root is None:
        yield
    else:
        with tracing_context(parent=root):
            yield
