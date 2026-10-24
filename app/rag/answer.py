"""Prompts, query rewriting and answer generation."""
import time

from langsmith import traceable

from app import clients
from app.clients import chat_model
from app.config import BOT_NAME, CATEGORY_MAX, DEFAULT_CATEGORY, HISTORY_CHARS, log, why

SYSTEM_PROMPT = f"""你是「{BOT_NAME}」，一位耐心、友好的知识库客服助手，用“您”称呼用户。
规则：
1. 资料类问题只能依据“知识库片段”回答；片段不足以回答时，明确说明知识库中没有找到相关内容，
   并建议换个说法提问或上传相关文档，不要编造。
2. 回答中用 [编号] 标注引用的片段，并说明来源文档（PDF 注明页码）。
3. 打招呼、致谢、闲聊等与资料无关的话，自然友好地回应即可，不需要引用片段，
   也不要说“知识库中没有找到相关内容”。
4. 结合上文理解追问（例如“它”“这个”“还有呢”），保持多轮对话连贯。
5. 回答简洁清晰，适当使用列表或分段。"""

REWRITE_PROMPT = """根据对话历史，把用户的最新问题改写成一句可以独立检索的问题。
要求：补全指代（它、这个、上面那个等）和省略的主语；只输出改写后的问题本身，不要解释、不要加引号；
如果最新问题本身已经完整，就原样输出。"""

CATEGORY_PROMPT = """给这份文档归一个简短分类，2 到 8 个汉字。
优先从「已有分类」里挑一个合适的；都不合适再起一个新的。
只输出分类名本身，不要解释、不要标点、不要引号。"""


def _first_line(text: str) -> str:
    text = (text or "").strip()
    return text.splitlines()[0].strip().strip('"“”\'：:、。 ') if text else ""


@traceable(name="问题改写", run_type="chain")
def rewrite_question(question: str, history) -> str:
    """Expand follow-ups like 它/这个 into a standalone search query.

    Vector search cannot resolve pronouns, so a bare "那它的上限呢" would recall
    nothing useful. Falls back to the original question whenever the model fails.
    """
    if not history:
        return question
    lines = "\n".join(f"{'用户' if role == 'user' else '助手'}：{content[:300]}"
                      for role, content in history[-4:])
    try:
        reply = clients.rewriter.invoke([("system", REWRITE_PROMPT),
                                 ("human", f"对话历史：\n{lines}\n\n最新问题：{question}")])
        rewritten = _first_line(reply.content)
    except Exception as exc:
        log.info("query rewrite failed: %s", why(exc))
        return question
    return rewritten if 0 < len(rewritten) <= 200 else question


@traceable(name="文档分类", run_type="chain")
def suggest_category(name: str, sample: str, existing) -> str:
    """Ask the model for a short category, reusing an existing one when it fits."""
    try:
        reply = clients.rewriter.invoke([
            ("system", CATEGORY_PROMPT),
            ("human", f"已有分类：{'、'.join(existing) or '（暂无）'}\n\n"
                      f"文件名：{name}\n\n内容节选：\n{sample}")])
        guess = _first_line(reply.content)
    except Exception as exc:
        log.info("category suggestion failed: %s", why(exc))
        return DEFAULT_CATEGORY
    return guess[:CATEGORY_MAX] or DEFAULT_CATEGORY


def build_messages(question: str, context: str, history):
    """System prompt + replayed history + retrieved context and the new question."""
    messages = [("system", SYSTEM_PROMPT)]
    for role, content in history:
        messages.append(("human" if role == "user" else "ai", content[:HISTORY_CHARS]))
    messages.append(("human", f"知识库片段：\n{context}\n\n用户的问题：{question}"))
    return messages


def stream_answer(messages, model: str | None = None):
    """Yield ("delta", text) as answer text arrives. `model` overrides the default chat model.

    思考型模型出正文前先来一串空 chunk（reasoning 文字被 ChatOpenAI 丢掉了），
    每半秒最多报一次 ("thinking", n)，页面据此显示模型还在动。
    """
    llm = clients.llm
    client = llm if not model or model == llm.model_name else chat_model(
        model=model, timeout=120, max_retries=1)
    thinking, reported = 0, 0.0
    for chunk in client.stream(messages):
        if chunk.content:
            yield "delta", chunk.content
        else:
            thinking += 1
            if time.monotonic() - reported >= 0.5:
                reported = time.monotonic()
                yield "thinking", thinking
