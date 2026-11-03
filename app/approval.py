"""应用自己存的、由审批口令把关的改动（对外接入的开关、清除审计、扩大令牌可见范围的分类改动）共用的几件事。

口令一律由工具服务核对（ops_client.verify_passphrase：只核对，不写；和批准工具共用输错计数、锁定）。只有它回 200 且
{"ok": true} 才算通过，别的一律不改：拒绝照原来的状态码；老工具服务 / OPS_PAGE_CONFIG=off 时这类改动不可用（403）；
连不上、超时 503；其余 502。口令不保存、不记日志，也不出现在回复和报错里。
"""
import json
import threading
import time

from fastapi import HTTPException, Request

from app import peer
from app.agent import ops_client
from app.config import WEB_USER, log

BODY_MAX = 64 * 1024
PER_MINUTE = 10
BAD_TARGET = str.maketrans({c: " " for c in map(chr, [*range(0x20), *range(0x7f, 0xa0), 0x2028, 0x2029])})


class Refused(Exception):
    """不做这次改动：status 是给页面的 HTTP 状态码；passphrase=True 时页面把口令框标红。"""

    def __init__(self, status, message, passphrase=False):
        super().__init__(message)
        self.status = status
        self.passphrase = passphrase


async def json_body(request: Request) -> dict:
    """请求体手动解析：FastAPI 的 422 会把输入（口令）回显出来。"""
    body = await request.body()
    if len(body) > BODY_MAX:
        raise HTTPException(413, "请求体太大")
    try:
        data = json.loads(body or b"{}")
    except ValueError:
        raise HTTPException(400, "请求体不是合法 JSON") from None
    if not isinstance(data, dict):
        raise HTTPException(400, "请求体必须是 JSON 对象")
    return data


def address(request: Request) -> str:
    return peer.address(request)


def caller(request: Request) -> str:
    """谁、从哪里改的：只进工具服务的日志。"""
    return f"web user={WEB_USER} ip={address(request)}"


_hits = {}
_hits_lock = threading.Lock()


def throttle(kind: str, ip: str, per_minute=PER_MINUTE) -> None:
    """同一个来源地址每分钟最多 per_minute 次这类改动；超了 429。"""
    now = time.monotonic()
    with _hits_lock:
        for key in [k for k, hits in _hits.items() if not hits or now - hits[-1] >= 60]:
            del _hits[key]
        hits = [at for at in _hits.get((kind, ip), []) if now - at < 60]
        if len(hits) >= per_minute:
            _hits[(kind, ip)] = hits
            raise HTTPException(429, f"操作太频繁了：{int(60 - (now - hits[0])) + 1} 秒后再试")
        _hits[(kind, ip)] = hits + [now]


def support_reason() -> str:
    """要口令的改动现在能不能做：空串是能；否则是给页面看的原因（没配工具服务、工具服务较旧、页面配置关了、连不上）。
    探测出了任何意外都当成「不能」，不让页面跟着报错。"""
    try:
        return ops_client.verify_support()["reason"]
    except Exception as exc:
        log.warning("probing the tool service for passphrase checks failed: %s", exc.__class__.__name__)
        return "连不上工具服务，核对不了审批口令：现在不能做要口令的改动"


def verify(passphrase, action: str, target: str, caller_text: str) -> None:
    """请工具服务核对口令；不通过抛 Refused。先查能不能做（不消耗口令次数），再核对。"""
    if not isinstance(passphrase, str) or not passphrase:
        raise Refused(400, "没有输入审批口令", passphrase=True)
    reason = support_reason()
    if reason:
        raise Refused(403, reason)
    try:
        ops_client.verify_passphrase(passphrase, action, str(target).translate(BAD_TARGET)[:120], caller_text)
    except ops_client.OpsUnavailable as exc:
        status = exc.status
        if status == 404:
            raise Refused(403, ops_client.OLD_SERVICE_VERIFY) from None
        if status in ops_client.VERIFY_REFUSALS:
            raise Refused(status, str(exc), passphrase=status in (400, 403)) from None
        raise Refused(status if status in (502, 503) else 502, str(exc)) from None
    except Exception as exc:
        log.warning("verifying the approval passphrase failed unexpectedly: %s", exc.__class__.__name__)
        raise Refused(502, "核对审批口令时出了意外，不算通过：没有改") from None
