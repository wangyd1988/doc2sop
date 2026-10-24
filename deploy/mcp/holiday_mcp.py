#!/usr/bin/env python3
"""玩具 MCP server（stdio 传输，纯标准库）：节假日与日期查询。

一份代码两个用途：
  · 演示——把场景包「行政-请假拼假」的两个工具换成 MCP 来源，同一条 SOP 照跑；
  · 单测——ops_readonly.py 里最小 MCP 客户端的被测对象。

四个工具各代表审批层要处理的一类情况：
  holiday_calendar  readOnlyHint=true     → 候选标「只读（server 声明）」
  date_info         readOnlyHint=true
  delete_holiday    destructiveHint=true  → 连 pending 都不进
  echo              无标注                → 批准时必须 --attest-readonly

环境变量：
  HOLIDAY_MCP_DATA_DIR    有则从该目录读 {year}.json，不联网（测试用）
  HOLIDAY_MCP_PAGE_SIZE   tools/list 每页条数，默认 2（故意分页，好让客户端测 nextCursor）
  HOLIDAY_MCP_TEST_HOOKS  设为 1 才启用下面的测试钩子，演示和生产不要开：
    --env-file PATH           启动时把自己看到的环境变量写进文件（验证客户端不泄露密钥）
    echo 收到 "__crash__"      直接退出（验证客户端崩溃重拉）
    echo 收到 "__hang__"       睡 60 秒不回（验证客户端超时）
    HOLIDAY_MCP_SCHEMA_VARIANT=1  给 echo 的 inputSchema 多加一个属性（验证 schema 漂移）
"""
import datetime
import json
import os
import sys
import time
import urllib.error
import urllib.request

PROTOCOL_VERSION = "2025-06-18"
HOLIDAY_URL = "https://cdn.jsdelivr.net/gh/NateScarlet/holiday-cn@master/{year}.json"
HOOKS = os.environ.get("HOLIDAY_MCP_TEST_HOOKS") == "1"


def _echo_schema():
    schema = {"type": "object",
              "properties": {"text": {"type": "string", "description": "原样返回的文字"}},
              "required": ["text"]}
    if HOOKS and os.environ.get("HOLIDAY_MCP_SCHEMA_VARIANT") == "1":
        schema["properties"]["times"] = {"type": "integer", "minimum": 1, "maximum": 3}
    return schema


def tools():
    return [
        {"name": "holiday_calendar",
         "title": "法定节假日",
         "description": "查询某一年国务院公布的法定节假日安排，包括放假日期和周末补班日期"
                        "（isOffDay=false 表示补班，要上班）。用户没说年份就按下一个该节日所在的年份查。"
                        "days 为空表示该年安排尚未公布，输出里会写明；此时按法定假日天数和往年调休规律推算并注明。",
         "inputSchema": {"type": "object",
                         "properties": {"year": {"type": "integer", "minimum": 2007,
                                                 "maximum": 2035, "description": "年份，例如 2027"}},
                         "required": ["year"]},
         "annotations": {"readOnlyHint": True, "openWorldHint": True}},
        {"name": "date_info",
         "title": "日期是星期几",
         "description": "查某个日期是星期几、当年第几周。推算请假天数、跨周末时用它。",
         "inputSchema": {"type": "object",
                         "properties": {"day": {"type": "string", "format": "date",
                                                "description": "日期，格式 YYYY-MM-DD"}},
                         "required": ["day"]},
         "annotations": {"readOnlyHint": True}},
        {"name": "delete_holiday",
         "description": "删除一条节假日记录（演示用：破坏性工具不应被列出）",
         "inputSchema": {"type": "object", "properties": {"day": {"type": "string"}},
                         "required": ["day"]},
         "annotations": {"destructiveHint": True}},
        {"name": "echo",
         "description": "原样返回输入（演示用：没有只读标注的工具）",
         "inputSchema": _echo_schema()},
    ]


UNPUBLISHED = "该年节假日安排尚未公布（国务院通常在前一年 11–12 月公布次年安排），只能按法定假日天数和往年调休规律推算。"


def _holidays(year):
    """读一年的数据；数据源还没有这一年的文件（404）等同于「安排尚未公布」，和 days 为空一个待遇。"""
    data_dir = os.environ.get("HOLIDAY_MCP_DATA_DIR")
    if data_dir:
        try:
            with open(os.path.join(data_dir, f"{year}.json"), encoding="utf-8") as handle:
                return json.load(handle)
        except FileNotFoundError:
            return {"year": year, "days": []}
    try:
        with urllib.request.urlopen(HOLIDAY_URL.format(year=year), timeout=10) as response:
            return json.load(response)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return {"year": year, "days": []}
        raise


def call(name, args):
    """返回 (content 文本, structuredContent 或 None)。抛异常则作为 isError 返回给客户端。"""
    if name == "holiday_calendar":
        year = int(args["year"])
        data = _holidays(year)
        picked = {"year": data.get("year", year), "days": data.get("days", [])}
        if not picked["days"]:
            # 空数组的含义由 server 说清楚，模型不用猜；放进同一份 JSON，客户端拍平时不会重复附带
            picked["note"] = UNPUBLISHED
        return json.dumps(picked, ensure_ascii=False, indent=1), picked
    if name == "date_info":
        day = datetime.date.fromisoformat(str(args["day"]))
        weekday = "一二三四五六日"[day.weekday()]
        week = day.isocalendar()[1]
        return f"{day.isoformat()} 星期{weekday} 第{week}周", \
            {"date": day.isoformat(), "weekday": day.isoweekday(), "week": week}
    if name == "delete_holiday":
        raise RuntimeError("演示 server 不会真的删除任何东西")
    if name == "echo":
        text = str(args.get("text", ""))
        if HOOKS and text == "__crash__":
            sys.stderr.write("holiday_mcp: 按测试钩子要求退出\n")
            sys.stderr.flush()
            os._exit(3)
        if HOOKS and text == "__hang__":
            time.sleep(60)
        return text * int(args.get("times", 1) or 1), None
    raise KeyError(f"未知工具：{name}")


def _write(stream, message):
    stream.write((json.dumps(message, ensure_ascii=False) + "\n").encode("utf-8"))
    stream.flush()


def _error(ident, code, message):
    return {"jsonrpc": "2.0", "id": ident, "error": {"code": code, "message": message}}


def handle(request):
    """一条请求 → 一条响应；通知返回 None。"""
    method = request.get("method", "")
    ident = request.get("id")
    params = request.get("params") or {}
    if method == "initialize":
        return {"jsonrpc": "2.0", "id": ident, "result": {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": "holiday-mcp", "version": "0.1"}}}
    if method.startswith("notifications/"):
        return None
    if ident is None:
        return None
    if method == "ping":
        return {"jsonrpc": "2.0", "id": ident, "result": {}}
    if method == "tools/list":
        page = max(1, int(os.environ.get("HOLIDAY_MCP_PAGE_SIZE", "2")))
        start = int(params.get("cursor") or 0)
        items = tools()
        result = {"tools": items[start:start + page]}
        if start + page < len(items):
            result["nextCursor"] = str(start + page)
        return {"jsonrpc": "2.0", "id": ident, "result": result}
    if method == "tools/call":
        name = params.get("name")
        if name not in {t["name"] for t in tools()}:
            return _error(ident, -32602, f"未知工具：{name}")
        try:
            text, structured = call(name, params.get("arguments") or {})
        except Exception as exc:
            return {"jsonrpc": "2.0", "id": ident, "result": {
                "content": [{"type": "text", "text": f"{exc.__class__.__name__}: {exc}"}],
                "isError": True}}
        result = {"content": [{"type": "text", "text": text}], "isError": False}
        if structured is not None:
            result["structuredContent"] = structured
        return {"jsonrpc": "2.0", "id": ident, "result": result}
    return _error(ident, -32601, f"不支持的方法：{method}")


def main():
    if HOOKS and "--env-file" in sys.argv:
        path = sys.argv[sys.argv.index("--env-file") + 1]
        with open(path, "w", encoding="utf-8") as out:
            json.dump(dict(os.environ), out, ensure_ascii=False)
    stdin, stdout = sys.stdin.buffer, sys.stdout.buffer
    for raw in iter(stdin.readline, b""):
        line = raw.strip()
        if not line:
            continue
        try:
            request = json.loads(line.decode("utf-8"))
        except ValueError:
            _write(stdout, _error(None, -32700, "不是合法 JSON"))
            continue
        if not isinstance(request, dict):
            _write(stdout, _error(None, -32600, "请求必须是对象"))
            continue
        response = handle(request)
        if response is not None:
            _write(stdout, response)
    return 0


if __name__ == "__main__":
    sys.exit(main())
