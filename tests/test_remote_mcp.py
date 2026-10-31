"""远程 MCP server（Streamable HTTP）：工具服务的客户端（deploy/ops_readonly.py 的 McpHttpServer）。

两部分：
- 手写的假 server 演各种情况：JSON 和 SSE 两种回应、会话 id、会话过期重连、SSE 断流后按 Last-Event-ID 续读、
  请求头里凭据的脱敏、拒绝跳转、响应大小上限、超时，以及发现 → 待审 → 批准 → 调用 → schema 漂移的完整流程；
- 用官方 MCP SDK 起真的 server：2025-11-25（有会话，JSON 和 SSE 两种回应）、2026-07-28（无会话）、auto 协商都要跑通，
  会话空闲过期后自动重新握手。
"""
import importlib.util
import json
import os
import socket
import sys
import tempfile
import threading
import time
import unittest
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from tests.support import clear_graph  # noqa: F401  (sets env before app imports)

REPO = Path(__file__).resolve().parent.parent

if "ops_readonly" in sys.modules:
    ops = sys.modules["ops_readonly"]
else:
    _SPEC = importlib.util.spec_from_file_location("ops_readonly", REPO / "deploy" / "ops_readonly.py")
    ops = importlib.util.module_from_spec(_SPEC)
    sys.modules["ops_readonly"] = ops
    _SPEC.loader.exec_module(ops)

META = "io.modelcontextprotocol/"
TOOLS = [{"name": "lookup", "description": "查文档", "annotations": {"readOnlyHint": True},
          "inputSchema": {"type": "object", "properties": {"term": {"type": "string"}}, "required": ["term"]}},
         {"name": "wipe", "description": "清空", "annotations": {"destructiveHint": True},
          "inputSchema": {"type": "object", "properties": {}}}]


class FakeMcp(BaseHTTPRequestHandler):
    """手写的 Streamable HTTP server。behavior 决定这次演哪种情况，seen 记下收到的每个请求。"""
    behavior = {}
    seen = []
    sessions = set()
    tools = TOOLS
    protocol_version = "HTTP/1.1"

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))) or b"{}")
        FakeMcp.seen.append(("POST", {k.lower(): v for k, v in self.headers.items()}, body))
        b = FakeMcp.behavior
        if b.get("redirect"):
            return self.send(307, b"", extra={"Location": b["redirect"]})
        method = body.get("method")
        if method is None:          # 客户端回给 server 的回应
            return self.send(202, b"")
        if b.get("modern"):
            meta = (body.get("params") or {}).get("_meta") or {}
            if meta.get(META + "protocolVersion") != "2026-07-28" or self.headers.get("Mcp-Method") != method:
                return self.error(body, 400, -32020, "header mismatch")
            if method == "server/discover":
                return self.result(body, {"supportedVersions": ["2026-07-28"], "capabilities": {"tools": {}},
                                          "_meta": {META + "serverInfo": {"name": "fake-modern", "version": "2"}}})
        else:
            if method == "server/discover":
                return self.error(body, 400, -32601, "Method not found")
            if method == "initialize":
                session = uuid.uuid4().hex
                FakeMcp.sessions.add(session)
                return self.result(body, {"protocolVersion": "2025-11-25", "capabilities": {"tools": {}},
                                          "serverInfo": {"name": "fake-legacy", "version": "1"}},
                                   extra={"Mcp-Session-Id": session})
            if self.headers.get("Mcp-Session-Id") not in FakeMcp.sessions:
                return self.send(404, b"session not found")
            if method == "notifications/initialized":
                return self.send(202, b"")
        if method == "tools/list":
            return self.result(body, {"tools": FakeMcp.tools})
        if method == "tools/call":
            if b.get("slow"):
                time.sleep(b["slow"])
            if b.get("huge"):
                return self.result(body, {"content": [{"type": "text", "text": "x" * b["huge"]}]})
            args = (body.get("params") or {}).get("arguments") or {}
            text = f"docs about {args.get('term')}; auth={self.headers.get('Authorization')}"
            return self.result(body, {"content": [{"type": "text", "text": text}]})
        return self.error(body, 404, -32601, "Method not found")

    def do_GET(self):
        FakeMcp.seen.append(("GET", {k.lower(): v for k, v in self.headers.items()}, None))
        pending = FakeMcp.behavior.get("resume")
        if pending and self.headers.get("Last-Event-ID") == "evt-1":
            return self.sse([f"id: evt-2\nevent: message\ndata: {json.dumps(pending)}\n\n"])
        return self.send(405, b"")

    def do_DELETE(self):
        FakeMcp.seen.append(("DELETE", {k.lower(): v for k, v in self.headers.items()}, None))
        FakeMcp.sessions.discard(self.headers.get("Mcp-Session-Id"))
        return self.send(200, b"")

    def result(self, request, result, extra=None):
        reply = {"jsonrpc": "2.0", "id": request["id"], "result": result}
        b = FakeMcp.behavior
        if b.get("resume_on") == request.get("method"):
            # 先发一个带 id 的空事件就断开：客户端要按 Last-Event-ID 用 GET 接着读
            FakeMcp.behavior["resume"] = reply
            return self.sse(["id: evt-1\ndata: \n\n"], extra)
        if b.get("sse"):
            events = [": keepalive\n\n",
                      f"event: message\ndata: {json.dumps({'jsonrpc': '2.0', 'method': 'notifications/tools/list_changed'})}\n\n",
                      f"event: message\ndata: {json.dumps({'jsonrpc': '2.0', 'id': 'srv-1', 'method': 'roots/list'})}\n\n",
                      f"event: ping\ndata: ignored\n\n",
                      "event: message\n" + "".join(f"data: {line}\n" for line in json.dumps(reply, indent=1).splitlines())
                      + "\n"]
            return self.sse(events, extra)
        return self.send(200, json.dumps(reply).encode(), "application/json", extra)

    def error(self, request, status, code, message):
        reply = {"jsonrpc": "2.0", "id": request.get("id"), "error": {"code": code, "message": message}}
        return self.send(status, json.dumps(reply).encode(), "application/json")

    def sse(self, events, extra=None):
        data = "".join(events).encode()
        return self.send(200, data, "text/event-stream", extra)

    def send(self, status, data, kind="text/plain", extra=None):
        self.send_response(status)
        self.send_header("Content-Type", kind)
        self.send_header("Content-Length", str(len(data)))
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


class QuietServer(ThreadingHTTPServer):
    def handle_error(self, request, client_address):
        pass   # 客户端读到上限就断开，是测试本身要的，不打印


class _Remote(unittest.TestCase):
    """一份临时主配置 + 一个假 server；mcp 注册表在用例结束时清空，别的用例看不到这里的 server。"""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        self.main = self.dir / "ops_tools.yaml"
        patcher = patch.dict(ops._state, {"path": self.main, "mtime": None, "omtime": None, "tmtime": None,
                                          "imtime": None, "mmtime": None, "includes": [], "tools": {},
                                          "problems": [], "mcp_servers": {}, "connections": {}, "hosts": None})
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(ops._mcp.configure, {})
        env = patch.dict(os.environ, {"OPS_SECRET_REMOTE_TOKEN": "remote-token-0123456789"})
        env.start()
        self.addCleanup(env.stop)
        FakeMcp.behavior, FakeMcp.seen, FakeMcp.sessions, FakeMcp.tools = {}, [], set(), TOOLS
        self.http = QuietServer(("127.0.0.1", 0), FakeMcp)
        threading.Thread(target=self.http.serve_forever, daemon=True).start()
        self.addCleanup(self.http.server_close)
        self.addCleanup(self.http.shutdown)
        self.url = f"http://127.0.0.1:{self.http.server_address[1]}/mcp"

    def configure(self, extra="", url=None):
        self.main.write_text(
            "mcp_servers:\n"
            f"  remote: {{url: '{url or self.url}', label: 远程文档, "
            f"headers: {{Authorization: 'Bearer ${{remote_token}}'}}{extra}}}\n"
            "tools: []\n", encoding="utf-8")
        ops.refresh(force=True)
        self.assertEqual(ops._state["problems"], [])
        return ops._mcp.get("remote")

    def requests(self, method):
        return [(headers, body) for verb, headers, body in FakeMcp.seen if verb == "POST" and body.get("method") == method]


class FakeServerTests(_Remote):
    def test_legacy_server_with_a_session_and_json_replies(self):
        """auto：先按 2026-07-28 发 server/discover，server 不认就退回 initialize；会话 id 和协议版本之后每个请求都带。"""
        server = self.configure()
        server.start()
        self.assertEqual((server.mode, server.protocol), ("legacy", "2025-11-25"))
        self.assertTrue(server.session)
        self.assertEqual(sorted(server.tools), ["lookup", "wipe"])
        result = server.call("lookup", {"term": "ingress"})
        self.assertEqual(result["content"][0]["text"], "docs about ingress; auth=Bearer remote-token-0123456789")
        headers, _ = self.requests("tools/call")[-1]
        self.assertEqual((headers["mcp-session-id"], headers["mcp-protocol-version"]), (server.session, "2025-11-25"))
        self.assertNotIn("mcp-session-id", self.requests("initialize")[0][0])
        self.assertEqual(len(self.requests("server/discover")), 1)
        server.stop()
        self.assertTrue(any(verb == "DELETE" for verb, _, _ in FakeMcp.seen))     # 有会话就告诉 server 可以收了

    def test_sse_replies_with_notifications_and_server_requests_in_between(self):
        FakeMcp.behavior = {"sse": True}
        server = self.configure()
        server.start()
        self.assertTrue(server.list_changed is False)                 # list_tools 之后清掉了
        result = server.call("lookup", {"term": "dns"})
        self.assertIn("docs about dns", result["content"][0]["text"])
        self.assertTrue(server.list_changed)                          # 夹在流里的通知记下了
        answers = [body for verb, _, body in FakeMcp.seen if verb == "POST" and body.get("id") == "srv-1"]
        self.assertTrue(answers)                                      # server 发来的请求回了「不支持」
        self.assertEqual(answers[0]["error"]["code"], -32601)

    def test_an_expired_session_is_renewed_and_the_request_sent_again(self):
        server = self.configure()
        server.start()
        first = server.session
        FakeMcp.sessions.clear()                                      # server 那边会话过期了
        result = server.call("lookup", {"term": "x"})
        self.assertIn("docs about x", result["content"][0]["text"])
        self.assertNotEqual(server.session, first)
        self.assertEqual(len(self.requests("initialize")), 2)

    def test_the_2026_protocol_has_no_session_and_carries_the_envelope(self):
        FakeMcp.behavior = {"modern": True}
        server = self.configure(", protocol: '2026-07-28'")
        server.start()
        self.assertEqual((server.mode, server.protocol, server.session), ("modern", "2026-07-28", None))
        self.assertEqual(server.server_info, {"name": "fake-modern", "version": "2"})
        server.call("lookup", {"term": "k8s"})
        for headers, body in self.requests("tools/list") + self.requests("tools/call"):
            self.assertNotIn("mcp-session-id", headers)
            self.assertEqual(headers["mcp-protocol-version"], "2026-07-28")
            meta = body["params"]["_meta"]
            self.assertEqual(meta[META + "protocolVersion"], "2026-07-28")
            self.assertIn(META + "clientCapabilities", meta)
        headers, _ = self.requests("tools/call")[-1]
        self.assertEqual((headers["mcp-method"], headers["mcp-name"]), ("tools/call", "lookup"))
        self.assertFalse(self.requests("initialize"))

    def test_auto_picks_2026_when_the_server_speaks_it(self):
        FakeMcp.behavior = {"modern": True}
        server = self.configure()
        server.start()
        self.assertEqual(server.protocol, "2026-07-28")

    def test_a_pinned_2026_against_a_legacy_server_fails_clearly(self):
        server = self.configure(", protocol: '2026-07-28'")
        with self.assertRaises(ops.McpError) as caught:
            server.start()
        self.assertIn("不支持 2026-07-28", str(caught.exception))

    def test_credentials_in_headers_never_come_back(self):
        """server 把请求头里的令牌原样回显，到模型、页面、日志之前都换成 ***。"""
        self.configure()
        ops._mcp.sync("remote", force=True)
        item = next(i for i in ops.list_pending() if i["tool"]["name"] == "remote__lookup")
        ops.approve_pending(item["id"])
        result = ops.run_tool("remote__lookup", {"term": "x"})
        self.assertTrue(result["ok"], result)
        self.assertIn("auth=Bearer ***", result["output"])
        page = {"tools": ops.describe_tools(), "mcp": ops.mcp_status(), "result": result}
        self.assertNotIn("remote-token-0123456789", json.dumps(page, ensure_ascii=False))
        self.assertEqual(ops.mcp_status()["remote"]["transport"], "http")
        self.assertEqual(ops.mcp_status()["remote"]["url"], self.url)

    def test_redirects_are_never_followed(self):
        FakeMcp.behavior = {"redirect": "http://evil.example/mcp"}
        server = self.configure()
        with self.assertRaises(ops.McpError) as caught:
            server.start()
        self.assertIn("拒绝跟随", str(caught.exception))
        FakeMcp.behavior = {"redirect": "/other"}
        server.next_retry = 0
        with self.assertRaises(ops.McpError) as caught:
            server.start()
        self.assertIn("同一主机的 /other", str(caught.exception))

    def test_oversized_replies_are_cut_off(self):
        server = self.configure()
        server.start()
        FakeMcp.behavior = {"huge": 64 * 1024}
        with patch.object(ops, "MCP_HTTP_MAX", 8 * 1024), self.assertRaises(ops.McpError) as caught:
            server.call("lookup", {"term": "x"})
        self.assertIn("回应超过", str(caught.exception))
        FakeMcp.behavior = {"huge": 64 * 1024, "sse": True}
        server.ensure()
        with patch.object(ops, "MCP_HTTP_MAX", 8 * 1024), self.assertRaises(ops.McpError) as caught:
            server.call("lookup", {"term": "x"})
        self.assertIn("回应超过", str(caught.exception))

    def test_a_slow_server_times_out(self):
        server = self.configure(", timeout: 1")
        server.start()
        FakeMcp.behavior = {"slow": 3}
        started = time.monotonic()
        with self.assertRaises(ops.McpError):
            server.call("lookup", {"term": "x"})
        self.assertLess(time.monotonic() - started, 2.9)
        self.assertFalse(server.online)                               # 下一次调用重新握手

    def test_a_dropped_sse_stream_resumes_with_last_event_id(self):
        FakeMcp.behavior = {"resume_on": "tools/call"}
        server = self.configure()
        server.start()
        result = server.call("lookup", {"term": "resumed"})
        self.assertIn("docs about resumed", result["content"][0]["text"])
        gets = [headers for verb, headers, _ in FakeMcp.seen if verb == "GET"]
        self.assertEqual(gets[-1]["last-event-id"], "evt-1")
        self.assertEqual(gets[-1]["mcp-session-id"], server.session)

    def test_discovery_approval_and_schema_drift(self):
        """和 stdio server 同一套：发现进待审，破坏性的不列出；批准后可用；server 改了参数形状就停用、重新进待审。"""
        self.configure()
        ops._mcp.sync("remote", force=True)
        pending = {item["tool"]["name"]: item for item in ops.list_pending()}
        self.assertEqual(sorted(pending), ["remote__lookup"])
        self.assertEqual(pending["remote__lookup"]["review"]["readonly"], "declared")
        self.assertIn("wipe：server 标为破坏性操作，不列出", ops._mcp.get("remote").notes)
        self.assertNotIn("remote__lookup", ops.available_tools())
        ops.approve_pending(pending["remote__lookup"]["id"])
        self.assertIn("remote__lookup", ops.available_tools())
        self.assertEqual(ops.available_tools()["remote__lookup"]["_meta"]["doc2sop"]["group"], "远程文档")
        FakeMcp.tools = [{**TOOLS[0], "inputSchema": {"type": "object", "properties": {"term": {"type": "integer"}}}}]
        ops._mcp.sync("remote", force=True)
        self.assertNotIn("remote__lookup", ops.available_tools())
        self.assertIn("schema 已变更", ops.run_tool("remote__lookup", {"term": "x"})["error"])
        self.assertEqual(ops.list_pending()[0]["review"]["reason"], "schema 已变更，需重新批准")

    def test_server_entries_are_checked(self):
        cases = [("{url: 'http://a.example/mcp', command: python3}", "只能写一种"),
                 ("{url: 'http://a.example/mcp?key=1'}", "不能带查询串"),
                 ("{url: 'ftp://a.example/mcp'}", "必须以 http:// 或 https:// 开头"),
                 ("{url: 'http://a.example/mcp', headers: {Mcp-Session-Id: x}}", "由 MCP 协议和传输层管"),
                 ("{url: 'http://a.example/mcp', headers: {X-Key: '${OPS_TOKEN}'}}", "凭据只能写成"),
                 ("{url: 'http://a.example/mcp', protocol: '2024-01-01'}", "protocol 只能是"),
                 ("{url: 'http://a.example/mcp', env: {A: b}}", "不认识的字段 env"),
                 ("{command: python3, headers: {A: b}}", "不认识的字段 headers")]
        for entry, needle in cases:
            with self.subTest(needle=needle):
                self.main.write_text(f"mcp_servers:\n  bad: {entry}\ntools: []\n", encoding="utf-8")
                ops.refresh(force=True)
                self.assertTrue(any(needle in p for p in ops._state["problems"]), ops._state["problems"])
                self.assertNotIn("bad", ops._state["mcp_servers"])


# --- 官方 SDK 起的真 server ----------------------------------------------------------------------

class Served:
    """在后台线程里起 uvicorn；with 块结束时关掉。"""

    def __init__(self, app):
        import uvicorn
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            self.port = probe.getsockname()[1]
        self.server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=self.port, log_level="warning"))
        self.url = f"http://127.0.0.1:{self.port}/mcp"

    def __enter__(self):
        self.thread = threading.Thread(target=self.server.run, daemon=True)
        self.thread.start()
        deadline = time.monotonic() + 20
        while not self.server.started and time.monotonic() < deadline:
            time.sleep(0.05)
        return self

    def __exit__(self, *exc):
        self.server.should_exit = True
        self.thread.join(10)


def sdk_app(json_response=False, idle=None):
    from mcp.server.mcpserver import MCPServer
    from mcp.types import ToolAnnotations

    server = MCPServer("doc2sop-remote-test", version="9.9")

    @server.tool(description="查文档", annotations=ToolAnnotations(readOnlyHint=True))
    def lookup(term: str) -> str:
        return f"docs about {term}"

    @server.tool(description="清空", annotations=ToolAnnotations(destructiveHint=True))
    def wipe() -> str:
        return "gone"

    kwargs = {"session_idle_timeout": idle} if idle else {}
    return server.streamable_http_app(json_response=json_response, **kwargs)


class OfficialSdkTests(_Remote):
    def approve_and_call(self, served, protocol):
        self.configure(f", protocol: '{protocol}'", url=served.url)
        ops._mcp.sync("remote", force=True)
        server = ops._mcp.get("remote")
        self.assertTrue(server.online, server.reason)
        pending = {item["tool"]["name"]: item for item in ops.list_pending()}
        self.assertEqual(sorted(pending), ["remote__lookup"])              # 破坏性的 wipe 不进待审
        ops.approve_pending(pending["remote__lookup"]["id"])
        result = ops.run_tool("remote__lookup", {"term": "ingress"})
        self.assertTrue(result["ok"], result)
        self.assertIn("docs about ingress", result["output"])
        return server

    def test_both_protocol_eras_and_both_reply_styles(self):
        for protocol, json_response, mode in (("2025-11-25", False, "legacy"), ("2025-11-25", True, "legacy"),
                                              ("2026-07-28", False, "modern"), ("auto", True, "modern")):
            with self.subTest(protocol=protocol, json_response=json_response), Served(sdk_app(json_response)) as served:
                for leftover in self.dir.glob("ops_tools.*.yaml"):
                    leftover.unlink()
                server = self.approve_and_call(served, protocol)
                self.assertEqual(server.mode, mode)
                self.assertEqual(server.protocol, "2026-07-28" if mode == "modern" else "2025-11-25")
                self.assertEqual(bool(server.session), mode == "legacy")
                self.assertEqual(server.server_info.get("name"), "doc2sop-remote-test")
                ops._mcp.configure({})

    def test_an_idle_session_expires_and_is_renewed(self):
        with Served(sdk_app(idle=1)) as served:
            server = self.approve_and_call(served, "2025-11-25")
            first = server.session
            time.sleep(2.5)
            result = ops.run_tool("remote__lookup", {"term": "again"})
            self.assertTrue(result["ok"], result)
            self.assertIn("docs about again", result["output"])
            self.assertNotEqual(server.session, first)


if __name__ == "__main__":
    unittest.main()
