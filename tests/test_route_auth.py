"""每条路由都要网页登录（Basic），只有两个入口例外：对外 MCP 的 /mcp（令牌在 mcp_server.TokenGate 里校验）
和告警入口 /api/alerts/hook（告警令牌，没配时 404），各带一条末尾带斜杠的。

FastAPI 的全局 Basic 依赖只管 APIRoute；直接挂在路由表上的原始 Route、Mount 它管不到。以后谁再挂一条不经登录的路由，
这里就会挂：要么让它经过登录，要么想清楚以后加进 PUBLIC，并在文档里写明它自己怎么认证。
"""
import re
import unittest

from fastapi import Depends, FastAPI
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

import tests.support  # noqa: F401  隔离 DATA_DIR 和环境变量
from app import main as app_main
from app import mcp_server
from app.config import WEB_PASSWORD, WEB_USER

PUBLIC = {"/mcp", "/mcp/", "/api/alerts/hook", "/api/alerts/hook/"}


def with_mcp():
    """生产开着对外 MCP：main.app 的路由原样拿来，再装上 /mcp（和 test_mcp_export.make_app 一样）。"""
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None, dependencies=[Depends(app_main.require_auth)])
    app.router.routes.extend(app_main.app.router.routes)
    mcp_server.install(app)
    return app


def leaves(routes, prefix=""):
    """路由表里的每一条。新版 FastAPI 的 include_router 不再把路由摊平，而是留着原来的路由器（_IncludedRouter），要往里走。"""
    for route in routes:
        inner = getattr(route, "original_router", None)
        if inner is not None:
            context = getattr(route, "include_context", None)
            yield from leaves(inner.routes, prefix + (getattr(context, "prefix", "") or ""))
        else:
            yield prefix + getattr(route, "path", ""), route


def concrete(path):
    return re.sub(r"\{[^}]+\}", "1", path)


class RouteAuthTests(unittest.TestCase):
    def assert_login_everywhere(self, app, expect_public):
        client = TestClient(app)
        public, checked = set(), 0
        for path, route in leaves(app.router.routes):
            if isinstance(route, APIRoute):
                for method in sorted(route.methods):
                    with self.subTest(method=method, path=path):
                        response = client.request(method, concrete(path))
                        self.assertEqual(response.status_code, 401, response.text[:200])
                    checked += 1
                continue
            with self.subTest(kind=type(route).__name__, path=path):
                self.assertIn(path, PUBLIC, "不经网页登录的路由：给它加上登录，或者想清楚以后加进 PUBLIC")
            public.add(path)
        self.assertEqual(public, expect_public)
        self.assertGreater(checked, 50, "没走到 include_router 挂进来的那些路由")
        return client

    def test_every_route_needs_the_web_login_except_the_alert_hook(self):
        client = self.assert_login_everywhere(app_main.app, {"/api/alerts/hook", "/api/alerts/hook/"})
        for path in ("/api/runs", "/api/schedules", "/api/alert-rules", "/api/gaps", "/api/automation"):
            self.assertEqual(client.get(path).status_code, 401, path)
        # 告警入口不认网页密码；没配告警令牌时对谁都是 404
        for auth in (None, (WEB_USER, WEB_PASSWORD)):
            self.assertEqual(client.post("/api/alerts/hook", json={"title": "x"}, auth=auth).status_code, 404)

    def test_with_the_mcp_exit_on_only_mcp_is_added(self):
        client = self.assert_login_everywhere(with_mcp(), PUBLIC)
        # /mcp 不认网页密码，只认对外接入签发的令牌
        for auth in (None, (WEB_USER, WEB_PASSWORD)):
            self.assertEqual(client.post("/mcp", json={}, auth=auth).status_code, 401)


if __name__ == "__main__":
    unittest.main()
