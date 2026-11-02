"""工具分组在页面上改（deploy/ops_readonly.py 的 group_change、/tools/group；app 的 /api/tools/group）。

分组只影响显示：写进覆盖层的 group 键，主配置一个字节都不动；不改分组时 /tools、/tools/full、/tools/pending 的输出逐字节不变。
"""
import contextlib
import io
import json
import textwrap
import threading
import unittest
import urllib.error
import urllib.request
from unittest.mock import patch

from fastapi.testclient import TestClient

from tests.test_page_approval import _Page, ops, quiet

from app import main as app_main
from app.agent import ops_client, registry
from app.config import WEB_PASSWORD, WEB_USER

CONFIG = textwrap.dedent("""\
    tools:
      - {name: host_disk, label: 磁盘用量, group: 主机, desc: 看磁盘, binary: df, argv: [df, -h], params: {}, export: true}
      - {name: host_mem, label: 内存, group: 主机, desc: 看内存, binary: free, argv: [free, -m], params: {}}
      - {name: pods, desc: 看 Pod, group: 容器, binary: kubectl, argv: [kubectl, get, pods], params: {}}
      - {name: loose, desc: 没写分组, binary: uptime, argv: [uptime], params: {}}
    """)


def dump(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


class GroupCase(_Page):
    def setUp(self):
        super().setUp()
        self.main.write_text(CONFIG, encoding="utf-8")
        quiet(ops.refresh, force=True)
        self.overrides = self.dir / "ops_tools.overrides.yaml"

    def change(self, **payload):
        return quiet(ops.group_change, payload)

    def snapshot(self):
        return (dump(ops.available_tools()), dump(ops.describe_tools()), dump(ops.list_pending()))


class OverrideTests(GroupCase):
    def test_setting_a_group_changes_only_that_tool_and_restoring_puts_every_byte_back(self):
        main_before, before = self.main.read_bytes(), self.snapshot()
        result, printed = self.change(action="set", name="pods", group="Kubernetes")
        self.assertEqual(result, {"changed": ["pods"]})
        self.assertEqual(self.main.read_bytes(), main_before)
        full = ops.describe_tools()
        self.assertEqual((full["pods"]["group"], full["pods"]["group_base"], full["pods"]["overridden"]),
                         ("Kubernetes", "容器", ["group"]))
        self.assertEqual(ops.available_tools()["pods"]["_meta"]["doc2sop"]["group"], "Kubernetes")
        for name in ("host_disk", "host_mem", "loose"):                  # 别的工具逐字节不变
            self.assertEqual(dump(full[name]), dump(json.loads(before[1])[name]))
        self.assertEqual(sorted(ops.available_tools()), sorted(json.loads(before[0])))      # 能用的工具不变
        self.assertEqual(self.change(action="reset", name="pods")[0], {"changed": ["pods"]})
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(self.change(action="reset", name="pods")[0], {"changed": []})     # 没覆盖时什么都不写

    def test_setting_the_main_config_group_back_is_the_same_as_restoring(self):
        before = self.snapshot()
        self.change(action="set", name="pods", group="Kubernetes")
        self.assertEqual(self.change(action="set", name="pods", group="容器")[0], {"changed": ["pods"]})
        self.assertEqual(self.snapshot(), before)

    def test_label_and_desc_overrides_keep_the_group_and_full_reset_drops_everything(self):
        self.change(action="set", name="pods", group="Kubernetes")
        quiet(ops.set_override, "pods", label="Pod 列表")
        self.assertEqual(ops.describe_tools()["pods"]["group"], "Kubernetes")
        self.change(action="reset", name="pods")                          # 只去掉分组，显示名还在
        self.assertEqual((ops.describe_tools()["pods"]["group"], ops.describe_tools()["pods"]["label"]), ("容器", "Pod 列表"))
        self.change(action="set", name="pods", group="Kubernetes")
        quiet(ops.reset_override, "pods")                                 # 「恢复为配置文件原值」：全部去掉
        self.assertEqual((ops.describe_tools()["pods"]["group"], ops.describe_tools()["pods"]["label"]), ("容器", ""))

    def test_renaming_a_group_moves_every_member_in_one_write(self):
        result, printed = self.change(action="rename", **{"from": "主机", "to": "基础设施"})
        self.assertEqual(result, {"changed": ["host_disk", "host_mem"]})
        groups = {n: t["group"] for n, t in ops.describe_tools().items()}
        self.assertEqual(groups, {"host_disk": "基础设施", "host_mem": "基础设施", "pods": "容器", "loose": ""})
        self.assertEqual(ops.available_tools()["host_disk"]["_meta"]["doc2sop"]["export"], True)   # 对外开放不变
        # 没写分组的在页面上叫「其他」：改它的名字就是给它们写上分组
        self.assertEqual(self.change(action="rename", **{"from": "其他", "to": "杂项"})[0], {"changed": ["loose"]})
        refused, _ = self.change(action="rename", **{"from": "主机", "to": "x"})
        self.assertIsInstance(refused, ops.ConfigError)                   # 已经没有「主机」了

    def test_bad_names_are_refused_and_nothing_is_written(self):
        for payload in ({"action": "set", "name": "pods", "group": "x" * 21},
                        {"action": "set", "name": "pods", "group": "a\nb"},
                        {"action": "set", "name": "pods", "group": "a\x1bb"},
                        {"action": "set", "name": "pods", "group": "   "},
                        {"action": "set", "name": "pods", "group": 3},
                        {"action": "set", "name": "nope", "group": "x"},
                        {"action": "rename", "from": "主机", "to": "主机"},
                        {"action": "rename", "from": "主机", "to": "a\u2028b"},
                        {"action": "drop", "name": "pods"}):
            with self.subTest(payload=payload):
                result, _ = self.change(**payload)
                self.assertIsInstance(result, ops.ConfigError)
        self.assertFalse(self.overrides.exists())

    def test_a_hand_edited_overrides_file_cannot_smuggle_a_bad_group(self):
        self.overrides.write_text("overrides:\n  pods: {group: \"" + "x" * 30 + "\"}\n  host_mem: {group: \"a\\nb\"}\n",
                                  encoding="utf-8")
        quiet(ops.refresh, force=True)
        groups = {n: t["group"] for n, t in ops.describe_tools().items()}
        self.assertEqual((groups["pods"], groups["host_mem"]), ("容器", "主机"))


class GroupHttpTests(GroupCase):
    def setUp(self):
        super().setUp()
        server = ops.ThreadingHTTPServer(("127.0.0.1", 0), ops.Handler)
        self.addCleanup(server.server_close)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.shutdown)
        self.url = f"http://127.0.0.1:{server.server_address[1]}"
        token = patch.object(ops.Handler, "token", "t0k")
        token.start()
        self.addCleanup(token.stop)
        self.printed = io.StringIO()
        redirect = contextlib.redirect_stdout(self.printed)
        redirect.__enter__()
        self.addCleanup(redirect.__exit__, None, None, None)

    def http(self, path, payload=None, token="t0k"):
        request = urllib.request.Request(self.url + path, json.dumps(payload).encode() if payload is not None else None,
                                         {"X-Ops-Token": token, "Content-Type": "application/json",
                                          "X-Ops-Caller": "web user=admin ip=10.0.0.1"})
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                return response.status, response.read()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read()

    def test_the_old_endpoints_are_byte_for_byte_the_same_until_a_group_is_changed(self):
        paths = ("/tools", "/tools/full", "/tools/pending")
        before = [self.http(p) for p in paths]
        self.assertEqual(self.http("/tools/group"), (200, b'{"supported": true}'))
        self.assertEqual(self.http("/tools/group", token="bad")[0], 401)
        self.assertEqual(self.http("/tools/group", {"action": "set", "name": "pods"}, token="bad")[0], 401)
        self.assertEqual(self.http("/tools/group", {"action": "set", "name": "pods", "group": "x" * 21})[0], 400)
        self.assertEqual([self.http(p) for p in paths], before)
        status, body = self.http("/tools/group", {"action": "set", "name": "pods", "group": "Kubernetes"})
        self.assertEqual((status, json.loads(body)), (200, {"changed": ["pods"]}))
        self.assertIn("[override] 改了分组：pods caller=web user=admin ip=10.0.0.1", self.printed.getvalue())
        self.assertNotEqual(self.http("/tools/full"), before[1])
        self.http("/tools/group", {"action": "reset", "name": "pods"})
        self.assertEqual([self.http(p) for p in paths], before)


class AppRouteTests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app_main.app)
        self.auth = (WEB_USER, WEB_PASSWORD)
        self.headers = {"Origin": "http://testserver"}

    def post(self, body, auth=True):
        return self.client.post("/api/tools/group", json=body, headers=self.headers, **({"auth": self.auth} if auth else {}))

    def test_the_app_forwards_only_known_fields(self):
        sent = []
        with patch.object(ops_client, "group_change", side_effect=lambda payload, caller="": sent.append(payload)
                          or {"changed": ["pods"]}):
            response = self.post({"action": "set", "name": "pods", "group": "Kubernetes", "enabled": False, "x": 1})
        self.assertEqual((response.status_code, response.json()), (200, {"changed": ["pods"]}))
        self.assertEqual(sent, [{"action": "set", "name": "pods", "group": "Kubernetes"}])
        self.assertEqual(self.post({"action": "drop"}).status_code, 400)
        self.assertEqual(self.post({"action": "set"}, auth=False).status_code, 401)

    def test_an_old_tool_service_and_refusals_are_reported(self):
        with patch.object(ops_client, "enabled", return_value=True), \
                patch.object(ops_client, "_request", side_effect=ops_client.OpsUnavailable("Not found", status=404)):
            old = self.post({"action": "reset", "name": "pods"})
        self.assertEqual((old.status_code, old.json()["detail"]), (501, ops_client.OLD_SERVICE_GROUP))
        with patch.object(ops_client, "enabled", return_value=True), \
                patch.object(ops_client, "_request", side_effect=ops_client.OpsUnavailable("分组名要 1..20 个字", status=400)):
            bad = self.post({"action": "set", "name": "pods", "group": "x" * 30})
        self.assertEqual((bad.status_code, bad.json()["detail"]), (400, "分组名要 1..20 个字"))
        with patch.object(ops_client, "enabled", return_value=True), \
                patch.object(ops_client, "_request", side_effect=ops_client.OpsUnavailable("连不上")):
            self.assertEqual(self.post({"action": "reset", "name": "pods"}).status_code, 502)

class ContractTests(GroupCase):
    def test_the_group_never_reaches_external_mcp_clients(self):
        self.change(action="set", name="host_disk", group="Kubernetes")
        entry = registry._normalize("host_disk", ops.available_tools()["host_disk"])
        public = registry.public_contract(registry.as_contract("host_disk", entry))
        self.assertNotIn("Kubernetes", json.dumps(public, ensure_ascii=False))
