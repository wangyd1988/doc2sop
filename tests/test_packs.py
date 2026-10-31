"""场景包：格式校验、导入（文档 + SOP）、幂等、导出、自动导入。

随仓库发布的包必须永远是干净的：pack.yaml 字段齐全、工具定义能被 ops_readonly 零问题加载、
SOP 只引用本包的工具。导入 SOP 仍然走 playbooks.validate，所以包不会带来新的执行权限。
"""
import importlib.util
import json
import re
import sqlite3
import sys
import tempfile
import unittest
from datetime import date
from pathlib import Path
from unittest.mock import patch

import yaml
from fastapi import HTTPException
from fastapi.testclient import TestClient

from tests.support import clear_graph  # noqa: F401  (sets env before app imports)

from app import config, packs, playbooks, settings
from app.config import WEB_PASSWORD, WEB_USER
from app.main import app

REPO = Path(__file__).resolve().parent.parent
SHIPPED = REPO / "packs"
DEMO = ("leave-planning", "model-selfcheck", "it-assets")

if "ops_readonly" in sys.modules:
    ops = sys.modules["ops_readonly"]
else:
    _SPEC = importlib.util.spec_from_file_location("ops_readonly", REPO / "deploy" / "ops_readonly.py")
    ops = importlib.util.module_from_spec(_SPEC)
    sys.modules["ops_readonly"] = ops
    _SPEC.loader.exec_module(ops)


def squash(text):
    """比对原句时忽略 Markdown 粗体标记和换行缩进。"""
    return re.sub(r"\s+|\*\*", "", text)


def load_as_included(pack_id, folder):
    """按真实用法加载一个包的工具：主配置 include 它；包要的演示库（pack.yaml 的 demo.sqlite）照演示 sidecar 的做法建好、
    在主配置里建连接。被包含的文件受场景包的规则约束（凭据只能经连接、或发往 ${…} 地址），直接当主文件加载就测不到。"""
    meta = yaml.safe_load((SHIPPED / pack_id / "pack.yaml").read_text(encoding="utf-8")) or {}
    demo = (meta.get("demo") or {}).get("sqlite")
    main = Path(folder) / "ops_tools.yaml"
    document = {"include": [str(SHIPPED / pack_id / "tools.yaml")], "tools": []}
    if demo:
        db = Path(folder) / f"{pack_id}.db"
        connection = sqlite3.connect(db)
        connection.executescript((SHIPPED / pack_id / demo["script"]).read_text(encoding="utf-8"))
        connection.commit()
        connection.close()
        document["connections"] = [{"name": demo["conn"], "type": "sqlite", "path": str(db)}]
    main.write_text(yaml.safe_dump(document, allow_unicode=True), encoding="utf-8")
    return main


class ShippedPacksTests(unittest.TestCase):
    """仓库里的三个包就是场景包格式的参考实现，必须一直通过校验。"""

    def setUp(self):
        self.found = packs.discover(SHIPPED)

    def test_every_shipped_pack_is_clean(self):
        self.assertEqual(sorted(self.found), ["it-assets", "leave-planning", "model-selfcheck", "ops-inspection"])
        for pack_id, pack in self.found.items():
            with self.subTest(pack=pack_id):
                self.assertEqual(pack["problems"], [])
                self.assertTrue(pack["docs"])
                self.assertTrue(pack["tools"])
                self.assertTrue(pack["summary"])
                self.assertTrue(pack["examples"])
                self.assertTrue(pack["category"])
                self.assertEqual(pack["id"], pack_id)

    def test_tool_definitions_load_in_ops_readonly_without_problems(self):
        for pack_id, pack in self.found.items():
            with self.subTest(pack=pack_id), tempfile.TemporaryDirectory() as folder:
                tools, problems = ops.load_tools(load_as_included(pack_id, folder))
                self.assertEqual(problems, [])
                self.assertEqual(sorted(tools), sorted(pack["tools"]))

    def test_demo_packs_need_no_infrastructure(self):
        """默认演示的包只用公网 HTTP、内置函数和随包建的 sqlite 演示库，不依赖工具服务所在机器装了什么；
        运维包才需要 docker，所以不在默认名单。"""
        for pack_id in DEMO:
            with tempfile.TemporaryDirectory() as folder:
                tools, _ = ops.load_tools(load_as_included(pack_id, folder))
            for name, spec in tools.items():
                with self.subTest(pack=pack_id, tool=name):
                    self.assertIn(spec.get("type"), ("http", "builtin", "sql"))
                    if spec["type"] == "sql":
                        self.assertEqual(spec["connection"]["type"], "sqlite")
        ops_tools, _ = ops.load_tools(SHIPPED / "ops-inspection" / "tools.yaml")
        self.assertIn("docker", {spec["binary"] for spec in ops_tools.values()})
        # 运维包的命令都是 Linux 写法（df -h、free -m）：声明了 os，在别的系统上是「不适用」而不是「缺命令」
        self.assertEqual({tuple(spec["os"]) for spec in ops_tools.values()}, {("linux",)})

    def test_gateway_tools_only_use_ops_secret_variables(self):
        tools, _ = ops.load_tools(SHIPPED / "model-selfcheck" / "tools.yaml")
        for name, spec in tools.items():
            text = json.dumps(spec["http"], ensure_ascii=False)
            self.assertIn("${OPS_SECRET_GATEWAY_URL}", text, name)
            self.assertNotIn("OPS_TOKEN", text, name)

    def test_leave_pack_sop_quotes_its_document(self):
        """演示包的 SOP 每一步的「依据」都得是文档里的原句，这是给人核对用的。"""
        pack = self.found["leave-planning"]
        doc = squash((SHIPPED / "leave-planning" / "docs" / "休假管理制度.md").read_text(encoding="utf-8"))
        sop = pack["sops"][0]
        self.assertEqual(sop["name"], "请假拼假核对")
        self.assertTrue(sop["enabled"])
        self.assertEqual([s["tool"] for s in sop["steps"]], ["holiday_calendar", "date_info"])
        for step in sop["steps"]:
            self.assertIn(squash(step["evidence"]), doc)

    def test_model_selfcheck_ships_without_sops_on_purpose(self):
        """它用来演示 SOP 从实践里长出来：grow 会和已有 SOP（含停用）去重，所以包里不能预置同路径的 SOP。"""
        self.assertEqual(self.found["model-selfcheck"]["sops"], [])

    def test_examples_say_what_they_are_for(self):
        """工作台按用途分组示例问题：{q, kind} 写法和老的纯文本写法（算查数据）都在用。"""
        kinds = {}
        for pack_id, pack in self.found.items():
            self.assertEqual([item["text"] for item in pack["example_items"]], pack["examples"])
            for item in pack["example_items"]:
                self.assertIn(item["kind"], packs.EXAMPLE_KINDS)
                kinds.setdefault(item["kind"], []).append(pack_id)
        self.assertLessEqual({"knowledge", "data", "sop"}, set(kinds))
        self.assertEqual({item["kind"] for item in self.found["model-selfcheck"]["example_items"]}, {"data"})
        self.assertEqual(self.found["leave-planning"]["example_items"][0],
                         {"text": "国庆想连休到 10 月 11 日要请几天年假", "kind": "sop"})

    def test_example_entries_are_validated(self):
        problems = []
        items = packs._examples(["纯文本", {"q": "查一下", "kind": "knowledge"}, {"q": "没写用途"},
                                 {"q": "写错用途", "kind": "magic"}, {"kind": "sop"}, ""], problems)
        self.assertEqual(items, [{"text": "纯文本", "kind": "data"}, {"text": "查一下", "kind": "knowledge"},
                                 {"text": "没写用途", "kind": "data"}])
        self.assertEqual(len(problems), 2)
        self.assertIn("kind 只能是", problems[0])
        self.assertIn("没写 q", problems[1])
        self.assertEqual(packs._examples("一句", []), [{"text": "一句", "kind": "data"}])

    def test_it_assets_sop_quotes_its_document(self):
        pack = self.found["it-assets"]
        doc = squash((SHIPPED / "it-assets" / "docs" / "IT资产管理规范.md").read_text(encoding="utf-8"))
        sop = pack["sops"][0]
        self.assertEqual([s["tool"] for s in sop["steps"]], ["asset_lookup", "asset_tickets"])
        for step in sop["steps"]:
            self.assertIn(squash(step["evidence"]), doc)

    def test_it_assets_demo_database_answers_the_examples(self):
        """演示库的日期按建库那天推算：什么时候跑，NB-0042「还在保、90 天内第二次报修」的结论都一样。"""
        with tempfile.TemporaryDirectory() as folder, \
                patch.dict(ops._state, {"path": load_as_included("it-assets", folder), "mtime": None, "omtime": None,
                                        "tmtime": None, "imtime": None, "mmtime": None, "includes": [], "tools": {},
                                        "problems": [], "mcp_servers": {}, "connections": {}, "hosts": None}):
            ops.refresh(force=True)
            lookup = ops.run_tool("asset_lookup", {"tag": "NB-0042"})["output"].splitlines()
            tickets = ops.run_tool("asset_tickets", {"tag": "NB-0042"})["output"].splitlines()
            expiring = ops.run_tool("assets_warranty_expiring", {"days": 60})["output"]
        warranty_end = lookup[1].split(" | ")[-1]
        self.assertGreater(warranty_end, date.today().isoformat())
        self.assertIn("王敏", lookup[1])
        self.assertEqual(tickets[-1], "（共 2 行）")
        self.assertIn("又有按键失灵", tickets[1])
        self.assertIn("NB-0042", expiring)
        self.assertIn("PC-0007", expiring)
        self.assertNotIn("PRN-0003", expiring)         # 80 天后才过保
        self.assertNotIn("NB-0057", expiring)          # 已经过保了

    def test_leave_pack_does_not_hard_code_a_year(self):
        """示例问题、文档、录制脚本都不写死年份：年底来的人不该看到「2026 年国庆」这种过期的提问。

        年份由 Agent 按「下一个该节日所在的年份」决定，规则写在工具 desc 和 SOP 检查点里；
        那一年还没公布时，工具输出会写明「尚未公布」。"""
        year = re.compile(r"20[2-9]\d\s*年")
        pack = self.found["leave-planning"]
        for text in pack["examples"]:
            self.assertIsNone(year.search(text), text)
        for path in (SHIPPED / "leave-planning" / "pack.yaml", SHIPPED / "leave-planning" / "tools.yaml",
                     SHIPPED / "leave-planning" / "sops.json", REPO / "README.md",
                     REPO / "docs" / "五分钟演示.md", REPO / "docs" / "场景包.md",
                     REPO / "deploy" / "demo" / "record.js"):
            with self.subTest(file=path.name):
                self.assertIsNone(year.search(path.read_text(encoding="utf-8")), f"{path.name} 写死了年份")
        tools, _ = ops.load_tools(SHIPPED / "leave-planning" / "tools.yaml")
        year_param = tools["holiday_calendar"]["params"]["year"]
        self.assertTrue(year_param["required"])
        self.assertNotIn("default", year_param)
        self.assertIn("下一个该节日所在的年份", tools["holiday_calendar"]["desc"])
        self.assertIn("尚未公布", tools["holiday_calendar"]["http"]["notes"]["empty"]["days"])
        self.assertIn("尚未公布", tools["holiday_calendar"]["http"]["notes"]["status"]["404"])
        self.assertIn("尚未公布", pack["sops"][0]["steps"][0]["checkpoint"])
        # 录制脚本不再钉死「3 天」，断言的是「请 N 天」这个模式
        script = (REPO / "deploy" / "demo" / "record.js").read_text(encoding="utf-8")
        self.assertNotIn("3\\s*天", script)
        self.assertIn("请假?", script)


def write_pack(root, pack_id="demo-pack", tools=("t_one", "t_two"), sops=None, docs=None,
               version=1, examples=("示例问题一", "示例问题二"), category="演示"):
    folder = Path(root) / pack_id
    (folder / "docs").mkdir(parents=True, exist_ok=True)
    for name, body in (docs or {"手册.md": "# 手册\n先看一，再看二。"}).items():
        (folder / "docs" / name).write_text(body, encoding="utf-8")
    (folder / "pack.yaml").write_text(
        f"id: {pack_id}\nname: 演示包\nversion: {version}\nsummary: 一句话\nroles: [测试]\n"
        f"requires: [无]\ncategory: {category}\nexamples: {json.dumps(list(examples), ensure_ascii=False)}\n",
        encoding="utf-8")
    entries = "".join(f"  - {{name: {t}, binary: free, argv: [free, -m], params: {{}}}}\n" for t in tools)
    (folder / "tools.yaml").write_text("tools:\n" + entries, encoding="utf-8")
    if sops is None:
        sops = [{"name": "演示 SOP", "trigger": "演示时", "enabled": False,
                 "steps": [{"tool": "t_one", "args": {}, "checkpoint": "看一", "evidence": "先看一"},
                           {"tool": "t_two", "args": {"x": ""}, "checkpoint": "看二", "evidence": "再看二"}]}]
    (folder / "sops.json").write_text(json.dumps(sops, ensure_ascii=False), encoding="utf-8")
    return folder


class FakeIngest:
    def __init__(self, fail=None):
        self.calls = []
        self.fail = fail

    def __call__(self, name, data, category="", report=lambda stage: None):
        report("解析文件")
        if self.fail:
            raise self.fail
        self.calls.append((name, len(data), category))
        return {"source": name, "chunks": 1}


class PackTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "packs"
        self.root.mkdir()
        for patcher in (patch.object(config, "PACKS_DIR", self.root),
                        patch.object(packs, "STATE_PATH", Path(self.tmp.name) / "packs.json"),
                        patch.object(config, "DEMO_PACKS", [])):
            patcher.start()
            self.addCleanup(patcher.stop)
        packs._notes.clear()
        packs._failed.clear()
        packs._progress.update(importing="", stage="")
        with playbooks.lock:
            playbooks.db.execute("DELETE FROM steps")
            playbooks.db.execute("DELETE FROM playbooks")
            playbooks.db.commit()
        clear_graph()
        self.ingest = FakeIngest()
        self.tools = {"t_one", "t_two", "t_other"}


class ImportTests(PackTestCase):
    def test_import_ingests_docs_and_saves_sops(self):
        write_pack(self.root)
        result = packs.import_pack("demo-pack", self.ingest, self.tools)
        self.assertFalse(result["skipped"])
        self.assertEqual([(name, category) for name, _, category in self.ingest.calls], [("手册.md", "演示")])
        saved = playbooks.list_all()
        self.assertEqual(len(saved), 1)
        self.assertEqual(saved[0]["id"], packs.stable_id("demo-pack", "演示 SOP"))
        self.assertEqual(saved[0]["source"], "手册.md")      # 默认挂在包里第一篇文档名下
        self.assertFalse(saved[0]["enabled"])
        self.assertEqual([s["tool"] for s in saved[0]["steps"]], ["t_one", "t_two"])
        self.assertEqual(saved[0]["steps"][1]["evidence"], "再看二")
        self.assertEqual(packs.imported("demo-pack")["sops"], ["演示 SOP"])

    def test_import_is_idempotent_until_forced(self):
        write_pack(self.root)
        packs.import_pack("demo-pack", self.ingest, self.tools)
        again = packs.import_pack("demo-pack", self.ingest, self.tools)
        self.assertTrue(again["skipped"])
        self.assertEqual(len(self.ingest.calls), 1)
        playbooks.set_enabled(packs.stable_id("demo-pack", "演示 SOP"), True)
        forced = packs.import_pack("demo-pack", self.ingest, self.tools, force=True)
        self.assertFalse(forced["skipped"])
        self.assertEqual(len(self.ingest.calls), 2)
        self.assertEqual(len(playbooks.list_all()), 1)      # 覆盖，不是再长一份
        self.assertFalse(playbooks.list_all()[0]["enabled"])  # 重导回到包里写的启停状态

    def test_waits_while_tools_are_missing(self):
        """工具没上线就不导：文档也不先入库，免得出现半个包。"""
        write_pack(self.root)
        with self.assertRaises(packs.PackWaiting) as caught:
            packs.import_pack("demo-pack", self.ingest, {"t_one"})
        self.assertIn("t_two", str(caught.exception))
        self.assertEqual(self.ingest.calls, [])
        self.assertIsNone(packs.imported("demo-pack"))
        self.assertEqual(playbooks.list_all(), [])

    def test_waits_until_a_model_is_configured(self):
        write_pack(self.root)
        with patch.object(settings, "configured", return_value=False):
            with self.assertRaises(packs.PackWaiting):
                packs.import_pack("demo-pack", self.ingest, self.tools)
        self.assertEqual(self.ingest.calls, [])

    def test_embedding_outage_is_retryable_but_bad_documents_are_not(self):
        write_pack(self.root)
        with self.assertRaises(packs.PackWaiting):
            packs.import_pack("demo-pack", FakeIngest(fail=HTTPException(502, "向量化失败")), self.tools)
        with self.assertRaises(packs.PackError):
            packs.import_pack("demo-pack", FakeIngest(fail=HTTPException(400, "没有提取到文字")), self.tools)
        self.assertIsNone(packs.imported("demo-pack"))

    def test_sop_may_only_use_tools_from_its_own_pack(self):
        """包必须自洽，别人装了这个包才跑得起来；这也是 validate 之前的第一道格式检查。"""
        write_pack(self.root, sops=[{"name": "越界", "steps": [{"tool": "t_other", "args": {}}]}])
        pack = packs.discover()["demo-pack"]
        self.assertTrue(any("t_other" in p for p in pack["problems"]), pack["problems"])
        with self.assertRaises(packs.PackError):
            packs.import_pack("demo-pack", self.ingest, self.tools)

    def test_script_tools_and_bad_ids_are_rejected(self):
        folder = write_pack(self.root, pack_id="Bad_Name")
        (folder / "tools.yaml").write_text(
            "tools:\n  - {name: sc, script: x.sh, params: {}}\n", encoding="utf-8")
        pack = packs.discover()["Bad_Name"]
        self.assertTrue(any("目录名" in p for p in pack["problems"]))
        self.assertTrue(any("脚本型" in p for p in pack["problems"]))

    def test_unknown_pack(self):
        with self.assertRaises(packs.PackError):
            packs.import_pack("nope", self.ingest, self.tools)

    def test_export_round_trips_the_sops_json_shape(self):
        write_pack(self.root)
        packs.import_pack("demo-pack", self.ingest, self.tools)
        exported = packs.export_sops("手册.md")
        self.assertEqual(exported, [{
            "name": "演示 SOP", "trigger": "演示时", "source": "手册.md", "enabled": False,
            "steps": [{"tool": "t_one", "args": {}, "checkpoint": "看一", "evidence": "先看一"},
                      {"tool": "t_two", "args": {"x": ""}, "checkpoint": "看二", "evidence": "再看二"}]}])
        self.assertEqual(packs.export_sops("别的来源"), [])
        self.assertEqual(len(packs.export_sops()), 1)

    def test_examples_and_status_follow_the_import(self):
        write_pack(self.root)
        with patch.object(config, "DEMO_PACKS", ["demo-pack"]):
            self.assertEqual(packs.examples(), [])
            before = packs.status(self.tools)[0]
            self.assertEqual((before["phase"], before["auto"], before["missing_tools"]), ("pending", True, []))
            self.assertEqual(packs.progress()["pending"], ["demo-pack"])
            packs.import_pack("demo-pack", self.ingest, self.tools)
            self.assertEqual(packs.examples(), ["示例问题一", "示例问题二"])
            self.assertEqual(packs.example_items(), [{"text": "示例问题一", "kind": "data"},
                                                     {"text": "示例问题二", "kind": "data"}])
            after = packs.status({"t_one"})[0]
            self.assertEqual(after["phase"], "imported")
            self.assertEqual(after["missing_tools"], ["t_two"])
            self.assertEqual(packs.progress()["pending"], [])
            write_pack(self.root, version=2)
            self.assertEqual(packs.status(self.tools)[0]["phase"], "outdated")


class AutoImportTests(PackTestCase):
    def test_background_loop_imports_then_stops(self):
        write_pack(self.root)
        with patch.object(config, "DEMO_PACKS", ["demo-pack", "missing-pack"]):
            packs._run(self.ingest, lambda: self.tools)
        self.assertEqual(packs.imported("demo-pack")["version"], 1)
        self.assertIn("missing-pack", packs._failed)
        self.assertIn("没有这个包", packs._notes["missing-pack"])

    def test_loop_keeps_waiting_for_tools_and_wakes_on_poke(self):
        write_pack(self.root)
        waits = []

        def fake_wait(delay):
            waits.append(delay)
            # 第一轮没工具；poke 之后第二轮工具到位
            if len(waits) == 1:
                self.tools_now.update(self.tools)
                return True
            return False

        self.tools_now = set()
        with patch.object(config, "DEMO_PACKS", ["demo-pack"]), \
                patch.object(packs._wake, "wait", side_effect=fake_wait):
            packs._run(self.ingest, lambda: set(self.tools_now))
        self.assertEqual(waits, [5])
        self.assertEqual(packs.imported("demo-pack")["docs"], ["手册.md"])
        self.assertNotIn("demo-pack", packs._notes)

    def test_nothing_starts_without_demo_packs(self):
        self.assertIsNone(packs.start_autoimport(self.ingest, lambda: self.tools))


class ApiTests(PackTestCase):
    def setUp(self):
        super().setUp()
        self.client = TestClient(app)
        self.addCleanup(self.client.close)
        self.auth = (WEB_USER, WEB_PASSWORD)
        for patcher in (patch("app.main.usable_tools", return_value={t: "说明" for t in self.tools}),
                        patch("app.main.ingest", self.ingest)):
            patcher.start()
            self.addCleanup(patcher.stop)
        write_pack(self.root)

    def test_list_import_and_export(self):
        listed = self.client.get("/api/packs", auth=self.auth).json()
        self.assertEqual([p["id"] for p in listed["packs"]], ["demo-pack"])
        self.assertEqual(listed["packs"][0]["phase"], "pending")
        self.assertEqual(listed["dir"], str(self.root))

        done = self.client.post("/api/packs/demo-pack/import", auth=self.auth)
        self.assertEqual(done.status_code, 200, done.text)
        self.assertEqual(done.json()["sops"], ["演示 SOP"])
        self.assertEqual(self.ingest.calls[0][0], "手册.md")

        docs = self.client.get("/api/documents", auth=self.auth).json()
        self.assertEqual(docs["examples"], ["示例问题一", "示例问题二"])
        self.assertEqual(docs["packs"]["pending"], [])

        exported = self.client.get("/api/packs/export?source=手册.md", auth=self.auth).json()
        self.assertEqual(exported["sops"][0]["name"], "演示 SOP")
        self.assertTrue(self.client.post("/api/packs/demo-pack/import", auth=self.auth).json()["skipped"])

    def test_waiting_and_bad_packs_map_to_409_and_400(self):
        with patch("app.main.usable_tools", return_value={}):
            waiting = self.client.post("/api/packs/demo-pack/import", auth=self.auth)
        self.assertEqual(waiting.status_code, 409)
        self.assertIn("等待工具上线", waiting.json()["detail"])
        self.assertEqual(self.client.post("/api/packs/nope/import", auth=self.auth).status_code, 400)

    def test_everything_needs_auth(self):
        self.assertEqual(self.client.get("/api/packs").status_code, 401)
        self.assertEqual(self.client.post("/api/packs/demo-pack/import").status_code, 401)
