"""文档分类的改名、合并、删除（app/categories.py）：令牌白名单只缩不放、会多看到的要口令、预览后有变化回 409。"""
import json
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

import tests.support  # noqa: F401
from tests.test_access_admin import GOOD, ORIGIN, FakeVerifier
from tests.test_mcp_export import BASIC, ExportCase, make_client, reset_access

from app import access, approval, categories, chat_config, mcp_server
from app import main as app_main
from app.agent import kb_tools, ops_client, registry, sop_tools
from app.config import CHAT_FILE
from app.rag import store


class CategoryCase(ExportCase):
    """文档：休假制度.md（人事）、巡检规范.md（运维）、值班表.md（运维）、未归类.md（没有 category 字段 = 未分类）。"""

    def setUp(self):
        super().setUp()
        self.addCleanup(reset_access)
        with access.lock:
            access.db.execute("DELETE FROM access_changes")
            access.db.commit()
        approval._hits.clear()
        self.add_doc("值班表.md", ["周末值班两人"], "运维")
        self.collection.add(["k9:0"], ["没有分类的老文档"], [[1.0, 0.0]], [{"source": "未归类.md"}])
        store._bump()
        self.http = TestClient(app_main.app)
        self.verifier = FakeVerifier()
        for p in (patch.object(ops_client, "verify_support", side_effect=lambda timeout=5: self.verifier.support()),
                  patch.object(ops_client, "verify_passphrase", side_effect=self.verifier.verify)):
            p.start()
            self.addCleanup(p.stop)
        self.addCleanup(lambda: (CHAT_FILE.unlink(missing_ok=True), chat_config.reset()))

    def token(self, name, cats, status="active"):
        token, _ = access.issue(name, ["knowledge", "sop"], cats)
        if status == "revoked":
            access.revoke(token["id"])
        return token["id"]

    def cats_of(self, token_id):
        return access.get(token_id)["categories"]

    def preview(self, body):
        return self.http.post("/api/categories/preview", auth=BASIC, json=body, headers=ORIGIN)

    def apply(self, body, version=None, passphrase=None):
        version = version or self.preview(body).json()["version"]
        payload = {**body, "version": version, **({"passphrase": passphrase} if passphrase is not None else {})}
        return self.http.post("/api/categories/apply", auth=BASIC, json=payload, headers=ORIGIN)

    def doc_categories(self):
        return {d["source"]: d["category"] for d in store.list_documents()}


class RenameTests(CategoryCase):
    def test_renaming_to_a_new_name_follows_into_whitelists_without_a_passphrase(self):
        ops = self.token("运维同事", ["运维"])
        both = self.token("两类都看", ["人事", "运维"])
        everyone = self.token("全部", None)
        body = {"action": "rename", "from": "运维", "to": "运维规范"}
        preview = self.preview(body).json()
        self.assertFalse(preview["merge"])
        self.assertFalse(preview["needs_passphrase"])
        self.assertEqual(preview["documents"], ["值班表.md", "巡检规范.md"])
        self.assertEqual({t["name"]: (t["after"], t["gained"], t["lost"]) for t in preview["tokens"]},
                         {"运维同事": (["运维规范"], 0, 0), "两类都看": (["人事", "运维规范"], 0, 0)})
        done = self.apply(body)
        self.assertEqual(done.status_code, 200, done.text)
        self.assertEqual(self.doc_categories()["巡检规范.md"], "运维规范")
        self.assertEqual(self.cats_of(ops), ["运维规范"])
        self.assertEqual(self.cats_of(both), ["人事", "运维规范"])
        self.assertIsNone(self.cats_of(everyone))
        self.assertEqual(self.verifier.calls, [])
        # 令牌照样看得到那几篇和来源在那里的 SOP
        turn = registry.Turn(categories=frozenset(self.cats_of(ops)))
        self.assertEqual(sorted(d["source"] for d in kb_tools.visible(turn)), ["值班表.md", "巡检规范.md"])
        self.assertEqual([p["name"] for p in sop_tools.visible(turn)], ["磁盘巡检"])
        record = access.list_changes()[0]
        self.assertEqual((record["kind"], record["count"]), ("token-categories", 2))
        self.assertIn("分类「运维」改名为「运维规范」", record["detail"])

    def test_merging_shrinks_tokens_that_had_only_the_old_one_down_to_nothing(self):
        only_ops = self.token("只看运维", ["运维"])
        body = {"action": "rename", "from": "运维", "to": "人事"}
        preview = self.preview(body).json()
        self.assertTrue(preview["merge"])
        self.assertEqual([(t["after"], t["gained"], t["lost"]) for t in preview["tokens"]], [([], 0, 2)])
        self.assertFalse(preview["needs_passphrase"])
        self.assertEqual(self.apply(body).status_code, 200)
        self.assertEqual(self.cats_of(only_ops), [])
        # 白名单空了 = 一篇都看不到：目录、检索、读原文、SOP 都是「没有」
        client = make_client(scopes=("knowledge", "sop"), categories=[])
        turn = registry.Turn(categories=frozenset())
        self.assertEqual(kb_tools.visible(turn), [])
        self.assertEqual(sop_tools.visible(turn), [])
        search, _ = mcp_server.call_tool(client, "kb_search", {"query": "磁盘"})
        self.assertNotIn("磁盘超过 80%", search)
        self.assertFalse(search.startswith("[执行失败]"), search)
        catalog, _ = mcp_server.call_tool(client, "kb_catalog", {})
        self.assertFalse(catalog.startswith("[执行失败]"), catalog)
        self.assertNotIn("巡检规范", catalog)
        self.assertNotIn("休假制度", catalog)
        read, _ = mcp_server.call_tool(client, "kb_read", {"source": "巡检规范.md", "page": 1})
        self.assertNotIn("磁盘超过 80%", read)
        listed, _ = mcp_server.call_tool(client, "sop_list", {})
        self.assertNotIn("磁盘巡检", listed)

    def test_a_merge_that_widens_an_active_token_needs_the_passphrase(self):
        hr = self.token("只看人事", ["人事"])
        old = self.token("吊销了的", ["人事"], status="revoked")
        body = {"action": "rename", "from": "运维", "to": "人事"}
        preview = self.preview(body).json()
        self.assertTrue(preview["needs_passphrase"])
        gained = {t["name"]: t["gained"] for t in preview["tokens"]}
        self.assertEqual(gained, {"只看人事": 2, "吊销了的": 2})
        missing = self.apply(body, preview["version"])
        self.assertEqual((missing.status_code, missing.json()["detail"]), (400, "没有输入审批口令"))
        wrong = self.apply(body, preview["version"], "guess")
        self.assertEqual(wrong.status_code, 403)
        self.assertNotIn("guess", wrong.text)
        self.assertEqual(self.doc_categories()["巡检规范.md"], "运维")              # 什么都没改
        done = self.apply(body, preview["version"], GOOD)
        self.assertEqual(done.status_code, 200, done.text)
        self.assertNotIn(GOOD, done.text)
        self.assertEqual(self.doc_categories()["巡检规范.md"], "人事")
        self.assertEqual(self.cats_of(hr), ["人事"])
        self.assertEqual(self.cats_of(old), ["人事"])
        self.assertEqual(self.verifier.calls, [("category-rename", "运维→人事")] * 2)
        self.assertEqual(access.list_changes(), [])        # 没有令牌的白名单要改，不记令牌的操作记录

    def test_only_revoked_tokens_widening_does_not_ask_for_the_passphrase(self):
        self.token("吊销了的", ["人事"], status="revoked")
        preview = self.preview({"action": "rename", "from": "运维", "to": "人事"}).json()
        self.assertFalse(preview["needs_passphrase"])


class DeleteTests(CategoryCase):
    def test_deleting_moves_documents_to_the_default_and_drops_the_name(self):
        ops = self.token("运维同事", ["运维", "人事"])
        body = {"action": "delete", "from": "运维"}
        preview = self.preview(body).json()
        self.assertEqual((preview["to"], preview["needs_passphrase"]), ("未分类", False))
        self.assertEqual(self.apply(body).status_code, 200)
        self.assertEqual(self.doc_categories()["值班表.md"], "未分类")
        self.assertEqual(self.cats_of(ops), ["人事"])

    def test_deleting_into_a_default_some_token_can_see_needs_the_passphrase(self):
        token, _ = access.issue("看未分类", ["knowledge"], ["未分类"])
        preview = self.preview({"action": "delete", "from": "运维"}).json()
        self.assertTrue(preview["needs_passphrase"])
        self.assertEqual([(t["id"], t["gained"]) for t in preview["tokens"]], [(token["id"], 2)])

    def test_chat_yaml_scopes_are_listed_and_count_when_they_would_widen(self):
        CHAT_FILE.write_text("groups:\n  1234567890123: {name: 人事群, categories: [人事]}\n"
                             "  2345678901234: {name: 运维群, categories: [运维]}\n", encoding="utf-8")
        chat_config.reset()
        preview = self.preview({"action": "rename", "from": "运维", "to": "人事"}).json()
        self.assertTrue(preview["needs_passphrase"])
        self.assertEqual({c["name"]: (c["gained"], c["lost"]) for c in preview["chat"]},
                         {"群 人事群": (2, 0), "群 运维群": (0, 2)})
        self.assertEqual(preview["chat_file"], str(CHAT_FILE))
        self.assertIn("运维", CHAT_FILE.read_text(encoding="utf-8"))        # 服务器上的文件不动


class GuardTests(CategoryCase):
    def test_reserved_names_and_bad_input(self):
        self.collection.add(["k8:0"], ["网上查到的"], [[1.0, 0.0]], [{"source": "网络补充-x.md", "category": "网络补充"}])
        store._bump()
        for body, status in ((({"action": "rename", "from": "网络补充", "to": "x"}), 400),
                             (({"action": "delete", "from": "网络补充"}), 400),
                             (({"action": "rename", "from": "运维", "to": "网络补充"}), 400),
                             (({"action": "delete", "from": "未分类"}), 400),
                             (({"action": "rename", "from": "运维", "to": "运维"}), 400),
                             (({"action": "rename", "from": "运维", "to": "一二三四五六七八九十一二三"}), 400),
                             (({"action": "rename", "from": "运维", "to": "a\x07b"}), 400),
                             (({"action": "rename", "from": "运维", "to": ""}), 400),
                             (({"action": "merge", "from": "运维", "to": "人事"}), 400),
                             (({"action": "rename", "from": "财务", "to": "人事"}), 409)):
            with self.subTest(body=body):
                self.assertEqual(self.preview(body).status_code, status)
                self.assertEqual(self.http.post("/api/categories/apply", auth=BASIC, headers=ORIGIN,
                                                json={**body, "version": "x", "passphrase": GOOD}).status_code, status)
        self.assertEqual(self.verifier.calls, [])
        approval._hits.clear()          # 上面十次 apply 用光了这一分钟的名额
        # 「未分类」可以改名（搬走它的文档），老片段没有 category 字段也一起改
        self.assertEqual(self.apply({"action": "rename", "from": "未分类", "to": "杂项"}).status_code, 200)
        self.assertEqual(self.doc_categories()["未归类.md"], "杂项")

    def test_apply_refuses_when_anything_changed_since_the_preview_without_using_the_passphrase(self):
        self.token("只看人事", ["人事"])
        body = {"action": "rename", "from": "运维", "to": "人事"}
        version = self.preview(body).json()["version"]
        access.issue("新签的", ["knowledge"], ["运维"])                      # 预览之后有人签了令牌
        stale = self.apply(body, version, GOOD)
        self.assertEqual(stale.status_code, 409)
        self.assertTrue(stale.json()["stale"])
        self.assertIn("新签的", json.dumps(stale.json()["preview"], ensure_ascii=False))
        version = stale.json()["preview"]["version"]
        store.set_category("值班表.md", "人事")                              # 又有人改了一篇的分类
        self.assertEqual(self.apply(body, version, GOOD).status_code, 409)
        self.assertEqual(self.verifier.calls, [])
        self.assertEqual(self.doc_categories()["巡检规范.md"], "运维")

    def test_a_change_while_the_passphrase_is_checked_is_caught_inside_the_lock(self):
        self.token("只看人事", ["人事"])
        body = {"action": "rename", "from": "运维", "to": "人事"}
        version = self.preview(body).json()["version"]

        def verify_then_change(*args, **kwargs):
            self.verifier.verify(*args, **kwargs)
            store.set_category("值班表.md", "人事")

        with patch.object(ops_client, "verify_passphrase", side_effect=verify_then_change):
            refused = self.apply(body, version, GOOD)
        self.assertEqual(refused.status_code, 409)
        self.assertEqual(self.doc_categories()["巡检规范.md"], "运维")

    def test_issuing_takes_the_same_lock_and_rechecks_the_categories(self):
        self.assertEqual(self.apply({"action": "delete", "from": "运维"}).status_code, 200)
        with self.assertRaises(access.AccessError):
            access.issue("晚了一步", ["knowledge"], ["运维"], known_categories=store.all_categories)
        with self.assertRaises(access.AccessError):     # 页面上签发也一样
            mcp_server.access.issue("晚了一步", ["knowledge"], ["运维"], known_categories=lambda: ["人事"])

    def test_the_routes_need_login_and_same_origin(self):
        body = {"action": "rename", "from": "运维", "to": "x"}
        self.assertEqual(self.http.post("/api/categories/preview", json=body).status_code, 401)
        self.assertEqual(self.http.post("/api/categories/apply", json=body).status_code, 401)
        with self.assertLogs("kb", "WARNING"):
            cross = self.http.post("/api/categories/apply", auth=BASIC, json=body, headers={"Origin": "http://evil.example"})
        self.assertEqual(cross.status_code, 403)
        self.assertEqual(self.http.post("/api/categories/apply", auth=BASIC, content=b"not json",
                                        headers={**ORIGIN, "Content-Type": "application/json"}).status_code, 400)


class NoAccessDbTests(unittest.TestCase):
    def test_without_mcp_ever_enabled_tokens_are_not_looked_at(self):
        with patch.object(categories, "MCP_ENABLED", False), \
                patch.object(categories, "DATA_DIR", categories.DATA_DIR / "nowhere"):
            self.assertIsNone(categories._access())


if __name__ == "__main__":
    unittest.main()
