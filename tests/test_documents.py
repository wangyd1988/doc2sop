"""Upload, categorising, download and failure reporting."""
import io
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient
from urllib.parse import quote, unquote

from tests.support import FakeCollection, FakeReply

from app import clients, config
from app.config import FILES_DIR, WEB_PASSWORD, WEB_USER
from app.main import app
from app.rag import answer, store


class DocumentTests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)
        self.addCleanup(self.client.close)
        self.auth = (WEB_USER, WEB_PASSWORD)

        self.store = {}
        collection = FakeCollection(self.store)
        for target in (store, ):
            patcher = patch.object(target, "collection", collection)
            patcher.start()
            self.addCleanup(patcher.stop)

        embed = patch.object(type(clients.embeddings), "embed_documents",
                             lambda _self, texts: [[0.1] * 768 for _ in texts])
        embed.start()
        self.addCleanup(embed.stop)

        for leftover in FILES_DIR.glob("*"):
            if leftover.is_file():
                leftover.unlink()

    def upload(self, name, body=None, category=None, suggestion="网络运维", content_type="text/plain"):
        payload = body if body is not None else "容器内存上限要在峰值之上留三成余量。".encode()
        files = {"file": (name, io.BytesIO(payload), content_type)}
        data = {"category": category} if category is not None else None
        with patch.object(type(clients.rewriter), "invoke",
                          lambda _s, _m, **kw: FakeReply(suggestion)):
            return self.client.post("/api/documents", files=files, data=data, auth=self.auth)

    def documents(self):
        return self.client.get("/api/documents", auth=self.auth).json()

    # --- categorising --------------------------------------------------------

    def test_auto_category_from_model(self):
        response = self.upload("内存笔记.txt")
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["category"], "网络运维")
        listed = self.documents()
        self.assertEqual(listed["documents"][0]["category"], "网络运维")
        self.assertEqual(listed["categories"], ["网络运维"])

    def test_explicit_category_skips_the_model(self):
        def boom(_self, _messages, **kwargs):
            raise AssertionError("模型不应被调用")

        files = {"file": ("手填分类.txt", io.BytesIO("内容".encode()), "text/plain")}
        with patch.object(type(clients.rewriter), "invoke", boom):
            response = self.client.post("/api/documents", files=files,
                                        data={"category": "我的笔记"}, auth=self.auth)
        self.assertEqual(response.json()["category"], "我的笔记")

    def test_category_falls_back_when_model_fails(self):
        def boom(_self, _messages, **kwargs):
            raise RuntimeError("model down")

        with patch.object(type(clients.rewriter), "invoke", boom):
            self.assertEqual(answer.suggest_category("a.txt", "内容", []), config.DEFAULT_CATEGORY)

    def test_category_is_trimmed_and_cleaned(self):
        cases = [('"网络运维"\n多余解释', "网络运维"),
                 ("  ", config.DEFAULT_CATEGORY),
                 ("超长分类名称超长分类名称超长", "超长分类名称超长分类名称")]
        for raw, expected in cases:
            with self.subTest(raw=raw), \
                 patch.object(type(clients.rewriter), "invoke",
                              lambda _s, _m, raw=raw, **kw: FakeReply(raw)):
                self.assertEqual(answer.suggest_category("a.txt", "内容", []), expected)

    def test_change_category_updates_every_chunk(self):
        self.upload("内存笔记.txt", body=("内存上限。" * 200).encode())
        before = self.documents()["documents"][0]
        self.assertGreater(before["chunks"], 1)

        response = self.client.patch("/api/documents/内存笔记.txt/category",
                                     json={"category": "K8S 网络"}, auth=self.auth)
        self.assertEqual(response.status_code, 200, response.text)
        after = self.documents()["documents"][0]
        self.assertEqual(after["category"], "K8S 网络")
        self.assertEqual(after["chunks"], before["chunks"])
        self.assertTrue(all(m["category"] == "K8S 网络" for _, m in self.store.values()))

    def test_change_category_rejects_unknown_and_empty(self):
        self.assertEqual(self.client.patch("/api/documents/没有这个.txt/category",
                                           json={"category": "x"}, auth=self.auth).status_code,
                         404)
        self.upload("有的.txt")
        self.assertEqual(self.client.patch("/api/documents/有的.txt/category",
                                           json={"category": ""}, auth=self.auth).status_code,
                         422)

    def test_documents_are_grouped_by_category(self):
        self.upload("甲.txt", suggestion="乙类")
        self.upload("乙.txt", suggestion="甲类")
        listed = self.documents()
        self.assertEqual([d["category"] for d in listed["documents"]], ["乙类", "甲类"])
        self.assertEqual(listed["categories"], ["乙类", "甲类"])

    # --- chunk identity ------------------------------------------------------

    def test_same_content_under_two_names_coexists(self):
        """Ids keyed by content would make the second upload silently erase the first."""
        same = "完全相同的内容".encode()
        self.upload("第一份.txt", body=same)
        self.upload("第二份.txt", body=same)
        names = sorted(d["source"] for d in self.documents()["documents"])
        self.assertEqual(names, ["第一份.txt", "第二份.txt"])

    def test_reupload_same_name_replaces_chunks(self):
        self.upload("覆盖.txt", body=("长内容。" * 300).encode())
        first = self.documents()["documents"][0]["chunks"]
        self.upload("覆盖.txt", body="短内容".encode())
        docs = self.documents()["documents"]
        self.assertEqual(len(docs), 1)
        self.assertLess(docs[0]["chunks"], first)

    # --- failure reporting ---------------------------------------------------

    def test_failure_reason_includes_original_message(self):
        self.assertEqual(config.why(ValueError("EOF marker not found")),
                         "ValueError：EOF marker not found")
        self.assertEqual(config.why(RuntimeError()), "RuntimeError")
        self.assertNotIn("\n", config.why(ValueError("第一行\n第二行")))

    def test_pdf_failure_surfaces_the_reason(self):
        files = {"file": ("坏文件.pdf", io.BytesIO(b"not really a pdf"), "application/pdf")}
        response = self.client.post("/api/documents", files=files, auth=self.auth)
        self.assertEqual(response.status_code, 400)
        detail = response.json()["detail"]
        # The concrete cause must be visible, not just the exception class name.
        self.assertRegex(detail, r"PDF 解析失败：\w+：.+")

    def test_embedding_failure_surfaces_the_reason(self):
        def boom(_self, _texts):
            raise ConnectionError("tunnel closed")

        files = {"file": ("普通.txt", io.BytesIO("内容".encode()), "text/plain")}
        with patch.object(type(clients.embeddings), "embed_documents", boom), \
             patch.object(type(clients.rewriter), "invoke",
                          lambda _s, _m, **kw: FakeReply("笔记")):
            response = self.client.post("/api/documents", files=files, auth=self.auth)
        self.assertEqual(response.status_code, 502)
        self.assertIn("tunnel closed", response.json()["detail"])

    def test_rejects_unsupported_and_empty_files(self):
        files = {"file": ("脚本.exe", io.BytesIO(b"MZ"), "application/octet-stream")}
        self.assertEqual(self.client.post("/api/documents", files=files,
                                          auth=self.auth).status_code, 400)
        files = {"file": ("空的.txt", io.BytesIO(b""), "text/plain")}
        self.assertEqual(self.client.post("/api/documents", files=files,
                                          auth=self.auth).status_code, 400)

    def test_oversize_upload_is_rejected_before_parsing(self):
        limit = config.MAX_FILE_BYTES
        files = {"file": ("太大.txt", io.BytesIO(b"x" * (limit + 1)), "text/plain")}
        with patch("app.main.extract_pages",
                   side_effect=AssertionError("不应进入解析")):
            response = self.client.post("/api/documents", files=files, auth=self.auth)
        self.assertEqual(response.status_code, 413)
        self.assertIn(str(limit // 1024 // 1024), response.json()["detail"])

    # --- download ------------------------------------------------------------

    def test_download_returns_original_bytes(self):
        for name in ("notes.txt", "配置 指南.txt", "a#b%&+.txt"):
            with self.subTest(name=name):
                data = b"\x00original bytes\xff\r\n"
                (FILES_DIR / name).write_bytes(data)
                response = self.client.get(
                    f"/api/documents/{quote(name, safe='')}/download", auth=self.auth)
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.content, data)
                disposition = unquote(response.headers["content-disposition"])
                self.assertTrue(disposition.startswith("attachment;"))
                self.assertIn(name, disposition)
                self.assertEqual(response.headers["cache-control"], "private, no-store")

    def test_download_requires_authentication(self):
        (FILES_DIR / "notes.txt").write_text("private")
        for auth in (None, ("invalid", "invalid")):
            self.assertEqual(
                self.client.get("/api/documents/notes.txt/download", auth=auth).status_code, 401)

    def test_download_rejects_traversal_and_symlinks(self):
        secret = FILES_DIR.parent / "secret.txt"
        secret.write_text("private")
        link = FILES_DIR / "linked.txt"
        if not link.exists():
            try:
                link.symlink_to(secret)
            except (OSError, NotImplementedError):
                link = None
        directory = FILES_DIR / "directory.txt"
        directory.mkdir(exist_ok=True)

        names = ["missing.txt", "..%2Fsecret.txt", "..%5Csecret.txt", "%00.txt",
                 ".env", "directory.txt"]
        if link is not None:
            names.append("linked.txt")
        for name in names:
            with self.subTest(name=name):
                response = self.client.get(f"/api/documents/{name}/download", auth=self.auth)
                self.assertEqual(response.status_code, 404)
                self.assertNotIn(b"private", response.content)

    def test_delete_removes_chunks_and_original_file(self):
        self.upload("待删除.txt")
        self.assertTrue((FILES_DIR / "待删除.txt").is_file())
        self.client.delete("/api/documents/待删除.txt", auth=self.auth)
        self.assertEqual(self.documents()["documents"], [])
        self.assertFalse((FILES_DIR / "待删除.txt").exists())


class WebNoteTests(unittest.TestCase):
    """联网得到的答案，经人确认后存成知识库文档。"""

    setUp = DocumentTests.setUp
    documents = DocumentTests.documents

    NOTE = {"title": "PostgreSQL VACUUM 区别", "question": "VACUUM FULL 和 VACUUM 有什么区别？",
            "answer": "知识库里没有找到相关内容，以下内容来自网络搜索。\n\n"
                      "VACUUM FULL 会重写整表并锁表 [W1]；参见内部规范 [2]。",
            "sources": [{"index": "W1", "location": "PostgreSQL 文档",
                         "url": "https://www.postgresql.org/docs/current/sql-vacuum.html"}]}

    def save(self, **change):
        return self.client.post("/api/web-notes", json={**self.NOTE, **change}, auth=self.auth)

    def test_saved_note_becomes_a_normal_document(self):
        response = self.save()
        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()
        self.assertEqual(body["source"], "网络补充-PostgreSQL VACUUM 区别.md")
        self.assertEqual(body["category"], "网络补充")
        listed = self.documents()["documents"]
        self.assertEqual([d["source"] for d in listed], [body["source"]])

    def test_note_records_where_it_came_from_and_when(self):
        self.save()
        text = (FILES_DIR / "网络补充-PostgreSQL VACUUM 区别.md").read_text(encoding="utf-8")
        self.assertIn("来源：网络搜索", text)
        self.assertIn(WEB_USER, text)
        self.assertIn("https://www.postgresql.org/docs/current/sql-vacuum.html", text)
        self.assertIn("[W1]", text)
        self.assertNotIn("[2]", text)   # 指向别的知识库文档的引用存进来会悬空，要去掉
        self.assertNotIn("知识库里没有", text)   # 存进来之后这句话就不成立了
        self.assertIn("VACUUM FULL 会重写整表", text)

    def test_only_web_sources_with_real_links_are_accepted(self):
        bad_sources = [
            [],
            [{"index": "1", "location": "x", "url": "https://a.example"}],
            [{"index": "W1", "location": "x", "url": "javascript:alert(1)"}],
        ]
        for sources in bad_sources:
            with self.subTest(sources=sources):
                self.assertEqual(self.save(sources=sources).status_code, 422)

    def test_title_cannot_escape_the_files_directory(self):
        response = self.save(title="../../etc/passwd")
        self.assertEqual(response.status_code, 200, response.text)
        self.assertNotIn("/", response.json()["source"])
        self.assertTrue((FILES_DIR / response.json()["source"]).is_file())

    def test_requires_login(self):
        response = self.client.post("/api/web-notes", json=self.NOTE)
        self.assertEqual(response.status_code, 401)


if __name__ == "__main__":
    unittest.main()
