"""Model connection settings editable from the page: masking, persistence, hot reload, reindex guard."""
import io
import os
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from tests.support import FakeCollection, FakeReply

from app import clients, config, settings
from app.config import WEB_PASSWORD, WEB_USER
from app.main import app
from app.rag import store


class SettingsTests(unittest.TestCase):
    def setUp(self):
        settings.reset()
        self.addCleanup(settings.reset)
        self.client = TestClient(app)
        self.addCleanup(self.client.close)
        self.auth = (WEB_USER, WEB_PASSWORD)
        self.store = {}
        p = patch.object(store, "collection", FakeCollection(self.store))
        p.start()
        self.addCleanup(p.stop)

    def test_defaults_come_from_env(self):
        cur = settings.current()
        self.assertEqual(cur["llm_base_url"], config.LLM_BASE_URL)
        self.assertEqual(cur["chat_model"], config.CHAT_MODEL)
        self.assertTrue(all(v == "env" for v in settings.public()["source"].values()))

    def test_key_is_never_returned(self):
        settings.save({"llm_api_key": "sk-secret-1234567890abcd"})
        data = self.client.get("/api/settings", auth=self.auth).json()
        self.assertNotIn("llm_api_key", data)
        self.assertTrue(data["llm_api_key_masked"].endswith("abcd"))
        self.assertNotIn("secret", data["llm_api_key_masked"])
        self.assertEqual(data["source"]["llm_api_key"], "page")

    def test_file_is_private_and_survives_reload(self):
        settings.save({"chat_model": "other-chat", "llm_api_key": "sk-x"})
        if os.name != "nt":
            self.assertEqual(oct(settings.PATH.stat().st_mode & 0o777), "0o600")
        settings._overrides.clear()
        settings._load()
        self.assertEqual(settings.get("chat_model"), "other-chat")

    def test_saving_rebuilds_clients(self):
        before = clients.llm
        settings.save({"llm_base_url": "http://127.0.0.1:9/other/v1", "chat_model": "new-model"})
        self.assertIsNot(clients.llm, before)
        self.assertEqual(clients.llm.model_name, "new-model")
        self.assertIn("other", str(clients.llm.openai_api_base))
        self.assertEqual(clients.embeddings.openai_api_base, "http://127.0.0.1:9/other/v1")

    def test_values_equal_to_env_are_not_marked_as_overrides(self):
        settings.save({"chat_model": config.CHAT_MODEL, "llm_base_url": config.LLM_BASE_URL})
        self.assertEqual(settings.public()["source"]["chat_model"], "env")
        self.assertEqual(settings.public()["source"]["llm_base_url"], "env")

    def test_embedding_can_live_on_its_own_endpoint(self):
        settings.save({"embed_base_url": "https://embed.example.com/v1", "embed_api_key": "sk-embed-0000abcd"})
        self.assertEqual(clients.embeddings.openai_api_base, "https://embed.example.com/v1")
        self.assertEqual(clients.llm.openai_api_base, config.LLM_BASE_URL)          # chat untouched
        pub = settings.public()
        self.assertTrue(pub["embed_api_key_masked"].endswith("abcd"))
        self.assertNotIn("embed_api_key", pub)
        # 清空地址 → 回到和对话同一处
        settings.save({"embed_base_url": ""})
        self.assertEqual(settings.embed_endpoint()[0], config.LLM_BASE_URL)
        self.assertEqual(settings.embed_endpoint()[1], config.LLM_API_KEY)   # 自己的 key 只在有自己的地址时才用

    def test_missing_models_endpoint_is_a_note_not_a_failure(self):
        with patch("langchain_openai.ChatOpenAI.invoke", return_value=FakeReply("OK")), \
             patch("langchain_openai.OpenAIEmbeddings.embed_query", return_value=[0.0] * 1024):
            r = settings.test("http://127.0.0.1:9/v1", "k", "chat", "embed")
        self.assertTrue(r["ok"])
        self.assertIn("列不出模型", r["models_note"])
        self.assertEqual(r["embed_dim"], 1024)

    def test_empty_key_keeps_the_old_one(self):
        settings.save({"llm_api_key": "sk-keep"})
        settings.save({"llm_api_key": "", "chat_model": "m2"})
        self.assertEqual(settings.get("llm_api_key"), "sk-keep")

    def body(self, **over):
        base = {"llm_base_url": config.LLM_BASE_URL, "llm_api_key": "", "chat_model": "chat-x",
                "embed_model": config.EMBED_MODEL, "vision_models": ["v1"]}
        base.update(over)
        return base

    def test_put_saves_and_exposes_defaults_to_the_page(self):
        r = self.client.put("/api/settings", json=self.body(), auth=self.auth)
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(self.client.get("/api/models", auth=self.auth).json()["default"], "chat-x")
        self.assertEqual(self.client.get("/api/documents", auth=self.auth).json()["chat_model"], "chat-x")

    def test_changing_embed_model_with_documents_requires_reindex(self):
        store.collection.add(["c1"], ["内容"], [[0.1, 0.2]], [{"source": "a.txt", "category": "x"}])
        r = self.client.put("/api/settings", json=self.body(embed_model="bge-large"), auth=self.auth)
        self.assertEqual(r.status_code, 409)
        self.assertIn("重建索引", r.json()["detail"])
        self.assertEqual(settings.get("embed_model"), config.EMBED_MODEL)   # nothing saved

    def test_reindex_recreates_the_collection_from_stored_files(self):
        # 其他测试可能留下了文件；本测试只认自己写的那一份
        for leftover in config.FILES_DIR.glob("*"):
            if leftover.is_file():
                leftover.unlink()
        (config.FILES_DIR / "重建.txt").write_bytes("重建后的内容".encode())
        self.addCleanup(lambda: (config.FILES_DIR / "重建.txt").unlink(missing_ok=True))
        store.collection.add(["old"], ["旧向量"], [[0.1, 0.2]], [{"source": "重建.txt", "category": "制度"}])

        def fake_reset():
            self.store.clear()

        with patch.object(store, "reset_collection", fake_reset), \
             patch.object(type(clients.embeddings), "embed_documents", lambda _s, texts: [[0.5] * 4 for _ in texts]), \
             patch.object(type(clients.rewriter), "invoke", lambda _s, _m, **kw: FakeReply("x")):
            r = self.client.put("/api/settings", json=self.body(embed_model="bge-large", reindex=True), auth=self.auth)
            self.assertEqual(r.status_code, 200, r.text)
            job_id = r.json()["reindex_job"]
            import time
            for _ in range(100):
                job = self.client.get(f"/api/jobs/{job_id}", auth=self.auth).json()
                if job["status"] in ("done", "error"):
                    break
                time.sleep(0.05)
        self.assertEqual(job["status"], "done", job)
        self.assertEqual(job["result"]["rebuilt"], 1)
        docs = store.list_documents()
        self.assertEqual([(d["source"], d["category"]) for d in docs], [("重建.txt", "制度")])   # category kept
        self.assertNotIn("old", self.store)

    def test_test_endpoint_reports_gateway_failure_without_saving(self):
        r = self.client.post("/api/settings/test", json=self.body(llm_base_url="http://127.0.0.1:9/v1"), auth=self.auth)
        data = r.json()
        self.assertFalse(data["ok"])
        self.assertTrue(data["errors"])
        self.assertEqual(settings.get("chat_model"), config.CHAT_MODEL)

    def test_reset_returns_to_env(self):
        settings.save({"chat_model": "zzz"})
        self.client.delete("/api/settings", auth=self.auth)
        self.assertEqual(settings.get("chat_model"), config.CHAT_MODEL)
        self.assertFalse(settings.PATH.exists())

    def test_requires_auth(self):
        self.assertEqual(self.client.get("/api/settings").status_code, 401)
        self.assertEqual(self.client.put("/api/settings", json=self.body()).status_code, 401)


if __name__ == "__main__":
    unittest.main()
