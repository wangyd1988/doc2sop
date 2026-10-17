"""Retrieval behaviour: scoring, cut-off, TOP_K and vector + keyword fusion."""
import unittest
from unittest.mock import patch

from tests.support import FakeCollection  # noqa: F401  (sets env before app imports)

from app.rag import lexical, retrieval, store


class RetrievalTests(unittest.TestCase):
    """Vector-only behaviour; the keyword retriever is silenced here."""

    def setUp(self):
        quiet = patch.object(retrieval.lexical, "search", lambda _q, _n: [])
        quiet.start()
        self.addCleanup(quiet.stop)

    def fake_store(self, documents, metadatas, distances):
        class Collection:
            def __init__(self):
                self.asked = {}

            def count(self):
                return len(documents)

            def query(self, **kwargs):
                self.asked.update(kwargs)
                size = kwargs["n_results"]
                return {"ids": [[f"c{i}" for i in range(min(size, len(documents)))]],
                        "documents": [documents[:size]],
                        "metadatas": [metadatas[:size]],
                        "distances": [distances[:size]]}

        return Collection()

    def test_low_score_chunks_are_dropped(self):
        collection = self.fake_store(["相关内容", "无关内容"],
                                     [{"source": "a.txt"}, {"source": "b.txt"}],
                                     [0.4, 0.9])
        with patch.object(retrieval.store, "collection", collection), \
             patch.object(retrieval, "embed_query", lambda _t: [0.0]):
            hits = retrieval.retrieve("问题")
        self.assertEqual([h["location"] for h in hits], ["a.txt"])
        # Indexes stay contiguous after filtering so citations line up.
        self.assertEqual(hits[0]["index"], 1)

    def test_candidates_go_deeper_than_top_k_and_results_are_capped(self):
        documents = [f"片段{i}" for i in range(50)]
        metadatas = [{"source": f"doc{i}.txt"} for i in range(50)]
        collection = self.fake_store(documents, metadatas, [0.3] * 50)
        with patch.object(retrieval.store, "collection", collection), \
             patch.object(retrieval, "embed_query", lambda _t: [0.0]), \
             patch.object(retrieval, "TOP_K", 8):
            hits = retrieval.retrieve("问题")
        self.assertEqual(collection.asked["n_results"], retrieval.CANDIDATES)
        self.assertEqual([h["index"] for h in hits], list(range(1, 9)))

    def test_requests_no_more_than_the_collection_holds(self):
        collection = self.fake_store(["a", "b", "c"], [{"source": "x.txt"}] * 3, [0.3] * 3)
        with patch.object(retrieval.store, "collection", collection), \
             patch.object(retrieval, "embed_query", lambda _t: [0.0]), \
             patch.object(retrieval, "TOP_K", 8):
            hits = retrieval.retrieve("问题")
        self.assertEqual(collection.asked["n_results"], 3)
        self.assertEqual(len(hits), 3)

    def test_empty_collection_returns_nothing(self):
        collection = self.fake_store([], [], [])
        with patch.object(retrieval.store, "collection", collection):
            self.assertEqual(retrieval.retrieve("问题"), [])

    def test_page_number_and_category_appear(self):
        collection = self.fake_store(["内容"], [{"source": "手册.pdf", "page": 48, "category": "网络补充"}], [0.3])
        with patch.object(retrieval.store, "collection", collection), \
             patch.object(retrieval, "embed_query", lambda _t: [0.0]):
            hits = retrieval.retrieve("问题")
        self.assertEqual(hits[0]["location"], "手册.pdf 第 48 页")
        self.assertEqual(hits[0]["category"], "网络补充")
        self.assertEqual(hits[0]["match"], "vector")

    def test_context_is_numbered_for_citation(self):
        hits = [{"index": 1, "location": "a.pdf 第 2 页", "text": "甲", "score": 0.7},
                {"index": 2, "location": "b.txt", "text": "乙", "score": 0.6}]
        context = retrieval.as_context(hits)
        self.assertIn("[1] 来源：a.pdf 第 2 页", context)
        self.assertIn("[2] 来源：b.txt", context)
        self.assertIn("没有检索到", retrieval.as_context([]))

    def test_overview_questions_are_recognised(self):
        for q in ["总结一下知识库里有哪些主要内容", "知识库里都有什么", "有哪些文档", "你有什么资料",
                  "介绍一下知识库", "知识库的分类"]:
            self.assertTrue(retrieval.is_overview(q), q)
        for q in ["容器内存上限怎么设", "年假有几天", "mem_limit 是什么", "总结一下这篇文档的要点"]:
            self.assertFalse(retrieval.is_overview(q), q)

    def test_catalog_groups_documents_by_category(self):
        docs = [{"source": "巡检.md", "chunks": 5, "category": "运维"},
                {"source": "休假.md", "chunks": 3, "category": "制度"},
                {"source": "排障.pdf", "chunks": 9, "category": "运维"}]
        with patch.object(retrieval.store, "list_documents", return_value=docs):
            text = retrieval.catalog_context()
        self.assertIn("共 3 个文档、17 个片段，分 2 类", text)
        self.assertIn("运维（2 篇）：《巡检》、《排障》", text)
        self.assertIn("制度（1 篇）：《休假》", text)
        self.assertIn("不要据此说", text)
        with patch.object(retrieval.store, "list_documents", return_value=[]):
            self.assertIn("空的", retrieval.catalog_context())


class LexicalTests(unittest.TestCase):
    def test_tokenizer_keeps_identifiers_whole_and_splits_cjk_into_bigrams(self):
        tokens = lexical.tokenize("设置 mem_limit=512m 后报 OOMKilled")
        self.assertIn("mem_limit", tokens)
        self.assertIn("512m", tokens)
        self.assertIn("oomkilled", tokens)
        self.assertIn("设置", tokens)
        self.assertNotIn("设置后", tokens)

    def test_exact_term_outranks_topic_overlap(self):
        texts = ["容器内存上限通过 mem_limit 字段设置，超过后会被 OOMKilled",
                 "容器的内存、CPU 等资源可以在编排文件里限制",
                 "数据库连接池大小的建议值"]
        index = lexical._Index([f"c{i}" for i in range(3)], texts, [{}] * 3)
        got = index.search("mem_limit 怎么配", 3)
        self.assertEqual(got[0][0], "c0")
        self.assertTrue(all(score > 0 for *_, score in got))

    def test_query_without_known_terms_matches_nothing(self):
        index = lexical._Index(["c0"], ["一些内容"], [{}])
        self.assertEqual(index.search("zzzz", 3), [])


class HybridTests(unittest.TestCase):
    """Vector and keyword results fuse; a keyword-only hit still gets a real cosine score."""

    def setUp(self):
        self.collection = FakeCollection()
        for target in (store, ):
            p = patch.object(target, "collection", self.collection)
            p.start()
            self.addCleanup(p.stop)
        # Force the BM25 index to rebuild for this collection.
        lexical._index, lexical._built_for = None, -1
        self.addCleanup(lambda: setattr(lexical, "_index", None))

    def add(self, cid, text, source, vector):
        self.collection.add([cid], [text], [vector], [{"source": source}])

    def test_weak_keyword_only_hits_are_not_admitted(self):
        """只靠常见双字命中、语义又不沾边的片段，不能挤进结果。"""
        self.add("v1", "休假制度：年假 5 天", "a.md", [1.0, 0.0])
        self.add("v2", "补班安排", "b.md", [1.0, 0.0])
        self.add("noise", "巡检有几项，几天做一次", "c.md", [0.0, 1.0])   # cosine 0, no identifiers
        with patch.object(retrieval, "embed_query", lambda _t: [1.0, 0.0]), \
             patch.object(retrieval, "CANDIDATES", 2):
            hits = retrieval.retrieve("年假有几天")
        self.assertNotIn("c.md", [h["location"] for h in hits])

    def test_keyword_only_hit_is_included_with_cosine_score(self):
        # Vector search (fake) returns the first N rows in insertion order; put the
        # exact-term chunk last so only BM25 can surface it.
        self.add("v1", "容器资源限制的一般原则", "a.md", [1.0, 0.0])
        self.add("v2", "内存与 CPU 的配额", "b.md", [1.0, 0.0])
        self.add("kw", "mem_limit 字段控制容器内存上限", "c.md", [0.6, 0.8])
        with patch.object(retrieval, "embed_query", lambda _t: [1.0, 0.0]), \
             patch.object(retrieval, "CANDIDATES", 2), patch.object(retrieval, "TOP_K", 8):
            hits = retrieval.retrieve("mem_limit 怎么设")
        by_loc = {h["location"]: h for h in hits}
        self.assertIn("c.md", by_loc)
        self.assertEqual(by_loc["c.md"]["match"], "lexical")
        self.assertAlmostEqual(by_loc["c.md"]["score"], 0.6, places=3)

    def test_chunk_found_by_both_ranks_first(self):
        self.add("x", "mem_limit 字段控制容器内存上限", "both.md", [1.0, 0.0])
        self.add("y", "容器资源限制的一般原则", "vec.md", [1.0, 0.0])
        with patch.object(retrieval, "embed_query", lambda _t: [1.0, 0.0]):
            hits = retrieval.retrieve("mem_limit")
        self.assertEqual(hits[0]["location"], "both.md")
        self.assertEqual(hits[0]["match"], "both")

    def test_index_rebuilds_after_store_changes(self):
        self.add("a", "旧内容", "a.md", [1.0, 0.0])
        with patch.object(retrieval, "embed_query", lambda _t: [1.0, 0.0]):
            retrieval.retrieve("新词")
        store.replace_document(["b"], ["包含 新词 的新文档"], [[1.0, 0.0]], [{"source": "b.md"}], "b.md")
        with patch.object(retrieval, "embed_query", lambda _t: [1.0, 0.0]):
            hits = retrieval.retrieve("新词")
        self.assertTrue(any(h["location"] == "b.md" and h["match"] in ("both", "lexical") for h in hits))

    def test_keyword_failure_degrades_to_vector_only(self):
        self.add("a", "内容", "a.md", [1.0, 0.0])

        def boom(_q, _n):
            raise RuntimeError("index broken")

        with patch.object(retrieval, "embed_query", lambda _t: [1.0, 0.0]), \
             patch.object(retrieval.lexical, "search", boom):
            hits = retrieval.retrieve("内容")
        self.assertEqual([h["location"] for h in hits], ["a.md"])


class RerankTests(unittest.TestCase):
    """Cross-encoder rerank is best-effort: reorders the fused head, never blocks answering."""

    def hits(self, n):
        return [{"index": i + 1, "location": f"d{i}.md", "text": f"片段{i}", "score": 0.5, "match": "vector"}
                for i in range(n)]

    def test_disabled_when_no_model_configured(self):
        from app.rag import rerank
        with patch.object(rerank.settings, "get", lambda k: "" if k == "rerank_model" else "x"):
            self.assertFalse(rerank.enabled())
            self.assertEqual([h["location"] for h in rerank.rerank("q", self.hits(12), 8)],
                             [f"d{i}.md" for i in range(8)])

    def test_reorders_by_score_and_renumbers(self):
        from app.rag import rerank
        captured = {}

        def fake_post(url, payload):
            captured.update(url=url, payload=payload)
            n = len(payload["documents"])
            return {"results": [{"index": i, "relevance_score": float(i)} for i in range(n)]}   # last is best

        with patch.object(rerank, "enabled", return_value=True), \
             patch.object(rerank.settings, "get", lambda k: {"rerank_model": "kb-rerank", "llm_base_url": "http://gw:4000/v1", "llm_api_key": "k"}[k]), \
             patch.object(rerank, "RERANK_CANDIDATES", 12), patch.object(rerank, "_post", fake_post):
            out = rerank.rerank("问题", self.hits(20), 8)
        self.assertEqual(captured["url"], "http://gw:4000/v1/rerank")
        self.assertEqual(captured["payload"]["model"], "kb-rerank")
        self.assertEqual(len(captured["payload"]["documents"]), 12)          # only the head is scored
        self.assertEqual([h["location"] for h in out], [f"d{i}.md" for i in range(11, 3, -1)])
        self.assertEqual([h["index"] for h in out], list(range(1, 9)))      # citations stay contiguous
        self.assertEqual(out[0]["rerank"], 11.0)

    def test_failure_falls_back_to_fused_order(self):
        from app.rag import rerank

        def boom(url, payload):
            raise TimeoutError("slow")

        with patch.object(rerank, "enabled", return_value=True), \
             patch.object(rerank.settings, "get", lambda k: "x"), patch.object(rerank, "_post", boom):
            out = rerank.rerank("q", self.hits(12), 8)
        self.assertEqual([h["location"] for h in out], [f"d{i}.md" for i in range(8)])
        self.assertNotIn("rerank", out[0])

    def test_retrieval_keeps_more_candidates_when_rerank_is_on(self):
        collection = RetrievalTests.fake_store(self, [f"片段{i}" for i in range(40)],
                                               [{"source": f"d{i}.md"} for i in range(40)], [0.3] * 40)
        seen = {}

        def fake_rerank(question, hits, keep):
            seen["n"] = len(hits)
            return hits[:keep]

        with patch.object(retrieval.store, "collection", collection), \
             patch.object(retrieval, "embed_query", lambda _t: [0.0]), \
             patch.object(retrieval.lexical, "search", lambda _q, _n: []), \
             patch.object(retrieval.rerank, "enabled", return_value=True), \
             patch.object(retrieval.rerank, "rerank", fake_rerank), \
             patch.object(retrieval, "TOP_K", 8), patch.object(retrieval, "RERANK_CANDIDATES", 12):
            out = retrieval.retrieve("问题")
        self.assertEqual(seen["n"], 12)
        self.assertEqual(len(out), 8)

    def test_context_shows_rerank_score_when_present(self):
        text = retrieval.as_context([{"index": 1, "location": "a.md", "text": "甲", "score": 0.6, "rerank": 4.25}])
        self.assertIn("重排分 4.2", text)


if __name__ == "__main__":
    unittest.main()
