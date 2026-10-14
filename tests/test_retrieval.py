"""Retrieval behaviour: scoring, cut-off and TOP_K."""
import unittest
from unittest.mock import patch

from tests import support  # noqa: F401  (sets env before app imports)

from app.rag import retrieval


class RetrievalTests(unittest.TestCase):
    def fake_store(self, documents, metadatas, distances):
        class Collection:
            def __init__(self):
                self.asked = {}

            def count(self):
                return len(documents)

            def query(self, **kwargs):
                self.asked.update(kwargs)
                size = kwargs["n_results"]
                return {"documents": [documents[:size]],
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

    def test_top_k_is_requested_and_capped(self):
        documents = [f"片段{i}" for i in range(50)]
        metadatas = [{"source": f"doc{i}.txt"} for i in range(50)]
        collection = self.fake_store(documents, metadatas, [0.3] * 50)
        with patch.object(retrieval.store, "collection", collection), \
             patch.object(retrieval, "embed_query", lambda _t: [0.0]), \
             patch.object(retrieval, "TOP_K", 8):
            hits = retrieval.retrieve("问题")
        self.assertEqual(collection.asked["n_results"], 8)
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

    def test_page_number_appears_in_the_location(self):
        collection = self.fake_store(["内容"], [{"source": "手册.pdf", "page": 48}], [0.3])
        with patch.object(retrieval.store, "collection", collection), \
             patch.object(retrieval, "embed_query", lambda _t: [0.0]):
            hits = retrieval.retrieve("问题")
        self.assertEqual(hits[0]["location"], "手册.pdf 第 48 页")

    def test_context_is_numbered_for_citation(self):
        hits = [{"index": 1, "location": "a.pdf 第 2 页", "text": "甲", "score": 0.7},
                {"index": 2, "location": "b.txt", "text": "乙", "score": 0.6}]
        context = retrieval.as_context(hits)
        self.assertIn("[1] 来源：a.pdf 第 2 页", context)
        self.assertIn("[2] 来源：b.txt", context)
        self.assertIn("没有检索到", retrieval.as_context([]))


if __name__ == "__main__":
    unittest.main()
