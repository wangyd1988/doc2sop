"""知识库缺口看板（app/gaps.py）：哪些回答算缺口、归类、按次数排、忽略、对话删了就不再列、人工反馈、后台补算向量。"""
import json
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from tests.support import clear_graph

from app import conversations, gaps, graph
from app.config import WEB_PASSWORD, WEB_USER
from app.main import app

KB_TOOL = [{"tool": "kb_search", "args": {"query": "x"}, "category": "knowledge"}]
DATA_TOOL = [{"tool": "host_disk", "args": {}, "category": "data"}]


def say(question, answer, tools=None, mode="kb"):
    conv = conversations.create(question)
    conversations.add_message(conv["id"], "user", question, mode=mode)
    message = conversations.add_message(conv["id"], "assistant", answer, tools=tools, mode=mode)
    return conv["id"], message


class ClassifyTests(unittest.TestCase):
    def test_what_counts(self):
        c = gaps.classify
        self.assertEqual(c("年假怎么请", "按公司规定提前三天。", [], "kb")[0], "no_citation")
        self.assertEqual(c("报销流程", "知识库里没有报销流程的内容。", [], "kb")[0], "kb_missing")
        self.assertEqual(c("报销流程", "知识库里没有找到相关内容，以下内容来自网络搜索：……[W1]", [], "kb")[0], "kb_missing")
        self.assertIsNone(c("年假几天", "工龄满 1 年 5 天 [1]。", [], "kb"))
        self.assertEqual(c("调休怎么算", "通常按加班时长折算 [💡]。", KB_TOOL, "smart")[0], "smart_general")
        self.assertIsNone(c("Kafka 是什么", "一个消息队列 [💡]。", [], "smart"))           # 没查知识库：通用问题
        self.assertIsNone(c("调休怎么算", "按制度折算 [2]。", KB_TOOL, "smart"))

    def test_what_does_not(self):
        c = gaps.classify
        for question in ("你好", "谢谢！", "你是谁", "知识库里有哪些文档", "继续", "好的", "今天北京天气怎么样", "执行 SOP《巡检》"):
            self.assertIsNone(c(question, "随便说点什么", [], "kb"), question)
        self.assertIsNone(c("kb-app 内存有问题吗", "内存 91%，偏高。", DATA_TOOL, "kb"))      # 查实际数据


class BoardCase(unittest.TestCase):
    def setUp(self):
        clear_graph()
        with conversations.lock:
            conversations.db.execute("DELETE FROM messages")
            conversations.db.execute("DELETE FROM conversations")
            conversations.db.commit()


class BoardTests(BoardCase):
    def test_groups_by_similar_questions_and_counts(self):
        say("年假怎么请", "知识库里没有年假的申请流程。")
        say("年假怎么请？", "知识库里没有。")
        say("年假怎么请呀", "按公司规定提前三天在系统里提交。")              # 没引用知识库
        say("报销发票丢了怎么办", "知识库里没有相关内容。")
        say("年假几天", "5 天 [1]。")                                   # 有引用，不算
        say("你好", "您好！")
        board = gaps.board(embed=False)
        self.assertEqual([(g["count"], g["example"]) for g in board["groups"]],
                         [(3, "年假怎么请呀"), (1, "报销发票丢了怎么办")])
        self.assertEqual(board["groups"][0]["kinds"], {"kb_missing": 2, "no_citation": 1})
        self.assertEqual(board["questions"], 4)
        self.assertEqual(board["grouping"], "lexical")
        link = board["groups"][0]["link"]
        self.assertEqual(set(link), {"conversation_id", "message_id"})

    def test_scan_is_incremental(self):
        say("年假怎么请", "知识库里没有。")
        self.assertEqual(gaps.scan(), 1)
        self.assertEqual(gaps.scan(), 0)
        say("报销流程", "知识库里没有。")
        self.assertEqual(gaps.scan(), 1)

    def test_ignore_hides_the_group_and_future_similar_questions(self):
        say("年假怎么请", "知识库里没有。")
        say("年假怎么请？", "知识库里没有。")
        say("报销流程是什么", "知识库里没有。")
        group = gaps.board(embed=False)["groups"][0]
        self.assertEqual(gaps.ignore(group["keys"]), 2)
        self.assertEqual([g["example"] for g in gaps.board(embed=False)["groups"]], ["报销流程是什么"])
        say("年假怎么请啊", "知识库里没有。")                              # 相似的新问题也不再出现
        board = gaps.board(embed=False)
        self.assertEqual([g["example"] for g in board["groups"]], ["报销流程是什么"])
        self.assertEqual(board["ignored"], 3)

    def test_deleted_conversations_drop_out(self):
        conv, _ = say("年假怎么请", "知识库里没有。")
        self.assertEqual(gaps.board(embed=False)["total"], 1)
        conversations.delete(conv)
        self.assertEqual(gaps.board(embed=False)["total"], 0)

    def test_human_feedback(self):
        conv, message = say("VPN 怎么连", "请联系 IT 部门 [1]。")         # 有引用，本来不算
        run = graph.start_execution(conv, "VPN 怎么连")
        graph.finish_execution(run, "请联系 IT 部门 [1]。", message_id=message)
        graph.record_feedback(run, "unhelpful")
        groups = gaps.board(embed=False)["groups"]
        self.assertEqual([(g["example"], g["kinds"]) for g in groups], [("VPN 怎么连", {"feedback": 1})])
        self.assertIn("没答好", groups[0]["detail"])
        other = graph.start_execution(conv, "q")
        graph.record_feedback(other, "correct")                              # 判断正确不算
        self.assertEqual(gaps.board(embed=False)["questions"], 1)

    def test_vectors_merge_paraphrases(self):
        say("年假怎么请", "知识库里没有。")
        say("请年休假需要提前几天", "知识库里没有。")
        self.assertEqual(gaps.board(embed=False)["total"], 2)            # 字面上不像
        with patch.object(gaps, "embed_documents", side_effect=lambda texts: [[1.0, 0.0, 0.1] for _ in texts]), \
             patch.object(gaps.settings, "configured", return_value=True):
            self.assertEqual(gaps.embed_batch(), 2)
        board = gaps.board(embed=False)
        self.assertEqual((board["total"], board["grouping"]), (1, "vector"))

    def test_embedding_failures_back_off(self):
        say("年假怎么请", "知识库里没有。")
        with patch.object(gaps, "embed_documents", side_effect=RuntimeError("网关挂了")):
            self.assertEqual(gaps.embed_batch(), 0)
        self.assertGreater(gaps._embed["next"], 0)


class ApiTests(BoardCase):
    def test_board_ignore_and_workbench_card(self):
        client = TestClient(app)
        self.addCleanup(client.close)
        auth = (WEB_USER, WEB_PASSWORD)
        say("年假怎么请", "知识库里没有。")
        with patch.object(gaps, "_maybe_embed"):
            board = client.get("/api/gaps", auth=auth).json()
        self.assertEqual(board["total"], 1)
        overview = client.get("/api/overview", auth=auth).json()
        self.assertEqual(overview["gaps"]["groups"][0]["example"], "年假怎么请")
        self.assertNotIn("keys", overview["gaps"]["groups"][0])
        response = client.post("/api/gaps/ignore", json={"keys": board["groups"][0]["keys"]}, auth=auth)
        self.assertEqual(response.json(), {"ignored": 1})
        self.assertEqual(client.post("/api/gaps/ignore", json={"keys": []}, auth=auth).status_code, 400)
        with patch.object(gaps, "_maybe_embed"):
            self.assertEqual(client.get("/api/gaps", auth=auth).json()["total"], 0)


if __name__ == "__main__":
    unittest.main()
