"""云上协同里的文字：纯文本、出处、截断、命令和推送的措辞（app/chat_format.py）。"""
import unittest

import tests.support  # noqa: F401  隔离 DATA_DIR 和环境变量

from app import chat_format as fmt
from app.chat_config import Scope

SOP = ("按 SOP《每日巡检》执行：\n\n| 步骤 | 查看 | 实际数据 | 结论 |\n|---|---|---|---|\n"
       "| 1 | 根分区使用率 | 87% | ⚠️ 超过阈值 85% |\n| 2 | 容器内存 | 512MB | ✅ 正常 |\n\n需要跟进：清理日志")


class PlainTests(unittest.TestCase):
    def test_markdown_becomes_readable_plain_text(self):
        text = ("## 处理步骤\n**先**看 `docker stats`，见[手册](https://wiki.example.com/a) [1]。[💡]\n"
                "- 第一项\n* 第二项\n> 引用\n---\n```bash\nls -l\n```")
        self.assertEqual(fmt.plain(text), "【处理步骤】\n先看 docker stats，见手册（https://wiki.example.com/a） [1]。"
                                          "（💡通用知识）\n• 第一项\n• 第二项\n引用\n\nls -l")

    def test_sop_table_becomes_one_line_per_step(self):
        self.assertEqual(fmt.plain(SOP), "按 SOP《每日巡检》执行：\n\n1. 根分区使用率：87% ⚠️（超过阈值 85%）\n"
                                         "2. 容器内存：512MB ✅（正常）\n\n需要跟进：清理日志")

    def test_other_tables_become_rows(self):
        self.assertEqual(fmt.plain("| 名称 | 值 |\n|---|---|\n| a | **1** |"), "名称｜值\na｜1")

    def test_markdown_switch_keeps_the_answer_as_is(self):
        self.assertEqual(fmt.plain(" ## 标题\n**粗** ", markdown=True), "## 标题\n**粗**")


class SourcesTests(unittest.TestCase):
    HITS = [{"index": 1, "location": "运维手册.md"}, {"index": 2, "location": "值班制度.docx 第 3 页"},
            {"index": 3, "location": "没引用的.md"},
            {"index": "W1", "location": "Redis 官方文档", "url": "https://redis.io/docs/x", "web": True}]

    def test_only_cited_sources_are_listed(self):
        answer = "先看内存 [1]，再按制度 [2,W1] 处理。"
        self.assertEqual(fmt.cited(answer), {"1", "2", "W1"})
        self.assertEqual(fmt.sources_line(answer, self.HITS),
                         "出处：[1] 运维手册.md　[2] 值班制度.docx 第 3 页　[W1] Redis 官方文档（redis.io）")

    def test_nothing_cited_means_no_line(self):
        self.assertEqual(fmt.sources_line("知识库里没有找到。", self.HITS), "")


class LengthTests(unittest.TestCase):
    def test_truncate_prefers_paragraph_boundaries(self):
        body = "第一段" * 10 + "\n\n" + "第二段" * 10
        self.assertEqual(fmt.truncate(body, 40), ("第一段" * 10, "第二段" * 10))
        self.assertEqual(fmt.truncate("短的", 40), ("短的", ""))

    def test_compose_marks_the_cut_and_keeps_the_tail(self):
        body = "第一段" * 10 + "\n\n" + "第二段" * 10
        text, rest = fmt.compose("↪ 回复 张三：问题", body, ["出处：[1] a.md", ""], 40)
        self.assertEqual(text, "↪ 回复 张三：问题\n" + "第一段" * 10 + "\n" + fmt.MORE_HINT + "\n\n出处：[1] a.md")
        self.assertEqual(rest, "第二段" * 10)

    def test_pieces_for_the_rest(self):
        self.assertEqual(fmt.pieces("x" * 7000, 3000, 2), (["x" * 3000, "x" * 3000], "x" * 1000))


class WordingTests(unittest.TestCase):
    def test_mention_is_removed_but_lines_stay(self):
        self.assertEqual(fmt.strip_mention("@doc2sop\u2005kb-app 内存高怎么办 ", "doc2sop"), "kb-app 内存高怎么办")
        self.assertEqual(fmt.strip_mention("@doc2sop 看看这段日志：\nERROR a\n  ERROR b", "doc2sop"),
                         "看看这段日志：\nERROR a\nERROR b")

    def test_reply_head_quotes_the_first_twenty_characters(self):
        self.assertEqual(fmt.reply_head("张三", "kb-app 的内存一直在涨，怎么排查比较好呢？"),
                         "↪ 回复 张三：kb-app 的内存一直在涨，怎么排查比…")

    def test_help_lists_what_this_place_can_do_and_where_data_goes(self):
        titles = {"host_disk": "磁盘使用率"}
        full = fmt.help_text(Scope("group", "1001", "值班群", tools=("host_disk",)), titles, group=True, web=True,
                             contact="王某某")
        self.assertIn("磁盘使用率", full)
        self.assertIn("执行 / 执行 2", full)
        self.assertIn("模型服务商", full)
        self.assertIn("搜索服务", full)
        self.assertIn("找 王某某", full)
        docs = fmt.help_text(Scope("person", "u1", "王某某"), titles, group=False, web=False)
        self.assertIn("只查文档", docs)
        self.assertNotIn("执行 /", docs)
        self.assertNotIn("搜索服务", docs)


class PushTextTests(unittest.TestCase):
    RUN = {"id": "a1b2c3d4" + "0" * 24, "level": "anomaly", "playbook_name": "磁盘巡检",
           "started_at": "2026-11-02T01:00:00+00:00", "trigger": "schedule", "note": "每天 09:00",
           "summary": "1 项异常：根分区（87%）", "params": {"host": "gw"},
           "report": {"findings": [{"mark": "warn", "step": "第 1 步 根分区", "value": "87%", "note": "超过 85%"}],
                      "followups": ["清理日志"]}}

    def test_push_has_the_conclusion_and_no_plain_http_link(self):
        text = fmt.push_text(self.RUN, "problem", None, "http://10.0.0.5:8765")
        self.assertTrue(text.startswith("【有异常】SOP《磁盘巡检》11-02 09:00\n"), text)
        for part in ("触发：定时（每天 09:00）", "参数：host=gw", "⚠️ 第 1 步 根分区：87%（超过 85%）", "• 清理日志",
                     "执行记录 a1b2c3（网页：SOP → 执行记录）"):
            self.assertIn(part, text)
        self.assertNotIn("http://", text)

    def test_https_site_gets_a_link_and_tags_follow_the_kind(self):
        text = fmt.push_text(self.RUN, "still", None, "https://kb.example.com")
        self.assertTrue(text.startswith("【仍未恢复·有异常】"))
        self.assertIn("查看完整报告：https://kb.example.com/sop?tab=runs&item=" + self.RUN["id"], text)
        self.assertTrue(fmt.push_text({**self.RUN, "level": "ok", "report": {}}, "recovered", None).startswith("【已恢复】"))

    def test_digest_lists_groups(self):
        text = fmt.digest_text([{"example": "如何申请 VPN 权限", "count": 6}], "运维值班群")
        self.assertIn("本周「运维值班群」里大家常问", text)
        self.assertIn("1. 如何申请 VPN 权限（6 次）", text)


if __name__ == "__main__":
    unittest.main()
