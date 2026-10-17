"""Large catalogues: group summaries, server-side paging and search; tool selection for the model."""
import unittest

from tests import support  # noqa: F401

from app import catalog
from app.agent import tools as agent_tools


def tool(group, enabled=True, runnable=True, **extra):
    return {"desc": extra.pop("desc", "说明"), "group": group, "enabled": enabled, "runnable": runnable,
            "command": extra.pop("command", "cmd"), "params": extra.pop("params", {}), **extra}


class PageToolsTests(unittest.TestCase):
    def setUp(self):
        self.tools = {f"host_{i:03d}": tool("宿主机") for i in range(45)}
        self.tools.update({f"gw_{i}": tool("模型网关", enabled=(i % 2 == 0)) for i in range(4)})
        self.tools["kube_x"] = tool("K8s", runnable=False)
        self.tools["odd"] = tool(None, desc="没有分组的")
        self.tools["disk_check"] = tool("宿主机", label="看磁盘", desc="查看各挂载点使用率",
                                        params={"mount": {"desc": "挂载点"}})

    def test_default_returns_groups_only(self):
        page = catalog.page_tools(self.tools)
        self.assertEqual(page["tools"], {})
        names = [g["name"] for g in page["groups"]]
        self.assertEqual(names[-1], "其他")                       # 「其他」永远排最后
        self.assertEqual(names[:-1], sorted(names[:-1]))
        by = {g["name"]: g for g in page["groups"]}
        self.assertEqual((by["模型网关"]["live"], by["模型网关"]["total"]), (2, 4))
        self.assertEqual((by["K8s"]["live"], by["K8s"]["total"]), (0, 1))
        self.assertEqual(page["count"], len(self.tools))
        self.assertEqual(page["live"], 45 + 2 + 1 + 1)

    def test_group_pages(self):
        first = catalog.page_tools(self.tools, group="宿主机")
        self.assertEqual(len(first["tools"]), 30)
        self.assertEqual(first["total"], 46)
        second = catalog.page_tools(self.tools, group="宿主机", offset=30)
        self.assertEqual(len(second["tools"]), 16)
        self.assertFalse(set(first["tools"]) & set(second["tools"]))
        self.assertEqual(len(catalog.page_tools(self.tools, group="宿主机", limit=1000)["tools"]), 46)
        self.assertLessEqual(catalog.clamp(0, 1000)[1], catalog.PAGE_MAX)

    def test_search_covers_name_label_desc_params(self):
        for q, expect in [("disk", ["disk_check"]), ("看磁盘", ["disk_check"]), ("挂载点", ["disk_check"]),
                          ("磁盘 使用率", ["disk_check"]), ("没有分组", ["odd"]), ("zzz", [])]:
            with self.subTest(q=q):
                self.assertEqual(sorted(catalog.page_tools(self.tools, q=q)["tools"]), expect)

    def test_search_wins_over_group(self):
        page = catalog.page_tools(self.tools, q="gw_1", group="宿主机")
        self.assertEqual(list(page["tools"]), ["gw_1"])


class SelectToolsTests(unittest.TestCase):
    def catalogue(self, n=200):
        tools = {f"noise_{i:03d}": {"desc": f"无关工具 {i}", "group": "杂项"} for i in range(n)}
        tools["host_disk"] = {"desc": "查看宿主机各挂载点磁盘使用率", "group": "宿主机", "label": "看磁盘"}
        tools["holiday_calendar"] = {"desc": "查询某年法定节假日与补班", "group": "日历"}
        tools["container_logs"] = {"desc": "查看容器最近日志", "group": "容器"}
        return tools

    def test_small_catalogue_is_untouched(self):
        few = {f"t{i}": {"desc": "x"} for i in range(10)}
        self.assertEqual(agent_tools.select_tools(few, "随便问"), few)

    def test_relevant_tools_survive_and_noise_is_cut(self):
        chosen = agent_tools.select_tools(self.catalogue(), "磁盘快满了吗，看看各挂载点使用率", limit=20)
        self.assertEqual(len(chosen), 20)
        self.assertIn("host_disk", chosen)

    def test_sop_tools_are_always_pinned(self):
        chosen = agent_tools.select_tools(self.catalogue(), "随便聊聊天气", must_have={"holiday_calendar"}, limit=5)
        self.assertIn("holiday_calendar", chosen)
        self.assertEqual(len(chosen), 5)

    def test_english_identifier_in_question_matches_tool_name(self):
        chosen = agent_tools.select_tools(self.catalogue(), "container_logs 里有没有报错", limit=3)
        self.assertIn("container_logs", chosen)


if __name__ == "__main__":
    unittest.main()
