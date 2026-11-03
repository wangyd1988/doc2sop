"""群聊机器人接钉钉以后，云上协同那条路逐字节不变（chat.yaml 不写 platform 时）。

tests/fixtures/chat_ccwork_baseline.json 是用接钉钉之前（6138381）的 app/chat_config.py、app/chat_format.py 跑下面同一组
输入得到的：每份 chat.yaml 解析出的结果（开通了谁、各自能查什么、暂停没有、问题说明一字不差）、发给模型的群聊提示、
「帮助」里的数据去向、测试推送的文字。这里用现在的代码再跑一遍，必须完全一样（页面接口多出的 platform、platform_name
两个键除外）。原来判错的配置（会话 ID 写成 cid…、拼错的顶层键、写错的 limits……）也在里面。
"""
import json
import os
import tempfile
import unittest
from pathlib import Path

import tests.support  # noqa: F401  隔离 DATA_DIR 和环境变量

from app import chat_config, chat_format

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "chat_ccwork_baseline.json"
NEW_KEYS = ("platform", "platform_name")

CORPUS = {
    "good": """
robot_name: doc2sop
contact: 王某某
paused: false
keep_days: 180
limits: {person_per_hour: 5, max_chars: 1000}
markdown: true
groups:
  1234567890123: {name: 运维值班群, tools: [host_disk, container_stats], categories: [运维], web: true}
  "2345678901234": {name: 研发交流群}
people:
  u_abc123: {name: 王某某, tools: host_uptime, mode: smart}
digest:
  - {target: 王某某, weekday: 1, hour: 9}
  - {target: 运维值班群, weekday: 5, hour: 17, group: "1234567890123"}
""",
    "dingtalk_ids_under_ccwork": """
groups:
  "cidAbCdEfGh123456==": {name: 钉钉群}
  "1001": {name: 数字群}
people:
  "manager1234": {name: 张三}
""",
    "misspelled_top_keys": "platfrom: dingtalk\nfoo: 1\ngroups:\n  \"1001\": {name: 群}\n",
    "bad_limits": "limits: {person_per_hour: 0, nope: 3}\ngroups:\n  \"1001\": {}\n",
    "limits_not_a_map": "limits: 5\n",
    "groups_not_a_map": "groups: [1001, 1002]\n",
    "scope_with_unknown_key": "groups:\n  \"1001\": {name: 群, category: [运维]}\npeople:\n  u1: {nam: x}\n",
    "empty_categories": "groups:\n  \"1001\": {name: 群, categories: []}\n  \"1002\": {categories: [\"\\x01\"]}\n",
    "digest_problems": ("groups:\n  \"1001\": {name: 群}\ndigest:\n  - {target: 王, weekday: 8}\n"
                        "  - {target: 群, group: \"9999\"}\n  - {weekday: 1}\n  - 3\n  - {target: 王, hour: 25}\n"),
    "mode_and_web": "groups:\n  \"1001\": {mode: deep, web: \"yes\", tools: [\"a b\", ok, ok, 3]}\n",
    "invalid_yaml": "groups: {\"1001\": [\n",
    "top_level_list": "- 1\n- 2\n",
    "paused_text": "paused: \"no\"\nunknown_reply: loud\n",
    "long_names": "robot_name: " + "长" * 40 + "\ncontact: \"a\\tb\"\n",
    "odd_ids": ("groups:\n  \"123456789012345678901\": {}\n  true: {}\n  \"-5\": {}\npeople:\n  \"has space\": {}\n"
                "  \"" + "x" * 65 + "\": {}\n  \"ok_id\": \n"),
    "keep_days": "keep_days: 0\n",
    "empty": "",
}


class FakeScope:
    def __init__(self, tools=(), name="值班群"):
        self.tools, self.name = tools, name


HELP_CASES = {
    "group_tools_web": (FakeScope(("host_disk",)), {"host_disk": "磁盘"}, True, True, "王某某"),
    "group_plain": (FakeScope(), {}, True, False, ""),
    "single_tools": (FakeScope(("a", "b")), {}, False, False, "李四"),
}


def outputs(config_module, format_module, new=False) -> dict:
    """同一组输入跑一遍：chat.yaml 的解析结果、提示词、帮助、测试推送。"""
    out = {"config": {}, "format": {}}
    with tempfile.TemporaryDirectory() as folder:
        for name, text in CORPUS.items():
            path = Path(folder, f"{name}.yaml")
            path.write_text(text, encoding="utf-8")
            if os.name != "nt":
                path.chmod(0o600)
            settings = config_module._parse(path, path.stat())
            view = config_module.public(settings)
            view.pop("file")
            for key in NEW_KEYS if new else ():
                view.pop(key)
            out["config"][name] = view
    out["format"]["chat_rules"] = format_module.CHAT_RULES
    for name, (scope, titles, group, web, contact) in HELP_CASES.items():
        out["format"][f"help_{name}"] = format_module.help_text(scope, titles, group=group, web=web, contact=contact)
    out["format"]["test_push"] = format_module.test_push_text("运维值班群")
    return out


class CcworkUnchangedTests(unittest.TestCase):
    maxDiff = None

    def test_same_as_before_dingtalk(self):
        baseline = json.loads(FIXTURE.read_text(encoding="utf-8"))
        now = json.loads(json.dumps(outputs(chat_config, chat_format, new=True), ensure_ascii=False))
        self.assertEqual(now["format"], baseline["format"])
        for name in CORPUS:
            with self.subTest(name):
                self.assertEqual(now["config"][name], baseline["config"][name])

    def test_platform_is_ccwork_unless_written(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder, "chat.yaml")
            path.write_text(CORPUS["good"], encoding="utf-8")
            self.assertEqual(chat_config._parse(path, path.stat()).platform, "ccwork")
        self.assertEqual(chat_format.chat_rules(), chat_format.chat_rules("ccwork"))
        self.assertEqual(chat_format.chat_rules(None), chat_format.CHAT_RULES)


if __name__ == "__main__":
    unittest.main()
