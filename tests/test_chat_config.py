"""云上协同的 chat.yaml：谁能用、能查什么（app/chat_config.py）。"""
import os
import unittest

import tests.support  # noqa: F401  隔离 DATA_DIR 和环境变量

from app import chat_config
from app.config import CHAT_FILE

GOOD = """
robot_name: doc2sop
contact: 王某某
paused: false
keep_days: 180
limits: {person_per_hour: 5, max_chars: 1000}
groups:
  1234567890123: {name: 运维值班群, tools: [host_disk, container_stats], categories: [运维], web: true}
  "2345678901234": {name: 研发交流群}
people:
  u_abc123: {name: 王某某, tools: host_uptime, mode: smart}
digest:
  - {target: 王某某, weekday: 1, hour: 9}
  - {target: 运维值班群, weekday: 5, hour: 17, group: "1234567890123"}
"""


def write(text):
    CHAT_FILE.write_text(text, encoding="utf-8")
    chat_config.reset()


class ChatConfigTests(unittest.TestCase):
    def tearDown(self):
        CHAT_FILE.unlink(missing_ok=True)
        chat_config.reset()

    def test_missing_file_means_nobody_is_enabled(self):
        CHAT_FILE.unlink(missing_ok=True)
        cfg = chat_config.load()
        self.assertFalse(cfg.exists)
        self.assertIsNone(cfg.scope("group", "1234567890123", "u1"))
        self.assertEqual(cfg.limits["person_per_hour"], 20)

    def test_good_file(self):
        write(GOOD)
        cfg = chat_config.load()
        self.assertEqual(cfg.problems, ())
        self.assertEqual((cfg.robot_name, cfg.contact, cfg.keep_days), ("doc2sop", "王某某", 180))
        self.assertEqual((cfg.limits["person_per_hour"], cfg.limits["max_chars"], cfg.limits["group_per_hour"]),
                         (5, 1000, 60))
        group = cfg.scope("group", "1234567890123", "anyone")
        self.assertEqual((group.name, group.tools, group.categories, group.mode, group.web),
                         ("运维值班群", ("host_disk", "container_stats"), ("运维",), "kb", True))
        self.assertEqual(cfg.scope("org", "2345678901234", "x").tools, ())      # 组织、部门会话按群对待
        self.assertIsNone(cfg.scope("single", "1234567890123", "u_other"))      # 私聊只认发送人
        person = cfg.scope("single", "", "u_abc123")
        self.assertEqual((person.tools, person.mode, person.categories), (("host_uptime",), "smart", None))
        self.assertEqual([(d.target, d.weekday, d.hour, d.group) for d in cfg.digest],
                         [("王某某", 1, 9, ""), ("运维值班群", 5, 17, "1234567890123")])

    def test_mistakes_are_reported_and_fall_back_safely(self):
        write("""
nonsense: 1
unknown_reply: loud
paused: "yes"
limits: {person_per_hour: 0, foo: 3}
groups:
  abc: {name: 不是数字}
  "1001": {name: 好的, tools: "a b", categories: [], mode: clever, extra: 1}
  "1002": [not, a, mapping]
people:
  "有空格 的": {name: x}
digest:
  - {target: 王某某, weekday: 9}
  - {target: 群, group: "9999"}
""")
        cfg = chat_config.load()
        text = "\n".join(cfg.problems)
        for part in ("不认识的配置项：nonsense", "unknown_reply 只能是", "paused 只能写", "limits.person_per_hour",
                     "limits 里不认识 foo", "（…abc）不像会话 ID", "categories 写了空的", "mode 只能是", "不认识 extra",
                     "tools 里有一项写得不对", "groups.1002 要写成", "不像用户 ID", "第 1 项的 weekday 要是 1–7",
                     "第 2 项的 group 要是 groups 里开通了的群"):
            self.assertIn(part, text)
        self.assertNotIn("王某某", text)        # 人名不进问题列表（它会进日志）
        self.assertEqual(cfg.unknown_reply, "once")
        self.assertFalse(cfg.paused)
        self.assertEqual(cfg.limits["person_per_hour"], 20)
        self.assertEqual(sorted(cfg.groups), ["1001"])
        scope = cfg.groups["1001"]
        self.assertEqual((scope.tools, scope.categories, scope.mode), ((), None, "kb"))
        self.assertEqual(cfg.people, {})
        self.assertEqual(cfg.digest, ())

    def test_broken_yaml_enables_nobody(self):
        write("groups: {1001: [\n")
        cfg = chat_config.load()
        self.assertIn("YAML 写错了", cfg.problems[0])
        self.assertEqual(cfg.groups, {})

    def test_changes_are_picked_up_without_restart(self):
        write("groups: {'1001': {name: 甲}}\n")
        self.assertEqual(chat_config.load().groups["1001"].name, "甲")
        CHAT_FILE.write_text("groups: {'1001': {name: 乙乙}}\n", encoding="utf-8")
        os.utime(CHAT_FILE, ns=(1, 1))      # 修改时间一定不同
        self.assertEqual(chat_config.load().groups["1001"].name, "乙乙")

    @unittest.skipIf(os.name == "nt", "Windows 上没有 Unix 权限位")
    def test_world_writable_file_is_flagged(self):
        write("paused: true\n")
        os.chmod(CHAT_FILE, 0o666)
        chat_config.reset()
        self.assertIn("太宽", chat_config.load().loose)

    def test_public_view(self):
        write(GOOD)
        view = chat_config.public()
        self.assertEqual(view["groups"][0], {"id": "1234567890123", "name": "运维值班群",
                                             "tools": ["host_disk", "container_stats"], "categories": ["运维"],
                                             "mode": "kb", "web": True})
        self.assertEqual(view["keep_days"], 180)


if __name__ == "__main__":
    unittest.main()
