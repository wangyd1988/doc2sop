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

    def test_scope_mistakes_never_widen_access(self):
        """一个群或一个人的设置写错：拼错的键、写了却一个能用的都没有的 categories → 不开通；tools、mode、web 写错的只少开。"""
        write("""
groups:
  "1001": {name: 拼错了键, category: [运维]}
  "1002": {name: 空分类, categories: []}
  "1003": {name: 全写错, categories: ["", "这个分类的名字超过了十二个字", {a: b}, true]}
  "1004": {name: 写了没值, categories: }
  "1005": {name: 部分写错, categories: [运维, "这个分类的名字超过了十二个字"]}
  "1006": {name: 少开, tools: [host_disk, "a b", {x: 1}], mode: clever, web: "yes"}
  "1007": [not, a, mapping]
  abc: {name: 不是数字}
people:
  "有空格 的": {name: x}
""")
        cfg = chat_config.load()
        text = "\n".join(cfg.problems)
        for part in ("groups.1001 里不认识 category（只认 name、tools、categories、mode、web），没有开通",
                     "groups.1002.categories 写了，可一个能用的分类都没有（不写才是全部分类），没有开通",
                     "groups.1003.categories 写了，可一个能用的分类都没有", "groups.1004.categories 写了",
                     "groups.1005.categories 里有一项写得不对", "groups.1006.tools 里有一项写得不对：a b",
                     "groups.1006.mode 只能是 kb 或 smart", "groups.1006.web 只能写 true 或 false",
                     "groups.1007 要写成", "（…abc）不像会话 ID", "不像用户 ID"):
            self.assertIn(part, text)
        self.assertEqual(sorted(cfg.groups), ["1005", "1006"])
        self.assertEqual(cfg.groups["1005"].categories, ("运维",))                  # 写错的那项不开，写对的照常
        six = cfg.groups["1006"]
        self.assertEqual((six.tools, six.categories, six.mode, six.web), (("host_disk",), None, "kb", False))
        self.assertEqual(cfg.people, {})
        self.assertFalse(cfg.paused)                # 群和人的设置写错不影响别的群
        self.assertEqual(cfg.unknown_reply, "once")

    def test_top_level_mistakes_pause_everything(self):
        """顶层写错（不认识的项可能是拼错的 paused、limits）：整个暂停；unknown_reply 写错按不回；digest 写错的那项不发。"""
        base = 'groups: {"1001": {name: 甲}}\n'
        for extra, problem in (("pause: true\n", "不认识的配置项：pause"),
                               ('paused: "true"\n', "paused 只能写 true 或 false，先按暂停处理"),
                               ("paused: 1\n", "paused 只能写 true 或 false"),
                               ("limits: {person_per_hour: 0}\n", "limits.person_per_hour 要是 1–1000 的整数"),
                               ("limits: {excute_per_hour: 0}\n", "limits 里不认识 excute_per_hour"),
                               ("limits: [1, 2]\n", "limits 要写成「名字: 数」")):
            with self.subTest(extra=extra.strip()):
                write(base + extra)
                cfg = chat_config.load()
                self.assertTrue(cfg.paused)
                self.assertIn(problem, "\n".join(cfg.problems))
                self.assertEqual(sorted(cfg.groups), ["1001"])                     # 开通的照旧，只是都暂停
        write(base + "unknown_reply: slient\n")
        cfg = chat_config.load()
        self.assertEqual((cfg.unknown_reply, cfg.paused), ("silent", False))
        self.assertIn("unknown_reply 只能是 once 或 silent，先按 silent", cfg.problems[0])
        write(base + 'digest:\n  - {target: 王某某, weekday: 9}\n  - {target: 群, group: "9999"}\n'
                     '  - {target: 王某某, weekday: 1}\n')
        cfg = chat_config.load()
        self.assertFalse(cfg.paused)
        self.assertEqual([(d.target, d.weekday) for d in cfg.digest], [("王某某", 1)])
        text = "\n".join(cfg.problems)
        self.assertIn("digest 第 1 项的 weekday 要是 1–7", text)
        self.assertIn("digest 第 2 项的 group 要是 groups 里开通了的群", text)
        self.assertNotIn("王某某", text)            # 人名不进问题列表（它会进日志）
        write(base + "paused: false\nlimits: {max_chars: 1000}\n")
        self.assertFalse(chat_config.load().paused)

    def test_unusable_file_enables_nobody_and_stays_quiet(self):
        for text, problem in (("groups: {1001: [\n", "YAML 写错了"), ("- a\n- b\n", "最外层要写成「键: 值」"),
                              ("x" * (chat_config.FILE_MAX + 1), "文件超过")):
            with self.subTest(problem=problem):
                write(text)
                cfg = chat_config.load()
                self.assertIn(problem, cfg.problems[0])
                self.assertTrue(cfg.problems[0].endswith("谁也没开通"))
                self.assertEqual((cfg.groups, cfg.people, cfg.unknown_reply, cfg.paused), ({}, {}, "silent", True))

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
