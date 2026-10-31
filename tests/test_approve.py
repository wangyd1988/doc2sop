"""批准申请写进主配置（ops_readonly.approve_pending）：插到顶层 tools 列表末尾，其余内容一个字节都不动。

覆盖：tools 后面依次跟 hosts、connections、export、只有注释、什么都没有；最后一行没有换行、CRLF、tools: []；
非空的流式写法和认不出的写法（不写，打印要手工加的那段）；验证不过（结果不是正好多一个工具、别的有变化）时
主配置不动、申请留在待审、脚本的哈希登记也恢复；生产现在的布局（hosts 在文件末尾，上面两行注释）；
原子写入保留属主和权限、留备份、不留临时文件；批准过程中文件被改过就不写；命令行的输出和退出码。
"""
import importlib.util
import io
import os
import stat
import sys
import tempfile
import textwrap
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

import yaml

REPO = Path(__file__).resolve().parent.parent

if "ops_readonly" in sys.modules:
    ops = sys.modules["ops_readonly"]
else:
    _SPEC = importlib.util.spec_from_file_location("ops_readonly", REPO / "deploy" / "ops_readonly.py")
    ops = importlib.util.module_from_spec(_SPEC)
    sys.modules["ops_readonly"] = ops
    _SPEC.loader.exec_module(ops)

POSIX = os.name == "posix"
TOOL = {"name": "get_pod", "label": "获取pod", "desc": "获取pod", "binary": "kubectl",
        "argv": ["kubectl", "get", "po", "-A"], "os": ["linux"], "params": {}}
TOOLS = textwrap.dedent("""\
    tools:
      - {name: one, desc: 看内存, binary: free, argv: [free, -m], params: {}}

      - name: two
        desc: 看日期
        binary: date
        argv: [date, -d, "{day}", "+%F"]
        params:
          day: {type: str, pattern: date, required: true, desc: 日期}
    """)
HOSTS = textwrap.dedent("""\
    # 远程主机：网关机，受控模式
    # 第二行说明
    hosts:
      list:
        - {name: b, address: 203.0.113.9, user: opsread, key: "${ssh_key}", os: linux,
           tools: [one]}
    """)
TAILS = {
    "hosts": "\n" + HOSTS,
    "connections": "\nconnections:\n  - {name: assets, type: sqlite, path: /srv/assets.db}\n",
    "export": "\nexport: [one]\n",
    "comments": "\n# 文件末尾的说明\n# 第二行\n",
    "nothing": "",
}
# 生产主配置现在的样子（节选）：连接在前，hosts 在文件末尾，上面紧挨着两行注释
PRODUCTION = textwrap.dedent("""\
    # 工具定义 —— 这是工具的唯一真相源。
    #
    # 改完这个文件，下一次提问就生效。

    connections:
      # LiteLLM 用量库：经专用隧道
      - name: litellm_db
        type: sqlite
        path: /srv/usage.db

    tools:
      - name: list_containers
        desc: 一眼看懂所有容器的状态和重启次数，挑出重启偏多的。
        binary: docker
        argv: [docker, ps, -a]
        params: {}

      # ---- 日历 ----------------------------------------------------------

      - name: date_info
        label: 日期是星期几
        group: 日历
        binary: date
        argv: [date, -d, "{day}", "+%Y-%m-%d %A 第%V周"]
        params:
          day:
            type: str
            pattern: date
            required: true
            desc: 日期，格式 YYYY-MM-DD

    # 远程主机（M4）：B 网关机，受控模式（主机上的执行器 + root 所有的白名单 + 强制命令公钥）。
    # 不写 default：target 不填就是本机，现有工具和 SOP 照常。
    hosts:
      list:
        - {name: gateway-b, address: 203.0.113.9, user: opsread, key: "${ssh_key}", os: linux, groups: [gateway],
           tools: [list_containers, date_info]}
    """)


class _Approve(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        self.main = self.dir / "ops_tools.yaml"
        for patcher in (
                patch.dict(ops._state, {"path": self.main, "mtime": None, "omtime": None, "tmtime": None,
                                        "imtime": None, "mmtime": None, "includes": [], "tools": {}, "problems": [],
                                        "mcp_servers": {}, "connections": {}, "hosts": None}),
                patch.object(ops.shutil, "which", lambda name: f"/usr/bin/{name}"),
                patch.object(ops._monitor, "wake", lambda: None)):
            patcher.start()
            self.addCleanup(patcher.stop)

    def propose(self, data, tool=TOOL):
        """主配置原样写成 data，清掉上一轮的待审、备份和哈希登记，再提交一条申请。"""
        for leftover in self.dir.glob("ops_tools.*"):
            if leftover != self.main:
                leftover.unlink()
        self.main.write_bytes(data)
        ops.refresh(force=True)
        return ops.propose_tool(dict(tool))

    def inserted(self, before, after):
        """after 是在 before 中间插进一段：返回插进去的那段（别的字节必须一模一样）。"""
        prefix = 0
        while prefix < len(before) and before[prefix] == after[prefix]:
            prefix += 1
        suffix = 0
        while suffix < len(before) - prefix and before[-1 - suffix] == after[-1 - suffix]:
            suffix += 1
        self.assertEqual(prefix + suffix, len(before), "除了插进去的那一段，别的字节也变了")
        return after[prefix:len(after) - suffix]

    def assertUntouched(self, before, item):
        self.assertEqual(self.main.read_bytes(), before)
        self.assertEqual([i["id"] for i in ops.list_pending()], [item["id"]])
        self.assertEqual(list(self.dir.glob("ops_tools.yaml.bak-*")), [])


class LayoutTests(_Approve):
    def test_the_entry_goes_to_the_end_of_the_tools_list_whatever_follows(self):
        for label, tail in TAILS.items():
            with self.subTest(after=label):
                before = (TOOLS + tail).encode("utf-8")
                spec = ops.approve_pending(self.propose(before)["id"])
                after = self.main.read_bytes()
                piece = self.inserted(before, after).decode("utf-8")
                self.assertIn("  - name: get_pod\n", piece)
                old, new = yaml.safe_load(before), yaml.safe_load(after)
                self.assertEqual(new["tools"], old["tools"] + [TOOL])
                self.assertEqual({k: v for k, v in new.items() if k != "tools"},
                                 {k: v for k, v in old.items() if k != "tools"})
                text = after.decode("utf-8")
                self.assertLess(text.index("day: {type: str"), text.index("- name: get_pod"))
                if tail.strip():   # 插在下一段（连同它上方顶格的注释）前面
                    self.assertLess(text.index("- name: get_pod"), text.index(tail.strip().splitlines()[0]))
                self.assertEqual(text.splitlines()[spec["written"]["line"] - 1], "  - name: get_pod")
                self.assertEqual(Path(spec["written"]["backup"]).read_bytes(), before)
                self.assertEqual(ops.list_pending(), [])
                self.assertIn("get_pod", ops.all_tools())

    def test_a_missing_final_newline_and_crlf_stay_as_they_were(self):
        before = TOOLS.rstrip("\n").encode("utf-8")
        ops.approve_pending(self.propose(before)["id"])
        after = self.main.read_bytes()
        self.inserted(before, after)
        self.assertFalse(after.endswith(b"\n"))
        self.assertEqual(yaml.safe_load(after)["tools"][-1], TOOL)

        before = (TOOLS + TAILS["hosts"]).replace("\n", "\r\n").encode("utf-8")
        ops.approve_pending(self.propose(before)["id"])
        after = self.main.read_bytes()
        piece = self.inserted(before, after)
        self.assertIn(b"  - name: get_pod\r\n", piece)
        self.assertEqual(after.count(b"\n"), after.count(b"\r\n"))       # 插进去的也是 CRLF，没有单独的 LF
        self.assertEqual(yaml.safe_load(after)["tools"][-1], TOOL)

    def test_an_empty_tools_list_only_loses_its_brackets(self):
        """演示 sidecar 生成的主配置是 tools: []：只去掉这一行的 []，注释、include 和别的内容原样。"""
        (self.dir / "pack.yaml").write_text("tools:\n  - {name: pk, binary: df, argv: [df, -h], params: {}}\n",
                                            encoding="utf-8")
        before = "# 演示用的主配置\ninclude: [pack.yaml]\ntools: []   # 先空着\n\n# 结尾\n".encode("utf-8")
        ops.approve_pending(self.propose(before)["id"])
        after = self.main.read_bytes()
        self.inserted(before.replace(b"tools: []", b"tools:"), after)
        self.assertIn("tools:   # 先空着\n  - name: get_pod\n".encode("utf-8"), after)
        document = yaml.safe_load(after)
        self.assertEqual((document["include"], document["tools"]), (["pack.yaml"], [TOOL]))
        self.assertEqual(sorted(ops.all_tools()), ["get_pod", "pk"])

    def test_the_production_layout_with_hosts_at_the_end(self):
        before = PRODUCTION.encode("utf-8")
        self.propose(before)
        old_hosts, old_problems = ops._state["hosts"], list(ops._state["problems"])
        ops.approve_pending("get_pod")
        after = self.main.read_bytes()
        piece = self.inserted(before, after).decode("utf-8")
        self.assertTrue(piece.startswith("  - name: get_pod\n") and piece.endswith("    params: {}\n\n"), piece)
        text = after.decode("utf-8")
        self.assertLess(text.index("desc: 日期，格式 YYYY-MM-DD"), text.index("- name: get_pod"))
        self.assertLess(text.index("- name: get_pod"), text.index("# 远程主机（M4）"))
        document = yaml.safe_load(after)
        self.assertEqual([t["name"] for t in document["tools"]], ["list_containers", "date_info", "get_pod"])
        self.assertEqual(document["hosts"], yaml.safe_load(before)["hosts"])
        self.assertIn("get_pod", ops.all_tools())
        self.assertEqual((ops._state["hosts"], ops._state["problems"]), (old_hosts, old_problems))


class RefusalTests(_Approve):
    def test_layouts_it_cannot_read_are_left_to_the_admin(self):
        layouts = {
            "流式写法": "tools: [{name: one, binary: free, argv: [free, -m], params: {}}]\n",
            "找不到顶层的 tools:": '"tools":\n  - {name: one, binary: free, argv: [free, -m], params: {}}\n',
            "第一项不是「- 」开头": "tools:\n  [{name: one, binary: free, argv: [free, -m], params: {}}]\n",
            "不止一个顶层的 tools:": ("tools:\n  - {name: one, binary: free, argv: [free, -m], params: {}}\n"
                                 "tools:\n  - {name: two, binary: uptime, argv: [uptime], params: {}}\n"),
        }
        for needle, body in layouts.items():
            with self.subTest(layout=needle):
                before = body.encode("utf-8")
                item = self.propose(before)
                with self.assertRaises(ops.ConfigError) as caught:
                    ops.approve_pending(item["id"])
                message = str(caught.exception)
                for part in (needle, "没有改主配置，申请仍在待审", "reject <id>", "  - name: get_pod\n    label: 获取pod"):
                    self.assertIn(part, message)
                self.assertUntouched(before, item)

    def test_a_result_that_is_not_exactly_one_more_tool_writes_nothing(self):
        cases = {
            # 顶层 export 早就列了这个名字：批准它会顺带把它对外开放，加载问题也跟着变
            "export": TOOLS + "export: [get_pod]\n",
            # 主机清单早就写了它：批准后主机能跑的工具、加载问题都会变
            "hosts": TOOLS + "\n" + HOSTS.replace("tools: [one]", "tools: [one, get_pod]"),
        }
        for label, body in cases.items():
            with self.subTest(case=label):
                before = body.encode("utf-8")
                item = self.propose(before)
                with self.assertRaises(ops.ConfigError) as caught:
                    ops.approve_pending(item["id"])
                self.assertIn("插入后的加载结果不对：加载问题变了", str(caught.exception))
                self.assertIn("没有改主配置，申请仍在待审", str(caught.exception))
                self.assertUntouched(before, item)
                self.assertNotIn("get_pod", ops.all_tools())

    def test_a_refused_script_approval_takes_back_its_hash(self):
        scripts = self.dir / "scripts"
        scripts.mkdir()
        for name in ("check.sh", "other.sh"):
            (scripts / name).write_text("#!/bin/sh\necho ok\n", encoding="utf-8")
            os.chmod(scripts / name, 0o755)
        before = (TOOLS + "export: [health]\n").encode("utf-8")
        item = self.propose(before, {"name": "health", "desc": "看容器健康", "script": "check.sh", "params": {}})
        trust = self.dir / "ops_tools.trust.yaml"
        with self.assertRaises(ops.ConfigError):            # 原来没有哈希登记文件：恢复成没有
            ops.approve_pending(item["id"])
        self.assertFalse(trust.exists())
        ops.trust_script("other.sh")
        registered = trust.read_bytes()
        with self.assertRaises(ops.ConfigError):            # 原来有：恢复成原来的字节
            ops.approve_pending(item["id"])
        self.assertEqual(trust.read_bytes(), registered)
        self.assertNotIn("check.sh", ops.load_trust())
        self.assertUntouched(before, item)

    def test_an_edit_during_approval_is_not_overwritten(self):
        before = TOOLS.encode("utf-8")
        item = self.propose(before)
        real = ops._check_insertion

        def meddle(*args):
            with open(self.main, "ab") as handle:
                handle.write("# 管理员刚加的一行\n".encode("utf-8"))
            return real(*args)

        with patch.object(ops, "_check_insertion", meddle), self.assertRaises(ops.ConfigError) as caught:
            ops.approve_pending(item["id"])
        self.assertIn("被改过", str(caught.exception))
        self.assertUntouched(before + "# 管理员刚加的一行\n".encode("utf-8"), item)


class WriteTests(_Approve):
    @unittest.skipUnless(POSIX, "属主和权限只在 POSIX 上有意义")
    def test_the_write_keeps_mode_and_owner_and_leaves_no_temporary_file(self):
        item = self.propose(TOOLS.encode("utf-8"))
        os.chmod(self.main, 0o640)
        info = os.stat(self.main)
        spec = ops.approve_pending(item["id"])
        now = os.stat(self.main)
        self.assertEqual((stat.S_IMODE(now.st_mode), now.st_uid, now.st_gid), (0o640, info.st_uid, info.st_gid))
        self.assertNotEqual(now.st_ino, info.st_ino)        # rename 过来的新文件，不是原地改写
        backup = Path(spec["written"]["backup"])
        self.assertEqual((backup.parent, stat.S_IMODE(os.stat(backup).st_mode)), (self.dir, 0o640))

    def test_backups_are_timestamped_and_no_temporary_file_is_left(self):
        before = TOOLS.encode("utf-8")
        spec = ops.approve_pending(self.propose(before)["id"])
        backup = Path(spec["written"]["backup"])
        self.assertRegex(backup.name, r"^ops_tools\.yaml\.bak-\d{14}$")
        self.assertEqual(backup.read_bytes(), before)
        self.assertEqual([p.name for p in self.dir.iterdir() if p.name.endswith(".tmp")], [])
        second = ops.approve_pending(ops.propose_tool({**TOOL, "name": "get_svc"})["id"])
        self.assertNotEqual(second["written"]["backup"], spec["written"]["backup"])   # 同一秒也不覆盖上一份
        self.assertEqual([t["name"] for t in yaml.safe_load(self.main.read_bytes())["tools"]],
                         ["one", "two", "get_pod", "get_svc"])


class CliTests(_Approve):
    def run_cli(self, ident):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = ops._cli("approve", ident, str(self.main))
        return code, out.getvalue(), err.getvalue()

    def test_approve_prints_where_it_wrote_and_how_many_tools_loaded(self):
        item = self.propose((TOOLS + TAILS["hosts"]).encode("utf-8"))
        code, out, err = self.run_cli(item["id"])
        self.assertEqual(code, 0, err)
        for part in ("已批准并写入配置：get_pod", "kubectl get po -A", "的 tools 列表末尾（第 11 行起）",
                     "改之前的备份：", "重新加载后共 3 个工具定义。", "下一次提问即可使用"):
            self.assertIn(part, out)

    def test_a_refusal_exits_non_zero_and_prints_the_yaml_to_add(self):
        before = "tools: [{name: one, binary: free, argv: [free, -m], params: {}}]\n".encode("utf-8")
        item = self.propose(before)
        code, out, err = self.run_cli(item["id"])
        self.assertEqual(code, 1)
        self.assertIn("失败：主配置里的 tools 是流式写法", err)
        self.assertIn("  - name: get_pod\n    label: 获取pod\n", err)
        self.assertNotIn("已批准", out)
        self.assertUntouched(before, item)


if __name__ == "__main__":
    unittest.main()
