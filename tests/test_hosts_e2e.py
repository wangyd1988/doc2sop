"""远程主机的端到端测试：真的 sshd + 带强制命令的公钥 + 主机上的执行器 + 工具服务，全程走系统的 ssh。

默认跳过。要跑需要两个环境变量：
  OPS_E2E_SSHD      sshd 程序的绝对路径（可以是从 openssh-server 的 deb 里解出来的，不用安装）
  OPS_E2E_EXEC_DIR  root 所有、只有 root 能写的目录，里面是 stage() 生成的 ops_exec.py 和 allowlist.json
                    （执行器发现执行账号能改它们就拒绝启动，所以必须由 root 放进去）

    python -m tests.test_hosts_e2e stage /tmp/doc2sop-e2e-stage
    # 以 root：install -d -o root -g root -m 0755 /tmp/doc2sop-e2e-exec
    #          install -o root -g root -m 0644 /tmp/doc2sop-e2e-stage/* /tmp/doc2sop-e2e-exec/
    OPS_E2E_SSHD=/path/to/sshd OPS_E2E_EXEC_DIR=/tmp/doc2sop-e2e-exec python -m unittest tests.test_hosts_e2e -v

sshd 以当前用户在 127.0.0.1 的高端口上跑，只能登录当前用户，四把公钥对应四台「主机」：
  e2e         受控模式：公钥带 restrict + 强制命令（python3 -I），执行器和白名单在 root 所有的目录里
  e2e-direct  直连模式：公钥只带 restrict，命令经登录 shell 执行
  e2e-unsafe  受控模式，但执行器放在执行账号自己的目录里：执行器应当拒绝启动
  e2e-noiso   受控模式，执行器没问题，但强制命令漏了 -I：执行器应当拒绝启动
"""
import getpass
import importlib.util
import io
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

REPO = Path(__file__).resolve().parent.parent

if "ops_readonly" in sys.modules:
    ops = sys.modules["ops_readonly"]
else:
    _SPEC = importlib.util.spec_from_file_location("ops_readonly", REPO / "deploy" / "ops_readonly.py")
    ops = importlib.util.module_from_spec(_SPEC)
    sys.modules["ops_readonly"] = ops
    _SPEC.loader.exec_module(ops)

SSHD = os.environ.get("OPS_E2E_SSHD", "")
EXEC_DIR = os.environ.get("OPS_E2E_EXEC_DIR", "")
PYTHON = "/usr/bin/python3"
LITERAL = ["a;b", "$(id)", "`id`", "x\ny", "*", "-rf", "'", "{{.Names}}"]


def config(port=22):
    """三个工具（都是命令型、os: linux）和三台主机。"""
    literal = ", ".join(json.dumps(item) for item in ["printf", "%s\n"] + LITERAL)
    return textwrap.dedent(f"""\
        tools:
          - {{name: e2e_uptime, desc: 负载, impl: {{type: command, argv: [uptime], os: linux}}}}
          - name: e2e_echo
            desc: 回显一个名字
            impl: {{type: command, argv: [printf, "%s|", "{{name}}"], os: linux}}
            params: {{name: {{type: str, pattern: name, required: true}}}}
          - {{name: e2e_literal, desc: 一串带 shell 元字符的字面量, impl: {{type: command, argv: [{literal}], os: linux}}}}
        hosts:
          defaults: {{port: {port}, user: {getpass.getuser()}, os: linux}}
          list:
            - {{name: e2e, address: 127.0.0.1, key: "${{e2e_guarded}}", groups: [e2e]}}
            - {{name: e2e-direct, address: 127.0.0.1, key: "${{e2e_direct}}", mode: direct, groups: [e2e]}}
            - {{name: e2e-unsafe, address: 127.0.0.1, key: "${{e2e_unsafe}}"}}
            - {{name: e2e-noiso, address: 127.0.0.1, key: "${{e2e_noiso}}"}}
        """)


def stage(directory):
    """生成要由 root 放进 OPS_E2E_EXEC_DIR 的两个文件：执行器和 e2e 这台主机的白名单（push 的生成函数产出）。"""
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        main = Path(tmp) / "ops_tools.yaml"
        main.write_text(config(), encoding="utf-8")
        with patch.dict(ops._state, {"path": main, "hosts": None}), patch.object(ops._monitor, "wake", lambda: None):
            ops.refresh(force=True)
            text = ops.allowlist_for(ops._state["hosts"]["hosts"]["e2e"])
    (directory / "allowlist.json").write_text(text, encoding="utf-8")
    shutil.copyfile(REPO / "deploy" / "ops_exec.py", directory / "ops_exec.py")
    return directory


def keygen(path, comment):
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", comment, "-f", str(path)],
                   stdin=subprocess.DEVNULL, check=True, timeout=30)
    return path.with_suffix(".pub").read_text(encoding="utf-8").strip()


def free_port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


@unittest.skipUnless(SSHD and EXEC_DIR and os.name == "posix", "端到端测试：设置 OPS_E2E_SSHD 和 OPS_E2E_EXEC_DIR 后才跑")
class EndToEndTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        root = Path(cls.tmp.name)
        staged = stage(root / "expected")
        for name in ("ops_exec.py", "allowlist.json"):
            if (Path(EXEC_DIR) / name).read_bytes() != (staged / name).read_bytes():
                raise unittest.SkipTest(f"{EXEC_DIR}/{name} 和 stage() 生成的不一致：重新 stage 并以 root 装一遍")
        keys = root / "keys"
        keys.mkdir(mode=0o700)
        host_pub = keygen(keys / "host", "e2e-host")
        cls.host_pub = host_pub
        guarded, direct, unsafe, noiso = (keygen(keys / name, name) for name in ("guarded", "direct", "unsafe", "noiso"))
        # 执行账号自己的目录里放一份执行器：受控模式下它应当拒绝启动
        cls.unsafe_dir = root / "unsafe"
        cls.unsafe_dir.mkdir()
        shutil.copyfile(staged / "ops_exec.py", cls.unsafe_dir / "ops_exec.py")
        shutil.copyfile(staged / "allowlist.json", cls.unsafe_dir / "allowlist.json")
        (root / "authorized_keys").write_text(
            f'restrict,command="{PYTHON} -I {EXEC_DIR}/ops_exec.py --stdio" {guarded}\n'
            f"restrict {direct}\n"
            f'restrict,command="{PYTHON} -I {cls.unsafe_dir}/ops_exec.py --stdio" {unsafe}\n'
            f'restrict,command="{PYTHON} {EXEC_DIR}/ops_exec.py --stdio" {noiso}\n', encoding="utf-8")
        cls.port = free_port()
        (root / "sshd_config").write_text(textwrap.dedent(f"""\
            Port {cls.port}
            ListenAddress 127.0.0.1
            HostKey {keys / 'host'}
            PidFile {root / 'sshd.pid'}
            AuthorizedKeysFile {root / 'authorized_keys'}
            AllowUsers {getpass.getuser()}
            StrictModes no
            UsePAM no
            PubkeyAuthentication yes
            PasswordAuthentication no
            KbdInteractiveAuthentication no
            PrintMotd no
            LogLevel VERBOSE
            """), encoding="utf-8")
        cls.log = open(root / "sshd.log", "wb")
        cls.sshd = subprocess.Popen([SSHD, "-D", "-e", "-f", str(root / "sshd_config")], stdout=cls.log,
                                    stderr=subprocess.STDOUT)
        deadline = time.monotonic() + 15
        while True:
            try:
                socket.create_connection(("127.0.0.1", cls.port), 1).close()
                break
            except OSError:
                if time.monotonic() > deadline or cls.sshd.poll() is not None:
                    cls.tearDownClass()
                    raise RuntimeError("sshd 没起来：" + (root / "sshd.log").read_text(errors="replace")[-2000:])
                time.sleep(0.2)

        cls.main = root / "ops" / "ops_tools.yaml"
        cls.main.parent.mkdir()
        cls.main.write_text(config(cls.port), encoding="utf-8")
        cls.patches = [patch.dict(ops._state, {"path": cls.main, "mtime": None, "omtime": None, "tmtime": None,
                                               "imtime": None, "mmtime": None, "includes": [], "tools": {},
                                               "problems": [], "mcp_servers": {}, "connections": {}, "hosts": None}),
                       patch.dict(os.environ, {"OPS_SECRET_E2E_GUARDED": str(keys / "guarded"),
                                               "OPS_SECRET_E2E_DIRECT": str(keys / "direct"),
                                               "OPS_SECRET_E2E_UNSAFE": str(keys / "unsafe"),
                                               "OPS_SECRET_E2E_NOISO": str(keys / "noiso")}),
                       patch.object(ops._monitor, "wake", lambda: None),
                       patch.dict(ops._host_status, {}, clear=True)]
        for patcher in cls.patches:
            patcher.start()
        ops.refresh(force=True)
        assert not ops._state["problems"], ops._state["problems"]
        # 真的 enroll：ssh-keyscan 取 host key，指纹对得上才登记（三台主机共用一个 sshd，各自按主机名登记）
        cls.fingerprint = subprocess.run(["ssh-keygen", "-lf", str(keys / "host.pub")], stdout=subprocess.PIPE,
                                         check=True).stdout.decode().split()[1]
        cls.enroll_output = io.StringIO()
        with redirect_stdout(cls.enroll_output):
            for name in ("e2e", "e2e-direct", "e2e-unsafe", "e2e-noiso"):
                ops.enroll(name, cls.fingerprint)

    @classmethod
    def tearDownClass(cls):
        for patcher in getattr(cls, "patches", []):
            patcher.stop()
        if getattr(cls, "sshd", None) is not None and cls.sshd.poll() is None:
            cls.sshd.terminate()
            cls.sshd.wait(10)
        if getattr(cls, "log", None) is not None:
            cls.log.close()
        cls.tmp.cleanup()

    def test_enroll_pinned_the_real_host_key(self):
        self.assertEqual(ops._pinned_keys("e2e"), [tuple(self.host_pub.split()[:2])])
        printed = self.enroll_output.getvalue()
        self.assertIn(self.fingerprint, printed)
        self.assertIn('restrict,from="<工具服务连过来的出口 IP>",command="/usr/bin/python3 -I /opt/ops-readonly/ops_exec.py',
                      printed)

    def test_guarded_mode_runs_through_the_forced_command(self):
        result = ops.run_tool("e2e_echo", {"name": "kb-app", "target": "e2e"})
        self.assertEqual((result["ok"], result["output"], result["host"]), (True, "kb-app|", "e2e"), result)
        uptime = ops.run_tool("e2e_uptime", {"target": "e2e"})
        self.assertTrue(uptime["ok"], uptime)
        self.assertIn("load average", uptime["output"])
        # 参数在工具服务这边就挡住；执行器那边也只认白名单里的东西
        self.assertIn("不合法", ops.run_tool("e2e_echo", {"name": "a;b", "target": "e2e"})["error"])

    def test_direct_mode_shell_sees_only_literal_words(self):
        expected = "\n".join(LITERAL)
        for target in ("e2e-direct", "e2e"):
            with self.subTest(target=target):
                result = ops.run_tool("e2e_literal", {"target": target})
                self.assertTrue(result["ok"], result)
                self.assertEqual(result["output"], expected)

    def test_a_group_runs_on_every_host(self):
        result = ops.run_tool("e2e_echo", {"name": "x1", "target": "@e2e"})
        self.assertTrue(result["ok"], result)
        self.assertIn("== e2e（成功）==\nx1|", result["output"])
        self.assertIn("== e2e-direct（成功）==\nx1|", result["output"])
        self.assertIn("共 2 台，成功 2 台，失败 0 台", result["output"])

    def test_an_executor_the_account_can_modify_refuses_to_start(self):
        result = ops.run_tool("e2e_uptime", {"target": "e2e-unsafe"})
        self.assertFalse(result["ok"])
        self.assertIn("执行器拒绝启动", result["error"])
        self.assertIn("属于执行账号自己", result["error"])

    def test_a_forced_command_without_isolated_mode_refuses_to_start(self):
        """执行器、白名单都没问题，只是强制命令漏了 -I：照样拒绝启动，原因说得清楚，status 也看得到。"""
        result = ops.run_tool("e2e_uptime", {"target": "e2e-noiso"})
        self.assertFalse(result["ok"])
        self.assertIn("执行器拒绝启动", result["error"])
        self.assertIn("python3 -I", result["error"])
        out = io.StringIO()
        with redirect_stdout(out):
            self.assertEqual(ops.status(target="e2e-noiso"), 1)
        self.assertIn("python3 -I", out.getvalue())

    def test_a_changed_host_key_fails_without_falling_back(self):
        pinned = ops._known_hosts().read_text(encoding="utf-8")
        other = keygen(Path(self.tmp.name) / "keys" / "impostor", "impostor").split()
        try:
            ops._write_known_hosts("e2e", other[0], other[1])
            result = ops.run_tool("e2e_echo", {"name": "kb-app", "target": "e2e"})
            self.assertFalse(result["ok"])
            self.assertIn("host key 和登记的不一致", result["error"])
            self.assertNotIn("output", result)
        finally:
            ops._known_hosts().write_text(pinned, encoding="utf-8")
        self.assertTrue(ops.run_tool("e2e_echo", {"name": "kb-app", "target": "e2e"})["ok"])

    def test_status_lists_versions_and_tools(self):
        out = io.StringIO()
        with redirect_stdout(out):
            bad = ops.status(target="e2e")
        self.assertEqual(bad, 0, out.getvalue())
        self.assertIn("✓ 连通；执行器 1.0；白名单 sha256:", out.getvalue())
        self.assertIn("能跑 3 个：e2e_echo、e2e_literal、e2e_uptime", out.getvalue())
        out = io.StringIO()
        with redirect_stdout(out):
            self.assertEqual(ops.status(target="e2e-unsafe"), 1)
        self.assertIn("执行器拒绝启动", out.getvalue())


if __name__ == "__main__" and sys.argv[1:2] == ["stage"]:
    print(stage(sys.argv[2]))
