"""计算沙箱服务（deploy/sandbox/sandbox_service.py）：起容器的那一层打桩，其余都是真的——HTTP、令牌、并发、管道、超时、清理。

替身 FakeDocker 记下每次 docker run 的参数和挂进去的文件；「容器」是本机的一个 Python 子进程，照样从 stdin 读代码、
往 stdout / stderr 写，被 docker kill 时真的被杀掉。所以超时、输出超限、清理都是实打实跑出来的。

钉住的：
- 传给 docker 的参数带齐全部限制（runsc、无网络、只读、nobody、去 capability、no-new-privileges、pids / CPU / 内存……），
  请求里的任何东西都进不了参数；多带字段整个请求拒绝，一个容器都不起；
- 令牌；并发上限、排队、排队也满了就拒绝；代码长度、文件数、输入总量、文件名；
- stdout 截断并终止、stderr 留末尾；超时、OOM、被杀、起不来、意外出错，容器和临时目录都清理；
- 每次执行只挂这次请求的文件；启动时清掉上次的残留；日志里没有代码和数据。
"""
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest.mock import patch

REPO = Path(__file__).resolve().parent.parent

if "sandbox_service" in sys.modules:
    svc = sys.modules["sandbox_service"]
else:
    _SPEC = importlib.util.spec_from_file_location("sandbox_service", REPO / "deploy" / "sandbox" / "sandbox_service.py")
    svc = importlib.util.module_from_spec(_SPEC)
    sys.modules["sandbox_service"] = svc
    _SPEC.loader.exec_module(svc)

TOKEN = "t" * 32
IMAGE = "doc2sop-sandbox:test"
# 「容器」：从 stdin 读代码、执行（Windows 上也只写 \n，和 Linux 容器里一样）
RUNNER = ("import sys\n"
          "sys.stdout.reconfigure(newline='\\n')\n"
          "sys.stderr.reconfigure(newline='\\n')\n"
          "code = sys.stdin.buffer.read().decode('utf-8')\n"
          "exec(compile(code, '<stdin>', 'exec'), {'__name__': '__main__'})\n")


class FakeDocker:
    """起容器那一层的替身。"""

    def __init__(self, oom=False):
        self.argvs, self.killed, self.removed = [], [], []
        self.mounted = {}           # 容器名 -> {文件名: 内容（字节）}，docker run 那一刻挂进去的
        self.procs = {}
        self.oom = oom
        self.fail_start = None      # docker run 本身抛的异常（比如 docker 不在）
        self.never_created = False  # docker run 报错退出、容器没建出来
        self.state_error = None     # docker inspect 时抛的异常（意外）
        self.leftover = []

    def start(self, argv):
        self.argvs.append(list(argv))
        if self.fail_start:
            raise self.fail_start
        name = argv[argv.index("--name") + 1]
        spec = dict(part.split("=", 1) for part in argv[argv.index("--mount") + 1].split(",") if "=" in part)
        self.mounted[name] = {path.name: path.read_bytes() for path in sorted(Path(spec["source"]).iterdir())}
        proc = subprocess.Popen([sys.executable, "-X", "utf8", "-c", RUNNER], stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                env=dict(os.environ, PYTHONIOENCODING="utf-8"))
        self.procs[name] = proc
        return proc

    def kill(self, name):
        self.killed.append(name)
        proc = self.procs.get(name)
        if proc is not None and proc.poll() is None:
            proc.kill()

    def state(self, name):
        if self.state_error:
            raise self.state_error
        if self.never_created or name not in self.procs:
            return None
        code = self.procs[name].poll()
        return {"ExitCode": 137 if name in self.killed else code, "OOMKilled": self.oom,
                "StartedAt": "2026-10-30T14:00:00.000000000Z", "Error": ""}

    def remove(self, name):
        self.removed.append(name)
        proc = self.procs.get(name)
        if proc is not None and proc.poll() is None:
            proc.kill()
        return True

    def leftovers(self):
        return list(self.leftover)


class Service:
    """起一个真的沙箱服务（127.0.0.1 随机端口），docker 换成替身。"""

    def __init__(self, docker=None, concurrency=1, queue_seconds=0.0):
        self.docker = docker or FakeDocker()
        self.root = Path(tempfile.mkdtemp())
        self.sandbox = svc.Sandbox(self.docker, IMAGE, self.root, concurrency, queue_seconds)
        handler = type("TestHandler", (svc.Handler,), {"sandbox": self.sandbox, "token": TOKEN.encode()})
        self.server = svc.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.server.daemon_threads = True
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"

    def post(self, payload=None, token=TOKEN, raw=None, headers=None):
        body = raw if raw is not None else json.dumps(payload, ensure_ascii=False).encode("utf-8")
        request = urllib.request.Request(self.url + "/run", body, {"Content-Type": "application/json",
                                                                   **({"X-Sandbox-Token": token} if token else {}),
                                                                   **(headers or {})})
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                return response.status, json.load(response)
        except urllib.error.HTTPError as exc:
            with exc:
                return exc.code, json.load(exc)

    def run(self, code, files=None):
        status, body = self.post({"code": code, "files": files or []})
        assert status == 200, (status, body)
        return body

    def leftovers(self):
        runs = self.root / "runs"
        return sorted(p.name for p in runs.iterdir()) if runs.exists() else []

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        shutil.rmtree(self.root, ignore_errors=True)


class ServiceCase(unittest.TestCase):
    concurrency, queue_seconds = 1, 0.0

    def setUp(self):
        self.logged = []
        patcher = patch.object(svc, "log", side_effect=self.logged.append)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.service = Service(concurrency=self.concurrency, queue_seconds=self.queue_seconds)
        self.addCleanup(self.service.close)
        self.docker = self.service.docker


# --- docker 参数 ------------------------------------------------------------------------

class ArgvTests(ServiceCase):
    def test_every_limit_is_in_the_docker_argv(self):
        argv = svc.docker_argv("doc2sop-sbx-0123456789abcdef", "/var/lib/doc2sop-sandbox/runs/0123456789abcdef/data",
                               IMAGE)
        self.assertEqual(argv, [
            "run", "--name", "doc2sop-sbx-0123456789abcdef", "--label", "doc2sop.sandbox=1",
            "--runtime", "runsc", "--network", "none", "--ipc", "none",
            "--read-only", "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=16m,mode=1777",
            "--mount", "type=bind,source=/var/lib/doc2sop-sandbox/runs/0123456789abcdef/data,target=/data,readonly",
            "--user", "65534:65534", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--pids-limit", "128", "--memory", "256m", "--memory-swap", "256m", "--cpus", "1",
            "--oom-score-adj", "1000", "--log-driver", "none", "--pull", "never",
            "--hostname", "sandbox", "--workdir", "/tmp", "--interactive",
            "--entrypoint", "/usr/bin/env", IMAGE,
            "-i", "PATH=/usr/local/bin:/usr/bin:/bin", "LANG=C.UTF-8", "HOME=/tmp",
            "/usr/bin/timeout", "-s", "KILL", "25",
            "/usr/local/bin/python3", "-I", "-B", "-X", "utf8", "-"])
        # 要紧的几项单独再钉一遍：改参数顺序没关系，少一项不行
        pairs = {(argv[i], argv[i + 1]) for i in range(len(argv) - 1)}
        for pair in (("--runtime", "runsc"), ("--network", "none"), ("--user", "65534:65534"), ("--cap-drop", "ALL"),
                     ("--security-opt", "no-new-privileges"), ("--memory", "256m"), ("--memory-swap", "256m"),
                     ("--pids-limit", "128"), ("--cpus", "1"), ("--log-driver", "none"), ("--pull", "never")):
            self.assertIn(pair, pairs)
        self.assertIn("--read-only", argv)
        self.assertNotIn("--privileged", argv)
        self.assertNotIn("--rm", argv)       # 退出后要先 inspect 退出码和 OOMKilled，再由服务删

    def test_nothing_from_the_request_reaches_the_argv(self):
        code = "print('--privileged --network host --runtime runc')"
        files = [{"name": "01-docker--privileged.txt", "content": "--volume /:/host --user root"}]
        result = self.service.run(code, files)
        self.assertEqual(result["status"], "ok")
        argv = self.docker.argvs[0]
        name = argv[argv.index("--name") + 1]
        data = dict(p.split("=", 1) for p in argv[argv.index("--mount") + 1].split(",") if "=" in p)["source"]
        self.assertEqual(argv, svc.docker_argv(name, data, IMAGE))
        self.assertRegex(name, r"^doc2sop-sbx-[0-9a-f]{16}$")
        self.assertEqual(Path(data).name, "data")
        self.assertNotIn("--privileged", " ".join(argv))
        self.assertNotIn("host", argv)

    def test_extra_fields_are_refused_and_nothing_starts(self):
        for extra in ({"image": "alpine"}, {"runtime": "runc"}, {"network": "host"}, {"args": ["--privileged"]},
                      {"env": {"A": "1"}}, {"timeout": 999}, {"memory": "4g"}):
            with self.subTest(extra=extra):
                status, body = self.service.post({"code": "print(1)", **extra})
                self.assertEqual(status, 400)
                self.assertIn("不接受的字段", body["error"])
                self.assertIn("只能带 code 和 files", body["error"])
        self.assertEqual(self.docker.argvs, [])


# --- 令牌与请求的上限 -----------------------------------------------------------------------

class RequestTests(ServiceCase):
    def test_token_is_required(self):
        for token in ("", "wrong-token-of-some-length", TOKEN[:-1]):
            with self.subTest(token=token):
                status, body = self.service.post({"code": "print(1)"}, token=token)
                self.assertEqual((status, body["error"]), (401, "令牌无效"))
        self.assertEqual(self.docker.argvs, [])
        with urllib.request.urlopen(self.service.url + "/health", timeout=10) as response:
            health = json.load(response)
        self.assertEqual((health["runtime"], health["image"], health["concurrency"]), ("runsc", IMAGE, 1))
        self.assertEqual(health["limits"]["timeout_seconds"], 20)

    def test_request_limits(self):
        cases = [
            ({"code": ""}, 400, "code 必须是非空的字符串"),
            ({"code": "x" * (svc.CODE_MAX + 1)}, 413, "代码太长"),
            ({"code": "print(1)", "files": {}}, 400, "files 必须是数组"),
            ({"code": "print(1)", "files": [{"name": f"f{i}.txt", "content": ""} for i in range(svc.FILES_MAX + 1)]},
             413, "数据文件太多"),
            ({"code": "print(1)", "files": [{"name": "a.txt", "content": "x", "mode": "rw"}]}, 400,
             "只能有 name 和 content"),
            ({"code": "print(1)", "files": [{"name": "a.txt", "content": 1}]}, 400, "内容必须是字符串"),
            ({"code": "print(1)", "files": [{"name": "a.txt", "content": ""}, {"name": "a.txt", "content": ""}]},
             400, "文件名重复"),
        ]
        for name in ("../etc/passwd", "a/b", ".hidden", "", "x" * 101, "a b", "数据.txt", "a\\b"):
            cases.append(({"code": "print(1)", "files": [{"name": name, "content": ""}]}, 400, "文件名不合规"))
        for payload, status, words in cases:
            with self.subTest(payload=str(payload)[:80]):
                got, body = self.service.post(payload)
                self.assertEqual(got, status)
                self.assertIn(words, body["error"])
        self.assertEqual(self.docker.argvs, [])

    def test_input_total_and_body_size_are_capped(self):
        with patch.object(svc, "INPUT_MAX", 10):
            status, body = self.service.post({"code": "print(1)", "files": [{"name": "a.txt", "content": "123456"},
                                                                            {"name": "b.txt", "content": "你好"}]})
            self.assertEqual((status, "数据文件合计超过" in body["error"]), (413, True))   # 6 + 6 字节 > 10
            self.assertEqual(self.service.run("print(1)", [{"name": "a.txt", "content": "1234567890"}])["status"],
                             "ok")
        with patch.object(svc, "BODY_MAX", 100):
            status, body = self.service.post({"code": "print(1)", "files": [{"name": "a.txt", "content": "x" * 200}]})
            self.assertEqual(status, 413)
        status, body = self.service.post(raw=b"{not json")
        self.assertEqual((status, body["error"]), (400, "请求体不是合法的 JSON"))


# --- 执行、输出、清理 ---------------------------------------------------------------------

class RunTests(ServiceCase):
    def test_runs_code_and_returns_output_exit_status_and_duration(self):
        result = self.service.run("import sys\nprint('你好', 6 * 7)\nprint('warn', file=sys.stderr)")
        self.assertEqual((result["ok"], result["status"], result["exit_code"]), (True, "ok", 0))
        self.assertEqual(result["stdout"].replace("\r\n", "\n"), "你好 42\n")
        self.assertIn("warn", result["stderr"])
        self.assertFalse(result["stdout_truncated"] or result["stderr_truncated"])
        self.assertGreaterEqual(result["duration_ms"], 0)
        self.assertEqual(self.service.leftovers(), [])
        self.assertEqual(self.docker.removed, list(self.docker.procs))

    def test_data_files_are_written_byte_for_byte(self):
        content = "第一行\r\nsecond line\n\ttab\u00a0nbsp"
        self.service.run("print(1)", [{"name": "01-container_logs.txt", "content": content},
                                      {"name": "02-kube_events.txt", "content": ""}])
        mounted = next(iter(self.docker.mounted.values()))
        self.assertEqual(mounted, {"01-container_logs.txt": content.encode("utf-8"), "02-kube_events.txt": b""})

    def test_each_run_only_sees_its_own_files_and_leaves_nothing_behind(self):
        self.service.run("print(1)", [{"name": "a.txt", "content": "first run"}])
        self.assertEqual(self.service.leftovers(), [])
        self.service.run("print(2)", [{"name": "b.txt", "content": "second run"}])
        self.service.run("print(3)")
        self.assertEqual([sorted(files) for files in self.docker.mounted.values()], [["a.txt"], ["b.txt"], []])
        self.assertEqual(self.service.leftovers(), [])
        self.assertEqual(len(set(self.docker.removed)), 3)

    def test_output_is_capped_and_the_container_stopped(self):
        code = "import sys, time\nsys.stdout.write('x' * 200000)\nsys.stdout.flush()\ntime.sleep(30)"
        started = time.monotonic()
        result = self.service.run(code)
        self.assertLess(time.monotonic() - started, 15)
        self.assertEqual(result["status"], "output_limit")
        self.assertTrue(result["stdout_truncated"])
        self.assertEqual(len(result["stdout"].encode("utf-8")), svc.STDOUT_MAX)
        self.assertEqual(self.docker.killed, list(self.docker.procs))
        self.assertEqual(self.service.leftovers(), [])

    def test_stderr_keeps_the_tail_where_the_traceback_is(self):
        result = self.service.run("import sys\nsys.stderr.write('noise ' * 4000)\nraise ValueError('boom')")
        self.assertEqual((result["status"], result["exit_code"]), ("error", 1))
        self.assertTrue(result["stderr_truncated"])
        self.assertLessEqual(len(result["stderr"].encode("utf-8")), svc.STDERR_MAX)
        self.assertIn("ValueError: boom", result["stderr"])

    def test_timeout_kills_the_container_and_cleans_up(self):
        with patch.object(svc, "TIMEOUT", 1):
            started = time.monotonic()
            result = self.service.run("print('started', flush=True)\nwhile True:\n    pass")
        self.assertLess(time.monotonic() - started, 15)
        self.assertEqual((result["status"], result["exit_code"]), ("timeout", 137))
        self.assertIn("started", result["stdout"])
        name = next(iter(self.docker.procs))
        self.assertEqual((self.docker.killed, self.docker.removed), ([name], [name]))
        self.assertEqual(self.service.leftovers(), [])
        self.assertEqual(self.service.run("print('next')")["status"], "ok")     # 名额已经还回去了

    def test_oom_and_external_kills_are_explained(self):
        self.docker.oom = True
        self.assertEqual(self.service.run("import sys\nsys.exit(137)")["status"], "oom")
        self.docker.oom = False
        self.assertEqual(self.service.run("import sys\nsys.exit(137)")["status"], "killed")
        self.assertEqual(self.service.run("import sys\nsys.exit(3)")["status"], "error")
        self.assertEqual(self.service.leftovers(), [])

    def test_start_failures_clean_up_and_say_why(self):
        self.docker.fail_start = FileNotFoundError("docker 不在 PATH 里")
        status, body = self.service.post({"code": "print(1)", "files": [{"name": "a.txt", "content": "x"}]})
        self.assertEqual(status, 500)
        self.assertIn("沙箱启动失败", body["error"])
        self.assertEqual(self.service.leftovers(), [])
        self.docker.fail_start = None
        self.docker.never_created = True        # docker run 自己报错退出（比如 runtime 没注册），容器没建出来
        status, body = self.service.post({"code": "print(1)"})
        self.assertEqual(status, 500)
        self.assertIn("沙箱启动失败", body["error"])
        self.assertEqual(self.service.leftovers(), [])
        self.assertEqual(len(self.docker.removed), 1)
        self.docker.never_created = False
        self.assertEqual(self.service.run("print(1)")["status"], "ok")

    def test_unexpected_errors_clean_up_too(self):
        self.docker.state_error = RuntimeError("inspect 挂了")
        status, body = self.service.post({"code": "import time\ntime.sleep(30)", "files": [{"name": "a", "content": ""}]})
        self.assertEqual((status, body["error"]), (500, "沙箱服务内部错误：RuntimeError"))
        name = next(iter(self.docker.procs))
        self.assertEqual(self.docker.removed, [name])
        self.assertEqual(self.service.leftovers(), [])
        self.docker.state_error = None
        self.assertEqual(self.service.run("print(1)")["status"], "ok")

    def test_logs_carry_the_shape_of_a_run_but_never_code_or_data(self):
        self.service.post({"code": "print('SECRET-CODE-123')", "files": [{"name": "a.txt", "content": "SECRET-DATA-456"}]},
                          headers={"X-Sandbox-Caller": "agent conversation=abc\tforged\x7fline"})
        text = "\n".join(self.logged)
        self.assertIn("[run] caller=agent conversation=abc?forged?line status=ok exit=0", text)
        self.assertNotIn("SECRET-CODE-123", text)
        self.assertNotIn("SECRET-DATA-456", text)


# --- 并发 ---------------------------------------------------------------------------------

class BusyTests(ServiceCase):
    """并发 1、不排队：忙的时候直接拒绝，说明原因。"""

    def test_a_second_request_is_refused_while_one_runs(self):
        first = {}
        thread = threading.Thread(target=lambda: first.update(
            result=self.service.run("import time\ntime.sleep(2)\nprint('done')")))
        thread.start()
        deadline = time.monotonic() + 10
        while not self.docker.procs and time.monotonic() < deadline:
            time.sleep(0.05)
        status, body = self.service.post({"code": "print(1)"})
        self.assertEqual(status, 429)
        self.assertIn("沙箱正忙：同时最多运行 1 个", body["error"])
        thread.join()
        self.assertEqual(first["result"]["stdout"].strip(), "done")
        self.assertEqual(self.service.run("print(1)")["status"], "ok")
        self.assertEqual(len(self.docker.argvs), 2)

    def test_concurrency_is_capped_at_two(self):
        self.assertEqual(svc.Sandbox(FakeDocker(), IMAGE, self.service.root, concurrency=5).concurrency, 2)
        self.assertEqual(svc.Sandbox(FakeDocker(), IMAGE, self.service.root, concurrency=0).concurrency, 1)


class QueueTests(ServiceCase):
    """并发 1、排队 10 秒：后来的等一等；排队的也满了就拒绝。"""
    queue_seconds = 10.0

    def test_requests_wait_in_line(self):
        results = []
        threads = [threading.Thread(target=lambda: results.append(self.service.run("import time\ntime.sleep(1)")))
                   for _ in range(2)]
        started = time.monotonic()
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual([r["status"] for r in results], ["ok", "ok"])
        self.assertGreaterEqual(time.monotonic() - started, 2)

    def test_the_line_is_bounded(self):
        outcomes = []

        def one():
            outcomes.append(self.service.post({"code": "import time\ntime.sleep(1.5)"}))

        with patch.object(svc, "QUEUE_MAX", 1):
            threads = [threading.Thread(target=one) for _ in range(3)]
            for thread in threads:
                thread.start()
                time.sleep(0.3)
            for thread in threads:
                thread.join()
        statuses = sorted(status for status, _ in outcomes)
        self.assertEqual(statuses, [200, 200, 429])
        self.assertIn("排队的也已经有 1 个", next(body["error"] for status, body in outcomes if status == 429))


# --- 残留 ---------------------------------------------------------------------------------

class SweepTests(ServiceCase):
    def test_startup_sweeps_what_was_left_last_time(self):
        stale = self.service.root / "runs" / "deadbeefdeadbeef" / "data"
        stale.mkdir(parents=True)
        (stale / "a.txt").write_text("left over", encoding="utf-8")
        self.docker.leftover = ["doc2sop-sbx-1", "doc2sop-sbx-2"]
        self.assertEqual(self.service.sandbox.sweep(), (2, 1))
        self.assertEqual(self.docker.removed, ["doc2sop-sbx-1", "doc2sop-sbx-2"])
        self.assertEqual(self.service.leftovers(), [])

    def test_shutdown_removes_what_is_still_running(self):
        self.service.sandbox.live.add("doc2sop-sbx-running")
        self.service.sandbox.shutdown()
        self.assertEqual(self.docker.removed, ["doc2sop-sbx-running"])

    def test_startup_refuses_without_runsc_or_the_image(self):
        class NoRunsc(svc.Docker):
            def _run(self, *args, timeout=30):
                if args[0] == "info":
                    return subprocess.CompletedProcess(args, 0, b'{"runc": {}}', b"")
                return subprocess.CompletedProcess(args, 1, b"", b"No such image")

        problems = NoRunsc().check(IMAGE)
        self.assertEqual(len(problems), 2)
        self.assertIn("没有注册 runsc", problems[0])
        self.assertIn(f"本机没有镜像 {IMAGE}", problems[1])


if __name__ == "__main__":
    unittest.main()
