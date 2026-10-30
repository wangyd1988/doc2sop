#!/usr/bin/env python3
"""计算沙箱服务：python_exec 的执行端（docs/工具.md「计算类与沙箱」，部署见 docs/正式部署.md「计算沙箱」）。

应用不挂 docker.sock，起容器的权限只在这个服务手里。它只认一种请求：一段 Python 代码，加本轮的数据文件。
每次执行起一个用完即弃的容器，跑完就删。镜像、runtime 和全部限制都写死在这里（docker_argv），
请求里带不进任何 docker 参数——多带一个字段，整个请求就拒绝。

    隔离       runtime 是 runsc（gVisor）：容器里的系统调用由 gVisor 的用户态内核接住，不直接落到宿主机内核
    每次执行   无网络；根文件系统只读，只有 /tmp 一个临时工作目录（tmpfs，16MB）；数据文件只读挂在 /data；
               用户 nobody，去掉全部 capabilities，no-new-privileges；环境变量只有 PATH、LANG、HOME；
               pids 128、CPU 1 核、内存 256MB（不给 swap）、时长 20 秒、stdout 32KB、stderr 留最后 8KB；
               宿主机内存紧张时先杀它（oom-score-adj 1000）；不写容器日志（log-driver none），输出只走管道
    并发       全局最多 SANDBOX_CONCURRENCY 个（默认 1，最多 2）；满了排队等 SANDBOX_QUEUE_SECONDS 秒（默认 10），
               还轮不到、或者已经有 4 个在排队，就直接拒绝（429）并说明原因
    清理       正常结束、超时、被 OOM 杀掉、输出超限、起不来，容器和临时目录都删掉；
               服务启动时、收到 SIGTERM 时再扫一遍（服务被强杀时留下的，下次启动清掉）。
               容器里还有一道兜底：服务自己没了，代码最多再跑 WATCHDOG 秒也会被杀

只监听 127.0.0.1，校验令牌（请求头 X-Sandbox-Token），只用标准库，由 systemd 管理：

    SANDBOX_TOKEN=... python3 sandbox_service.py --port 8797

接口：
    POST /run     {"code": "...", "files": [{"name": "01-container_logs.txt", "content": "..."}]}
                  代码跑了就是 200（代码自己出错也是）：{"ok": true, "status", "exit_code", "stdout", "stdout_truncated",
                  "stderr", "stderr_truncated", "duration_ms"}，status 是 ok / error / timeout / oom / killed / output_limit；
                  没跑成是 4xx / 5xx：{"ok": false, "error": "原因"}
    GET  /health  {"status": "ok", "runtime", "image", "concurrency", "running", "waiting", "limits"}，不要令牌
"""
import argparse
import hmac
import json
import os
import re
import secrets
import shutil
import signal
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HOST = "127.0.0.1"          # 只监听本机，不提供配置项
DEFAULT_PORT = 8797
DEFAULT_IMAGE = "doc2sop-sandbox:latest"
DEFAULT_STATE_DIR = "/var/lib/doc2sop-sandbox"

# --- 每次执行的限制：全部写死，请求改不了 ---------------------------------------------
RUNTIME = "runsc"
MEMORY = "256m"
CPUS = "1"
PIDS = 128                  # gVisor 自己的线程也算在里面，留些余量；fork 炸弹照样撞上限
TIMEOUT = 20                # 秒，从 docker run 算起
WATCHDOG = TIMEOUT + 5      # 容器里的兜底（timeout -s KILL）：服务被强杀了，代码也最多再跑这么久
TMPFS = "/tmp:rw,nosuid,nodev,noexec,size=16m,mode=1777"
STDOUT_MAX = 32 * 1024      # 字节；超了就截断并终止运行
STDERR_MAX = 8 * 1024       # 字节；留最后这么多（报错的堆栈在末尾）
ENV = ("PATH=/usr/local/bin:/usr/bin:/bin", "LANG=C.UTF-8", "HOME=/tmp")
PYTHON = ("/usr/local/bin/python3", "-I", "-B", "-X", "utf8", "-")   # 代码从 stdin 读，不落盘

# --- 请求的上限 ------------------------------------------------------------------------
CODE_MAX = 20000            # 字
FILES_MAX = 64
INPUT_MAX = 4 * 1024 * 1024     # 数据文件合计多少字节（UTF-8）
BODY_MAX = 16 * 1024 * 1024
FIELDS = ("code", "files")
FILE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")
QUEUE_MAX = 4               # 最多几个请求排队等名额
CONCURRENCY_MAX = 2
KILL_GRACE = 10             # docker kill 之后等 docker run 退出的秒数

LABEL = "doc2sop.sandbox"
PREFIX = "doc2sop-sbx-"
TOKEN_HEADER = "X-Sandbox-Token"
CALLER_HEADER = "X-Sandbox-Caller"
SAFE_DIR = re.compile(r"^/[A-Za-z0-9._/-]+$")     # 状态目录要拼进 --mount 的 source=，不能有逗号、引号、冒号


def log(message):
    print(message, flush=True)


class Rejected(Exception):
    """请求不合规：不执行，按 status 回给调用方。"""

    def __init__(self, status, message):
        super().__init__(message)
        self.status = status


class Failed(Exception):
    """容器没跑起来（docker 出错、镜像或 runtime 不在）：回 500，说明原因。"""


def docker_argv(name, data_dir, image):
    """docker run 的全部参数。只由常量、这次执行的名字、临时目录和服务端配置的镜像拼成，请求里的东西一样都进不来。"""
    return ["run", "--name", name, "--label", f"{LABEL}=1",
            "--runtime", RUNTIME, "--network", "none", "--ipc", "none",
            "--read-only", "--tmpfs", TMPFS,
            "--mount", f"type=bind,source={data_dir},target=/data,readonly",
            "--user", "65534:65534", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--pids-limit", str(PIDS), "--memory", MEMORY, "--memory-swap", MEMORY, "--cpus", CPUS,
            "--oom-score-adj", "1000", "--log-driver", "none", "--pull", "never",
            "--hostname", "sandbox", "--workdir", "/tmp", "--interactive",
            # 镜像自带的 ENV（PYTHON_VERSION、GPG_KEY……）一概不要：env -i 之后只剩这里列的三个
            "--entrypoint", "/usr/bin/env", image,
            "-i", *ENV, "/usr/bin/timeout", "-s", "KILL", str(WATCHDOG), *PYTHON]


def parse(payload):
    """校验请求，返回 (code, files)。只认 code 和 files 两个字段：镜像、runtime、各项限制都不归请求管。"""
    if not isinstance(payload, dict):
        raise Rejected(400, "请求体必须是 JSON 对象")
    extra = sorted(str(key) for key in payload if key not in FIELDS)
    if extra:
        raise Rejected(400, f"不接受的字段：{', '.join(extra)[:200]}。镜像、runtime 和各项限制都由沙箱服务定，"
                            "请求只能带 code 和 files")
    code = payload.get("code")
    if not isinstance(code, str) or not code.strip():
        raise Rejected(400, "code 必须是非空的字符串")
    if len(code) > CODE_MAX:
        raise Rejected(413, f"代码太长：{len(code)} 字，最多 {CODE_MAX} 字")
    _utf8(code, "code")
    files = payload.get("files", [])
    if not isinstance(files, list):
        raise Rejected(400, "files 必须是数组")
    if len(files) > FILES_MAX:
        raise Rejected(413, f"数据文件太多：{len(files)} 个，最多 {FILES_MAX} 个")
    out, seen, total = [], set(), 0
    for item in files:
        if not isinstance(item, dict) or set(item) != {"name", "content"}:
            raise Rejected(400, "files 里每一项只能有 name 和 content 两个字段")
        name, content = item["name"], item["content"]
        if not isinstance(name, str) or not FILE_NAME.fullmatch(name):
            raise Rejected(400, f"文件名不合规：{str(name)[:80]!r}（只能用字母、数字、点、下划线、连字符，"
                                "以字母或数字开头，最长 100 个字符）")
        if name in seen:
            raise Rejected(400, f"文件名重复：{name}")
        if not isinstance(content, str):
            raise Rejected(400, f"文件 {name} 的内容必须是字符串")
        total += len(_utf8(content, name))
        if total > INPUT_MAX:
            raise Rejected(413, f"数据文件合计超过 {INPUT_MAX // (1024 * 1024)}MB 上限")
        seen.add(name)
        out.append({"name": name, "content": content})
    return code, out


def _utf8(text, what):
    try:
        return text.encode("utf-8")
    except UnicodeEncodeError:
        raise Rejected(400, f"{what} 里有无法编码成 UTF-8 的字符") from None


def _caller(raw):
    """请求头里的调用方（项目 Agent 的会话、图谱执行）只进日志：留可打印的 ASCII，防止伪造日志行。"""
    text = "".join(ch if " " <= ch <= "~" else "?" for ch in str(raw or ""))
    return " ".join(text.split())[:200]


# --- 起容器的那一层：只有这里调 docker 命令（单测换成替身）-------------------------------

class Docker:
    def __init__(self, binary="docker"):
        self.binary = binary

    def _run(self, *args, timeout=30):
        return subprocess.run([self.binary, *args], stdin=subprocess.DEVNULL, capture_output=True, timeout=timeout)

    def start(self, argv):
        """docker run（前台、接着 stdin / stdout / stderr）：返回进程，代码从它的 stdin 写进去。"""
        return subprocess.Popen([self.binary, *argv], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)

    def kill(self, name):
        try:
            self._run("kill", name, timeout=15)
        except (OSError, subprocess.SubprocessError) as exc:
            log(f"[warn] docker kill {name} 失败：{exc}")

    def state(self, name):
        """容器的 State（ExitCode、OOMKilled、StartedAt、Error）；容器根本没建出来时返回 None。"""
        try:
            done = self._run("inspect", "--type", "container", "--format", "{{json .State}}", name, timeout=15)
        except (OSError, subprocess.SubprocessError):
            return None
        if done.returncode != 0:
            return None
        try:
            state = json.loads(done.stdout)
        except ValueError:
            return None
        return state if isinstance(state, dict) else None

    def remove(self, name):
        try:
            done = self._run("rm", "-f", name, timeout=30)
        except (OSError, subprocess.SubprocessError):
            return False
        return done.returncode == 0 or b"No such container" in done.stderr

    def leftovers(self):
        """带本服务标签的容器（上次没删掉的）。"""
        try:
            done = self._run("ps", "-aq", "--filter", f"label={LABEL}", timeout=30)
        except (OSError, subprocess.SubprocessError):
            return []
        return done.stdout.decode("ascii", "replace").split() if done.returncode == 0 else []

    def check(self, image):
        """启动前的自检：连得上 docker、runsc 已经注册、镜像在本机。返回问题列表，空的就是都好。"""
        problems = []
        try:
            done = self._run("info", "--format", "{{json .Runtimes}}")
        except (OSError, subprocess.SubprocessError) as exc:
            return [f"调不了 docker：{exc}"]
        if done.returncode != 0:
            return [f"连不上 docker：{done.stderr.decode('utf-8', 'replace').strip()[:300]}"]
        try:
            runtimes = json.loads(done.stdout)
        except ValueError:
            runtimes = {}
        if not isinstance(runtimes, dict) or RUNTIME not in runtimes:
            problems.append(f"docker 里没有注册 {RUNTIME}（gVisor）这个 runtime：见 docs/正式部署.md「计算沙箱」")
        try:
            done = self._run("image", "inspect", "--format", "{{.Id}}", image)
        except (OSError, subprocess.SubprocessError) as exc:
            return problems + [f"查不了镜像 {image}：{exc}"]
        if done.returncode != 0:
            problems.append(f"本机没有镜像 {image}：先用 deploy/sandbox/Dockerfile 构建")
        return problems


# --- 读输出 -----------------------------------------------------------------------------

class _Streams:
    """往 docker run 的 stdin 写代码，读它的 stdout / stderr。

    stdout 留前 STDOUT_MAX 字节，超了就报 overflow（由调用方终止容器）；stderr 留最后 STDERR_MAX 字节。
    多出来的照样读掉、丢弃——不读的话容器会卡在写输出上，docker run 也就退不出来。
    """

    def __init__(self, proc, code):
        self.stdout, self.stderr = bytearray(), bytearray()
        self.stdout_cut = self.stderr_cut = False
        self.overflow = threading.Event()
        self.threads = [threading.Thread(target=self._feed, args=(proc.stdin, code), daemon=True),
                        threading.Thread(target=self._read_out, args=(proc.stdout,), daemon=True),
                        threading.Thread(target=self._read_err, args=(proc.stderr,), daemon=True)]
        for thread in self.threads:
            thread.start()

    @staticmethod
    def _feed(pipe, code):
        try:
            pipe.write(code.encode("utf-8"))
        except (OSError, ValueError):
            pass    # 容器没起来或者已经退出了
        finally:
            try:
                pipe.close()
            except OSError:
                pass

    @staticmethod
    def _chunks(pipe):
        read = getattr(pipe, "read1", pipe.read)
        while True:
            try:
                chunk = read(65536)
            except (OSError, ValueError):
                return
            if not chunk:
                return
            yield chunk

    def _read_out(self, pipe):
        try:
            for chunk in self._chunks(pipe):
                room = STDOUT_MAX - len(self.stdout)
                if room > 0:
                    self.stdout += chunk[:room]
                if len(chunk) > room:
                    self.stdout_cut = True
                    self.overflow.set()
        finally:
            pipe.close()

    def _read_err(self, pipe):
        try:
            for chunk in self._chunks(pipe):
                self.stderr += chunk
                if len(self.stderr) > STDERR_MAX:
                    del self.stderr[:len(self.stderr) - STDERR_MAX]
                    self.stderr_cut = True
        finally:
            pipe.close()

    def join(self):
        for thread in self.threads:
            thread.join(timeout=5)

    def text(self, which):
        return bytes(getattr(self, which)).decode("utf-8", "replace")


def _status(reason, state):
    exit_code = state.get("ExitCode")
    exit_code = exit_code if isinstance(exit_code, int) and not isinstance(exit_code, bool) else -1
    if reason:
        return reason, exit_code
    if state.get("OOMKilled"):
        return "oom", exit_code
    if exit_code == 0:
        return "ok", exit_code
    if exit_code == 137:    # SIGKILL：不是我们杀的，多半是内存超了（gVisor 里不一定报 OOMKilled）
        return "killed", exit_code
    return "error", exit_code


def _started(state):
    started = str(state.get("StartedAt") or "")
    return bool(started) and not started.startswith("0001-")


# --- 一次执行 ---------------------------------------------------------------------------

class Sandbox:
    def __init__(self, docker, image, root, concurrency=1, queue_seconds=10.0):
        self.docker, self.image = docker, image
        self.runs = Path(root) / "runs"
        self.concurrency = max(1, min(CONCURRENCY_MAX, int(concurrency)))
        self.queue_seconds = max(0.0, float(queue_seconds))
        self.slots = threading.BoundedSemaphore(self.concurrency)
        self.lock = threading.Lock()
        self.waiting = 0
        self.live = set()       # 正在跑的容器名：收到 SIGTERM 时清掉

    # 名额 ---------------------------------------------------------------------------
    def admit(self):
        """占一个名额：有空位马上占；没有就排队等 queue_seconds 秒。占到了返回 None，否则返回拒绝的原因。"""
        if self.slots.acquire(blocking=False):
            return None
        with self.lock:
            full = self.waiting >= QUEUE_MAX
            if not full and self.queue_seconds > 0:
                self.waiting += 1
        if full:
            return f"沙箱正忙：同时最多运行 {self.concurrency} 个，排队的也已经有 {QUEUE_MAX} 个，请稍后再试"
        if self.queue_seconds <= 0:
            return f"沙箱正忙：同时最多运行 {self.concurrency} 个，请稍后再试"
        try:
            if self.slots.acquire(timeout=self.queue_seconds):
                return None
        finally:
            with self.lock:
                self.waiting -= 1
        return f"沙箱正忙：同时最多运行 {self.concurrency} 个，排队 {self.queue_seconds:g} 秒还没轮到，请稍后再试"

    def release(self):
        self.slots.release()

    # 执行 ---------------------------------------------------------------------------
    def execute(self, code, files):
        """起一个用完即弃的容器跑这段代码。不管怎么结束，容器和临时目录都删掉。"""
        run_id = secrets.token_hex(8)
        name = PREFIX + run_id
        workdir = self.runs / run_id
        started = time.monotonic()
        proc = None
        with self.lock:
            self.live.add(name)
        try:
            data = self._prepare(workdir, files)
            try:
                proc = self.docker.start(docker_argv(name, data, self.image))
            except OSError as exc:
                raise Failed(f"沙箱启动失败：{exc}") from exc
            streams = _Streams(proc, code)
            reason = self._wait(proc, streams, name, started)
            state = self.docker.state(name)
            if state is None or state.get("Error") or not _started(state):
                detail = ((state or {}).get("Error") or streams.text("stderr").strip()
                          or f"docker run 退出码 {proc.returncode}")
                raise Failed(f"沙箱启动失败：{str(detail).strip()[-500:]}")
            if not reason and (state.get("Running") or proc.returncode != state.get("ExitCode")):
                # docker run 客户端自己先没了（被杀、daemon 重启……）：输出可能不全，不能当成跑完了
                where = "还在运行" if state.get("Running") else f"的退出码是 {state.get('ExitCode')}"
                raise Failed(f"沙箱执行中断：docker run 提前退出（退出码 {proc.returncode}），容器{where}；"
                             "输出可能不完整，容器已清理")
            status, exit_code = _status(reason, state)
            return {"ok": True, "status": status, "exit_code": exit_code,
                    "stdout": streams.text("stdout"), "stdout_truncated": streams.stdout_cut,
                    "stderr": streams.text("stderr"), "stderr_truncated": streams.stderr_cut,
                    "duration_ms": int((time.monotonic() - started) * 1000)}
        finally:
            self._cleanup(name, workdir, proc)

    def _prepare(self, workdir, files):
        """这次执行的临时目录：<状态目录>/runs/<随机 id>/data，每个数据文件原样写进去（不转换换行）。"""
        data = workdir / "data"
        data.mkdir(parents=True)
        os.chmod(workdir, 0o711)
        os.chmod(data, 0o755)
        for item in files:
            path = data / item["name"]
            with open(path, "x", encoding="utf-8", newline="") as handle:
                handle.write(item["content"])
            os.chmod(path, 0o644)
        return data

    def _wait(self, proc, streams, name, started):
        """等 docker run 结束；超时或者输出超限就 docker kill。返回提前终止的原因，正常结束是空串。"""
        reason = ""
        deadline = started + TIMEOUT
        while proc.poll() is None:
            if streams.overflow.is_set():
                reason = "output_limit"
                break
            if time.monotonic() >= deadline:
                reason = "timeout"
                break
            streams.overflow.wait(0.1)
        if reason:
            self.docker.kill(name)
        try:
            proc.wait(timeout=KILL_GRACE)
        except subprocess.TimeoutExpired:
            proc.kill()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
        streams.join()
        return reason

    def _cleanup(self, name, workdir, proc):
        removed = True
        if proc is not None:        # 没调过 docker run 就没有容器可删
            if proc.poll() is None:
                self.docker.kill(name)
                proc.kill()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    pass
            removed = self.docker.remove(name)
        shutil.rmtree(workdir, ignore_errors=True)
        with self.lock:
            self.live.discard(name)
        if not removed:
            log(f"[warn] 容器 {name} 没删掉，下次启动时再清")
        if workdir.exists():
            log(f"[warn] 临时目录 {workdir} 没删掉，下次启动时再清")

    # 残留 ---------------------------------------------------------------------------
    def sweep(self):
        """清掉上次留下的：带本服务标签的容器、runs 下的临时目录。只在启动时调用。"""
        names = self.docker.leftovers()
        for name in names:
            self.docker.remove(name)
        stale = sorted(self.runs.iterdir()) if self.runs.is_dir() else []
        for path in stale:
            shutil.rmtree(path, ignore_errors=True)
        return len(names), len(stale)

    def shutdown(self):
        """停服务时：还在跑的容器一并删掉。"""
        with self.lock:
            names = sorted(self.live)
        for name in names:
            self.docker.remove(name)

    def health(self):
        with self.lock:
            running, waiting = len(self.live), self.waiting
        return {"status": "ok", "runtime": RUNTIME, "image": self.image, "concurrency": self.concurrency,
                "running": running, "waiting": waiting,
                "limits": {"memory": MEMORY, "cpus": CPUS, "pids": PIDS, "timeout_seconds": TIMEOUT,
                           "stdout_bytes": STDOUT_MAX, "code_chars": CODE_MAX, "files": FILES_MAX,
                           "input_bytes": INPUT_MAX, "queue_seconds": self.queue_seconds, "queue_max": QUEUE_MAX}}


# --- HTTP --------------------------------------------------------------------------------

class Handler(BaseHTTPRequestHandler):
    sandbox = None
    token = b""
    timeout = 60                # 套接字超时：慢吞吞的客户端占不住线程
    server_version = "doc2sop-sandbox"
    sys_version = ""

    def log_message(self, format, *args):    # noqa: A002  每次执行自己记一行，不要默认的访问日志
        pass

    def _send(self, status, payload):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _authorised(self):
        supplied = self.headers.get(TOKEN_HEADER, "")
        return bool(self.token) and hmac.compare_digest(supplied.encode("utf-8", "replace"), self.token)

    def _drain(self, limit=1024 * 1024):
        """不处理这个请求也先把（不大的）请求体读掉：不读就关连接，对方可能只收到 RST，看不到错误说明。"""
        try:
            length = int(self.headers.get("Content-Length", "") or 0)
        except ValueError:
            return
        if 0 < length <= limit:
            try:
                self.rfile.read(length)
            except OSError:
                pass

    def do_GET(self):
        if self.path == "/health":
            return self._send(200, self.sandbox.health())
        self._send(404, {"ok": False, "error": "Not found"})

    def do_POST(self):
        if self.path != "/run":
            self._drain()
            return self._send(404, {"ok": False, "error": "Not found"})
        if not self._authorised():
            self._drain()
            return self._send(401, {"ok": False, "error": "令牌无效"})
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            return self._send(411, {"ok": False, "error": "要带 Content-Length"})
        if length < 0 or length > BODY_MAX:
            self.close_connection = True
            return self._send(413, {"ok": False, "error": f"请求体超过 {BODY_MAX // (1024 * 1024)}MB 上限"})
        try:
            code, files = parse(json.loads(self.rfile.read(length)))
        except Rejected as exc:
            return self._send(exc.status, {"ok": False, "error": str(exc)})
        except (ValueError, UnicodeDecodeError):
            return self._send(400, {"ok": False, "error": "请求体不是合法的 JSON"})
        caller = _caller(self.headers.get(CALLER_HEADER, "")) or "-"
        busy = self.sandbox.admit()
        if busy:
            log(f"[busy] caller={caller} {busy}")
            return self._send(429, {"ok": False, "error": busy})
        try:
            result = self.sandbox.execute(code, files)
        except Failed as exc:
            log(f"[fail] caller={caller} {exc}")
            return self._send(500, {"ok": False, "error": str(exc)})
        except Exception as exc:
            log(f"[fail] caller={caller} {exc.__class__.__name__}: {exc}")
            return self._send(500, {"ok": False, "error": f"沙箱服务内部错误：{exc.__class__.__name__}"})
        finally:
            self.sandbox.release()
        # 代码和数据都不进日志（可能有敏感内容），只记结果的形状
        log(f"[run] caller={caller} status={result['status']} exit={result['exit_code']} "
            f"ms={result['duration_ms']} files={len(files)} code_chars={len(code)} "
            f"stdout={len(result['stdout'])}{'+' if result['stdout_truncated'] else ''}")
        self._send(200, result)


def _setting(name, default, low, high, kind):
    raw = os.environ.get(name, "").strip()
    try:
        value = kind(raw) if raw else default
    except ValueError:
        log(f"[warn] {name}={raw!r} 不是数字，用默认值 {default}")
        value = default
    if not low <= value <= high:
        log(f"[warn] {name}={value} 超出范围 {low}–{high}，按边界取值")
        value = max(low, min(high, value))
    return value


def _stop(signum, frame):
    raise SystemExit(0)


def main():
    parser = argparse.ArgumentParser(description="计算沙箱服务（python_exec 的执行端），只监听 127.0.0.1")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    args = parser.parse_args()

    token = os.environ.get("SANDBOX_TOKEN", "").strip()
    if len(token) < 16:
        print("错误：环境变量 SANDBOX_TOKEN 至少要 16 个字符", file=sys.stderr)
        return 1
    image = os.environ.get("SANDBOX_IMAGE", "").strip() or DEFAULT_IMAGE
    concurrency = _setting("SANDBOX_CONCURRENCY", 1, 1, CONCURRENCY_MAX, int)
    queue_seconds = _setting("SANDBOX_QUEUE_SECONDS", 10.0, 0.0, 60.0, float)
    # systemd 的 StateDirectory= 会给 STATE_DIRECTORY；临时目录要让 docker daemon 看得见，不能放 PrivateTmp 里
    root = (os.environ.get("SANDBOX_STATE_DIR", "").strip() or os.environ.get("STATE_DIRECTORY", "").split(":")[0]
            or DEFAULT_STATE_DIR)
    if not SAFE_DIR.fullmatch(root):
        print(f"错误：状态目录 {root!r} 要是绝对路径，只能有字母、数字和 ._/-", file=sys.stderr)
        return 1
    docker = Docker(os.environ.get("SANDBOX_DOCKER", "").strip() or "docker")
    problems = docker.check(image)
    if problems:
        for problem in problems:
            print(f"错误：{problem}", file=sys.stderr)
        return 1

    sandbox = Sandbox(docker, image, root, concurrency, queue_seconds)
    sandbox.runs.mkdir(parents=True, exist_ok=True)
    os.chmod(sandbox.runs, 0o711)
    containers, dirs = sandbox.sweep()
    if containers or dirs:
        log(f"清掉了上次的残留：容器 {containers} 个、临时目录 {dirs} 个")
    Handler.sandbox, Handler.token = sandbox, token.encode("utf-8")
    server = ThreadingHTTPServer((HOST, args.port), Handler)
    server.daemon_threads = True
    signal.signal(signal.SIGTERM, _stop)
    log(f"计算沙箱服务启动于 {HOST}:{args.port}：runtime={RUNTIME} 镜像={image} 并发 {sandbox.concurrency} "
        f"排队 {sandbox.queue_seconds:g} 秒；每次 内存 {MEMORY} CPU {CPUS} pids {PIDS} 时长 {TIMEOUT} 秒")
    try:
        server.serve_forever()
    except (KeyboardInterrupt, SystemExit):
        pass
    finally:
        server.server_close()
        sandbox.shutdown()
        log("计算沙箱服务已停止")
    return 0


if __name__ == "__main__":
    sys.exit(main())
