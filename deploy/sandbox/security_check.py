#!/usr/bin/env python3
"""计算沙箱的真实环境安全用例：在装好 gVisor、起好沙箱服务的宿主机上，以 root 身份对着真实的服务跑一遍。

    python3 security_check.py [--url http://127.0.0.1:8797] [--env-file /etc/doc2sop-sandbox.env]

全部通过才退出 0。有一条没过就退出 1——按 docs/正式部署.md「计算沙箱」的规矩：先撤掉沙箱，再回报。
令牌从环境变量 SANDBOX_TOKEN 或 --env-file 里读，不打印。

    接口      不带令牌、令牌不对都是 401；夹带 docker 参数、文件名带路径都是 400，一个容器都不起
    断网      连外网（IP 直连、域名、HTTP）、连宿主机上的应用 8765、工具服务 8799、沙箱服务 8797、模型网关隧道 14000、
              docker 网关、云元数据、宿主机自己的 IP，DNS 解析，全部失败
    文件      根文件系统、/data、/run 等都写不进去，只有 /tmp 能写（/dev/shm 和 /tmp 实际能写多少另外报出来）；
              读不到宿主机上的文件（.env、docker.sock、/var/lib/docker）；读不到别的执行的数据
    身份      nobody、没有任何 capability（/proc 的说法之外再实际试 setuid(0)、chown、setgroups）、NoNewPrivs；
              环境变量只有 PATH、LANG、HOME（Python 的 locale 处理可能补一个 LC_CTYPE），没有凭据
    资源      fork 炸弹、内存炸弹、死循环、超大输出都按上限收手；跑完宿主机上的生产容器没被重启
    隔离      容器的 runtime 是 runsc，各项限制确实加上了；容器里看到的内核不是宿主机的
    并发      满了排队；排队的也满了就 429
    清理      跑完没有残留的容器和临时目录
    内存      整个检查期间每 0.1 秒记一次宿主机可用内存，报最低值（低于 250MB 另外标出来）；每个沙箱容器 cgroup 的峰值
"""
import argparse
import json
import os
import re
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

LABEL = "doc2sop.sandbox"
RUNS_DIR = "/var/lib/doc2sop-sandbox/runs"
PRODUCTION = "kb-app"           # 应用容器：它必须在跑，而且跑完用例后没被重启（别的在跑的容器同样核对）
LOCAL_PORTS = (8765, 8766, 8797, 8799, 14000)
LOW_MEMORY_MB = 250             # 检查期间宿主机可用内存低于这个数，单独标出来
# 沙箱服务在本机：不走环境变量里的代理
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))

results = []


def record(name, passed, detail=""):
    results.append((name, bool(passed), detail))
    print(f"{'PASS' if passed else 'FAIL'}  {name}" + (f"：{detail}" if detail else ""), flush=True)


def note(name, detail):
    """只报告、不计入通过与否的观测值（内存占用、/tmp 实际能写多少）。"""
    print(f"INFO  {name}：{detail}", flush=True)


def read_token(env_file):
    token = os.environ.get("SANDBOX_TOKEN", "").strip()
    if token or not env_file:
        return token
    try:
        with open(env_file, encoding="utf-8") as handle:
            for line in handle:
                key, _, value = line.strip().partition("=")
                if key == "SANDBOX_TOKEN":
                    return value.strip().strip("'\"")
    except OSError:
        pass
    return ""


class Client:
    def __init__(self, url, token):
        self.url, self.token = url.rstrip("/"), token

    def post(self, payload, token=None, timeout=120):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        headers = {"Content-Type": "application/json", "X-Sandbox-Caller": "security_check"}
        if token is None:
            token = self.token
        if token:
            headers["X-Sandbox-Token"] = token
        request = urllib.request.Request(self.url + "/run", body, headers)
        try:
            with OPENER.open(request, timeout=timeout) as response:
                return response.status, json.load(response)
        except urllib.error.HTTPError as exc:
            with exc:
                try:
                    return exc.code, json.load(exc)
                except ValueError:
                    return exc.code, {}

    def run(self, code, files=None):
        status, result = self.post({"code": code, "files": files or []})
        if status != 200:
            raise RuntimeError(f"HTTP {status}：{result.get('error')}")
        return result

    def health(self):
        with OPENER.open(self.url + "/health", timeout=10) as response:
            return json.load(response)


def docker(*args, timeout=30):
    try:
        done = subprocess.run(["docker", *args], capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError):
        return ""
    return done.stdout.strip() if done.returncode == 0 else ""


def running_containers():
    """宿主机上此刻在跑的容器（沙箱自己的除外）：名字 -> 启动时间和重启次数。跑完再比一次，看有没有被重启。"""
    names = [n for n in docker("ps", "--format", "{{.Names}}").split() if not n.startswith("doc2sop-sbx-")]
    return {name: docker("inspect", "--format", "{{.State.StartedAt}} {{.RestartCount}}", name) for name in names}


def last_json(text):
    for line in reversed((text or "").strip().splitlines()):
        try:
            return json.loads(line)
        except ValueError:
            continue
    return None


def host_ips():
    out = subprocess.run(["hostname", "-I"], capture_output=True, text=True).stdout.split()
    return [ip for ip in out if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", ip)]


# --- 用例 ---------------------------------------------------------------------------------

def check_api(client):
    code = "print('hi')"
    status, _ = client.post({"code": code}, token="")
    record("接口：不带令牌是 401", status == 401, f"HTTP {status}")
    status, _ = client.post({"code": code}, token="x" * 40)
    record("接口：令牌不对是 401", status == 401, f"HTTP {status}")
    for extra in ({"image": "alpine"}, {"runtime": "runc"}, {"network": "host"}, {"privileged": True},
                  {"args": ["--privileged"]}, {"env": {"A": "1"}}):
        status, body = client.post({"code": code, **extra})
        record(f"接口：夹带 {next(iter(extra))} 被拒", status == 400, f"HTTP {status} {body.get('error', '')[:60]}")
    status, _ = client.post({"code": code, "files": [{"name": "../escape", "content": "x"}]})
    record("接口：文件名带路径被拒", status == 400, f"HTTP {status}")


NETWORK = r'''
import json, socket, urllib.request
targets = json.load(open("/data/targets.json"))
out = {}
for host, port in targets:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(3)
    try:
        s.connect((host, port))
        out[f"{host}:{port}"] = "CONNECTED"
    except Exception as exc:
        out[f"{host}:{port}"] = type(exc).__name__
    finally:
        s.close()
for name in ("pypi.tuna.tsinghua.edu.cn", "www.baidu.com", "storage.googleapis.com"):
    try:
        socket.getaddrinfo(name, 443)
        out["dns " + name] = "RESOLVED"
    except Exception as exc:
        out["dns " + name] = type(exc).__name__
try:
    urllib.request.urlopen("http://www.baidu.com/", timeout=3)
    out["http"] = "FETCHED"
except Exception as exc:
    out["http"] = type(exc).__name__
try:
    out["interfaces"] = [name for _, name in socket.if_nameindex()]
except Exception as exc:
    out["interfaces"] = type(exc).__name__
print(json.dumps(out))
'''


def check_network(client):
    targets = [["1.1.1.1", 443], ["114.114.114.114", 53], ["223.5.5.5", 53], ["169.254.169.254", 80],
               ["100.100.100.200", 80], ["172.17.0.1", 14000], ["172.17.0.1", 8765]]
    targets += [["127.0.0.1", port] for port in LOCAL_PORTS]
    targets += [[ip, port] for ip in host_ips() for port in (8765, 22)]
    result = client.run(NETWORK, [{"name": "targets.json", "content": json.dumps(targets)}])
    seen = last_json(result["stdout"]) or {}
    leaked = {k: v for k, v in seen.items() if v in ("CONNECTED", "RESOLVED", "FETCHED")}
    record("断网：外网、宿主机端口、网关、云元数据、DNS、HTTP 全部失败",
           bool(seen) and not leaked and result["status"] == "ok",
           f"{len(seen) - 1} 项都失败；网卡 {seen.get('interfaces')}" if seen and not leaked
           else f"连上了 {leaked}" if leaked else f"没跑成：{result['status']} {result['stderr'][-200:]}")


FILES = r'''
import json, os
out = {}
for path in ("/", "/etc", "/usr", "/usr/local/lib/python3.12/site-packages", "/var/tmp", "/root", "/home",
             "/data", "/dev", "/run", "/sys", "/proc", "/dev/shm"):
    target = os.path.join(path, "sbx-write-test")
    try:
        with open(target, "w") as handle:
            handle.write("x")
        out[path] = "WRITABLE"
        os.remove(target)
    except Exception as exc:
        out[path] = type(exc).__name__
try:
    with open("/tmp/ok", "w") as handle:
        handle.write("x")
    out["/tmp"] = "ok"
except Exception as exc:
    out["/tmp"] = "FAIL " + type(exc).__name__
written = 0
try:
    with open("/tmp/fill", "wb") as handle:
        for _ in range(64):
            handle.write(b"\0" * (1024 * 1024))
            handle.flush()
            written += 1
except Exception as exc:
    out["tmp_fill_error"] = type(exc).__name__
out["tmp_written_mb"] = written
host = {}
for path in ("/opt/kb-app/.env", "/etc/ops-readonly.env", "/etc/doc2sop-sandbox.env", "/var/run/docker.sock",
             "/run/docker.sock", "/run/containerd/containerd.sock", "/var/lib/docker", "/opt/doc2sop", "/opt/ops",
             "/root/.ssh", "/var/lib/doc2sop-sandbox", "/proc/1/root/opt/kb-app/.env"):
    host[path] = os.path.exists(path)
out["host_paths"] = host
out["passwd_is_host"] = "litellm-tunnel" in open("/etc/passwd").read()
out["hostname"] = open("/etc/hostname").read().strip()
out["data"] = sorted(os.listdir("/data"))
print(json.dumps(out))
'''


def check_files(client):
    result = client.run(FILES, [{"name": "only-this-run.txt", "content": "x"}])
    seen = last_json(result["stdout"]) or {}
    # /dev/shm 不是根文件系统：--ipc none 时 docker 不挂它；gVisor 若自己给一个，也是沙箱内存里的 tmpfs，用完即弃，只报告
    writable = [k for k, v in seen.items() if v == "WRITABLE" and k != "/dev/shm"]
    record("文件：根文件系统、/data 等都写不进去", bool(seen) and not writable,
           f"可写：{writable}" if writable else "")
    note("/dev/shm", "可写（沙箱内存里的 tmpfs，算在 256MB 里）" if seen.get("/dev/shm") == "WRITABLE"
         else f"写不进去（{seen.get('/dev/shm')}）")
    record("文件：/tmp 能写（唯一的临时工作目录）", seen.get("/tmp") == "ok", f"/tmp={seen.get('/tmp')}")
    note("/tmp 的上限（tmpfs size=16m；超出的部分也算在 256MB 内存里）",
         f"写到 {seen.get('tmp_written_mb')}MB 时 {seen.get('tmp_fill_error') or '没有报错'}")
    exposed = [k for k, v in (seen.get("host_paths") or {}).items() if v]
    record("文件：读不到宿主机上的文件", bool(seen) and not exposed and not seen.get("passwd_is_host"),
           f"看得见：{exposed}" if exposed else f"/etc/passwd 是宿主机的" if seen.get("passwd_is_host") else "")
    record("文件：/data 里只有这次请求带的文件", seen.get("data") == ["only-this-run.txt"], f"{seen.get('data')}")


IDENTITY = r'''
import ctypes, json, os
status = open("/proc/self/status").read()
fields = {line.split(":")[0]: line.split(":", 1)[1].strip() for line in status.splitlines()
          if line.startswith(("Cap", "NoNewPrivs"))}
try:
    nnp = ctypes.CDLL(None, use_errno=True).prctl(39, 0, 0, 0, 0)    # PR_GET_NO_NEW_PRIVS
except Exception as exc:
    nnp = type(exc).__name__
# 不靠 /proc 的说法，直接试三件要 capability 的事（CAP_SETUID、CAP_CHOWN、CAP_SETGID）：都该失败。
# 不试绑低端口：docker 默认把容器里的 ip_unprivileged_port_start 设成 0，那一条不说明有没有 capability
tries = {}
for label, action in (("setuid0", lambda: os.setuid(0)),
                      ("chown", lambda: (open("/tmp/c", "w").close(), os.chown("/tmp/c", 0, 0))),
                      ("setgroups", lambda: os.setgroups([0]))):
    try:
        action()
        tries[label] = "ALLOWED"
    except Exception as exc:
        tries[label] = type(exc).__name__
try:
    init_env = open("/proc/1/environ", "rb").read().decode("utf-8", "replace").split("\0")
except OSError as exc:
    init_env = ["(读不到 /proc/1/environ：" + type(exc).__name__ + ")"]
print(json.dumps({"uid": os.getuid(), "gid": os.getgid(), "groups": os.getgroups(), "status": fields,
                  "no_new_privs": nnp, "tries": tries, "env": dict(os.environ),
                  "init_env": [e for e in init_env if e]}))
'''


def check_identity(client, token):
    result = client.run(IDENTITY)
    seen = last_json(result["stdout"]) or {}
    status = seen.get("status") or {}
    caps = {k: v for k, v in status.items() if k.startswith("Cap") and k != "CapAmb"}
    tries = seen.get("tries") or {}
    no_caps = all(int(v, 16) == 0 for v in caps.values()) and bool(tries) and "ALLOWED" not in tries.values()
    record("身份：nobody（65534），没有 capability，NoNewPrivs",
           seen.get("uid") == 65534 and seen.get("gid") == 65534 and seen.get("no_new_privs") == 1 and no_caps,
           f"uid={seen.get('uid')} gid={seen.get('gid')} no_new_privs={seen.get('no_new_privs')} {caps} {tries}")
    env = seen.get("env") or {}
    text = json.dumps(seen.get("env")) + json.dumps(seen.get("init_env"))
    secretish = [k for k in env if re.search(r"TOKEN|KEY|SECRET|PASS|AUTH|CRED", k, re.I)]
    record("环境变量：只有 PATH、LANG、HOME，没有凭据",
           bool(env) and set(env) <= {"PATH", "LANG", "HOME", "LC_CTYPE"} and not secretish
           and (not token or token not in text),
           f"{sorted(env)}")


def check_runtime(client, monitor):
    """跑一段要几秒的代码，趁它在跑查容器：runtime、各项限制、cgroup 里实际生效的上限、内存。"""
    holder = {}

    def slow():
        holder["result"] = client.run("import time\ntime.sleep(6)\nprint(open('/proc/version').read().strip())")

    thread = threading.Thread(target=slow)
    thread.start()
    name, inspected, limits = "", "", {}
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline and thread.is_alive():
        if not name:
            name = docker("ps", "--filter", f"label={LABEL}", "--format", "{{.Names}}").split("\n")[0]
            if name:
                inspected = docker("inspect", "--format", "{{json .HostConfig}}", name)
        path = monitor.cgroups.get(name, "") if name else ""
        if path and not limits:
            limits = {key: cgroup_text(path, key) for key in ("memory.max", "memory.swap.max", "pids.max", "cpu.max")}
        time.sleep(0.2)
    thread.join()
    config = json.loads(inspected) if inspected else {}
    expected = {"Runtime": "runsc", "NetworkMode": "none", "ReadonlyRootfs": True, "Privileged": False,
                "Memory": 256 * 1024 * 1024, "MemorySwap": 256 * 1024 * 1024, "NanoCpus": 10 ** 9,
                "PidsLimit": 128, "CapDrop": ["ALL"], "SecurityOpt": ["no-new-privileges"], "IpcMode": "none",
                "OomScoreAdj": 1000, "Tmpfs": {"/tmp": "rw,nosuid,nodev,noexec,size=16m,mode=1777"}}
    wrong = {k: config.get(k) for k, v in expected.items() if config.get(k) != v}
    if (config.get("LogConfig") or {}).get("Type") != "none":
        wrong["LogConfig"] = config.get("LogConfig")
    mounts = config.get("Mounts") or []
    if [(m.get("Target"), m.get("ReadOnly")) for m in mounts] != [("/data", True)]:
        wrong["Mounts"] = mounts
    record("隔离：容器的 runtime 是 runsc，各项限制都加上了", bool(config) and not wrong,
           f"容器 {name}" if config and not wrong else f"不对：{wrong}" if config else "没赶上查到容器")
    host_kernel = open("/proc/version").read().strip()
    inside = (holder.get("result") or {}).get("stdout", "").strip()
    record("隔离：容器里看到的内核不是宿主机的（gVisor）", bool(inside) and inside != host_kernel, inside[:80])
    note("cgroup 里实际生效的上限", f"{monitor.cgroups.get(name) or '没找到 cgroup'} {limits}")
    note("内存（一次普通执行）", f"容器 cgroup 峰值 {monitor.peaks.get(name, {}).get('memory', '?')}MB"
                          f"（含 gVisor 自身，上限 256MB），pids 峰值 {monitor.peaks.get(name, {}).get('pids', '?')}")


def available_mb():
    with open("/proc/meminfo") as handle:
        for line in handle:
            if line.startswith("MemAvailable:"):
                return int(line.split()[1]) // 1024
    return 0


def cgroup_text(path, name):
    try:
        with open(os.path.join(path, name)) as handle:
            return handle.read().strip()
    except OSError:
        return ""


def cgroup_number(path, name):
    try:
        return int(cgroup_text(path, name))
    except ValueError:
        return 0


def cgroup_dir(pid):
    """一个宿主机进程所在的 cgroup v2 目录（/proc/<pid>/cgroup 的「0::」那行）；不猜 docker-<id>.scope 这种路径。"""
    if not str(pid).isdigit() or int(pid) <= 0:
        return ""
    try:
        with open(f"/proc/{int(pid)}/cgroup") as handle:
            for line in handle:
                if line.startswith("0::"):
                    return "/sys/fs/cgroup" + line[3:].strip()
    except OSError:
        pass
    return ""


class Monitor(threading.Thread):
    """整个检查期间：每 0.1 秒记一次宿主机可用内存的最低值；每 0.3 秒找一次新起的沙箱容器，
    记下它 cgroup 的内存峰值和 pids 峰值（memory.peak / pids.peak 本身就是峰值，容器退出前读到就准）。"""

    def __init__(self):
        super().__init__(daemon=True)
        self.done = threading.Event()
        self.baseline = self.lowest = available_mb()
        self.cgroups = {}       # 容器名 -> cgroup 目录（找不到是 ""），按发现的先后
        self.peaks = {}         # 容器名 -> {"memory": MB, "pids": 个}

    def run(self):
        tick = 0
        while not self.done.is_set():
            self.lowest = min(self.lowest, available_mb())
            if tick % 3 == 0:
                for name in docker("ps", "--filter", f"label={LABEL}", "--format", "{{.Names}}").split():
                    if name not in self.cgroups:
                        self.cgroups[name] = cgroup_dir(docker("inspect", "--format", "{{.State.Pid}}", name))
            for name, path in list(self.cgroups.items()):
                memory = max(cgroup_number(path, "memory.peak"), cgroup_number(path, "memory.current")) if path else 0
                if memory:
                    peak = self.peaks.setdefault(name, {"memory": 0, "pids": 0})
                    peak["memory"] = max(peak["memory"], memory // (1024 * 1024))
                    peak["pids"] = max(peak["pids"], cgroup_number(path, "pids.peak"),
                                       cgroup_number(path, "pids.current"))
            tick += 1
            self.done.wait(0.1)

    def mark(self):
        return len(self.cgroups)

    def since(self, mark):
        """mark 之后新起的容器的峰值，按起的先后。"""
        return [(name, self.peaks.get(name)) for name in list(self.cgroups)[mark:]]

    def stop(self):
        self.done.set()
        self.join(timeout=5)


def check_isolation_between_runs(client):
    marker = "MARKER-" + os.urandom(8).hex()
    first = client.run("import os; print(sorted(os.listdir('/data')))", [{"name": "secret.txt", "content": marker}])
    leftover = os.listdir(RUNS_DIR) if os.path.isdir(RUNS_DIR) else []
    second = client.run(
        "import os\nfound = []\nfor root in ('/data', '/tmp'):\n    for d, _, fs in os.walk(root):\n"
        "        for f in fs:\n            p = os.path.join(d, f)\n"
        f"            if '{marker}' in open(p, errors='ignore').read(): found.append(p)\n"
        "print(sorted(os.listdir('/data')), found)")
    record("文件：读不到别的执行的数据",
           "secret.txt" in first["stdout"] and second["stdout"].strip() == "[] []" and not leftover,
           f"第二次看到 {second['stdout'].strip()}；第一次跑完宿主机上的临时目录 {leftover or '已删'}")


BOMBS = {
    "fork 炸弹": "import os\nwhile True:\n    try:\n        os.fork()\n    except OSError:\n        pass\n",
    "内存炸弹": "blocks = []\nwhile True:\n    blocks.append(b'\\x01' * (16 * 1024 * 1024))\n"
              "    print(len(blocks) * 16, flush=True)\n",
    "死循环": "while True:\n    pass\n",
    "超大输出": "import sys\nwhile True:\n    sys.stdout.write('x' * 65536)\n",
}


def check_bombs(client, monitor):
    for label, code in BOMBS.items():
        started = time.monotonic()
        mark = monitor.mark()
        try:
            result = client.run(code)
        except Exception as exc:
            record(f"资源：{label}按上限收手", False, str(exc)[:200])
            continue
        elapsed = time.monotonic() - started
        status = result["status"]
        if label == "内存炸弹":
            numbers = [int(x) for x in re.findall(r"^\d+$", result["stdout"], re.M)]
            peak = max(numbers, default=0)
            ok = status in ("oom", "killed", "error") and peak <= 256
            detail = f"{status}，最多分配到 {peak}MB"
        elif label == "超大输出":
            ok = status == "output_limit" and result["stdout_truncated"] and len(result["stdout"]) <= 32 * 1024
            detail = f"{status}，留下 {len(result['stdout'])} 字"
        elif label == "死循环":
            ok = status == "timeout" and 19 <= result["duration_ms"] / 1000 <= 35
            detail = f"{status}，{result['duration_ms'] / 1000:.1f} 秒"
        else:
            ok = status != "ok" and elapsed <= 60
            detail = f"{status}，{elapsed:.1f} 秒"
        seen = monitor.since(mark)
        healthy = client.run("print(1 + 1)")["stdout"].strip() == "2"
        record(f"资源：{label}按上限收手，之后沙箱照常可用", ok and healthy, detail)
        if seen and seen[0][1]:
            note(f"{label}的容器 cgroup 峰值", f"内存 {seen[0][1]['memory']}MB，pids {seen[0][1]['pids']}")


def check_concurrency(client):
    """按服务此刻的配置（并发、排队秒数、排队上限）同时发一批：至少并发数个跑成，多出来的说明「沙箱正忙」被拒。"""
    health = client.health()
    concurrency = int(health.get("concurrency") or 1)
    queue_max = int((health.get("limits") or {}).get("queue_max") or 4)
    outcomes = []

    def one():
        status, body = client.post({"code": "import time\ntime.sleep(3)\nprint('ok')"})
        outcomes.append((status, body.get("error", "")))

    threads = [threading.Thread(target=one) for _ in range(concurrency + queue_max + 2)]
    for thread in threads:
        thread.start()
        time.sleep(0.1)
    for thread in threads:
        thread.join()
    statuses = sorted(status for status, _ in outcomes)
    busy = [error for status, error in outcomes if status == 429]
    record("并发：满了排队、排满了拒绝并说明原因",
           statuses.count(200) >= concurrency and bool(busy) and all("沙箱正忙" in e for e in busy)
           and set(statuses) <= {200, 429},
           f"并发 {concurrency}、排队上限 {queue_max}，同时来 {len(threads)} 个：{statuses}")


def check_cleanup():
    containers = docker("ps", "-aq", "--filter", f"label={LABEL}")
    dirs = os.listdir(RUNS_DIR) if os.path.isdir(RUNS_DIR) else []
    record("清理：没有残留的容器和临时目录", not containers and not dirs,
           f"容器 {containers.split() or '无'}，临时目录 {dirs or '无'}")


def main():
    parser = argparse.ArgumentParser(description="计算沙箱的真实环境安全用例")
    parser.add_argument("--url", default="http://127.0.0.1:8797")
    parser.add_argument("--env-file", default="/etc/doc2sop-sandbox.env")
    args = parser.parse_args()
    token = read_token(args.env_file)
    if not token:
        print("错误：拿不到 SANDBOX_TOKEN（环境变量或 --env-file）", file=sys.stderr)
        return 2
    client = Client(args.url, token)
    try:
        print(f"沙箱服务：{json.dumps(client.health(), ensure_ascii=False)}", flush=True)
    except Exception as exc:
        print(f"错误：连不上沙箱服务 {args.url}：{exc}", file=sys.stderr)
        return 2
    before = running_containers()
    monitor = Monitor()
    monitor.start()
    for case in (lambda: check_api(client), lambda: check_network(client), lambda: check_files(client),
                 lambda: check_identity(client, token), lambda: check_runtime(client, monitor),
                 lambda: check_isolation_between_runs(client), lambda: check_bombs(client, monitor),
                 lambda: check_concurrency(client)):
        try:
            case()
        except Exception as exc:
            record("用例本身出错", False, f"{exc.__class__.__name__}: {exc}")
    time.sleep(1)
    monitor.stop()
    check_cleanup()
    after = running_containers()
    changed = {name: (was, after.get(name)) for name, was in before.items() if after.get(name) != was}
    record("宿主机：跑之前在跑的容器都没被重启（应用容器 kb-app 在其中）", PRODUCTION in before and not changed,
           f"{len(before)} 个容器：{', '.join(sorted(before))}" if not changed else f"变了：{changed}")
    peaks = [p["memory"] for p in monitor.peaks.values() if p]
    note("内存（整个检查期间）",
         f"宿主机可用内存基线 {monitor.baseline}MB，最低 {monitor.lowest}MB；"
         f"沙箱容器 cgroup 峰值最高 {max(peaks, default='?')}MB（读到 {len(peaks)}/{len(monitor.cgroups)} 个容器）")
    if monitor.lowest < LOW_MEMORY_MB:
        print(f"WARN  检查期间宿主机可用内存最低 {monitor.lowest}MB，低于 {LOW_MEMORY_MB}MB", flush=True)
    failed = [name for name, passed, _ in results if not passed]
    print(f"\n{len(results) - len(failed)} 通过 / {len(failed)} 失败", flush=True)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
