#!/usr/bin/env python3
"""计算沙箱的真实环境安全用例：在装好 gVisor、起好沙箱服务的宿主机上，以 root 身份对着真实的服务跑一遍。

    python3 security_check.py [--url http://127.0.0.1:8797] [--env-file /etc/doc2sop-sandbox.env]

全部通过才退出 0。有一条没过就退出 1——按 docs/正式部署.md「计算沙箱」的规矩：先撤掉沙箱，再回报。
令牌从环境变量 SANDBOX_TOKEN 或 --env-file 里读，不打印。

    接口      不带令牌、令牌不对都是 401；夹带 docker 参数、文件名带路径都是 400，一个容器都不起
    断网      连外网（IP 直连、域名、HTTP）、连宿主机上的应用 8765、工具服务 8799、沙箱服务 8797、模型网关隧道 14000、
              docker 网关、云元数据、宿主机自己的 IP，DNS 解析，全部失败
    文件      根文件系统、/data、/dev/shm、/run 等都写不进去，只有 /tmp 能写（实际能写多少另外报出来）；
              读不到宿主机上的文件（.env、docker.sock、/var/lib/docker）；读不到别的执行的数据
    身份      nobody、没有任何 capability、NoNewPrivs；环境变量只有 PATH、LANG、HOME，没有凭据
    资源      fork 炸弹、内存炸弹、死循环、超大输出都按上限收手；跑完宿主机上的生产容器没被重启
    隔离      容器的 runtime 是 runsc，各项限制确实加上了；容器里看到的内核不是宿主机的
    并发      满了排队；排队的也满了就 429
    清理      跑完没有残留的容器和临时目录
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
PRODUCTION = ("kb-app", "demo-app", "demo-ops")
LOCAL_PORTS = (8765, 8766, 8797, 8799, 14000)

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
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return response.status, json.load(response)
        except urllib.error.HTTPError as exc:
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
        with urllib.request.urlopen(self.url + "/health", timeout=10) as response:
            return json.load(response)


def docker(*args, timeout=30):
    done = subprocess.run(["docker", *args], capture_output=True, text=True, timeout=timeout)
    return done.stdout.strip() if done.returncode == 0 else ""


def started_at(names):
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
             "/data", "/dev", "/dev/shm", "/run", "/sys", "/proc"):
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
    writable = [k for k, v in seen.items() if v == "WRITABLE"]
    record("文件：根文件系统、/data、/dev/shm 等都写不进去", bool(seen) and not writable,
           f"可写：{writable}" if writable else "")
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
init_env = open("/proc/1/environ", "rb").read().decode("utf-8", "replace").split("\0")
print(json.dumps({"uid": os.getuid(), "gid": os.getgid(), "groups": os.getgroups(), "status": fields,
                  "no_new_privs": nnp, "env": dict(os.environ), "init_env": [e for e in init_env if e]}))
'''


def check_identity(client, token):
    result = client.run(IDENTITY)
    seen = last_json(result["stdout"]) or {}
    status = seen.get("status") or {}
    caps = {k: v for k, v in status.items() if k.startswith("Cap") and k != "CapAmb"}
    record("身份：nobody（65534），没有 capability，NoNewPrivs",
           seen.get("uid") == 65534 and seen.get("gid") == 65534 and seen.get("no_new_privs") == 1
           and bool(caps) and all(int(v, 16) == 0 for v in caps.values()),
           f"uid={seen.get('uid')} gid={seen.get('gid')} no_new_privs={seen.get('no_new_privs')} {caps}")
    env = seen.get("env") or {}
    text = json.dumps(seen.get("env")) + json.dumps(seen.get("init_env"))
    secretish = [k for k in env if re.search(r"TOKEN|KEY|SECRET|PASS|AUTH|CRED", k, re.I)]
    record("环境变量：只有 PATH、LANG、HOME，没有凭据",
           set(env) <= {"PATH", "LANG", "HOME"} and not secretish and (not token or token not in text),
           f"{sorted(env)}")


KERNEL = "print(open('/proc/version').read().strip())"


def check_runtime(client):
    """跑一段要几秒的代码，趁它在跑查容器：runtime、各项限制；顺便量一下内存。"""
    holder = {}

    def slow():
        holder["result"] = client.run("import time\ntime.sleep(6)\nprint(open('/proc/version').read().strip())")

    thread = threading.Thread(target=slow)
    baseline = available_mb()
    thread.start()
    name, inspected, scope, lowest, peak = "", "", "", baseline, 0
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline and thread.is_alive():
        lowest = min(lowest, available_mb())
        if not name:
            name = docker("ps", "--filter", f"label={LABEL}", "--format", "{{.Names}}").split("\n")[0]
            if name:
                inspected = docker("inspect", "--format", "{{json .HostConfig}}", name)
                scope = f"/sys/fs/cgroup/system.slice/docker-{docker('inspect', '--format', '{{.Id}}', name)}.scope"
        if scope:
            peak = max(peak, cgroup_mb(scope, "memory.peak"), cgroup_mb(scope, "memory.current"))
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
    note("内存（一次空跑）", f"宿主机可用内存最多少了 {max(0, baseline - lowest)}MB（基线 {baseline}MB）；"
                        f"容器 cgroup 峰值 {peak or '?'}MB（含 gVisor 自身，上限 256MB）")


def available_mb():
    with open("/proc/meminfo") as handle:
        for line in handle:
            if line.startswith("MemAvailable:"):
                return int(line.split()[1]) // 1024
    return 0


def cgroup_mb(scope, name):
    try:
        with open(os.path.join(scope, name)) as handle:
            return int(handle.read().strip()) // (1024 * 1024)
    except (OSError, ValueError):
        return 0


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


def check_bombs(client):
    for label, code in BOMBS.items():
        started = time.monotonic()
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
        healthy = client.run("print(1 + 1)")["stdout"].strip() == "2"
        record(f"资源：{label}按上限收手，之后沙箱照常可用", ok and healthy, detail)


def check_concurrency(client):
    health = client.health()
    if health.get("concurrency") != 1:
        record("并发：满了排队、排满了拒绝", False, f"这条用例按并发 1 写的，现在是 {health.get('concurrency')}")
        return
    outcomes = []

    def one():
        status, body = client.post({"code": "import time\ntime.sleep(3)\nprint('ok')"})
        outcomes.append((status, body.get("error", "")))

    threads = [threading.Thread(target=one) for _ in range(6)]
    for thread in threads:
        thread.start()
        time.sleep(0.1)
    for thread in threads:
        thread.join()
    statuses = sorted(status for status, _ in outcomes)
    busy = [error for status, error in outcomes if status == 429]
    record("并发：满了排队、排满了拒绝",
           statuses.count(200) >= 2 and busy and all("沙箱正忙" in e for e in busy) and set(statuses) <= {200, 429},
           f"6 个同时来：{statuses}")


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
    before = started_at(PRODUCTION)
    for case in (lambda: check_api(client), lambda: check_network(client), lambda: check_files(client),
                 lambda: check_identity(client, token), lambda: check_runtime(client),
                 lambda: check_isolation_between_runs(client), lambda: check_bombs(client),
                 lambda: check_concurrency(client)):
        try:
            case()
        except Exception as exc:
            record("用例本身出错", False, f"{exc.__class__.__name__}: {exc}")
    time.sleep(1)
    check_cleanup()
    after = started_at(PRODUCTION)
    record("宿主机：生产容器没有被重启", before == after and all(before.values()),
           "; ".join(f"{k} {v}" for k, v in after.items()))
    failed = [name for name, passed, _ in results if not passed]
    print(f"\n{len(results) - len(failed)} 通过 / {len(failed)} 失败", flush=True)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
