#!/usr/bin/env python3
"""Read-only ops endpoint.

The agent must never get a shell. It can only name a tool and supply typed
arguments; this service maps that to a fixed argv template and runs it with no
shell involved. Anything not on the allowlist is refused.

Runs on the host (it needs docker/kubectl), binds loopback only, and requires a
shared token. Standard library only, so it runs on any box with Python 3.9+.

    OPS_TOKEN=... python ops_readonly.py --port 8799
"""
import argparse
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MAX_OUTPUT = 20000      # characters returned to the agent
TIMEOUT = 20            # seconds per command

# Argument validators. Anything not matching is refused before reaching argv.
NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,120}$")
K8S_NAME = re.compile(r"^[a-z0-9][a-z0-9.-]{0,120}$")
RESOURCE = re.compile(r"^[a-z][a-z0-9.-]{0,40}$")


def _lines(value, default=100, cap=500):
    try:
        number = int(value)
    except (TypeError, ValueError):
        return default
    return max(1, min(number, cap))


def _name(value, pattern=NAME):
    value = str(value or "").strip()
    if not pattern.match(value):
        raise ValueError(f"参数不合法：{value[:40]!r}")
    return value


# tool name -> (描述, 需要的可执行文件, 构造 argv 的函数)
TOOLS = {
    "list_containers": (
        "列出所有容器及其状态",
        "docker",
        lambda a: ["docker", "ps", "-a", "--no-trunc", "--format",
                   "{{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}"]),
    "container_logs": (
        "查看指定容器最近的日志",
        "docker",
        lambda a: ["docker", "logs", "--tail", str(_lines(a.get("lines"))),
                   _name(a.get("name"))]),
    "container_stats": (
        "查看容器的 CPU 与内存占用",
        "docker",
        lambda a: ["docker", "stats", "--no-stream", "--format",
                   "{{.Name}}\tCPU={{.CPUPerc}}\tMEM={{.MemUsage}} ({{.MemPerc}})"]),
    "container_inspect": (
        "查看容器的配置：镜像、资源限制、挂载、重启策略",
        "docker",
        lambda a: ["docker", "inspect", "--format",
                   "镜像={{.Config.Image}}\n状态={{.State.Status}}\n"
                   "重启次数={{.RestartCount}}\n内存上限={{.HostConfig.Memory}}\n"
                   "网络={{.HostConfig.NetworkMode}}\n"
                   "挂载={{range .Mounts}}{{.Source}}->{{.Destination}} {{end}}",
                   _name(a.get("name"))]),
    "host_resources": (
        "查看宿主机的内存、磁盘与负载",
        "free",
        lambda a: ["free", "-m"]),
    "kube_get": (
        "查询 Kubernetes 资源列表或单个资源的 YAML",
        "kubectl",
        lambda a: ["kubectl", "get", _name(a.get("resource"), RESOURCE)]
                  + ([_name(a.get("name"), K8S_NAME)] if a.get("name") else [])
                  + ["-n", _name(a.get("namespace", "default"), K8S_NAME)]
                  + (["-o", "yaml"] if a.get("name") else ["-o", "wide"])),
    "kube_describe": (
        "查看 Kubernetes 资源的详情与事件",
        "kubectl",
        lambda a: ["kubectl", "describe", _name(a.get("resource"), RESOURCE),
                   _name(a.get("name"), K8S_NAME),
                   "-n", _name(a.get("namespace", "default"), K8S_NAME)]),
    "kube_logs": (
        "查看 Pod 日志",
        "kubectl",
        lambda a: ["kubectl", "logs", _name(a.get("name"), K8S_NAME),
                   "-n", _name(a.get("namespace", "default"), K8S_NAME),
                   "--tail", str(_lines(a.get("lines")))]),
    "kube_events": (
        "按时间查看命名空间下的最近事件",
        "kubectl",
        lambda a: ["kubectl", "get", "events",
                   "-n", _name(a.get("namespace", "default"), K8S_NAME),
                   "--sort-by=.lastTimestamp"]),
}

# Refuse these even if a template somehow produced them.
FORBIDDEN = {"exec", "attach", "cp", "rm", "rmi", "kill", "stop", "start", "restart",
             "run", "create", "delete", "apply", "patch", "edit", "scale", "drain",
             "cordon", "taint", "set", "replace", "port-forward", "proxy"}


def available_tools():
    """Only advertise tools whose binary actually exists on this host."""
    return {name: meta[0] for name, meta in TOOLS.items() if shutil.which(meta[1])}


def run_tool(name, args):
    if name not in TOOLS:
        return {"ok": False, "error": f"未知工具：{name}"}
    _description, binary, build = TOOLS[name]

    # 先校验参数再看本机有没有这个命令：不可信输入是安全边界，要最先挡掉。
    try:
        argv = build(args or {})
    except ValueError as exc:
        return {"ok": False, "error": str(exc)}

    # Defence in depth: the template is fixed, but verify anyway.
    if any(part in FORBIDDEN for part in argv[1:]):
        return {"ok": False, "error": "拒绝执行：命中写操作黑名单"}

    if not shutil.which(binary):
        return {"ok": False, "error": f"本机没有 {binary}，该工具不可用"}

    try:
        done = subprocess.run(argv, capture_output=True, text=True,
                              timeout=TIMEOUT, shell=False)
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": f"执行超时（{TIMEOUT}s）", "command": " ".join(argv)}
    except Exception as exc:
        return {"ok": False, "error": f"{exc.__class__.__name__}: {exc}"}

    output = (done.stdout or done.stderr or "").strip()
    truncated = len(output) > MAX_OUTPUT
    return {"ok": done.returncode == 0, "command": " ".join(argv),
            "output": output[:MAX_OUTPUT] + ("\n…（输出已截断）" if truncated else ""),
            "exit_code": done.returncode}


class Handler(BaseHTTPRequestHandler):
    token = ""

    def _send(self, status, payload):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _authorised(self):
        supplied = self.headers.get("X-Ops-Token", "")
        return secrets.compare_digest(supplied, self.token)

    def do_GET(self):
        if self.path == "/health":
            return self._send(200, {"status": "ok", "tools": sorted(available_tools())})
        if self.path == "/tools":
            if not self._authorised():
                return self._send(401, {"error": "令牌无效"})
            return self._send(200, {"tools": available_tools()})
        self._send(404, {"error": "Not found"})

    def do_POST(self):
        if self.path != "/exec":
            return self._send(404, {"error": "Not found"})
        if not self._authorised():
            return self._send(401, {"error": "令牌无效"})
        try:
            length = int(self.headers.get("Content-Length", "0"))
            payload = json.loads(self.rfile.read(length)) if length else {}
        except (ValueError, UnicodeDecodeError):
            return self._send(400, {"error": "请求体不是合法 JSON"})

        name = payload.get("tool")
        result = run_tool(name, payload.get("args"))
        print(f"[exec] {name} args={payload.get('args')} ok={result.get('ok')}", flush=True)
        self._send(200, result)

    def log_message(self, *args):
        pass


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8799)
    parser.add_argument("--host", default="127.0.0.1",
                        help="Loopback by default; do not expose this publicly.")
    args = parser.parse_args()

    token = os.environ.get("OPS_TOKEN", "").strip()
    if not token:
        print("错误：必须设置环境变量 OPS_TOKEN", file=sys.stderr)
        return 1
    Handler.token = token

    tools = available_tools()
    print(f"只读运维接口启动于 {args.host}:{args.port}")
    print(f"可用工具 {len(tools)} 个：{', '.join(sorted(tools))}")
    missing = sorted(set(TOOLS) - set(tools))
    if missing:
        print(f"（本机缺少对应命令，暂不可用：{', '.join(missing)}）")
    ThreadingHTTPServer((args.host, args.port), Handler).serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
