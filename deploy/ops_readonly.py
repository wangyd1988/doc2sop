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
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MAX_OUTPUT = 20000      # characters returned to the agent
TIMEOUT = 20            # seconds per command

# Argument validators. Anything not matching is refused before reaching argv.
NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,120}$")
K8S_NAME = re.compile(r"^[a-z0-9][a-z0-9.-]{0,120}$")
RESOURCE = re.compile(r"^[a-z][a-z0-9.-]{0,40}$")


# 配置里只能引用这些预置正则，不能自带正则：一个 ".*" 就能把白名单废掉。
PATTERNS = {"name": NAME, "k8s_name": K8S_NAME, "resource": RESOURCE}

# argv 元素必须"整个"是 {参数名} 才算占位符，不做片段拼接。
# 这样 docker 的 "{{.Names}}" 之类模板不会被误伤，参数值也永远独占一个 argv 项。
PLACEHOLDER = re.compile(r"^\{([a-z_][a-z0-9_]*)\}$")
TOOL_NAME = re.compile(r"^[a-z][a-z0-9_]{0,40}$")

DEFAULT_CONFIG = Path(__file__).resolve().parent / "ops_tools.yaml"

# Refuse these even if a template somehow produced them.
FORBIDDEN = {"exec", "attach", "cp", "rm", "rmi", "kill", "stop", "start", "restart",
             "run", "create", "delete", "apply", "patch", "edit", "scale", "drain",
             "cordon", "taint", "set", "replace", "port-forward", "proxy"}


class ConfigError(ValueError):
    """A tool definition is malformed; that tool is skipped, not fatal."""


def _check_param(tool, key, raw):
    if not isinstance(raw, dict):
        raise ConfigError(f"{tool}.params.{key} 必须是映射")
    kind = str(raw.get("type", "str"))
    if kind not in ("str", "int"):
        raise ConfigError(f"{tool}.params.{key}.type 只能是 str 或 int")
    spec = {"type": kind, "desc": str(raw.get("desc", "")),
            "required": bool(raw.get("required", False))}
    if kind == "int":
        try:
            spec["default"] = int(raw.get("default", 100))
            spec["min"] = int(raw.get("min", 1))
            spec["max"] = int(raw.get("max", 10000))
        except (TypeError, ValueError):
            raise ConfigError(f"{tool}.params.{key} 的 default/min/max 必须是整数") from None
        if not spec["min"] <= spec["default"] <= spec["max"]:
            raise ConfigError(f"{tool}.params.{key} 的默认值不在 min..max 之间")
        return spec

    pattern = raw.get("pattern")
    if pattern not in PATTERNS:
        raise ConfigError(
            f"{tool}.params.{key}.pattern 必须是 {'、'.join(PATTERNS)} 之一")
    spec["pattern"] = pattern
    if not spec["required"]:
        # 非必填就得有个合法默认值，否则运行时会往 argv 里塞空串。
        default = str(raw.get("default", ""))
        if not PATTERNS[pattern].match(default):
            raise ConfigError(f"{tool}.params.{key} 非必填，就必须给一个合法的 default")
        spec["default"] = default
    return spec


def _check_tool(raw):
    """Validate one entry. Everything that could widen privilege is checked here."""
    if not isinstance(raw, dict):
        raise ConfigError("每个工具必须是映射")
    name = str(raw.get("name", "")).strip()
    if not TOOL_NAME.match(name):
        raise ConfigError(f"工具名不合法：{name[:40]!r}")
    binary = str(raw.get("binary", "")).strip()
    if not binary:
        raise ConfigError(f"{name} 缺少 binary")

    argv = raw.get("argv")
    if not isinstance(argv, list) or not argv:
        raise ConfigError(f"{name}.argv 必须是非空列表")
    argv = [str(part) for part in argv]

    params = {}
    for key, value in (raw.get("params") or {}).items():
        key = str(key)
        if not TOOL_NAME.match(key):
            raise ConfigError(f"{name} 的参数名不合法：{key[:40]!r}")
        params[key] = _check_param(name, key, value)

    if argv[0] != binary:
        raise ConfigError(f"{name}.argv 的第一项必须就是 binary（{binary}）")
    for part in argv:
        found = PLACEHOLDER.match(part)
        if found and found.group(1) not in params:
            raise ConfigError(f"{name}.argv 用到了未声明的参数 {found.group(1)}")
    for part in argv[1:]:
        if not PLACEHOLDER.match(part) and part in FORBIDDEN:
            raise ConfigError(f"{name}.argv 含写操作动词 {part}")

    return {"name": name, "desc": str(raw.get("desc", "")).strip(),
            "binary": binary, "argv": argv, "params": params,
            "enabled": bool(raw.get("enabled", True))}


def load_tools(path):
    """Parse the definition file. A bad entry is skipped; a bad file raises."""
    try:
        import yaml
    except ImportError:
        raise ConfigError("需要 PyYAML：apt install python3-yaml") from None
    try:
        with open(path, encoding="utf-8") as handle:
            document = yaml.safe_load(handle) or {}
    except Exception as exc:
        raise ConfigError(f"配置读取失败：{exc}") from None
    entries = document.get("tools") if isinstance(document, dict) else None
    if not isinstance(entries, list):
        raise ConfigError("配置里缺少 tools 列表")

    tools, problems = {}, []
    for entry in entries:
        try:
            spec = _check_tool(entry)
        except ConfigError as exc:
            problems.append(str(exc))
            continue
        if spec["name"] in tools:
            problems.append(f"工具名重复：{spec['name']}")
            continue
        tools[spec["name"]] = spec
    return tools, problems


_state = {"path": DEFAULT_CONFIG, "mtime": None, "tools": {}, "problems": []}


def refresh(force=False):
    """Reload when the file changed, so adding a tool needs no restart.

    A broken edit must not take the service down: we keep the last good set.
    """
    path = _state["path"]
    try:
        mtime = os.stat(path).st_mtime
    except OSError as exc:
        if not _state["tools"]:
            _state["problems"] = [f"读不到配置文件 {path}：{exc}"]
        return _state["tools"]
    if not force and mtime == _state["mtime"]:
        return _state["tools"]

    try:
        tools, problems = load_tools(path)
    except ConfigError as exc:
        _state["problems"] = [str(exc)]
        print(f"[config] 加载失败，沿用上一版（{len(_state['tools'])} 个）：{exc}", flush=True)
        return _state["tools"]

    _state.update(mtime=mtime, tools=tools, problems=problems)
    for problem in problems:
        print(f"[config] 跳过一个工具：{problem}", flush=True)
    print(f"[config] 已加载 {len(tools)} 个工具定义", flush=True)
    return tools


def all_tools():
    return refresh()


def available_tools():
    """Only advertise enabled tools whose binary actually exists on this host."""
    return {name: {"desc": spec["desc"], "params": spec["params"]}
            for name, spec in all_tools().items()
            if spec["enabled"] and shutil.which(spec["binary"])}


def _value(key, spec, args):
    supplied = args.get(key)
    if spec["type"] == "int":
        try:
            number = int(supplied)
        except (TypeError, ValueError):
            number = spec["default"]
        return str(max(spec["min"], min(number, spec["max"])))

    text = str(supplied if supplied is not None else "").strip()
    if not text:
        if spec["required"]:
            raise ValueError(f"缺少必填参数：{key}")
        return spec["default"]
    if not PATTERNS[spec["pattern"]].match(text):
        raise ValueError(f"参数 {key} 不合法：{text[:40]!r}")
    return text


def build_argv(spec, args):
    """Fill the fixed template. Each value lands in its own argv slot."""
    args = args or {}
    values = {key: _value(key, param, args) for key, param in spec["params"].items()}
    argv = []
    for part in spec["argv"]:
        found = PLACEHOLDER.match(part)
        argv.append(values[found.group(1)] if found else part)
    return argv


def run_tool(name, args):
    spec = all_tools().get(name)
    if spec is None or not spec["enabled"]:
        return {"ok": False, "error": f"未知工具：{name}"}

    # 先校验参数再看本机有没有这个命令：不可信输入是安全边界，要最先挡掉。
    try:
        argv = build_argv(spec, args)
    except ValueError as exc:
        return {"ok": False, "error": str(exc)}

    # Defence in depth: the template is fixed, but verify anyway.
    if any(part in FORBIDDEN for part in argv[1:]):
        return {"ok": False, "error": "拒绝执行：命中写操作黑名单"}

    if not shutil.which(spec["binary"]):
        return {"ok": False, "error": f"本机没有 {spec['binary']}，该工具不可用"}

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
    parser.add_argument("--config", default=str(DEFAULT_CONFIG),
                        help="Tool definitions; edits are picked up live.")
    parser.add_argument("--host", default="127.0.0.1",
                        help="Loopback by default; do not expose this publicly.")
    args = parser.parse_args()

    token = os.environ.get("OPS_TOKEN", "").strip()
    if not token:
        print("错误：必须设置环境变量 OPS_TOKEN", file=sys.stderr)
        return 1
    Handler.token = token
    _state["path"] = Path(args.config)

    tools = available_tools()
    print(f"只读运维接口启动于 {args.host}:{args.port}")
    print(f"可用工具 {len(tools)} 个：{', '.join(sorted(tools))}")
    missing = sorted(set(all_tools()) - set(tools))
    if missing:
        print(f"（本机缺少对应命令，暂不可用：{', '.join(missing)}）")
    ThreadingHTTPServer((args.host, args.port), Handler).serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
