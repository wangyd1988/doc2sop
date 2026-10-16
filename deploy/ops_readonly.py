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
import difflib
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import textwrap
import time
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
MAX_LABEL = 40

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
        raise ConfigError(
            f"工具名不合法：{name[:40]!r}。它会作为函数名发给模型，"
            f"按 function calling 的规范只能用小写字母、数字和下划线，不能用中文；"
            f"中文名请写在 label 字段里，界面会显示它。")
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

    return {"name": name, "label": str(raw.get("label", "")).strip()[:MAX_LABEL],
            "desc": str(raw.get("desc", "")).strip(),
            "binary": binary, "argv": argv, "params": params,
            "enabled": bool(raw.get("enabled", True))}


def _yaml():
    try:
        import yaml
    except ImportError:
        raise ConfigError("需要 PyYAML：apt install python3-yaml") from None
    return yaml


def _read_yaml(path):
    """Read a yaml mapping. A missing file is simply empty."""
    try:
        with open(path, encoding="utf-8") as handle:
            document = _yaml().safe_load(handle) or {}
    except FileNotFoundError:
        return {}
    except Exception as exc:
        raise ConfigError(f"读取失败 {path}：{exc}") from None
    if not isinstance(document, dict):
        raise ConfigError(f"{path} 的顶层必须是映射")
    return document


def _write_yaml(path, document):
    """Write atomically, so an interrupted write can't leave half a file."""
    temporary = f"{path}.tmp"
    with open(temporary, "w", encoding="utf-8") as handle:
        _yaml().safe_dump(document, handle, allow_unicode=True, sort_keys=False)
    os.replace(temporary, path)


def _sibling(kind):
    """The two files the web UI may write, next to the main one.

    The main file stays hand-written and root-owned — it is the only place a
    command can be defined, and the UI never touches it.
    """
    path = Path(_state["path"])
    return path.with_name(f"{path.stem}.{kind}{path.suffix}")


def load_tools(path):
    """Parse the definition file. A bad entry is skipped; a bad file raises."""
    entries = _read_yaml(path).get("tools")
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


# 覆盖层只允许改这几个字段：一个是开关（缩权方向），两个是给人和模型看的文字。
# 它们都不改变实际执行的命令，所以覆盖层即使被完全写坏也无法提权。
OVERRIDABLE = ("enabled", "desc", "label")
MAX_DESC = 300


def load_overrides():
    entries = _read_yaml(_sibling("overrides")).get("overrides")
    if not isinstance(entries, dict):
        return {}
    clean = {}
    for name, patch in entries.items():
        if not isinstance(patch, dict):
            continue
        kept = {}
        if "enabled" in patch:
            kept["enabled"] = bool(patch["enabled"])
        if "desc" in patch:
            kept["desc"] = str(patch["desc"]).strip()[:MAX_DESC]
        if "label" in patch:
            kept["label"] = str(patch["label"]).strip()[:MAX_LABEL]
        if kept:
            clean[str(name)] = kept
    return clean


def _apply_overrides(tools, overrides):
    for name, patch in overrides.items():
        spec = tools.get(name)
        if spec is None:
            continue
        spec.update(patch)
        spec["overridden"] = sorted(patch)
    return tools


_state = {"path": DEFAULT_CONFIG, "mtime": None, "omtime": None,
          "tools": {}, "problems": []}


def _mtimes():
    def stamp(path):
        try:
            return os.stat(path).st_mtime
        except OSError:
            return None

    return stamp(_state["path"]), stamp(_sibling("overrides"))


def refresh(force=False):
    """Reload when either file changed, so adding a tool needs no restart.

    A broken edit must not take the service down: we keep the last good set.
    """
    mtime, omtime = _mtimes()
    if mtime is None:
        if not _state["tools"]:
            _state["problems"] = [f"读不到配置文件 {_state['path']}"]
        return _state["tools"]
    if not force and (mtime, omtime) == (_state["mtime"], _state["omtime"]):
        return _state["tools"]

    try:
        tools, problems = load_tools(_state["path"])
    except ConfigError as exc:
        _state["problems"] = [str(exc)]
        print(f"[config] 加载失败，沿用上一版（{len(_state['tools'])} 个）：{exc}", flush=True)
        return _state["tools"]
    try:
        overrides = load_overrides()
    except ConfigError as exc:
        overrides = {}
        problems = problems + [f"覆盖层已忽略：{exc}"]

    _state.update(mtime=mtime, omtime=omtime, problems=problems,
                  tools=_apply_overrides(tools, overrides))
    for problem in problems:
        print(f"[config] {problem}", flush=True)
    print(f"[config] 已加载 {len(tools)} 个工具定义，"
          f"{len(overrides)} 个被页面覆盖", flush=True)
    return _state["tools"]


def all_tools():
    return refresh()


def available_tools():
    """Only advertise enabled tools whose binary actually exists on this host."""
    return {name: {"desc": spec["desc"], "params": spec["params"]}
            for name, spec in all_tools().items()
            if spec["enabled"] and shutil.which(spec["binary"])}


def describe_tools():
    """Everything the UI needs in order to show what the agent can really run."""
    return {name: {"desc": spec["desc"], "params": spec["params"],
                   "label": spec.get("label", ""),
                   "binary": spec["binary"],
                   "command": " ".join(spec["argv"]),
                   "enabled": spec["enabled"],
                   "runnable": bool(shutil.which(spec["binary"])),
                   "overridden": spec.get("overridden", [])}
            for name, spec in all_tools().items()}


def set_override(name, enabled=None, desc=None, label=None):
    """The only change the web UI may make to a live tool."""
    if name not in all_tools():
        raise ConfigError(f"未知工具：{name}")
    patch = dict((_read_yaml(_sibling("overrides")).get("overrides") or {}).get(name) or {})
    if enabled is not None:
        patch["enabled"] = bool(enabled)
    if desc is not None:
        text = str(desc).strip()
        if not 1 <= len(text) <= MAX_DESC:
            raise ConfigError(f"描述长度需在 1..{MAX_DESC} 之间")
        patch["desc"] = text
    if label is not None:
        text = str(label).strip()
        if len(text) > MAX_LABEL:
            raise ConfigError(f"显示名不能超过 {MAX_LABEL} 个字")
        patch["label"] = text
    if not patch:
        raise ConfigError("没有要修改的字段")

    entries = _read_yaml(_sibling("overrides")).get("overrides")
    entries = entries if isinstance(entries, dict) else {}
    entries[name] = {key: patch[key] for key in OVERRIDABLE if key in patch}
    _write_yaml(_sibling("overrides"), {"overrides": entries})
    refresh(force=True)
    return describe_tools()[name]


def reset_override(name):
    """Drop the UI's changes and fall back to the hand-written definition."""
    entries = _read_yaml(_sibling("overrides")).get("overrides")
    if isinstance(entries, dict) and entries.pop(name, None) is not None:
        _write_yaml(_sibling("overrides"), {"overrides": entries})
        refresh(force=True)
    return describe_tools().get(name)


def list_pending():
    entries = _read_yaml(_sibling("pending")).get("pending")
    return entries if isinstance(entries, list) else []


def suggest_binaries(wanted, limit=3):
    """Commands on PATH that look like the one they typed.

    Turns a blunt "no such command" into "did you mean date?", which is the
    difference between a usable form and a guessing game.
    """
    wanted = str(wanted or "").strip()
    if not wanted:
        return []
    names = set()
    for directory in os.environ.get("PATH", "").split(os.pathsep):
        if not directory:
            continue
        try:
            names.update(os.listdir(directory))
        except OSError:
            continue
    names.discard(wanted)
    # 先看是不是多写了后缀（datetime -> date），再退回模糊匹配。
    prefix = sorted((n for n in names if len(n) >= 3 and wanted.startswith(n)),
                    key=len, reverse=True)
    fuzzy = difflib.get_close_matches(wanted, names, n=limit * 2, cutoff=0.6)
    return (prefix + [n for n in fuzzy if n not in prefix])[:limit]


def propose_tool(raw, author="web"):
    """Queue a new tool for review. Proposals are never loaded as usable tools."""
    spec = _check_tool(raw)  # 当场校验，让申请人立刻看到问题
    if spec["name"] in all_tools():
        raise ConfigError(f"已存在同名工具：{spec['name']}")
    if not shutil.which(spec["binary"]):
        # 批准之后才发现跑不了，是最差的体验：现在就说清楚，并给出替代。
        hint = suggest_binaries(spec["binary"])
        raise ConfigError(
            f"本机没有 {spec['binary']} 这个命令"
            + (f"，你是不是想用 {hint[0]}？" if hint else "。")
            + (f"（相近的还有：{'、'.join(hint[1:])}）" if len(hint) > 1 else "")
            + " 申请的工具必须现在就能跑；若要装好再用，请直接写进配置文件。")
    entries = list_pending()
    if any((item.get("tool") or {}).get("name") == spec["name"] for item in entries):
        raise ConfigError(f"已有同名待审申请：{spec['name']}")
    if len(entries) >= 50:
        raise ConfigError("待审队列已满，请先在宿主机上处理")

    item = {"id": secrets.token_hex(4),
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "author": str(author)[:40], "tool": raw}
    entries.append(item)
    _write_yaml(_sibling("pending"), {"pending": entries})
    return item


def _find_pending(ident):
    for item in list_pending():
        if item.get("id") == ident or (item.get("tool") or {}).get("name") == ident:
            return item
    raise ConfigError(f"找不到待审申请：{ident}")


def drop_pending(ident):
    item = _find_pending(ident)
    _write_yaml(_sibling("pending"),
                {"pending": [i for i in list_pending() if i.get("id") != item["id"]]})
    return item


def approve_pending(ident):
    """Append an approved tool to the main file. Only runs on the host."""
    item = _find_pending(ident)
    spec = _check_tool(item.get("tool") or {})  # 再校验一次，文件可能被改过
    if spec["name"] in all_tools():
        raise ConfigError(f"已存在同名工具：{spec['name']}")
    block = _yaml().safe_dump([item["tool"]], allow_unicode=True,
                              sort_keys=False, default_flow_style=None)
    with open(_state["path"], "a", encoding="utf-8") as handle:
        handle.write("\n" + textwrap.indent(block, "  "))
    drop_pending(item["id"])
    refresh(force=True)
    return spec


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
        if not self._authorised():
            return self._send(401, {"error": "令牌无效"})
        if self.path == "/tools":
            return self._send(200, {"tools": available_tools()})
        if self.path == "/tools/full":
            return self._send(200, {"tools": describe_tools(),
                                    "pending": len(list_pending())})
        if self.path == "/tools/pending":
            return self._send(200, {"pending": list_pending()})
        self._send(404, {"error": "Not found"})

    def do_POST(self):
        if self.path not in ("/exec", "/tools/override", "/tools/propose"):
            return self._send(404, {"error": "Not found"})
        if not self._authorised():
            return self._send(401, {"error": "令牌无效"})
        try:
            length = int(self.headers.get("Content-Length", "0"))
            payload = json.loads(self.rfile.read(length)) if length else {}
        except (ValueError, UnicodeDecodeError):
            return self._send(400, {"error": "请求体不是合法 JSON"})
        if not isinstance(payload, dict):
            return self._send(400, {"error": "请求体必须是对象"})

        if self.path == "/tools/override":
            return self._override(payload)
        if self.path == "/tools/propose":
            return self._propose(payload)

        name = payload.get("tool")
        result = run_tool(name, payload.get("args"))
        print(f"[exec] {name} args={payload.get('args')} ok={result.get('ok')}", flush=True)
        self._send(200, result)

    def _override(self, payload):
        """Toggle a tool or reword its description. Nothing else is accepted."""
        name = str(payload.get("name", ""))
        try:
            if payload.get("reset"):
                tool = reset_override(name)
                print(f"[override] {name} 恢复为配置文件原值", flush=True)
            else:
                enabled = payload.get("enabled")
                tool = set_override(name,
                                    enabled=None if enabled is None else bool(enabled),
                                    desc=payload.get("desc"),
                                    label=payload.get("label"))
                print(f"[override] {name} enabled={enabled} "
                      f"desc={'改了' if payload.get('desc') else '未改'}", flush=True)
        except ConfigError as exc:
            return self._send(400, {"error": str(exc)})
        return self._send(200, {"tool": tool})

    def _propose(self, payload):
        """Queue a proposal. It stays inert until a human approves it on the host."""
        try:
            item = propose_tool(payload.get("tool") or {},
                                author=str(payload.get("author", "web")))
        except ConfigError as exc:
            return self._send(400, {"error": str(exc)})
        print(f"[propose] 收到新工具申请 {item['id']} "
              f"{(item.get('tool') or {}).get('name')}，待宿主机批准", flush=True)
        return self._send(200, {"pending": item, "total": len(list_pending())})

    def log_message(self, *args):
        pass


def _print_pending():
    items = list_pending()
    if not items:
        print("没有待审申请")
        return 0
    print(f"待审申请 {len(items)} 条：\n")
    for item in items:
        tool = item.get("tool") or {}
        print(f"  [{item.get('id')}] {tool.get('name')}"
              f"    {item.get('author')} 于 {item.get('created_at')} 提交")
        print(f"      说明：{tool.get('desc')}")
        print(f"      命令：{' '.join(str(p) for p in tool.get('argv') or [])}")
        params = tool.get("params") or {}
        if params:
            print(f"      参数：{', '.join(params)}")
        if item.get("reason"):
            print(f"      理由：{item['reason']}")
        print()
    print("批准：ops_readonly.py approve <id>     拒绝：ops_readonly.py reject <id>")
    print("批准前请逐字读一遍「命令」那一行——这是它唯一会执行的东西。")
    return 0


def _cli(command, ident, config):
    """Review proposals from the host. Approving is deliberately not an API."""
    _state["path"] = Path(config)
    if command == "pending":
        return _print_pending()
    if not ident:
        print(f"用法：ops_readonly.py {command} <id>", file=sys.stderr)
        return 2
    try:
        if command == "approve":
            spec = approve_pending(ident)
            print(f"已批准并写入配置：{spec['name']}")
            print(f"  命令：{' '.join(spec['argv'])}")
            print("下一次提问即可使用，无需重启。")
        else:
            item = drop_pending(ident)
            print(f"已拒绝：{(item.get('tool') or {}).get('name')}")
    except ConfigError as exc:
        print(f"失败：{exc}", file=sys.stderr)
        return 1
    return 0


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command", nargs="?", default="serve",
                        choices=["serve", "pending", "approve", "reject"],
                        help="serve 起服务；其余用于在宿主机上审批新工具申请")
    parser.add_argument("ident", nargs="?", help="待审申请的 id 或工具名")
    parser.add_argument("--port", type=int, default=8799)
    parser.add_argument("--config", default=str(DEFAULT_CONFIG),
                        help="Tool definitions; edits are picked up live.")
    parser.add_argument("--host", default="127.0.0.1",
                        help="Loopback by default; do not expose this publicly.")
    args = parser.parse_args()

    if args.command != "serve":
        return _cli(args.command, args.ident, args.config)

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
    waiting = len(list_pending())
    if waiting:
        print(f"（有 {waiting} 条新工具申请待审：ops_readonly.py pending）")
    ThreadingHTTPServer((args.host, args.port), Handler).serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
