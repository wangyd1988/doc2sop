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
import hashlib
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import textwrap
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MAX_OUTPUT = 20000      # characters returned to the agent
TIMEOUT = 20            # seconds per command
HTTP_TIMEOUT = 10       # seconds per HTTP request
MAX_HTTP_BYTES = 512 * 1024

# Argument validators. Anything not matching is refused before reaching argv.
NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,120}$")
K8S_NAME = re.compile(r"^[a-z0-9][a-z0-9.-]{0,120}$")
RESOURCE = re.compile(r"^[a-z][a-z0-9.-]{0,40}$")
DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


# 配置里只能引用这些预置正则，不能自带正则：一个 ".*" 就能把白名单废掉。
PATTERNS = {"name": NAME, "k8s_name": K8S_NAME, "resource": RESOURCE, "date": DATE}

# 接口型工具的凭据只能来自宿主机环境变量，且必须以这个前缀命名：
# 这样即便配置写得马虎，也不可能把 OPS_TOKEN 之类的服务自身凭据发到外部接口。
SECRET_PREFIX = "OPS_SECRET_"
SECRET_REF = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")
URL_PARAM = re.compile(r"\{([a-z_][a-z0-9_]*)\}")
HEADER_NAME = re.compile(r"^[A-Za-z0-9-]{1,60}$")
QUERY_KEY = re.compile(r"^[A-Za-z0-9_.-]{1,60}$")
PICK_PATH = re.compile(r"^[A-Za-z0-9_]+(\[\])?(\.[A-Za-z0-9_]+(\[\])?)*$")
GROUP_MAX = 20

# argv 元素必须"整个"是 {参数名} 才算占位符，不做片段拼接。
# 这样 docker 的 "{{.Names}}" 之类模板不会被误伤，参数值也永远独占一个 argv 项。
PLACEHOLDER = re.compile(r"^\{([a-z_][a-z0-9_]*)\}$")
TOOL_NAME = re.compile(r"^[a-z][a-z0-9_]{0,40}$")
# 脚本只能是 scripts 目录下的文件名，不能带路径，自然就跳不出目录。
SCRIPT_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,80}$")
MAX_LABEL = 40

DEFAULT_CONFIG = Path(__file__).resolve().parent / "ops_tools.yaml"

# 这些 binary 本身就能"执行另一段命令"，一旦允许，固定 argv 的前提就没了：
# bash -c "任意" 、env FOO=x 任意、xargs 任意、find -exec 任意……
# 所以普通工具不许用它们当 binary。要跑脚本，走下面的脚本型工具（哈希锁定）。
INTERPRETERS = {
    "bash", "sh", "dash", "zsh", "ksh", "csh", "tcsh", "fish", "rbash", "ash",
    "python", "python2", "python3", "perl", "ruby", "node", "nodejs", "php",
    "lua", "luajit", "tclsh", "expect", "rscript",
    "awk", "gawk", "mawk", "nawk", "sed",
    "env", "xargs", "find", "watch", "timeout", "nohup", "stdbuf", "setsid",
    "unshare", "chroot", "flock", "nice", "ionice", "parallel", "script",
    "ssh", "sshpass", "scp", "rsync", "socat", "ncat", "nc",
    "eval", "exec", "command", "source", "make", "sudo", "su", "doas",
}

# Refuse these even if a template somehow produced them.
FORBIDDEN = {"exec", "attach", "cp", "rm", "rmi", "kill", "stop", "start", "restart",
             "run", "create", "delete", "apply", "patch", "edit", "scale", "drain",
             "cordon", "taint", "set", "replace", "port-forward", "proxy"}


def _scripts_dir():
    """Where approved shell scripts live, next to the config. Root-owned."""
    return Path(_state["path"]).parent / "scripts"


def _hash_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


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


def _check_script_tool(raw, name):
    """脚本型工具：页面不定义脚本内容，只引用 scripts 目录里已有的脚本。

    脚本文件只能由宿主机 root 放进去；页面和申请都只能"选一个已有脚本"，
    碰不到它的内容。这和「文档自动生成工具」的区别就在这里——那是上传代码，
    这是引用一份审过的代码。内容是否被改动，由哈希在加载和执行时各校验一次。
    """
    script = str(raw.get("script", "")).strip()
    if not SCRIPT_NAME.match(script) or ".." in script:
        raise ConfigError(f"脚本名不合法：{script[:40]!r}，只能是 scripts 目录下的文件名，"
                          f"不能带路径")
    path = _scripts_dir() / script
    if not path.is_file():
        raise ConfigError(f"scripts 目录下找不到脚本 {script}")
    if not os.access(path, os.X_OK):
        raise ConfigError(f"脚本 {script} 没有执行权限，先在宿主机上 chmod +x")
    return {"name": name, "label": str(raw.get("label", "")).strip()[:MAX_LABEL],
            "desc": str(raw.get("desc", "")).strip(),
            "binary": str(path), "argv": [str(path)], "params": {},
            "enabled": bool(raw.get("enabled", True)),
            "type": "script", "script": script}


def _common(raw, name):
    """Fields every tool type shares: what humans and the model read about it."""
    return {"name": name, "label": str(raw.get("label", "")).strip()[:MAX_LABEL],
            "desc": str(raw.get("desc", "")).strip(),
            "group": str(raw.get("group", "")).strip()[:GROUP_MAX],
            "enabled": bool(raw.get("enabled", True))}


def _check_params(name, raw):
    params = {}
    for key, value in (raw.get("params") or {}).items():
        key = str(key)
        if not TOOL_NAME.match(key):
            raise ConfigError(f"{name} 的参数名不合法：{key[:40]!r}")
        params[key] = _check_param(name, key, value)
    return params


def _check_secret_refs(name, text):
    for ref in SECRET_REF.findall(text):
        if not ref.startswith(SECRET_PREFIX):
            raise ConfigError(f"{name} 引用了环境变量 {ref}；接口凭据必须以 {SECRET_PREFIX} 开头，"
                              f"以免把服务自身的令牌发到外部")


def _check_http_tool(raw, name):
    """接口型工具：只读 GET，主机名固定，参数只能落在路径段或查询参数的值里。

    和命令型工具同一个思路——模型只能填空，不能改"去哪儿、怎么调"：
      · 主机名在配置里写死（或来自宿主机环境变量），参数进不了主机名
      · 参数值一律 URL 编码，拼不出新的路径或查询
      · 请求头只能由管理员写，模型参数进不了请求头
      · 不跟随重定向，避免被带到别的主机
    """
    http = raw.get("http")
    if not isinstance(http, dict):
        raise ConfigError(f"{name}.http 必须是映射")
    method = str(http.get("method", "GET")).upper()
    if method != "GET":
        raise ConfigError(f"{name} 只允许 GET 请求，当前为 {method}")
    params = _check_params(name, raw)

    url = str(http.get("url", "")).strip()
    env_base = re.match(r"^\$\{([A-Za-z_][A-Za-z0-9_]*)\}(.*)$", url)
    if env_base:
        rest = env_base.group(2)
    else:
        literal = re.match(r"^https?://([^/?#]+)(.*)$", url)
        if not literal:
            raise ConfigError(f"{name}.http.url 必须以 http:// 或 https:// 开头")
        if re.search(r"[{}$]", literal.group(1)):
            raise ConfigError(f"{name}.http.url 的主机名部分不能包含参数或变量")
        rest = literal.group(2)
    if rest and not rest.startswith("/"):
        raise ConfigError(f"{name}.http.url 主机名后面必须直接是路径（以 / 开头）")
    if "?" in rest or "#" in rest:
        raise ConfigError(f"{name}.http.url 里不能直接写查询串，请写在 http.query 里")
    for found in URL_PARAM.findall(rest):
        if found not in params:
            raise ConfigError(f"{name}.http.url 用到了未声明的参数 {found}")
    if re.search(r"[{}$]", URL_PARAM.sub("", rest)):
        raise ConfigError(f"{name}.http.url 的路径里有无法识别的花括号或 $ 符号")
    _check_secret_refs(name, url)

    query = {}
    for key, value in (http.get("query") or {}).items():
        key, value = str(key), str(value)
        if not QUERY_KEY.match(key):
            raise ConfigError(f"{name}.http.query 的键名不合法：{key[:40]!r}")
        whole_param = PLACEHOLDER.match(value)
        if whole_param and whole_param.group(1) not in params:
            raise ConfigError(f"{name}.http.query 用到了未声明的参数 {whole_param.group(1)}")
        if not whole_param and URL_PARAM.search(value):
            raise ConfigError(f"{name}.http.query 的值要么是固定值，要么整个是 {{参数名}}")
        _check_secret_refs(name, value)
        query[key] = value

    headers = {}
    for key, value in (http.get("headers") or {}).items():
        key, value = str(key), str(value)
        if not HEADER_NAME.match(key):
            raise ConfigError(f"{name}.http.headers 的名字不合法：{key[:40]!r}")
        if URL_PARAM.search(SECRET_REF.sub("", value)):
            raise ConfigError(f"{name} 的请求头 {key} 不能使用模型参数，"
                              f"只能写固定值或 ${{{SECRET_PREFIX}...}}")
        _check_secret_refs(name, value)
        headers[key] = value

    pick = [str(p) for p in (http.get("pick") or [])]
    for path in pick:
        if not PICK_PATH.match(path):
            raise ConfigError(f"{name}.http.pick 的路径不合法：{path[:40]!r}")

    return {**_common(raw, name), "type": "http", "binary": "", "argv": [],
            "params": params,
            "http": {"url": url, "query": query, "headers": headers, "pick": pick}}


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

    if raw.get("script"):
        spec = _check_script_tool(raw, name)
        spec["group"] = _common(raw, name)["group"]
        return spec
    if raw.get("http") is not None:
        return _check_http_tool(raw, name)

    binary = str(raw.get("binary", "")).strip()
    if not binary:
        raise ConfigError(f"{name} 缺少 binary")
    if binary.lower() in INTERPRETERS:
        raise ConfigError(
            f"{name} 的 binary 是 {binary}，它能执行任意命令，不能直接作为工具。"
            f"要跑一段脚本，请把脚本放到 scripts 目录，再用 script 字段引用它。")

    argv = raw.get("argv")
    if not isinstance(argv, list) or not argv:
        raise ConfigError(f"{name}.argv 必须是非空列表")
    argv = [str(part) for part in argv]
    params = _check_params(name, raw)

    if argv[0] != binary:
        raise ConfigError(f"{name}.argv 的第一项必须就是 binary（{binary}）")
    for part in argv:
        found = PLACEHOLDER.match(part)
        if found and found.group(1) not in params:
            raise ConfigError(f"{name}.argv 用到了未声明的参数 {found.group(1)}")
    for part in argv[1:]:
        if not PLACEHOLDER.match(part) and part in FORBIDDEN:
            raise ConfigError(f"{name}.argv 含写操作动词 {part}")

    return {**_common(raw, name), "binary": binary, "argv": argv, "params": params,
            "type": "command"}


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


def _trust_file():
    """Approved-script hashes. Root-only; the UI never writes here."""
    return _sibling("trust")


def load_trust():
    data = _read_yaml(_trust_file()).get("trusted")
    return data if isinstance(data, dict) else {}


def trust_script(name):
    """Record the current hash of a script as approved. Only called on the host."""
    digest = _hash_file(_scripts_dir() / name)
    trusted = load_trust()
    trusted[name] = digest
    _write_yaml(_trust_file(), {"trusted": trusted})
    return digest


def _script_untrusted_reason(spec):
    """Why a script tool must not load/run, or None if it is trusted as-is."""
    expected = load_trust().get(spec["script"])
    if not expected:
        return f"脚本 {spec['script']} 还没在宿主机上确认过（trust），暂不生效"
    try:
        actual = _hash_file(Path(spec["binary"]))
    except OSError as exc:
        return f"脚本 {spec['script']} 读取失败：{exc}"
    if actual != expected:
        return f"脚本 {spec['script']} 的内容与登记的不一致，可能被改过，已暂停；"\
               f"确认无误后在宿主机上重新 trust"
    return None


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
        if spec.get("type") == "script":
            reason = _script_untrusted_reason(spec)
            if reason:
                problems.append(reason)
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


_state = {"path": DEFAULT_CONFIG, "mtime": None, "omtime": None, "tmtime": None,
          "tools": {}, "problems": []}


def _mtimes():
    def stamp(path):
        try:
            return os.stat(path).st_mtime
        except OSError:
            return None

    return (stamp(_state["path"]), stamp(_sibling("overrides")),
            stamp(_trust_file()))


def refresh(force=False):
    """Reload when any of the files changed, so changes need no restart.

    A broken edit must not take the service down: we keep the last good set.
    """
    mtime, omtime, tmtime = _mtimes()
    if mtime is None:
        if not _state["tools"]:
            _state["problems"] = [f"读不到配置文件 {_state['path']}"]
        return _state["tools"]
    if not force and (mtime, omtime, tmtime) == (
            _state["mtime"], _state["omtime"], _state["tmtime"]):
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

    _state.update(mtime=mtime, omtime=omtime, tmtime=tmtime, problems=problems,
                  tools=_apply_overrides(tools, overrides))
    for problem in problems:
        print(f"[config] {problem}", flush=True)
    print(f"[config] 已加载 {len(tools)} 个工具定义，"
          f"{len(overrides)} 个被页面覆盖", flush=True)
    return _state["tools"]


def all_tools():
    return refresh()


def _runnable(spec):
    """Command/script tools need their binary here; HTTP tools only need the network."""
    if spec.get("type") == "http":
        return True
    return bool(spec.get("binary") and shutil.which(spec["binary"]))


def _http_display(spec):
    """What the UI and logs show for an HTTP tool. Never includes secret values."""
    http = spec["http"]
    text = "GET " + http["url"]
    if http["query"]:
        text += "?" + "&".join(f"{k}={v}" for k, v in http["query"].items())
    if http["headers"]:
        text += f"  （请求头：{'、'.join(http['headers'])}）"
    return text


def _display(spec):
    if spec.get("type") == "script":
        return "脚本：" + spec["binary"]
    if spec.get("type") == "http":
        return _http_display(spec)
    return " ".join(spec["argv"])


def available_tools():
    """Only advertise enabled tools that can actually run on this host."""
    return {name: {"desc": spec["desc"], "params": spec["params"]}
            for name, spec in all_tools().items()
            if spec["enabled"] and _runnable(spec)}


def describe_tools():
    """Everything the UI needs in order to show what the agent can really run."""
    return {name: {"desc": spec["desc"], "params": spec["params"],
                   "label": spec.get("label", ""),
                   "group": spec.get("group", ""),
                   "binary": spec["binary"],
                   "command": _display(spec),
                   "type": spec.get("type", "command"),
                   "script": spec.get("script", ""),
                   "enabled": spec["enabled"],
                   "runnable": _runnable(spec),
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


MAX_SCRIPT_VIEW = 8000


def list_scripts():
    """Scripts on disk, with trust status and which tool references each.

    The UI shows these so a reviewer can read exactly what a script tool runs.
    """
    directory = _scripts_dir()
    trusted = load_trust()
    used = {spec.get("script"): name for name, spec in all_tools().items()
            if spec.get("type") == "script"}
    out = []
    try:
        names = sorted(p.name for p in directory.iterdir() if p.is_file())
    except OSError:
        names = []
    for script in names:
        path = directory / script
        try:
            body = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            body = f"（读取失败：{exc}）"
        truncated = len(body) > MAX_SCRIPT_VIEW
        current = None
        try:
            current = _hash_file(path)
        except OSError:
            pass
        out.append({"name": script,
                    "executable": os.access(path, os.X_OK),
                    "trusted": bool(trusted.get(script) and trusted[script] == current),
                    "used_by": used.get(script, ""),
                    "content": body[:MAX_SCRIPT_VIEW] + ("\n…（已截断）" if truncated else "")})
    return out


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


def _missing_binary(binary):
    hint = suggest_binaries(binary)
    return (f"本机没有 {binary} 这个命令"
            + (f"，你是不是想用 {hint[0]}？" if hint else "。")
            + (f"（相近的还有：{'、'.join(hint[1:])}）" if len(hint) > 1 else ""))


def propose_tool(raw, author="web"):
    """Queue a new tool for review. Proposals are never loaded as usable tools."""
    # 页面上最常见的两类错误一次说全，别让人改一处、提交、再撞下一处。
    # 措辞用表单上的栏目名，而不是配置文件里的字段名。
    raw = raw if isinstance(raw, dict) else {}
    name = str(raw.get("name", "")).strip()
    binary = str(raw.get("binary", "")).strip()
    problems = []
    if not TOOL_NAME.match(name):
        problems.append(
            f"工具名「{name[:40]}」不能用：它会作为函数名发给模型，只能用小写英文字母、"
            f"数字和下划线，例如 host_time。中文请填在「中文显示名」那一栏。")
    if binary and not shutil.which(binary):
        # 批准之后才发现跑不了，是最差的体验：现在就说清楚，并给出替代。
        problems.append(_missing_binary(binary)
                        + " 申请的工具必须现在就能跑；要先装软件再用，请直接写进配置文件。")
    if problems:
        if len(problems) == 1:
            raise ConfigError(problems[0])
        raise ConfigError("\n".join(f"{i}. {p}" for i, p in enumerate(problems, 1)))

    if raw.get("http") is not None:
        # 页面申请的接口工具不能带凭据：否则一条申请就能把宿主机上的密钥发到任意地址，
        # 只差审批时的一次疏忽。需要鉴权的接口，由管理员直接写进配置文件。
        http = raw.get("http") if isinstance(raw.get("http"), dict) else {}
        if http.get("headers"):
            raise ConfigError("页面申请的接口工具不能设置请求头；需要鉴权的接口请让管理员在宿主机配置")
        if "${" in json.dumps(http, ensure_ascii=False):
            raise ConfigError("页面申请的接口工具不能引用宿主机环境变量")

    spec = _check_tool(raw)  # 其余规则（argv 首项、写动词、占位符）与正式配置一致
    if spec["name"] in all_tools():
        raise ConfigError(f"已存在同名工具：{spec['name']}")
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
    if spec.get("type") == "script":
        # 批准脚本 = 认可此刻的脚本内容，把它的哈希登记为可信。
        trust_script(spec["script"])
    current = _read_yaml(_state["path"]).get("tools")
    if isinstance(current, list) and current:
        # 文件里已有条目：直接在末尾追加，保留手写的注释与格式。
        block = _yaml().safe_dump([item["tool"]], allow_unicode=True,
                                  sort_keys=False, default_flow_style=None)
        with open(_state["path"], "a", encoding="utf-8") as handle:
            handle.write("\n" + textwrap.indent(block, "  "))
    else:
        # 空列表（没有可追加的锚点）：整体重写一份。
        _write_yaml(_state["path"], {"tools": (current or []) + [item["tool"]]})
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


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """接口返回 3xx 时不跟随：主机名是审过的，不能被一次跳转带去别处。"""

    def redirect_request(self, *args, **kwargs):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def _http_get(url, headers):
    """One GET. Returns (status, body_bytes). Isolated so tests can replace it."""
    request = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with _OPENER.open(request, timeout=HTTP_TIMEOUT) as response:
            return response.status, response.read(MAX_HTTP_BYTES + 1)
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(MAX_HTTP_BYTES + 1) if exc.fp else b""


def _secret(name):
    value = os.environ.get(name, "")
    if not name.startswith(SECRET_PREFIX) or not value:
        raise ValueError(f"宿主机没有配置 {name}，该工具暂不可用")
    return value


def _fill_secrets(text, used):
    def replace(match):
        value = _secret(match.group(1))
        used.append(value)
        return value
    return SECRET_REF.sub(replace, text)


def _pick(data, path):
    parts = path.split(".")

    def walk(node, index):
        if index == len(parts):
            return node
        part = parts[index]
        if part.endswith("[]"):
            key = part[:-2]
            node = node.get(key) if key and isinstance(node, dict) else node
            if not isinstance(node, list):
                return None
            return [walk(item, index + 1) for item in node]
        if isinstance(node, dict):
            return walk(node.get(part), index + 1)
        return None

    return walk(data, 0)


def build_request(spec, args):
    """Resolve an HTTP tool to (url, headers, secrets_used). Raises ValueError on bad input."""
    args = args or {}
    values = {key: _value(key, param, args) for key, param in spec["params"].items()}
    http = spec["http"]
    secrets_used = []

    url = http["url"]
    env_base = re.match(r"^\$\{([A-Za-z_][A-Za-z0-9_]*)\}(.*)$", url)
    if env_base:
        base = _secret(env_base.group(1)).rstrip("/")
        secrets_used.append(base)
        if not re.match(r"^https?://[^/?#]+(/[^?#]*)?$", base):
            raise ValueError(f"{env_base.group(1)} 不是合法的 http(s) 地址")
        rest = env_base.group(2)
    else:
        base, rest = "", url
    # 参数值整体做 URL 编码（连 / 也编码），因此只能停留在它所在的那一段里。
    rest = URL_PARAM.sub(lambda m: urllib.parse.quote(values[m.group(1)], safe=""), rest)
    full = base + rest

    query = []
    for key, raw in http["query"].items():
        found = PLACEHOLDER.match(raw)
        query.append((key, values[found.group(1)] if found
                      else _fill_secrets(raw, secrets_used)))
    if query:
        full += "?" + urllib.parse.urlencode(query)

    headers = {"User-Agent": "ops-readonly/1", "Accept": "application/json, */*"}
    for key, raw in http["headers"].items():
        headers[key] = _fill_secrets(raw, secrets_used)
    return full, headers, [s for s in secrets_used if s]


def _scrub(text, secrets_used):
    """Never hand a secret back to the model, even if the API echoes it."""
    for secret in sorted(set(secrets_used), key=len, reverse=True):
        if len(secret) >= 6:
            text = text.replace(secret, "***")
    return text


def _run_http(spec, args):
    try:
        url, headers, secrets_used = build_request(spec, args)
    except ValueError as exc:
        return {"ok": False, "error": str(exc)}
    shown = _scrub(url, secrets_used)
    try:
        status, body = _http_get(url, headers)
    except Exception as exc:
        return {"ok": False, "error": _scrub(f"请求失败：{exc.__class__.__name__}: {exc}",
                                             secrets_used), "command": "GET " + shown}

    text = body[:MAX_HTTP_BYTES].decode("utf-8", errors="replace")
    if spec["http"]["pick"]:
        try:
            data = json.loads(text)
            text = json.dumps({path: _pick(data, path) for path in spec["http"]["pick"]},
                              ensure_ascii=False, indent=1)
        except ValueError:
            pass
    text = _scrub(text.strip(), secrets_used)
    truncated = len(text) > MAX_OUTPUT
    if 300 <= status < 400:
        text = f"接口返回 {status} 跳转，已拒绝跟随（只允许访问配置里写明的主机）"
    return {"ok": 200 <= status < 300, "command": "GET " + shown, "status": status,
            "output": text[:MAX_OUTPUT] + ("\n…（输出已截断）" if truncated else "")}


def run_tool(name, args):
    spec = all_tools().get(name)
    if spec is None or not spec["enabled"]:
        return {"ok": False, "error": f"未知工具：{name}"}

    if spec.get("type") == "http":
        return _run_http(spec, args)

    # 先校验参数再看本机有没有这个命令：不可信输入是安全边界，要最先挡掉。
    try:
        argv = build_argv(spec, args)
    except ValueError as exc:
        return {"ok": False, "error": str(exc)}

    # Defence in depth: the template is fixed, but verify anyway.
    if any(part in FORBIDDEN for part in argv[1:]):
        return {"ok": False, "error": "拒绝执行：命中写操作黑名单"}

    # 脚本型工具：执行前再比一次哈希。配置 mtime 不变也挡得住"脚本被偷换内容"。
    if spec.get("type") == "script":
        reason = _script_untrusted_reason(spec)
        if reason:
            return {"ok": False, "error": reason}

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
        if self.path == "/tools/scripts":
            return self._send(200, {"scripts": list_scripts(),
                                    "directory": str(_scripts_dir())})
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
        if tool.get("script"):
            print(f"      脚本：scripts/{tool['script']}（批准前请逐行读脚本内容）")
        elif isinstance(tool.get("http"), dict):
            http = tool["http"]
            query = "&".join(f"{k}={v}" for k, v in (http.get("query") or {}).items())
            print(f"      接口：GET {http.get('url', '')}{'?' + query if query else ''}")
        else:
            print(f"      命令：{' '.join(str(p) for p in tool.get('argv') or [])}")
        params = tool.get("params") or {}
        if params:
            print(f"      参数：{', '.join(params)}")
        if item.get("reason"):
            print(f"      理由：{item['reason']}")
        print()
    print("批准：ops_readonly.py approve <id>     拒绝：ops_readonly.py reject <id>")
    print("批准前请逐字读一遍「命令」或脚本内容——这是它唯一会执行的东西。")
    return 0


def _print_scripts():
    scripts = list_scripts()
    directory = _scripts_dir()
    if not scripts:
        print(f"{directory} 下还没有脚本。把 .sh 放进去并 chmod +x，再在页面上申请引用它。")
        return 0
    print(f"{directory} 下的脚本：\n")
    for item in scripts:
        marks = []
        marks.append("可执行" if item["executable"] else "没有执行位")
        marks.append("已信任" if item["trusted"] else "未信任")
        if item["used_by"]:
            marks.append(f"被工具 {item['used_by']} 引用")
        print(f"  {item['name']}    （{'，'.join(marks)}）")
    print("\n信任某个脚本的当前内容：ops_readonly.py trust <脚本名>")
    return 0


def _cli(command, ident, config):
    """Review proposals from the host. Approving is deliberately not an API."""
    _state["path"] = Path(config)
    if command == "pending":
        return _print_pending()
    if command == "scripts":
        return _print_scripts()
    if not ident:
        print(f"用法：ops_readonly.py {command} <id>", file=sys.stderr)
        return 2
    try:
        if command == "approve":
            spec = approve_pending(ident)
            print(f"已批准并写入配置：{spec['name']}")
            print(f"  {_display(spec)}")
            print("下一次提问即可使用，无需重启。")
        elif command == "trust":
            if ident not in {s["name"] for s in list_scripts()}:
                raise ConfigError(f"scripts 目录下没有脚本 {ident}")
            digest = trust_script(ident)
            refresh(force=True)
            print(f"已信任脚本 {ident} 的当前内容：{digest[:16]}…")
            print("引用它的工具下一次提问即可使用。")
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
                        choices=["serve", "pending", "approve", "reject",
                                 "scripts", "trust"],
                        help="serve 起服务；其余用于在宿主机上审批工具与脚本")
    parser.add_argument("ident", nargs="?", help="待审申请的 id、工具名或脚本名")
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
