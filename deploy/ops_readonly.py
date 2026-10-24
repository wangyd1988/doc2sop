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
import atexit
import difflib
import glob
import hashlib
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import textwrap
import threading
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

# ---- MCP：第四种工具类型 ----------------------------------------------------
# 工具服务自己当 MCP 客户端（stdio 传输，标准库手写，不引入 SDK——单文件零依赖是这个脚本的卖点）。
# server 由主文件顶层 mcp_servers 声明，它是跑在宿主机上的任意代码，所以只能由 root 手写，
# 页面连申请都不能申请。发现到的工具一律先进 pending，批准前不出现在 /tools、不能执行。
MCP_PROTOCOL = "2025-06-18"     # 本期只用 tools/list、tools/call，各版本一致；接受 server 回复的任何版本
MCP_REFRESH = 600               # 每隔多久重新 tools/list 一次，看看 schema 有没有变
MCP_BACKOFF = (5, 30, 120)      # 连接失败后的重试间隔；三次都失败则标离线，等下一次调用再试
MCP_INIT_TIMEOUT = 30
MCP_SERVER_ID = re.compile(r"^[a-z][a-z0-9_]{0,30}$")
MCP_STDERR_KEEP = 20            # 每个 server 最多保留多少行 stderr 供排错
# 子进程只拿到这些环境变量 + 配置里显式声明的。不继承 OPS_TOKEN 和任何 OPS_SECRET_*：
# server 是第三方代码，它不该知道工具服务自己的凭据。SYSTEMROOT/PATHEXT 是 Windows 起进程的硬需求。
MCP_PASS_ENV = ("PATH", "HOME", "USERPROFILE", "LANG", "LC_ALL", "TEMP", "TMP", "TMPDIR",
                "SYSTEMROOT", "SYSTEMDRIVE", "PATHEXT", "COMSPEC")
# 名字里出现这些词的 MCP 工具，在 pending 里标「名称疑似写操作」。只是提醒审批人，不是拒绝。
MCP_WRITE_WORDS = FORBIDDEN | {"write", "update", "remove", "put", "post", "send", "execute",
                               "insert", "upload", "move", "rename", "modify", "destroy",
                               "purge", "drop", "truncate", "deploy", "install", "uninstall"}


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


def _include_patterns(document):
    """主文件顶层 `include:` 列表里的路径或 glob，原样返回字符串。"""
    entries = document.get("include") or []
    if not isinstance(entries, list):
        raise ConfigError("include 必须是列表")
    return [str(e).strip() for e in entries if str(e).strip()]


def _expand_includes(patterns, base):
    """把 include 模式展开成实际文件：相对路径相对主文件所在目录，支持 glob，按名排序。

    零匹配不致命，只作为 problem 报出来——演示容器里最常见的原因是场景包目录没挂上，
    这句话比「工具列表为空」有用得多。
    """
    files, problems = [], []
    for pattern in patterns:
        full = pattern if os.path.isabs(pattern) else os.path.join(base, pattern)
        matched = sorted(p for p in glob.glob(full) if os.path.isfile(p))
        if not matched:
            problems.append(f"include 没有匹配到文件：{pattern}")
        files.extend(matched)
    return files, problems


def load_tools(path):
    """Parse the definition file. A bad entry is skipped; a bad file raises.

    除了自己的 `tools:`，主文件还可以用顶层 `include:` 引入别的定义文件（例如一个场景包的
    tools.yaml）。被包含的文件和主文件同等可信——它们是管理员亲手写进主文件的路径，所以同样
    只能由宿主机 root 维护；它们自己不能再 include，避免链条越拉越长看不清。
    """
    document = _read_yaml(path)
    entries = document.get("tools")
    if not isinstance(entries, list):
        raise ConfigError("配置里缺少 tools 列表")
    patterns = _include_patterns(document)
    files, problems = _expand_includes(patterns, os.path.dirname(os.path.abspath(str(path))))

    sources = [(str(path), entries)]
    for included in files:
        try:
            sub = _read_yaml(included)
        except ConfigError as exc:
            problems.append(str(exc))
            continue
        if sub.get("include"):
            problems.append(f"{included} 里的 include 已忽略：被包含的文件不能再包含别的文件")
        sub_entries = sub.get("tools")
        if not isinstance(sub_entries, list):
            problems.append(f"{included} 缺少 tools 列表")
            continue
        sources.append((included, sub_entries))

    tools = {}
    for origin, items in sources:
        for entry in items:
            try:
                spec = _check_tool(entry)
            except ConfigError as exc:
                problems.append(str(exc) if origin == str(path) else f"{exc}（{origin}）")
                continue
            if spec["name"] in tools:
                problems.append(f"工具名重复：{spec['name']}"
                                + ("" if origin == str(path) else f"（{origin}，已忽略）"))
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


_state = {"path": DEFAULT_CONFIG, "mtime": None, "omtime": None, "tmtime": None, "imtime": None,
          "includes": [], "tools": {}, "problems": []}


def _mtimes():
    def stamp(path):
        try:
            return os.stat(path).st_mtime
        except OSError:
            return None

    # 被包含的文件按上一次加载记下的模式重新展开：新增一个匹配文件、改动任何一个，都算变化。
    files, _ = _expand_includes(_state["includes"], os.path.dirname(os.path.abspath(str(_state["path"]))))
    return (stamp(_state["path"]), stamp(_sibling("overrides")),
            stamp(_trust_file()), tuple((f, stamp(f)) for f in files))


def refresh(force=False):
    """Reload when any of the files changed, so changes need no restart.

    A broken edit must not take the service down: we keep the last good set.
    """
    mtime, omtime, tmtime, imtime = _mtimes()
    if mtime is None:
        if not _state["tools"]:
            _state["problems"] = [f"读不到配置文件 {_state['path']}"]
        return _state["tools"]
    if not force and (mtime, omtime, tmtime, imtime) == (
            _state["mtime"], _state["omtime"], _state["tmtime"], _state["imtime"]):
        return _state["tools"]

    try:
        tools, problems = load_tools(_state["path"])
        includes = _include_patterns(_read_yaml(_state["path"]))
    except ConfigError as exc:
        _state["problems"] = [str(exc)]
        print(f"[config] 加载失败，沿用上一版（{len(_state['tools'])} 个）：{exc}", flush=True)
        return _state["tools"]
    try:
        overrides = load_overrides()
    except ConfigError as exc:
        overrides = {}
        problems = problems + [f"覆盖层已忽略：{exc}"]

    _state.update(mtime=mtime, omtime=omtime, tmtime=tmtime, includes=includes, problems=problems,
                  tools=_apply_overrides(tools, overrides))
    # 模式列表可能刚变，用它重新算一次被包含文件的印章，下一次请求才不会白白重载
    _state["imtime"] = _mtimes()[3]
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


def _form_wording(message, name):
    """校验器的措辞面向配置文件（argv、params.x.pattern）；页面上没有这些字段名，换成栏目名。"""
    swaps = [
        (re.compile(rf"^{re.escape(name)}\.argv 用到了未声明的参数 (\S+)$"),
         r"命令里用了参数 {\1}，请在下方「参数」里把它的类型填好"),
        (re.compile(rf"^{re.escape(name)}\.http\.(?:url|query) 用到了未声明的参数 (\S+)$"),
         r"接口地址里用了参数 {\1}，请在下方「参数」里把它的类型填好"),
        (re.compile(rf"^{re.escape(name)}\.argv 含写操作动词 (\S+)$"),
         r"命令含写操作动词 \1：页面只能申请只读命令，写操作不开放给模型"),
        (re.compile(rf"^{re.escape(name)}\.params\.(\S+?) 非必填，就必须给一个合法的 default$"),
         r"参数 \1 没勾「必填」，就要给一个合法的默认值"),
        (re.compile(rf"^{re.escape(name)}\.params\.(\S+?)\.pattern 必须是 (.+) 之一$"),
         r"参数 \1 的类型只能是：\2"),
        (re.compile(rf"^{re.escape(name)} 的参数名不合法：(.+)$"),
         r"参数名 \1 不合法：只能用小写字母、数字、下划线"),
    ]
    for pattern, repl in swaps:
        if pattern.match(message):
            return pattern.sub(repl, message)
    return message.replace(f"{name}.argv", "命令").replace(f"{name}.params.", "参数 ")


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

    try:
        spec = _check_tool(raw)  # 其余规则（argv 首项、写动词、占位符）与正式配置一致
    except ConfigError as exc:
        raise ConfigError(_form_wording(str(exc), name)) from None
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
    document = _read_yaml(_state["path"])
    current = document.get("tools")
    if isinstance(current, list) and current:
        # 文件里已有条目：直接在末尾追加，保留手写的注释与格式。
        block = _yaml().safe_dump([item["tool"]], allow_unicode=True,
                                  sort_keys=False, default_flow_style=None)
        with open(_state["path"], "a", encoding="utf-8") as handle:
            handle.write("\n" + textwrap.indent(block, "  "))
    else:
        # 空列表（没有可追加的锚点）：整体重写一份，其他顶层键（如 include）原样保留。
        _write_yaml(_state["path"], {**document, "tools": (current or []) + [item["tool"]]})
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
    ok = 200 <= status < 300
    # 只在成功时摘字段；出错时原样保留厂商的报错正文（Invalid token、404 page not found……），
    # 否则模型看到的是一串 null，解释不了为什么失败。
    if ok and spec["http"]["pick"]:
        try:
            data = json.loads(text)
            text = json.dumps({path: _pick(data, path) for path in spec["http"]["pick"]},
                              ensure_ascii=False, indent=1)
        except ValueError:
            pass
    text = _scrub(text.strip(), secrets_used)
    if not ok:
        text = f"接口返回 {status}：{text or '（无正文）'}"
    truncated = len(text) > MAX_OUTPUT
    if 300 <= status < 400:
        text = f"接口返回 {status} 跳转，已拒绝跟随（只允许访问配置里写明的主机）"
    return {"ok": ok, "command": "GET " + shown, "status": status,
            "output": text[:MAX_OUTPUT] + ("\n…（输出已截断）" if truncated else "")}


# ---- MCP 客户端 ------------------------------------------------------------

class McpError(RuntimeError):
    """和某个 MCP server 打交道失败：没连上、超时、server 返回 JSON-RPC 错误。"""


def _check_mcp_servers(document, problems):
    """主文件顶层 mcp_servers → {id: 配置}。坏条目跳过并记 problem，不拖垮其他 server。

    command 不受 INTERPRETERS 限制：MCP server 本来就是 python/node 跑的一段程序。这不是放宽，
    而是把「允许宿主机跑哪段代码」这个决定完整交给手写主文件的 root——和脚本型工具的 trust 同一个意思。
    """
    raw = document.get("mcp_servers")
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        problems.append("mcp_servers 必须是映射：server id → {command, args, env, cwd}")
        return {}
    servers = {}
    for ident, entry in raw.items():
        ident = str(ident).strip()
        try:
            if not MCP_SERVER_ID.match(ident):
                raise ConfigError(f"MCP server id 不合法：{ident[:40]!r}，只能用小写字母、数字、下划线，"
                                  f"它会成为工具名的前缀")
            if not isinstance(entry, dict):
                raise ConfigError(f"mcp_servers.{ident} 必须是映射")
            command = str(entry.get("command", "")).strip()
            if not command:
                raise ConfigError(f"mcp_servers.{ident} 缺少 command")
            args = entry.get("args") or []
            if not isinstance(args, list):
                raise ConfigError(f"mcp_servers.{ident}.args 必须是列表")
            env = entry.get("env") or {}
            if not isinstance(env, dict):
                raise ConfigError(f"mcp_servers.{ident}.env 必须是映射")
            for key, value in env.items():
                if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", str(key)):
                    raise ConfigError(f"mcp_servers.{ident}.env 的变量名不合法：{str(key)[:40]!r}")
                if str(key) == "OPS_TOKEN" or str(key).startswith(SECRET_PREFIX):
                    raise ConfigError(f"mcp_servers.{ident}.env 不能把 {key} 交给 server："
                                      f"那是工具服务自己的凭据")
                _check_secret_refs(f"mcp_servers.{ident}.env.{key}", str(value))
            cwd = entry.get("cwd")
            servers[ident] = {"label": str(entry.get("label", "")).strip()[:GROUP_MAX] or ident,
                              "command": command, "args": [str(a) for a in args],
                              "env": {str(k): str(v) for k, v in env.items()},
                              "cwd": str(cwd).strip() if cwd else ""}
        except ConfigError as exc:
            problems.append(str(exc))
    return servers


def _mcp_child_env(config, secrets_used):
    env = {key: os.environ[key] for key in MCP_PASS_ENV if key in os.environ}
    for key, raw in config.get("env").items():
        env[key] = _fill_secrets(raw, secrets_used)
    return env


class McpServer:
    """一个 MCP server 子进程 + 它上面的 JSON-RPC 会话。

    stdio 传输：每行一条 JSON，stdin 发、stdout 收；stderr 是 server 的日志，单独排水，否则
    管道一满 server 就卡住。请求串行、id 递增、按 id 对响应；server 发来的通知只认
    tools/list_changed，发来的请求一律回「不支持」——本期不做 sampling / elicitation。
    """

    def __init__(self, ident, config):
        self.id = ident
        self.config = config
        self.label = config.get("label") or ident
        self.proc = None
        self.online = False
        self.reason = "尚未连接"
        self.tools = {}             # server 原名 -> tools/list 里的那条
        self.failures = 0
        self.next_retry = 0.0
        self.list_changed = False
        self.last_discovery = 0.0
        self.secrets = []           # env 里解析出来的密钥值，输出脱敏用
        self.server_info = {}
        self.protocol = ""
        self.stderr_tail = []
        self._send_lock = threading.Lock()
        self._state_lock = threading.Lock()
        self._waiting = {}          # 请求 id -> [Event, 响应]
        self._next_id = 0

    # --- 进程 ---------------------------------------------------------------

    def alive(self):
        return self.proc is not None and self.proc.poll() is None

    def _spawn(self):
        command = self.config["command"]
        binary = command if os.path.isabs(command) else shutil.which(command)
        if not binary:
            raise McpError(f"本机没有 {command} 这个命令")
        self._kill()   # 上一个进程哪怕已经死了，管道也要关掉
        self.secrets = []
        try:
            env = _mcp_child_env(self.config, self.secrets)
        except ValueError as exc:
            raise McpError(str(exc)) from None
        self.secrets = [s for s in self.secrets if s]
        kwargs = {}
        if hasattr(subprocess, "CREATE_NO_WINDOW"):
            kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW
        try:
            self.proc = subprocess.Popen(
                [binary] + self.config["args"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, bufsize=0, env=env,
                cwd=self.config["cwd"] or None, shell=False, **kwargs)
        except OSError as exc:
            raise McpError(f"启动失败：{exc}") from None
        self.stderr_tail = []
        proc = self.proc
        threading.Thread(target=self._read_loop, args=(proc,), daemon=True,
                         name=f"mcp-{self.id}-stdout").start()
        threading.Thread(target=self._drain_stderr, args=(proc,), daemon=True,
                         name=f"mcp-{self.id}-stderr").start()

    def _drain_stderr(self, proc):
        try:
            for raw in iter(proc.stderr.readline, b""):
                line = raw.decode("utf-8", errors="replace").rstrip()
                if not line:
                    continue
                self.stderr_tail = (self.stderr_tail + [line])[-MCP_STDERR_KEEP:]
                print(f"[mcp:{self.id}] {line}", flush=True)
        except (OSError, ValueError):
            pass   # 我们自己关了管道

    def _read_loop(self, proc):
        try:
            for raw in iter(proc.stdout.readline, b""):
                line = raw.strip()
                if not line:
                    continue
                try:
                    message = json.loads(line.decode("utf-8"))
                except ValueError:
                    print(f"[mcp:{self.id}] 收到非 JSON 的一行，已忽略", flush=True)
                    continue
                if isinstance(message, dict):
                    self._dispatch(message)
        except (OSError, ValueError):
            return   # stop() 关了管道，不是 server 退出
        # 进程退出：唤醒所有还在等的请求，让它们拿到一个明确的错误而不是等到超时
        if proc is self.proc:
            try:
                code = proc.wait(2)
            except subprocess.TimeoutExpired:
                code = proc.poll()
            self._go_offline(f"server 进程已退出（退出码 {code}）"
                             + (f"：{self.stderr_tail[-1]}" if self.stderr_tail else ""))

    def _dispatch(self, message):
        if "method" in message:
            if message.get("id") is not None:
                # server 向客户端发请求（sampling、roots、elicitation）：本期一律不支持
                self._send({"jsonrpc": "2.0", "id": message["id"],
                            "error": {"code": -32601, "message": "doc2sop 工具服务不支持该方法"}})
            elif message["method"] == "notifications/tools/list_changed":
                self.list_changed = True
            return
        ident = message.get("id")
        with self._state_lock:
            slot = self._waiting.get(ident)
        if slot is not None:
            slot[1] = message
            slot[0].set()

    def _send(self, message):
        data = (json.dumps(message, ensure_ascii=False) + "\n").encode("utf-8")
        with self._send_lock:
            try:
                self.proc.stdin.write(data)
                self.proc.stdin.flush()
            except (OSError, ValueError, AttributeError) as exc:
                raise McpError(f"写入 server 失败：{exc}") from None

    def _go_offline(self, reason):
        self.online = False
        self.reason = reason
        with self._state_lock:
            waiting = list(self._waiting.values())
            self._waiting.clear()
        for event, _ in waiting:
            event.set()

    # --- JSON-RPC -----------------------------------------------------------

    def request(self, method, params=None, timeout=TIMEOUT):
        if not self.alive():
            raise McpError(self.reason or "server 未连接")
        with self._state_lock:
            self._next_id += 1
            ident = self._next_id
            slot = [threading.Event(), None]
            self._waiting[ident] = slot
        message = {"jsonrpc": "2.0", "id": ident, "method": method}
        if params is not None:
            message["params"] = params
        try:
            self._send(message)
            if not slot[0].wait(timeout):
                raise McpError(f"{method} 超时（{timeout}s）")
        finally:
            with self._state_lock:
                self._waiting.pop(ident, None)
        response = slot[1]
        if response is None:
            raise McpError(self.reason or "server 已断开")
        if "error" in response:
            error = response["error"] if isinstance(response["error"], dict) else {}
            raise McpError(f"server 返回错误 {error.get('code', '')}：{error.get('message', '')}".strip())
        return response.get("result")

    def notify(self, method, params=None):
        message = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            message["params"] = params
        self._send(message)

    # --- 生命周期 -------------------------------------------------------------

    def start(self):
        """拉起子进程并握手、拉一次工具列表。失败则记退避，连续三次标离线。"""
        if self.alive() and self.online:
            return
        now = time.monotonic()
        if now < self.next_retry:
            raise McpError(self.reason)
        try:
            if self.alive():
                self.stop("重新连接")
            self._spawn()
            result = self.request("initialize", {
                "protocolVersion": MCP_PROTOCOL, "capabilities": {},
                "clientInfo": {"name": "doc2sop", "version": "1"}}, timeout=MCP_INIT_TIMEOUT) or {}
            self.protocol = str(result.get("protocolVersion", ""))
            self.server_info = result.get("serverInfo") or {}
            self.notify("notifications/initialized")
            self.online = True
            self.reason = ""
            self.list_tools()
        except McpError as exc:
            self.failures += 1
            delay = MCP_BACKOFF[min(self.failures, len(MCP_BACKOFF)) - 1]
            self.next_retry = time.monotonic() + delay
            self._go_offline(f"连接失败（第 {self.failures} 次）：{exc}；{delay}s 后重试")
            self._kill()
            raise McpError(self.reason) from None
        self.failures = 0
        self.next_retry = 0.0
        print(f"[mcp:{self.id}] 已连接 {self.server_info.get('name', '')} "
              f"{self.server_info.get('version', '')}（协议 {self.protocol}），"
              f"发现 {len(self.tools)} 个工具", flush=True)

    def ensure(self):
        """调用前保证在线：进程死了就按退避重拉。"""
        if not (self.alive() and self.online):
            self.start()

    def list_tools(self):
        found, cursor = {}, None
        for _ in range(100):   # 分页上限，防 server 一直给 nextCursor
            params = {"cursor": cursor} if cursor else None
            result = self.request("tools/list", params) or {}
            for tool in result.get("tools") or []:
                if isinstance(tool, dict) and str(tool.get("name", "")).strip():
                    found[str(tool["name"])] = tool
            cursor = result.get("nextCursor")
            if not cursor:
                break
        self.tools = found
        self.list_changed = False
        self.last_discovery = time.monotonic()
        return found

    def call(self, tool, arguments, timeout=TIMEOUT):
        self.ensure()
        return self.request("tools/call", {"name": tool, "arguments": arguments or {}},
                            timeout=timeout) or {}

    def _kill(self):
        proc, self.proc = self.proc, None
        if proc is None:
            return
        # 先结束进程再关管道：读线程正阻塞在 readline 上，Windows 上先关管道会等到它返回为止
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(3)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(3)
        for stream in (proc.stdin, proc.stdout, proc.stderr):
            try:
                stream.close()
            except OSError:
                pass

    def stop(self, reason="已停止"):
        self._go_offline(reason)
        self._kill()

    def status(self, approved=0):
        return {"label": self.label, "online": bool(self.online and self.alive()),
                "reason": "" if self.online else self.reason,
                "discovered": len(self.tools), "approved": approved,
                "server": self.server_info, "protocol": self.protocol}


class McpRegistry:
    """按配置管一组 server：配置变了就启停对应子进程；后台线程负责重连与定期重新发现。"""

    def __init__(self):
        self.servers = {}
        self.on_discovered = None       # server -> None；发现/刷新后由审批层接手（写 pending、比 hash）
        self._lock = threading.Lock()
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._thread = None

    def configure(self, configs):
        """只创建/替换对象，不拉进程：进程由后台线程或下一次调用按需拉起，CLI 子命令永远不会碰到。"""
        with self._lock:
            for ident in list(self.servers):
                if ident not in configs or self.servers[ident].config != configs[ident]:
                    self.servers.pop(ident).stop("配置已变更")
            for ident, config in configs.items():
                if ident not in self.servers:
                    self.servers[ident] = McpServer(ident, config)
        self._wake.set()

    def get(self, ident):
        return self.servers.get(ident)

    def sync(self, ident=None, force=False):
        """同步地把（某个/所有）server 连上并刷新工具列表，再交给审批层。测试与后台线程都走这里。"""
        for server in ([self.servers[ident]] if ident in self.servers else list(self.servers.values())):
            try:
                if not (server.alive() and server.online):
                    server.start()
                elif force or server.list_changed or \
                        time.monotonic() - server.last_discovery > MCP_REFRESH:
                    server.list_tools()
                else:
                    continue
            except McpError as exc:
                print(f"[mcp:{server.id}] {exc}", flush=True)
                continue
            if self.on_discovered:
                try:
                    self.on_discovered(server)
                except Exception as exc:   # 审批层出错不能把后台线程弄死
                    print(f"[mcp:{server.id}] 处理发现结果失败：{exc.__class__.__name__}: {exc}", flush=True)

    def start_background(self):
        if self._thread is not None:
            return
        self._thread = threading.Thread(target=self._loop, daemon=True, name="mcp-registry")
        self._thread.start()
        atexit.register(self.shutdown)

    def _loop(self):
        while not self._stop.is_set():
            self._wake.clear()
            try:
                self.sync()
            except Exception as exc:
                print(f"[mcp] 后台刷新失败：{exc.__class__.__name__}: {exc}", flush=True)
            self._wake.wait(5)

    def shutdown(self):
        self._stop.set()
        self._wake.set()
        with self._lock:
            for server in self.servers.values():
                server.stop("工具服务退出")

    def status(self, approved_counts=None):
        counts = approved_counts or {}
        return {ident: server.status(counts.get(ident, 0))
                for ident, server in sorted(self.servers.items())}


_mcp = McpRegistry()


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
