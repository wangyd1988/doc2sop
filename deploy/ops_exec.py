#!/usr/bin/env python3
"""doc2sop 只读命令的执行核心，兼受控模式的主机执行器。

同一份代码，两种用法：

1. 工具服务（deploy/ops_readonly.py）把它当库用：命令型工具的参数校验、argv 拼装、写动词黑名单、
   超时与输出上限都在这里。工具服务在本机执行（via: local）走的就是这几个函数，本地和远程只有一份校验。
2. 装在被巡检的主机上，作为受控模式的强制命令：

       restrict,from="<工具服务地址>",command="/usr/bin/python3 -I /opt/ops-readonly/ops_exec.py --stdio" ssh-ed25519 AAAA… doc2sop

   从 stdin 读一条 JSON 请求，按同目录的 allowlist.json 校验后执行，往 stdout 写一条 JSON 回应。只认三种请求：
     exec   执行白名单里的一个工具（工具名 + 参数，执行器自己拼 argv，不经过 shell）
     list   这台主机开放了哪些工具、白名单版本、各工具的命令在不在
     probe  某几个命令在不在
   执行器不能以 root 运行；执行账号拥有或能写白名单、执行器自身、或它们所在的任一级目录时，拒绝启动。
   强制命令必须带 -I（Python 的隔离模式），否则 python 启动时会加载执行账号自己能写的 ~/.local，没带也拒绝启动。

只用标准库，兼容 Python 3.6，几百行，主机负责人审得过来。

    python3 -I ops_exec.py --stdio                  # 强制命令（白名单默认在同一目录的 allowlist.json）
    python3 ops_exec.py --check [allowlist.json]    # 校验白名单格式（push 装完后用，不做权限自检）
    python3 ops_exec.py --version
"""
import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import sys

__version__ = "1.0"
PROTOCOL = 1                 # 请求里的 v；不一致就拒绝，工具服务据此提示升级

MAX_OUTPUT = 20000           # characters returned to the agent
TIMEOUT = 20                 # seconds per command

# Argument validators. Anything not matching is refused before reaching argv.
NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,120}$")
K8S_NAME = re.compile(r"^[a-z0-9][a-z0-9.-]{0,120}$")
RESOURCE = re.compile(r"^[a-z][a-z0-9.-]{0,40}$")
DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")

# 配置里只能引用这些预置正则，不能自带正则：一个 ".*" 就能把白名单废掉。
PATTERNS = {"name": NAME, "k8s_name": K8S_NAME, "resource": RESOURCE, "date": DATE}

# argv 元素必须"整个"是 {参数名} 才算占位符，不做片段拼接。
# 这样 docker 的 "{{.Names}}" 之类模板不会被误伤，参数值也永远独占一个 argv 项。
PLACEHOLDER = re.compile(r"^\{([a-z_][a-z0-9_]*)\}$")
# 64 而不是 40：MCP 工具名是 server__tool 两段拼起来的，40 不够用。
TOOL_NAME = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
MAX_ARGV = 64
MAX_ARG_LEN = 4096

# 这些 binary 本身就能"执行另一段命令"，一旦允许，固定 argv 的前提就没了：
# bash -c "任意" 、env FOO=x 任意、xargs 任意、find -exec 任意……
# 所以普通工具不许用它们当 binary。要跑脚本，走工具服务的脚本型工具（哈希锁定）。
INTERPRETERS = {
    "bash", "sh", "dash", "zsh", "ksh", "csh", "tcsh", "fish", "rbash", "ash", "busybox",
    "python", "python2", "python3", "pypy", "ipython", "perl", "ruby", "node", "nodejs", "deno", "bun",
    "php", "lua", "luajit", "tclsh", "expect", "rscript",
    "awk", "gawk", "mawk", "nawk", "sed",
    "env", "xargs", "find", "watch", "timeout", "nohup", "stdbuf", "setsid",
    "unshare", "chroot", "flock", "nice", "ionice", "parallel", "script",
    "ssh", "sshpass", "scp", "rsync", "socat", "ncat", "nc",
    "eval", "exec", "command", "source", "make", "sudo", "su", "doas",
    # 命令型工具可以声明 os: windows 了，Windows 上能执行任意命令的也一并挡掉
    "cmd", "powershell", "pwsh", "cscript", "wscript", "mshta",
}

# Refuse these even if a template somehow produced them.
FORBIDDEN = {"exec", "attach", "cp", "rm", "rmi", "kill", "stop", "start", "restart",
             "run", "create", "delete", "apply", "patch", "edit", "scale", "drain",
             "cordon", "taint", "set", "replace", "port-forward", "proxy"}


class ConfigError(ValueError):
    """A tool definition is malformed; that tool is skipped, not fatal."""


def host_os():
    if sys.platform.startswith("linux"):
        return "linux"
    if sys.platform == "darwin":
        return "darwin"
    if sys.platform in ("win32", "cygwin"):
        return "windows"
    return sys.platform


# ---- 工具定义的校验（工具服务加载配置、执行器加载白名单，都走这里）-----------------------

def check_param(tool, key, raw):
    if not isinstance(raw, dict):
        raise ConfigError(f"{tool}.params.{key} 必须是映射")
    kind = str(raw.get("type", "str"))
    if kind not in ("str", "int"):
        raise ConfigError(f"{tool}.params.{key}.type 只能是 str 或 int")
    spec = {"type": kind, "desc": str(raw.get("desc", "")),
            "required": bool(raw.get("required", False))}
    if kind == "int":
        try:
            # 必填的 int 可以没有默认值（模型必须给，比如「哪一年」）；老写法 default 照常可用
            if "default" in raw or not spec["required"]:
                spec["default"] = int(raw.get("default", 100))
            spec["min"] = int(raw.get("min", 1))
            spec["max"] = int(raw.get("max", 10000))
        except (TypeError, ValueError):
            raise ConfigError(f"{tool}.params.{key} 的 default/min/max 必须是整数") from None
        if "default" in spec and not spec["min"] <= spec["default"] <= spec["max"]:
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


def check_params(name, params):
    if params is None:
        return {}
    if not isinstance(params, dict):
        raise ConfigError(f"{name}.params 必须是映射：参数名 → {{type, pattern, required, …}}")
    out = {}
    for key, value in params.items():
        key = str(key)
        if not TOOL_NAME.match(key):
            raise ConfigError(f"{name} 的参数名不合法：{key[:40]!r}")
        out[key] = check_param(name, key, value)
    return out


def interpreter(binary):
    """binary 是不是解释器一类。按文件名比：去掉路径、.exe、-dbg、ABI 后缀（3.13t、3.7m）和版本号再比。

    只用 split / rstrip 这类线性操作：页面申请里的 binary 长度没有上限，回溯型正则会被一条申请拖住整个服务。
    """
    head = re.split(r"[\\/]", binary)[-1].lower()
    for suffix in (".exe", "-dbg", "-debug"):
        if head.endswith(suffix):
            head = head[:-len(suffix)]
    names = {head}
    trimmed = head.rstrip("dmt")
    if trimmed[-1:].isdigit():
        head = trimmed
    names.add(head.rstrip("0123456789."))
    return bool(names & INTERPRETERS)


def check_command(name, binary, argv, params):
    """命令型工具的执行部分：(binary, argv, params)。能扩权的地方都在这里挡。"""
    binary = str(binary or "").strip()
    if not binary:
        raise ConfigError(f"{name} 缺少 binary")
    if len(binary) > 255:
        raise ConfigError(f"{name} 的 binary 太长")
    if interpreter(binary):
        raise ConfigError(
            f"{name} 的 binary 是 {binary}，它能执行任意命令，不能直接作为工具。"
            f"要跑一段脚本，请把脚本放到 scripts 目录，再用 script 字段引用它。")

    if not isinstance(argv, list) or not argv:
        raise ConfigError(f"{name}.argv 必须是非空列表")
    argv = [str(part) for part in argv]
    if len(argv) > MAX_ARGV or any(len(part) > MAX_ARG_LEN for part in argv):
        raise ConfigError(f"{name}.argv 太长：最多 {MAX_ARGV} 项，每项最多 {MAX_ARG_LEN} 个字符")
    params = check_params(name, params)

    if argv[0] != binary:
        raise ConfigError(f"{name}.argv 的第一项必须就是 binary（{binary}）")
    for part in argv:
        found = PLACEHOLDER.match(part)
        if found and found.group(1) not in params:
            raise ConfigError(f"{name}.argv 用到了未声明的参数 {found.group(1)}")
    for part in argv[1:]:
        if not PLACEHOLDER.match(part) and part in FORBIDDEN:
            raise ConfigError(f"{name}.argv 含写操作动词 {part}")
    return binary, argv, params


def exec_params(params):
    """参数里决定「执行什么」的部分：类型、预置正则、必填、默认值、范围。说明文字不算。"""
    out = {}
    for key, spec in params.items():
        kept = {"type": spec["type"], "required": bool(spec.get("required"))}
        for field in ("pattern", "default", "min", "max"):
            if field in spec:
                kept[field] = spec[field]
        out[key] = kept
    return out


def fingerprint(argv, params):
    """一个命令型工具的指纹：argv 模板 + 参数校验规则。白名单和工具服务两边算，对不上就要重新 push。"""
    body = json.dumps({"argv": list(argv), "params": exec_params(params)}, sort_keys=True,
                      ensure_ascii=False, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(body.encode("utf-8")).hexdigest()


# ---- 参数 → argv → 执行 ------------------------------------------------------------

def value(key, spec, args):
    supplied = args.get(key)
    if spec["type"] == "int":
        try:
            number = int(supplied)
        except (TypeError, ValueError):
            if spec["required"]:
                # 必填的 int 没有默认值可退：缺了或给的不是整数都得说清楚，不能悄悄换成别的值
                if supplied is None or str(supplied).strip() == "":
                    raise ValueError(f"缺少必填参数：{key}") from None
                raise ValueError(f"参数 {key} 不合法：{str(supplied)[:40]!r}，应为整数") from None
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


def values(spec, args):
    """校验后的参数值（都是字符串）：发给主机上的执行器时只发这一份，执行器再校验一遍。"""
    args = args or {}
    return {key: value(key, param, args) for key, param in spec["params"].items()}


def build_argv(spec, args):
    """Fill the fixed template. Each value lands in its own argv slot."""
    filled = values(spec, args)
    argv = []
    for part in spec["argv"]:
        found = PLACEHOLDER.match(part)
        argv.append(filled[found.group(1)] if found else part)
    return argv


def forbidden(argv):
    """Defence in depth: the template is fixed, but verify anyway."""
    return any(part in FORBIDDEN for part in argv[1:])


def _text(data):
    """命令输出按 UTF-8 解码，坏字节换成 �；换行统一成 \\n（和 universal_newlines 一样）。"""
    return (data or b"").decode("utf-8", "replace").replace("\r\n", "\n").replace("\r", "\n")


def run_argv(argv, timeout=TIMEOUT, max_output=MAX_OUTPUT, utf8=False):
    """执行一条 argv（不经过 shell），超时和输出上限在这里统一处理。

    utf8=False 按本机语言环境解码（工具服务在本机执行时的老行为，一个字节都不变）；
    主机上的执行器用 utf8=True：远程账号的语言环境说不准，坏字节也不该让一次巡检报错。
    """
    try:
        if utf8:
            done = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  timeout=timeout, shell=False)
            stdout, stderr = _text(done.stdout), _text(done.stderr)
        else:
            done = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  universal_newlines=True, timeout=timeout, shell=False)
            stdout, stderr = done.stdout, done.stderr
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": f"执行超时（{timeout}s）", "command": " ".join(argv)}
    except Exception as exc:
        return {"ok": False, "error": f"{exc.__class__.__name__}: {exc}"}

    output = (stdout or stderr or "").strip()
    truncated = len(output) > max_output
    return {"ok": done.returncode == 0, "command": " ".join(argv),
            "output": output[:max_output] + ("\n…（输出已截断）" if truncated else ""),
            "exit_code": done.returncode}


# ---- 白名单 -------------------------------------------------------------------------
# 由工具服务的 push 生成（按主机的 os、分组），管理员用自己的 SSH 身份装到主机上，root 所有。
# 执行器只认这里的工具：工具服务被攻破，也只能在这台主机上跑这些只读命令。

ALLOWLIST_FORMAT = 1
ALLOWLIST_MAX = 1024 * 1024
ENTRY_FIELDS = ("name", "argv", "params", "fp")
TIMEOUT_RANGE = (1, 120)
OUTPUT_RANGE = (1000, 200000)


def check_entry(entry):
    """白名单里的一个工具。和工具服务加载配置时同一套校验：解释器、写动词、占位符、预置正则。"""
    if not isinstance(entry, dict):
        raise ConfigError("白名单里的每个工具必须是对象")
    name = str(entry.get("name", "")).strip()
    if not TOOL_NAME.match(name):
        raise ConfigError(f"工具名不合法：{name[:40]!r}")
    unknown = sorted(str(key) for key in entry if key not in ENTRY_FIELDS)
    if unknown:
        raise ConfigError(f"{name} 里有不认识的字段 {'、'.join(unknown)}")
    argv = entry.get("argv")
    binary = argv[0] if isinstance(argv, list) and argv else ""
    binary, argv, params = check_command(name, binary, argv, entry.get("params"))
    digest = fingerprint(argv, params)
    if entry.get("fp") is not None and entry.get("fp") != digest:
        raise ConfigError(f"{name} 的 fp 和内容对不上：白名单被手改过？请重新 push")
    return {"name": name, "binary": binary, "argv": argv, "params": params, "fp": digest}


def _bounded(raw, low, high, default):
    try:
        number = int(raw)
    except (TypeError, ValueError):
        return default
    return max(low, min(number, high))


def parse_allowlist(document):
    """白名单内容 → (tools, info, problems)。坏条目跳过并记进 problems；整份不对抛 ConfigError。"""
    if not isinstance(document, dict) or document.get("format") != ALLOWLIST_FORMAT:
        raise ConfigError(f"白名单格式不对：顶层要是对象，format 为 {ALLOWLIST_FORMAT}")
    entries = document.get("tools")
    if not isinstance(entries, list):
        raise ConfigError("白名单缺少 tools 列表")
    tools, problems = {}, []
    for entry in entries:
        try:
            spec = check_entry(entry)
        except ConfigError as exc:
            problems.append(str(exc))
            continue
        if spec["name"] in tools:
            problems.append(f"工具名重复：{spec['name']}")
            continue
        tools[spec["name"]] = spec
    canonical = json.dumps(sorted([name, spec["fp"]] for name, spec in tools.items()), separators=(",", ":"))
    info = {"version": "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
            "host": str(document.get("host") or "")[:64],
            "generated_at": str(document.get("generated_at") or "")[:40],
            "timeout": _bounded(document.get("timeout"), TIMEOUT_RANGE[0], TIMEOUT_RANGE[1], TIMEOUT),
            "max_output": _bounded(document.get("max_output"), OUTPUT_RANGE[0], OUTPUT_RANGE[1], MAX_OUTPUT)}
    return tools, info, problems


def load_allowlist(path):
    try:
        with open(path, "rb") as handle:
            raw = handle.read(ALLOWLIST_MAX + 1)
    except OSError as exc:
        raise ConfigError(f"读不到白名单 {path}：{exc}") from None
    if len(raw) > ALLOWLIST_MAX:
        raise ConfigError(f"白名单太大（超过 {ALLOWLIST_MAX} 字节）")
    try:
        document = json.loads(raw.decode("utf-8"))
    except ValueError as exc:
        raise ConfigError(f"白名单不是合法的 JSON：{exc}") from None
    return parse_allowlist(document)


def render_allowlist(host, entries, generated_at="", timeout=TIMEOUT, max_output=MAX_OUTPUT):
    """生成白名单文件的内容（push 用）。entries：[(工具名, argv, 校验过的 params)]。"""
    tools = []
    for name, argv, params in sorted(entries, key=lambda item: item[0]):
        tools.append({"name": name, "argv": list(argv), "params": exec_params(params),
                      "fp": fingerprint(argv, params)})
    document = {"format": ALLOWLIST_FORMAT, "host": host, "generated_at": generated_at,
                "generator": "ops_readonly.py push", "timeout": timeout, "max_output": max_output,
                "tools": tools}
    return json.dumps(document, ensure_ascii=False, indent=1) + "\n"


# ---- 自检：执行账号不能改白名单和执行器 -------------------------------------------------

class GuardError(RuntimeError):
    """执行器所在的环境不安全，拒绝启动。"""


def _chain(path):
    """path 本身（解析符号链接后）和它的每一级上级目录。"""
    path = os.path.realpath(path)
    out = [path]
    while True:
        parent = os.path.dirname(path)
        if parent == path:
            return out
        out.append(parent)
        path = parent


def guard(paths, euid=None):
    """不能以 root 运行；白名单、执行器和它们的各级目录，都不能属于执行账号，也不能被它写。

    粘滞位目录（/tmp 这种）可写没关系：里面不属于自己的东西它改不了、换不掉。
    """
    if not hasattr(os, "geteuid"):
        raise GuardError("执行器只能在类 Unix 系统上作为强制命令运行")
    euid = os.geteuid() if euid is None else euid
    if euid == 0:
        raise GuardError("不能以 root 身份运行：受控模式的执行账号必须是普通账号")
    for path in paths:
        for index, item in enumerate(_chain(path)):
            try:
                info = os.stat(item)
            except OSError as exc:
                raise GuardError(f"读不到 {item}：{exc}") from None
            if info.st_uid == euid:
                raise GuardError(f"{item} 属于执行账号自己，它随时能改；要归 root 所有")
            if os.access(item, os.W_OK) and (index == 0 or not info.st_mode & stat.S_ISVTX):
                raise GuardError(f"执行账号能写 {item}；白名单、执行器和它们所在的目录只能由 root 写")


# ---- 请求处理 -------------------------------------------------------------------------

REQUEST_MAX = 64 * 1024
PROBE_MAX = 64
BINARY = re.compile(r"^(?:[A-Za-z0-9][A-Za-z0-9._+-]{0,63}|(?:/[A-Za-z0-9_+-][A-Za-z0-9._+-]{0,63}){1,16})$")


def _reply(ok, **fields):
    fields.update(ok=ok, ops_exec=__version__, protocol=PROTOCOL)
    return fields


def _refuse(error, code="bad_request"):
    return _reply(False, error=error, code=code)


def _exec(request, tools, info):
    name = request.get("tool")
    spec = tools.get(name) if isinstance(name, str) else None
    if spec is None:
        return _refuse(f"这台主机没有开放工具 {str(name)[:64]}（不在白名单里）", "not_allowed")
    if request.get("fp") is not None and request.get("fp") != spec["fp"]:
        return _refuse(f"这台主机上 {name} 的定义和工具服务的不一致（白名单 {info['version'][:19]}…），"
                       f"请管理员重新 push", "fp_mismatch")
    args = request.get("args")
    if args is not None and not isinstance(args, dict):
        return _refuse("args 必须是对象")
    try:
        argv = build_argv(spec, args or {})
    except ValueError as exc:
        return _refuse(str(exc), "bad_args")
    if forbidden(argv):
        return _refuse("拒绝执行：命中写操作黑名单", "forbidden")
    if not shutil.which(spec["binary"]):
        return _refuse(f"本机没有 {spec['binary']}，该工具不可用", "missing")
    result = run_argv(argv, timeout=info["timeout"], max_output=info["max_output"], utf8=True)
    ok = result.pop("ok")
    return _reply(ok, **result)


def _list(tools, info, problems):
    listed = {name: {"fp": spec["fp"], "binary": spec["binary"], "runnable": bool(shutil.which(spec["binary"]))}
              for name, spec in tools.items()}
    return _reply(True, allowlist=dict(info, problems=list(problems)[:20]), tools=listed,
                  python=platform.python_version(), os=host_os())


def _probe(request):
    names = request.get("binaries")
    if not isinstance(names, list) or len(names) > PROBE_MAX:
        return _refuse(f"binaries 必须是命令名列表，最多 {PROBE_MAX} 个")
    found = {}
    for name in names:
        if not isinstance(name, str) or not BINARY.match(name) or "/../" in name + "/":
            return _refuse(f"命令名不合法：{str(name)[:40]!r}")
        found[name] = bool(shutil.which(name))
    return _reply(True, binaries=found)


def handle(request, tools, info, problems=()):
    """一条请求 → 一条回应（都是 dict）。不认识的一律拒绝。"""
    if not isinstance(request, dict):
        return _refuse("请求必须是 JSON 对象")
    if request.get("v") != PROTOCOL:
        return _refuse(f"协议版本不一致：执行器 {PROTOCOL}，请求 {str(request.get('v'))[:10]}；请升级执行器或工具服务",
                       "protocol")
    op = request.get("op")
    if op == "exec":
        return _exec(request, tools, info)
    if op == "list":
        return _list(tools, info, problems)
    if op == "probe":
        return _probe(request)
    return _refuse(f"不认识的请求：{str(op)[:20]!r}（只认 exec、list、probe）")


def _audit(request, response):
    """主机自己的审计：每次请求记一行 syslog（谁连的、调了什么、成没成功）。没有 syslog 就算了。"""
    try:
        import syslog
        tool = request.get("tool") if isinstance(request, dict) else None
        line = "op={} tool={} ok={} code={} from={}".format(
            str((request or {}).get("op") if isinstance(request, dict) else "?")[:10], str(tool)[:64],
            response.get("ok"), response.get("code", "-"),
            (os.environ.get("SSH_CONNECTION") or "-").split(" ")[0])
        syslog.openlog("doc2sop-ops-exec")
        syslog.syslog(syslog.LOG_INFO, line)
    except Exception:
        pass


def _write(stream, response):
    # 只输出 ASCII：远程账号的语言环境说不准，中文一律转义
    stream.write((json.dumps(response, ensure_ascii=True, sort_keys=True) + "\n").encode("ascii"))
    stream.flush()


def serve(stdin, stdout, allowlist_path, executor_path, euid=None):
    """强制命令的入口：自检 → 读一条请求 → 回一条。返回退出码（0：已回应；3：自检不过，拒绝启动）。"""
    try:
        guard([executor_path, allowlist_path], euid)
    except GuardError as exc:
        _write(stdout, _refuse(f"执行器拒绝启动：{exc}", "guard"))
        return 3
    raw = stdin.read(REQUEST_MAX + 1)
    request = None
    if len(raw) > REQUEST_MAX:
        response = _refuse(f"请求太大（超过 {REQUEST_MAX} 字节）")
    else:
        try:
            request = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            response = _refuse("请求不是合法的 JSON")
        else:
            try:
                tools, info, problems = load_allowlist(allowlist_path)
            except ConfigError as exc:
                response = _refuse(f"白名单不可用：{exc}", "allowlist")
            else:
                response = handle(request, tools, info, problems)
    _audit(request, response)
    _write(stdout, response)
    return 0


def main(argv=None):
    here = os.path.dirname(os.path.abspath(__file__))
    parser = argparse.ArgumentParser(description="doc2sop 受控模式执行器")
    parser.add_argument("--stdio", action="store_true", help="作为强制命令：stdin 一条请求，stdout 一条回应")
    parser.add_argument("--allowlist", default=os.path.join(here, "allowlist.json"), help="白名单路径")
    parser.add_argument("--check", nargs="?", const="", metavar="ALLOWLIST",
                        help="只校验白名单格式（不做权限自检），默认校验 --allowlist")
    parser.add_argument("--version", action="store_true")
    args = parser.parse_args(argv)
    if args.version:
        print(f"ops_exec {__version__}（协议 {PROTOCOL}）")
        return 0
    if args.check is not None:
        path = args.check or args.allowlist
        try:
            tools, info, problems = load_allowlist(path)
        except ConfigError as exc:
            print(f"白名单不可用：{exc}", file=sys.stderr)
            return 1
        print(f"白名单 {path}：{len(tools)} 个工具，版本 {info['version']}，主机 {info['host'] or '-'}")
        for problem in problems:
            print(f"  已跳过：{problem}")
        return 1 if problems else 0
    if args.stdio:
        if not sys.flags.isolated:
            # 不带 -I，python 启动时会加载执行账号能写的 ~/.local（site-packages、.pth、usercustomize），也认 PYTHON* 环境变量。
            # 走到这里时那些代码已经跑过了，拦不住；拒绝启动是为了让漏写 -I 的安装当场暴露（status 里看得到），而不是一直开着口子
            _write(sys.stdout.buffer, _refuse("执行器拒绝启动：强制命令要用 python3 -I（隔离模式）启动，"
                                              "否则 python 会加载执行账号自己能写的 ~/.local", "guard"))
            return 3
        return serve(sys.stdin.buffer, sys.stdout.buffer, args.allowlist, os.path.abspath(__file__))
    parser.print_help(sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
