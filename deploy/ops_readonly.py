#!/usr/bin/env python3
"""Read-only ops endpoint.

The agent must never get a shell. It can only name a tool and supply typed
arguments; this service maps that to a fixed argv template and runs it with no
shell involved. Anything not on the allowlist is refused.

A tool is a capability (name, description, typed parameters) plus an
implementation: a builtin function shipped in this file, a command or script
run on a host, a read-only HTTP call (optionally through a shared connection that
holds the address and credential references), or a tool on an MCP server.

Command tools run on hosts: this machine by default, or — once the main config
declares `hosts` — on remote Linux hosts over the system OpenSSH client, either
through a forced-command executor (ops_exec.py, guarded mode) or as a quoted
command line (direct mode). The validation core lives in ops_exec.py next to
this file, so local and remote execution share one copy of the rules.

Binds loopback only and requires a shared token. Standard library only (plus
PyYAML), so it runs on any box with Python 3.9+. That includes the MCP client:
the host may declare MCP servers — stdio child processes or remote Streamable
HTTP endpoints — and their tools go through the same approve-before-use flow as
everything else. Database tools (sql) need a driver only when a connection of
that type is configured: sqlite is in the standard library, PostgreSQL and MySQL
drivers are imported lazily (from the system or from the vendor/ directory next
to this file); a missing driver disables only the tools that need it.

    OPS_TOKEN=... python ops_readonly.py --port 8799
"""
import argparse
import atexit
import base64
import datetime
import glob
import hashlib
import importlib.util
import ipaddress
import json
import os
import re
import secrets
import shlex
import shutil
import ssl
import stat
import subprocess
import sys
import textwrap
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, wait
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def _load_core():
    """执行核心 ops_exec.py：和本文件放在同一个目录（升级工具服务时两个文件一起拷）。"""
    path = Path(__file__).resolve().with_name("ops_exec.py")
    loaded = sys.modules.get("ops_exec")
    if loaded is not None and Path(getattr(loaded, "__file__", "") or ".").resolve() == path:
        return loaded
    if not path.is_file():
        raise SystemExit(f"找不到 {path}：ops_exec.py 是命令型工具的执行核心，要和 ops_readonly.py 放在同一个目录")
    spec = importlib.util.spec_from_file_location("ops_exec", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    sys.modules["ops_exec"] = module
    return module


ops_exec = _load_core()

MAX_OUTPUT = ops_exec.MAX_OUTPUT      # characters returned to the agent
TIMEOUT = ops_exec.TIMEOUT            # seconds per command
HTTP_TIMEOUT = 10       # seconds per HTTP request
MAX_HTTP_BYTES = 512 * 1024

# 参数的预置正则、占位符、解释器与写动词黑名单都在执行核心里：本机执行和主机上的执行器用的是同一份。
NAME, K8S_NAME, RESOURCE, DATE = ops_exec.NAME, ops_exec.K8S_NAME, ops_exec.RESOURCE, ops_exec.DATE
PATTERNS = ops_exec.PATTERNS

# 接口型工具的凭据只能来自宿主机环境变量，且必须以这个前缀命名：
# 这样即便配置写得马虎，也不可能把 OPS_TOKEN 之类的服务自身凭据发到外部接口。
# 配置里按名字引用：${prom_token} 就是环境变量 OPS_SECRET_PROM_TOKEN；老写法 ${OPS_SECRET_X} 照常可用。
SECRET_PREFIX = "OPS_SECRET_"
SECRET_REF = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")
SECRET_NAME = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
ENV_BASE = re.compile(r"^\$\{([A-Za-z_][A-Za-z0-9_]*)\}(.*)$")
# 连接：一个数据源的地址和凭据引用，多个工具共用。接口型工具用 http 连接，sql 工具用数据库连接。
CONN_NAME = re.compile(r"^[a-z][a-z0-9_]{0,30}$")
DB_TYPES = ("postgres", "mysql", "sqlite")
CONN_TYPES = ("http",) + DB_TYPES
# 每种连接认哪些字段：不认识的字段整条拒绝（写了 insecure: true 却被悄悄忽略，比加载失败危险）
CONN_FIELDS = {
    "http": ("name", "type", "label", "base", "headers", "ca", "bearer", "bearer_file", "external"),
    "postgres": ("name", "type", "label", "host", "port", "database", "user", "password", "tls", "ca", "timeout",
                 "external"),
    "mysql": ("name", "type", "label", "host", "port", "database", "user", "password", "tls", "ca", "timeout",
              "external"),
    "sqlite": ("name", "type", "label", "path", "timeout", "external"),
}
DB_PORTS = {"postgres": 5432, "mysql": 3306}
DB_TLS = {"postgres": ("disable", "prefer", "require", "verify"), "mysql": ("disable", "require", "verify")}
DB_IDENT = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.$@-]{0,62}$")
SQL_TIMEOUT = (5, 1, 60)          # 语句超时（秒）：默认、最小、最大
SQL_ROWS = (100, 1, 1000)         # 每次最多返回几行：默认、最小、最大
SQL_CELL = 500                    # 每个格子最多多少字

# 「外部」：调用会把实参发到组织外面（公网上的接口、远程 MCP server、数据库）。按地址判断，管理员可以声明覆盖。
# 这几类主机名按内部处理：localhost、不带点的单标签名、常见的内网后缀。其余主机名、公网 IP 都算外部。
INTERNAL_SUFFIXES = (".localhost", ".local", ".localdomain", ".internal", ".intranet", ".lan", ".corp", ".home",
                     ".home.arpa", ".svc", ".cluster.local")

# 模板里嵌参数（PromQL 的 {instance="{host}"}、K8s 的 labelSelector=app={app}）：只对这些预置正则开放。
# 它们只允许字母、数字和 . _ -：没有引号、反引号、反斜杠、花括号、空白、逗号、= ! ( )，参数值关不掉
# 字符串字面量、加不了匹配条件，也拼不出别的选择器。整数同理。新增的预置正则要逐个判断能不能进这个集合。
EMBED_SAFE = ("name", "k8s_name", "resource", "date")
# 替换场景包工具时，参数的 pattern 不能放宽：键是场景包的 pattern，值是「不比它宽」的预置正则
# （K8S_NAME、RESOURCE、DATE 允许的字符串都是 NAME 的子集；RESOURCE、DATE 又都是 K8S_NAME 的子集）
PATTERN_WITHIN = {"name": ("name", "k8s_name", "resource", "date"),
                  "k8s_name": ("k8s_name", "resource", "date"),
                  "resource": ("resource",), "date": ("date",)}

# 命令型、脚本型工具可以声明适用的系统；和工具服务所在机器不符时是「不适用」，不是「缺命令」。
OS_NAMES = ("linux", "darwin", "windows")
_host_os = ops_exec.host_os
HOST_OS = _host_os()
URL_PARAM = re.compile(r"\{([a-z_][a-z0-9_]*)\}")
HEADER_NAME = re.compile(r"^[A-Za-z0-9-]{1,60}$")
QUERY_KEY = re.compile(r"^[A-Za-z0-9_.-]{1,60}$")
PICK_PATH = re.compile(r"^[A-Za-z0-9_]+(\[\])?(\.[A-Za-z0-9_]+(\[\])?)*$")
GROUP_MAX = 20

# argv 占位符（整个元素是 {参数名}）与工具名的规则，见 ops_exec.py。
PLACEHOLDER = ops_exec.PLACEHOLDER
TOOL_NAME = ops_exec.TOOL_NAME
# MCP 工具的参数名由 server 定（常见 camelCase），只要求能当 Python 标识符且不以下划线开头。
MCP_PARAM_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,63}$")
# 脚本只能是 scripts 目录下的文件名，不能带路径，自然就跳不出目录。
SCRIPT_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,80}$")
MAX_LABEL = 40

DEFAULT_CONFIG = Path(__file__).resolve().parent / "ops_tools.yaml"

# 能「执行另一段命令」的 binary（bash、env、xargs、ssh……）不能当工具；写动词运行时再拦一次。见 ops_exec.py。
INTERPRETERS = ops_exec.INTERPRETERS
FORBIDDEN = ops_exec.FORBIDDEN

# ---- MCP：第四种工具类型 ----------------------------------------------------
# 工具服务自己当 MCP 客户端，两种传输都是标准库手写：stdio（宿主机上的子进程），和 Streamable HTTP（远程 server）。
# 不用官方 SDK：它是异步的（anyio + httpx），要在这个同步的线程模型里另起事件循环；跳转、响应大小、超时这些安全边界
# 也得钻进它的内部去改。我们只用得到 initialize / server/discover、tools/list、tools/call 这几个方法，手写更好审。
# 互通性由测试保证：tests/test_remote_mcp.py 用官方 SDK 起真的 server，两个协议版本都跑。
# server 由主文件顶层 mcp_servers 声明，它是跑在宿主机上的任意代码（或一个能拿到实参的远程服务），所以只能由 root 手写，
# 页面连申请都不能申请。发现到的工具一律先进 pending，批准前不出现在 /tools、不能执行。
MCP_PROTOCOL = "2025-06-18"     # stdio 用这个版本握手；只用 tools/list、tools/call，各版本一致；接受 server 回复的任何版本
MCP_REFRESH = 600               # 每隔多久重新 tools/list 一次，看看 schema 有没有变
MCP_BACKOFF = (5, 30, 120)      # 连接失败后的重试间隔；三次都失败则标离线，等下一次调用再试
MCP_INIT_TIMEOUT = 30
MCP_SERVER_ID = re.compile(r"^[a-z][a-z0-9_]{0,30}$")
MCP_STDERR_KEEP = 20            # 每个 server 最多保留多少行 stderr 供排错
# 远程 server（Streamable HTTP）：2025-11-25 是 initialize 握手 + Mcp-Session-Id 会话；2026-07-28 没有握手和会话，
# 每个请求自带 _meta 信封（协议版本、客户端信息、能力）和 Mcp-Method / Mcp-Name 请求头，用 server/discover 问能力。
# protocol: auto（默认）先按 2026-07-28 发 server/discover，server 不认再退回 initialize。
MCP_MODERN = "2026-07-28"
MCP_HANDSHAKE = "2025-11-25"
MCP_HANDSHAKE_VERSIONS = ("2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25")
MCP_HTTP_PROTOCOLS = ("auto", MCP_HANDSHAKE, MCP_MODERN)
MCP_HTTP_MAX = 4 * 1024 * 1024  # 一次响应最多读多少字节（JSON 或整条 SSE 流），再多就断开、报错
MCP_HTTP_FIELDS = ("label", "url", "headers", "protocol", "timeout", "ca", "external")
MCP_STDIO_FIELDS = ("label", "command", "args", "env", "cwd", "external")
MCP_META = "io.modelcontextprotocol/"
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


ConfigError = ops_exec.ConfigError
_check_param = ops_exec.check_param


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
            "type": "script", "script": script, "os": _check_os(name, raw.get("os"))}


def _common(raw, name):
    """Fields every tool type shares: what humans and the model read about it."""
    return {"name": name, "label": str(raw.get("label", "")).strip()[:MAX_LABEL],
            "desc": str(raw.get("desc", "")).strip(),
            "group": str(raw.get("group", "")).strip()[:GROUP_MAX],
            "enabled": bool(raw.get("enabled", True))}


def _check_params(name, raw):
    return ops_exec.check_params(name, raw.get("params"))


def _secret_env(ref):
    """凭据引用 → 环境变量名：${prom_token} → OPS_SECRET_PROM_TOKEN，${OPS_SECRET_X} 原样。别的都不是凭据。"""
    if ref.startswith(SECRET_PREFIX):
        return ref
    if SECRET_NAME.match(ref):
        return SECRET_PREFIX + ref.upper()
    return None


def _check_secret_refs(name, text):
    for ref in SECRET_REF.findall(text):
        if _secret_env(ref) is None:
            raise ConfigError(f"{name} 引用了环境变量 {ref}；凭据只能写成 ${{小写名字}}（对应环境变量 "
                              f"{SECRET_PREFIX}大写名字）或 ${{{SECRET_PREFIX}…}}，以免把服务自身的令牌发到外部")


def _check_os(name, raw):
    """适用的系统：不写就是不限。写了就和工具服务所在机器比（见 _not_here）。"""
    if raw is None or raw == "" or raw == []:
        return []
    out = []
    for value in raw if isinstance(raw, list) else [raw]:
        text = str(value).strip().lower()
        if text not in OS_NAMES:
            raise ConfigError(f"{name}.os 只能是 {'、'.join(OS_NAMES)}（可以写成列表），不是 {str(value)[:20]!r}")
        if text not in out:
            out.append(text)
    return out


def _no_os(raw, name, kind):
    if raw.get("os") is not None:
        raise ConfigError(f"{name} 是{kind}工具，不能声明 os：只有命令型、脚本型工具和机器有关")


# 主机分组名、主机名：小写字母或数字开头，可含 . _ -。target 里的 @组名 就是它前面加 @。
HOST_NAME = re.compile(r"^[a-z0-9][a-z0-9._-]{0,62}$")


def _check_groups(name, raw):
    """命令型工具的「适用分组」：配了主机清单后，只在这些组里的主机上跑。不写就是不限。"""
    if raw is None or raw == "" or raw == []:
        return []
    out = []
    for value in raw if isinstance(raw, list) else [raw]:
        text = str(value).strip()
        if not HOST_NAME.match(text) or text == "all":
            raise ConfigError(f"{name}.groups 的组名不合法：{text[:30]!r}（小写字母、数字、. _ -；all 是保留名）")
        if text not in out:
            out.append(text)
    return out


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
    # 用了连接：地址前缀和凭据都在连接里（见 _check_connections），这里只写路径
    conn = str(http.get("conn") or "").strip()
    env_base = None if conn else ENV_BASE.match(url)
    if conn:
        if not CONN_NAME.match(conn):
            raise ConfigError(f"{name}.http.conn 不合法：{conn[:40]!r}")
        if not url.startswith("/"):
            raise ConfigError(f"{name} 用了连接 {conn}，地址只写路径（以 / 开头）：主机名和凭据都在连接里")
        rest = url
    elif env_base:
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
        # 先去掉凭据引用再找 {参数}：${weather_key} 里的 {weather_key} 不是模型参数
        embedded = [] if whole_param else URL_PARAM.findall(SECRET_REF.sub("", value))
        if embedded:
            # 参数嵌在查询值里（PromQL 的 {instance="{host}"}、K8s 的 labelSelector=app={app}）：
            # 只对 EMBED_SAFE 的预置正则和整数开放，参数值里不可能有引号、花括号、反斜杠，见 EMBED_SAFE 的说明
            if "$" in value:
                raise ConfigError(f"{name}.http.query.{key} 嵌了参数，就不能再引用凭据或写 $")
            for found in embedded:
                if found not in params:
                    raise ConfigError(f"{name}.http.query 用到了未声明的参数 {found}")
                if not _embed_safe(params[found]):
                    raise ConfigError(f"{name}.http.query.{key} 嵌了参数 {found}：只有整数和 {'、'.join(EMBED_SAFE)} "
                                      f"这几种预置正则能嵌进查询值（它们不含引号、花括号、反斜杠），"
                                      f"要么改用这几种，要么让 {{{found}}} 整个占一个值")
        _check_secret_refs(name, value)
        query[key] = value

    headers = {}
    for key, value in (http.get("headers") or {}).items():
        key, value = str(key), str(value)
        if not HEADER_NAME.match(key):
            raise ConfigError(f"{name}.http.headers 的名字不合法：{key[:40]!r}")
        if URL_PARAM.search(SECRET_REF.sub("", value)):
            raise ConfigError(f"{name} 的请求头 {key} 不能使用模型参数，"
                              f"只能写固定值或凭据引用 ${{名字}} / ${{{SECRET_PREFIX}...}}")
        _check_secret_refs(name, value)
        headers[key] = value

    pick = [str(p) for p in (http.get("pick") or [])]
    for path in pick:
        if not PICK_PATH.match(path):
            raise ConfigError(f"{name}.http.pick 的路径不合法：{path[:40]!r}")

    # 可选 notes：pick 出的字段为空、或接口返回某个状态码时，附在输出末尾的一句解释。
    # 「days 为 []」和「404」在数据源那边都表示「该年安排尚未公布」，由管理员在这里写明，
    # 模型就不用自己猜一个空数组是什么意思。只能写在 YAML 里，页面申请的工具带不了。
    notes = {"empty": {}, "status": {}}
    raw_notes = http.get("notes") or {}
    if not isinstance(raw_notes, dict):
        raise ConfigError(f"{name}.http.notes 必须是映射")
    for key, value in raw_notes.items():
        key = str(key)
        if key == "empty":
            if not isinstance(value, dict):
                raise ConfigError(f"{name}.http.notes.empty 必须是「pick 路径: 说明」的映射")
            for path, text in value.items():
                if str(path) not in pick:
                    raise ConfigError(f"{name}.http.notes.empty 的字段 {str(path)[:40]!r} 不在 pick 里")
                notes["empty"][str(path)] = str(text).strip()
        elif re.fullmatch(r"[1-5]\d\d", key):
            notes["status"][key] = str(value).strip()
        else:
            raise ConfigError(f"{name}.http.notes 的键只能是 empty 或三位状态码，不是 {key[:40]!r}")

    return {**_common(raw, name), "type": "http", "binary": "", "argv": [],
            "params": params,
            "http": {"url": url, "conn": conn, "query": query, "headers": headers, "pick": pick,
                     "notes": notes, "external": _check_external(name, http.get("external"))}}


def _embed_safe(param):
    return param.get("type") == "int" or param.get("pattern") in EMBED_SAFE


# ---- MCP 工具条目 -----------------------------------------------------------

# 算 schema 指纹时只看这些结构键。description/title/examples 变了不算漂移——
# 文案改动不该让一个已批准的工具停掉；类型、必填、枚举、范围变了才要重新审。
SCHEMA_STRUCT_KEYS = ("type", "required", "items", "enum", "const", "anyOf", "oneOf", "allOf",
                      "additionalProperties", "minimum", "maximum", "exclusiveMinimum",
                      "exclusiveMaximum", "minLength", "maxLength", "minItems", "maxItems",
                      "format", "pattern")
MAX_MCP_DESC = 600


def _normalize_schema(node):
    if isinstance(node, dict):
        out = {}
        for key in SCHEMA_STRUCT_KEYS:
            if key in node:
                out[key] = _normalize_schema(node[key])
        if isinstance(node.get("properties"), dict):
            out["properties"] = {str(k): _normalize_schema(v) for k, v in node["properties"].items()}
        if isinstance(out.get("required"), list):
            out["required"] = sorted(str(r) for r in out["required"])
        return out
    if isinstance(node, list):
        return [_normalize_schema(item) for item in node]
    return node


def _mcp_hash(tool):
    """一个 MCP 工具的指纹：结构化后的 inputSchema + 只读/破坏性标注。

    标注也进指纹：server 把一个工具从「只读」改成「不只读」，和改参数一样需要人重新看一眼。
    """
    annotations = tool.get("annotations") or {}
    body = {"schema": _normalize_schema(tool.get("inputSchema") or {}),
            "readOnly": annotations.get("readOnlyHint") is True,
            "destructive": annotations.get("destructiveHint") is True}
    digest = hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":"),
                                       ensure_ascii=False).encode("utf-8")).hexdigest()
    return "sha256:" + digest


def _check_restrict(name, raw):
    """管理员给 MCP 参数加的收紧项，比 server 的 schema 更严，执行前双重校验。"""
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise ConfigError(f"{name}.restrict 必须是映射：参数名 → {{pattern, enum, max_len, min, max}}")
    clean = {}
    for key, rule in raw.items():
        key = str(key)
        if not MCP_PARAM_NAME.match(key):
            raise ConfigError(f"{name}.restrict 的参数名不合法：{key[:40]!r}")
        if not isinstance(rule, dict):
            raise ConfigError(f"{name}.restrict.{key} 必须是映射")
        kept = {}
        if "pattern" in rule:
            if rule["pattern"] not in PATTERNS:
                raise ConfigError(f"{name}.restrict.{key}.pattern 必须是 {'、'.join(PATTERNS)} 之一")
            kept["pattern"] = rule["pattern"]
        if "enum" in rule:
            if not isinstance(rule["enum"], list) or not rule["enum"]:
                raise ConfigError(f"{name}.restrict.{key}.enum 必须是非空列表")
            kept["enum"] = [v for v in rule["enum"] if isinstance(v, (str, int, float, bool))]
        for bound in ("max_len", "min", "max"):
            if bound in rule:
                try:
                    kept[bound] = int(rule[bound]) if bound == "max_len" else float(rule[bound])
                except (TypeError, ValueError):
                    raise ConfigError(f"{name}.restrict.{key}.{bound} 必须是数字") from None
        if kept:
            clean[key] = kept
    return clean


def _params_from_schema(schema, restrict=None):
    """inputSchema 的顶层属性 → 现有 params 形状，给应用侧清洗 args 键、给图谱播种实体用。

    只是"尽量映射"：string/integer/number/boolean/enum 直译，嵌套对象和数组标 json。
    真正的校验按完整 schema 做（见 _check_shape），这里不承担安全职责。
    """
    restrict = restrict or {}
    properties = schema.get("properties") if isinstance(schema, dict) else None
    required = set(str(r) for r in (schema.get("required") or [])) if isinstance(schema, dict) else set()
    params = {}
    for key, prop in (properties or {}).items():
        key = str(key)
        if not MCP_PARAM_NAME.match(key) or not isinstance(prop, dict):
            continue
        kind = prop.get("type")
        if isinstance(kind, list):
            kind = next((k for k in kind if k != "null"), "json")
        mapped = {"string": "str", "integer": "int", "number": "float", "boolean": "bool"}.get(kind, "json")
        if "enum" in prop and isinstance(prop["enum"], list):
            mapped = "enum"
        spec = {"type": mapped, "desc": str(prop.get("description") or prop.get("title") or "")[:300],
                "required": key in required}
        if mapped == "enum":
            spec["enum"] = [v for v in prop["enum"] if isinstance(v, (str, int, float, bool))]
        if "default" in prop and isinstance(prop["default"], (str, int, float, bool)):
            spec["default"] = prop["default"]
        rule = restrict.get(key) or {}
        if "pattern" in rule:
            spec["pattern"] = rule["pattern"]
        if "enum" in rule:
            spec["enum"] = list(rule["enum"])
            spec["type"] = "enum"
        params[key] = spec
    return params


def _check_mcp_tool(raw, name):
    """MCP 型工具：条目只是一张「允许调用 server 上哪个工具」的许可，执行的是 server 那边的代码。

    和前三种一样，模型只能填参数；不同的是参数形状由 server 的 inputSchema 决定，所以条目里
    记一份 schema 快照和指纹——server 悄悄改了形状，指纹对不上，工具自动停用、重新进 pending。
    """
    mcp = raw.get("mcp")
    if not isinstance(mcp, dict):
        raise ConfigError(f"{name}.mcp 必须是映射：{{server: <id>, tool: <server 上的原名>}}")
    server = str(mcp.get("server", "")).strip()
    tool = str(mcp.get("tool", "")).strip()
    if not MCP_SERVER_ID.match(server):
        raise ConfigError(f"{name}.mcp.server 不合法：{server[:40]!r}")
    if not tool or len(tool) > 120:
        raise ConfigError(f"{name}.mcp.tool 不能为空")
    schema = raw.get("input_schema")
    if schema is not None and not isinstance(schema, dict):
        raise ConfigError(f"{name}.input_schema 必须是映射（JSON Schema）")
    schema_hash = str(raw.get("schema_hash") or "").strip()
    restrict = _check_restrict(name, raw.get("restrict"))
    for key in restrict:
        if schema and key not in (schema.get("properties") or {}):
            raise ConfigError(f"{name}.restrict 收紧了 schema 里没有的参数 {key}")
    spec = {**_common(raw, name), "type": "mcp", "binary": "", "argv": [],
            "mcp": {"server": server, "tool": tool},
            "input_schema": schema or {}, "schema_hash": schema_hash, "restrict": restrict,
            "params": _params_from_schema(schema or {}, restrict),
            "readonly_declared": raw.get("readonly_declared") is True,
            "readonly_attested": raw.get("readonly_attested") is True}
    spec["desc"] = spec["desc"][:MAX_MCP_DESC]
    spec["group"] = spec["group"] or server
    return spec


def _check_tool(raw):
    """Validate one entry. Everything that could widen privilege is checked here.

    两种写法：老写法（binary/argv、script、http、mcp 直接写在工具上），和分层写法——工具 = 能力（name、
    label、group、desc、params、enabled）+ 实现 impl: {type: builtin | command | script | http | mcp, …}。
    分层写法先摊成老写法再走同一套校验，两种写法的安全规则只有一份。
    """
    if not isinstance(raw, dict):
        raise ConfigError("每个工具必须是映射")
    name = str(raw.get("name", "")).strip()
    if not TOOL_NAME.match(name):
        raise ConfigError(
            f"工具名不合法：{name[:40]!r}。它会作为函数名发给模型，"
            f"按 function calling 的规范只能用小写字母、数字和下划线，不能用中文；"
            f"中文名请写在 label 字段里，界面会显示它。")

    if raw.get("impl") is not None:
        return _check_impl(raw, name)
    if raw.get("binary") is None and raw.get("argv") is None:
        _no_groups(raw, name)
    if raw.get("mcp") is not None:
        _no_os(raw, name, " MCP 型")
        return _check_mcp_tool(raw, name)
    if raw.get("script"):
        spec = _check_script_tool(raw, name)
        spec["group"] = _common(raw, name)["group"]
        return spec
    if raw.get("http") is not None:
        _no_os(raw, name, "接口型")
        return _check_http_tool(raw, name)
    if raw.get("sql") is not None:
        raise ConfigError(f"{name}：sql 工具只能写成 impl: {{type: sql, conn: 连接名, query: …, max_rows: …}}")
    return _check_command_tool(raw, name)


def _no_groups(raw, name):
    if raw.get("groups") is not None:
        raise ConfigError(f"{name} 不是命令型工具，不能声明适用分组 groups：只有命令型工具在远程主机上跑")


_interpreter = ops_exec.interpreter
MAX_ARGV = ops_exec.MAX_ARGV
MAX_ARG_LEN = ops_exec.MAX_ARG_LEN


def _check_command_tool(raw, name):
    binary, argv, params = ops_exec.check_command(name, raw.get("binary", ""), raw.get("argv"), raw.get("params"))
    return {**_common(raw, name), "binary": binary, "argv": argv, "params": params,
            "type": "command", "os": _check_os(name, raw.get("os")),
            "groups": _check_groups(name, raw.get("groups"))}


# impl 里每种实现认哪些字段。不认识的一律报错而不是忽略：比如写了 via: ssh 却被悄悄当成本机执行，
# 比加载失败危险得多。在哪台主机上跑是主机清单（hosts）和 target 参数的事，不写在工具上。
IMPL_FIELDS = {
    "builtin": ("func",),
    "command": ("argv", "binary", "os", "groups"),
    "script": ("script", "os"),
    "http": ("url", "conn", "method", "query", "headers", "pick", "notes", "external"),
    "sql": ("conn", "query", "max_rows"),
    "mcp": ("server", "tool"),
}
LEGACY_FIELDS = ("binary", "argv", "script", "http", "mcp", "sql")


def _check_impl(raw, name):
    impl = raw["impl"]
    if not isinstance(impl, dict):
        raise ConfigError(f"{name}.impl 必须是映射：{{type: {' | '.join(IMPL_FIELDS)}, …}}")
    kind = str(impl.get("type", "")).strip()
    if kind not in IMPL_FIELDS:
        raise ConfigError(f"{name}.impl.type 只能是 {'、'.join(IMPL_FIELDS)} 之一，不是 {kind[:20]!r}")
    mixed = [key for key in LEGACY_FIELDS if raw.get(key) is not None]
    if mixed:
        raise ConfigError(f"{name} 同时写了 impl 和老写法的 {'、'.join(mixed)}，两种写法只能选一种")
    if raw.get("os") is not None:
        raise ConfigError(f"{name}.os 要写在 impl 里：适用哪种系统是实现的事，不是能力的事")
    if raw.get("groups") is not None:
        raise ConfigError(f"{name}.groups 要写在 impl 里：适用哪些主机分组是实现的事，不是能力的事")
    unknown = sorted(str(key) for key in impl if key != "type" and key not in IMPL_FIELDS[kind])
    if unknown:
        raise ConfigError(f"{name}.impl 里有不认识的字段 {'、'.join(unknown)}"
                          f"（{kind} 型只认 {'、'.join(IMPL_FIELDS[kind])}）")
    body = {key: value for key, value in impl.items() if key != "type"}
    base = {key: value for key, value in raw.items() if key != "impl"}
    if kind == "builtin":
        return _check_builtin_tool(base, name, body)
    if kind == "command":
        argv = body.get("argv")
        if not isinstance(argv, list) or not argv:
            raise ConfigError(f"{name}.impl.argv 必须是非空列表，第一项就是要执行的命令")
        binary = body.get("binary") or argv[0]
        return _check_command_tool({**base, "binary": binary, "argv": argv, "os": body.get("os"),
                                    "groups": body.get("groups")}, name)
    if kind == "script":
        spec = _check_script_tool({**base, "script": str(body.get("script") or ""), "os": body.get("os")}, name)
        spec["group"] = _common(base, name)["group"]
        return spec
    if kind == "http":
        return _check_http_tool({**base, "http": body}, name)
    if kind == "sql":
        return _check_sql_tool({**base, "sql": body}, name)
    return _check_mcp_tool({**base, "mcp": body}, name)


# ---- sql：只读的查询模板 ---------------------------------------------------------------
# 查询由管理员写成模板，模型只能填参数，参数一律用驱动的占位符绑定，从不拼进 SQL 文本。只读有三层：
#   1. 连接用只读账号（文档要求，见 docs/工具.md）；
#   2. 工具服务以只读方式执行：sqlite 只读打开 + query_only + 授权回调只放行读；PostgreSQL 只读事务
#      （default_transaction_read_only + BEGIN READ ONLY）；MySQL START TRANSACTION READ ONLY；
#   3. 模板只能是一条 SELECT 或 WITH：不能有分号、注释、反斜杠、$ ? { }，写语句和副作用函数的关键字一律拒绝。
# 另有语句超时、最多行数、每格和整体的输出上限，输出里出现的连接凭据（密码、来自 ${名字} 的地址和账号）替换成 ***。
#
#   - name: cmdb_host
#     params: {host: {type: str, pattern: name, required: true}}
#     impl: {type: sql, conn: cmdb, query: "SELECT owner, env FROM v_hosts WHERE hostname = :host", max_rows: 5}

SQL_MAX = 4000
SQL_PLACEHOLDER = re.compile(r":([a-z_][a-z0-9_]*)")
SQL_WORD = re.compile(r"[A-Za-z_][A-Za-z0-9_$]*")
# 引号外出现这些词就拒绝：写语句（WITH 里的 DELETE、SELECT … INTO、FOR UPDATE 也都靠它拦）、导入导出、锁
SQL_DENY_WORDS = frozenset({
    "insert", "update", "delete", "merge", "upsert", "into", "truncate", "drop", "alter", "create", "grant",
    "revoke", "copy", "call", "exec", "execute", "attach", "detach", "pragma", "vacuum", "reindex", "lock",
    "unlock", "handler", "outfile", "dumpfile", "prepare", "deallocate", "notify", "listen", "savepoint",
    "commit", "rollback", "begin"})
# 有副作用、能读服务器文件、能拖住数据库的函数
SQL_DENY_FUNCS = frozenset({
    "pg_read_file", "pg_read_binary_file", "pg_ls_dir", "pg_stat_file", "lo_import", "lo_export", "lo_get",
    "lo_put", "lo_from_bytea", "dblink", "dblink_exec", "dblink_connect", "pg_sleep", "pg_sleep_for",
    "pg_sleep_until", "pg_terminate_backend", "pg_cancel_backend", "pg_reload_conf", "pg_rotate_logfile",
    "set_config", "nextval", "setval", "pg_advisory_lock", "pg_notify", "load_file", "sleep", "benchmark",
    "get_lock", "release_lock", "sys_exec", "sys_eval", "load_extension", "readfile", "writefile", "edit",
    "fts3_tokenizer"})


def _sql_segments(owner, query):
    """查询模板 → [("text", 原文) | ("param", 参数名)]。逐字扫一遍，引号里的内容原样保留、不当成语法。

    扫描时顺带落实第三层：一条语句、没有注释、没有 $ ? { } 反斜杠、冒号只用于 :参数 和 :: 类型转换。
    返回 (片段, 引号外的文字)：后者给关键字检查用，引号里的字符串字面量、带引号的标识符都换成了空格。
    """
    if "\\" in query or "\x00" in query:
        raise ConfigError(f"{owner} 里不能有反斜杠（各家数据库对它的转义规则不一样，扫描和执行会理解得不一样）")
    segments, outside, buffer, i, n = [], [], [], 0, len(query)
    while i < n:
        char = query[i]
        if char in "'\"`":
            end = i + 1
            while True:
                end = query.find(char, end)
                if end < 0:
                    raise ConfigError(f"{owner} 的引号没有闭合")
                if end + 1 < n and query[end + 1] == char:   # 两个引号是转义的一个引号
                    end += 2
                    continue
                break
            buffer.append(query[i:end + 1])
            outside.append(" ")
            i = end + 1
            continue
        if char == ";":
            raise ConfigError(f"{owner} 只能是一条语句，中间不能有分号")
        if query.startswith("--", i) or query.startswith("/*", i) or char == "#":
            raise ConfigError(f"{owner} 里不能有注释（-- /* #）")
        if char in "$?{}":
            raise ConfigError(f"{owner} 里不能有 {char}：参数只能写成 :名字")
        if char == ":":
            if query.startswith("::", i):
                buffer.append("::")
                outside.append(" :: ")
                i += 2
                continue
            found = SQL_PLACEHOLDER.match(query, i)
            if not found:
                raise ConfigError(f"{owner} 里的冒号后面要跟参数名（:小写名字），或者写成 :: 类型转换")
            if buffer:
                segments.append(("text", "".join(buffer)))
                buffer = []
            segments.append(("param", found.group(1)))
            outside.append(" ")
            i = found.end()
            continue
        buffer.append(char)
        outside.append(char)
        i += 1
    if buffer:
        segments.append(("text", "".join(buffer)))
    return segments, "".join(outside)


def _check_sql_query(owner, query, params):
    """校验查询模板（第三层），返回 (去掉结尾分号的模板, 片段)。"""
    text = query.strip()
    if text.endswith(";"):
        text = text[:-1].rstrip()
    if not text:
        raise ConfigError(f"{owner} 不能为空")
    if len(text) > SQL_MAX:
        raise ConfigError(f"{owner} 太长：最多 {SQL_MAX} 个字符")
    segments, outside = _sql_segments(owner, text)
    words = [word.lower() for word in SQL_WORD.findall(outside)]
    if not words or words[0] not in ("select", "with"):
        raise ConfigError(f"{owner} 只能是一条 SELECT 或 WITH 查询")
    denied = [word for word in words if word in SQL_DENY_WORDS]
    if denied:
        raise ConfigError(f"{owner} 里有 {denied[0].upper()}：查询模板只能读，不能有写语句、导入导出和加锁")
    denied = [word for word in words if word in SQL_DENY_FUNCS]
    if denied:
        raise ConfigError(f"{owner} 用了函数 {denied[0]}：它有副作用、能读服务器上的文件或拖住数据库，不能用")
    used = [value for kind, value in segments if kind == "param"]
    for name in used:
        if name not in params:
            raise ConfigError(f"{owner} 用到了未声明的参数 {name}")
    for name in params:
        if name not in used:
            raise ConfigError(f"{owner} 没有用到参数 {name}：声明了就要用 :{name} 写进查询")
    return text, segments


def _check_sql_tool(raw, name):
    """sql 工具：模板 + 参数，连接（地址、账号、密码）由管理员在主配置的 connections 里定。"""
    sql = raw.get("sql")
    if not isinstance(sql, dict):
        raise ConfigError(f"{name}.impl 必须是映射")
    params = _check_params(name, raw)
    conn = str(sql.get("conn") or "").strip()
    if not CONN_NAME.match(conn):
        raise ConfigError(f"{name}.impl.conn 要写主配置里一个数据库连接的名字")
    query = sql.get("query")
    if not isinstance(query, str):
        raise ConfigError(f"{name}.impl.query 要写成一条 SELECT 或 WITH 查询")
    query, segments = _check_sql_query(f"{name}.impl.query", query, params)
    rows = sql.get("max_rows", SQL_ROWS[0])
    if isinstance(rows, bool) or not isinstance(rows, int) or not SQL_ROWS[1] <= rows <= SQL_ROWS[2]:
        raise ConfigError(f"{name}.impl.max_rows 要是 {SQL_ROWS[1]}..{SQL_ROWS[2]} 之间的整数")
    return {**_common(raw, name), "type": "sql", "binary": "", "argv": [], "params": params,
            "sql": {"conn": conn, "query": query, "max_rows": rows, "segments": segments}}


# ---- 内置函数（builtin）--------------------------------------------------------
# 纯计算，随工具服务的代码发布：没有副作用，不碰网络和文件，也不依赖本机装了什么命令，所以在哪台机器上都能用。
# 只能在代码里定义；配置按名字引用（impl: {type: builtin, func: date_info}），页面不能申请。

WEEKDAYS = ("Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday")


def _builtin_date_info(values):
    """星期几、当年第几周，输出和 date -d DAY '+%Y-%m-%d %A 第%V周' 逐字一致（C / en_US 语言环境）。"""
    text = values["day"]
    year, month, day = (int(part) for part in text.split("-"))
    # GNU date 认 0000 年，Python 不认。公历 400 年一个周期（146097 天，正好整周），借 400 年算，星期、周数都一样
    try:
        value = datetime.date(year or 400, month, day)
    except ValueError:
        raise ValueError(f"日期不存在：{text}") from None
    return f"{text} {WEEKDAYS[value.weekday()]} 第{value.isocalendar()[1]:02d}周"


BUILTINS = {
    "date_info": {
        "label": "日期是星期几", "group": "日历",
        "desc": "查某个日期是星期几、当年第几周。推算请假天数、跨周末时用它，不要自己心算星期。",
        "params": {"day": {"type": "str", "pattern": "date", "required": True, "desc": "日期，格式 YYYY-MM-DD"}},
        "run": _builtin_date_info,
    },
}


def _check_builtin_tool(base, name, body):
    """参数由函数决定。配置可以不写 params（用函数自带的），写了就要和函数对得上：名字、类型、预置正则一致。"""
    func = str(body.get("func", "")).strip()
    builtin = BUILTINS.get(func)
    if builtin is None:
        raise ConfigError(f"{name}.impl.func 不是内置函数：{func[:40]!r}（现有：{'、'.join(sorted(BUILTINS))}）")
    expected = _check_params(name, {"params": builtin["params"]})
    if base.get("params") is None:
        params = expected
    else:
        params = _check_params(name, base)
        if sorted(params) != sorted(expected):
            raise ConfigError(f"{name} 的参数要和内置函数 {func} 一致：{'、'.join(sorted(expected)) or '（无参数）'}")
        for key, spec in params.items():
            if (spec["type"], spec.get("pattern")) != (expected[key]["type"], expected[key].get("pattern")):
                want = expected[key].get("pattern") or expected[key]["type"]
                raise ConfigError(f"{name}.params.{key} 的类型要和内置函数 {func} 一致（{want}）")
    common = _common(base, name)
    return {**common, "label": common["label"] or builtin["label"], "desc": common["desc"] or builtin["desc"],
            "group": common["group"] or builtin["group"],
            "type": "builtin", "builtin": func, "binary": "", "argv": [], "params": params}


def _run_builtin(spec, args):
    args = args or {}
    try:
        values = {key: _value(key, param, args) for key, param in spec["params"].items()}
        values = {key: int(value) if spec["params"][key]["type"] == "int" else value
                  for key, value in values.items()}
        output = str(BUILTINS[spec["builtin"]]["run"](values))
    except ValueError as exc:
        return {"ok": False, "error": str(exc)}
    except Exception as exc:   # 内置函数出错是工具服务自己的 bug，也不能把 /exec 弄崩
        return {"ok": False, "error": f"内置函数 {spec['builtin']} 执行失败：{exc.__class__.__name__}: {exc}"}
    truncated = len(output) > MAX_OUTPUT
    call = ", ".join(f"{key}={value}" for key, value in values.items())
    return {"ok": True, "command": f"{_display(spec)}({call})",
            "output": output[:MAX_OUTPUT] + ("\n…（输出已截断）" if truncated else "")}


# ---- 连接 --------------------------------------------------------------------
# 一个数据源的地址和凭据引用，写在主文件顶层 connections 里，多个工具用 conn: 共用。
# 地址和凭据去哪儿是宿主机管理员的决定：被 include 的文件、页面申请都只能引用已有的连接，不能新建。
#
#   connections:
#     - {name: prom, type: http, base: https://prom.example.internal:9090, ca: /etc/ops-readonly/prom-ca.pem,
#        bearer: ${prom_token}}
#     - {name: k8s, type: http, base: https://127.0.0.1:16443, ca: ${k8s_ca}, bearer_file: /etc/ops-readonly/k8s-token}
#     - {name: cmdb, type: postgres, host: db.example.internal, database: cmdb, user: doc2sop_ro,
#        password: ${cmdb_password}}
#     - {name: assets, type: sqlite, path: /srv/data/assets.db}

def _check_conn_base(name, base):
    env_base = ENV_BASE.match(base)
    if env_base:
        _check_secret_refs(f"连接 {name}", base)
        rest = env_base.group(2)
    else:
        literal = re.match(r"^https?://([^/?#]+)(.*)$", base)
        if not literal:
            raise ConfigError(f"连接 {name} 的 base 必须以 http:// 或 https:// 开头，或者以 ${{名字}} 开头")
        if re.search(r"[{}$@]", literal.group(1)):
            raise ConfigError(f"连接 {name} 的 base 主机名部分不能有参数、变量或用户名密码（凭据写在 headers 里）")
        rest = literal.group(2)
    if rest and not rest.startswith("/"):
        raise ConfigError(f"连接 {name} 的 base 主机名后面必须直接是路径（以 / 开头）")
    if re.search(r"[{}$?#]", rest):
        raise ConfigError(f"连接 {name} 的 base 只能是地址前缀，不能带参数、查询串或变量")
    return base.rstrip("/")


def _ref_or_literal(owner, raw, literal=None, what="值"):
    """一个字段：要么整个是凭据引用 ${名字}，要么是符合 literal 的字面量（literal 为 None 表示只能写引用）。"""
    text = str(raw if raw is not None else "").strip()
    found = KEY_REF.match(text)
    if found:
        if _secret_env(found.group(1)) is None:
            raise ConfigError(f"{owner} 引用了 {text}；凭据只能写成 ${{小写名字}}（环境变量 {SECRET_PREFIX}大写名字）"
                              f"或 ${{{SECRET_PREFIX}…}}")
        return text
    if literal is None:
        raise ConfigError(f"{owner} 只能写凭据引用 ${{名字}}（值放在宿主机环境变量里），不能直接写{what}")
    if not literal.match(text):
        raise ConfigError(f"{owner} 不合法：{text[:60]!r}")
    return text


def _resolve(text, used=None):
    """字段的值：${名字} 取凭据（记进 used，输出脱敏用），字面量原样。凭据没配置抛 ValueError。"""
    found = KEY_REF.match(text or "")
    if not found:
        return text
    value = _secret(found.group(1))
    if used is not None:
        used.append(value)
    return value


ABS_PATH = re.compile(r"^(/|[A-Za-z]:[\\/])[^\x00\r\n]{0,4000}$")


def _check_path_value(owner, raw):
    return _ref_or_literal(owner, raw, ABS_PATH, "路径")


_ssl_cache = {}
_ssl_lock = threading.Lock()


def _ssl_context(cafile):
    """只信这一个 CA 文件的 TLS 上下文（不再信系统自带的根证书）。文件换了（mtime、大小变了）就重新读。"""
    try:
        info = os.stat(cafile)
    except OSError as exc:
        raise ConfigError(f"CA 文件读不到（{exc.strerror or exc.__class__.__name__}）") from None
    if not stat.S_ISREG(info.st_mode):
        raise ConfigError("CA 文件不是普通文件")
    key = (cafile, info.st_mtime_ns, info.st_size)
    with _ssl_lock:
        context = _ssl_cache.get(key)
        if context is None:
            try:
                context = ssl.create_default_context(cafile=cafile)
            except (ssl.SSLError, OSError, ValueError) as exc:
                raise ConfigError(f"CA 文件不是合法的 PEM 证书（{exc.__class__.__name__}）") from None
            if len(_ssl_cache) > 32:
                _ssl_cache.clear()
            _ssl_cache[key] = context
    return context


def _check_ca(owner, raw):
    """ca：固定路径或 ${名字}（值是路径）。加载时就读一遍：文件不在、不是合法的 PEM 证书，连接不加载。"""
    if raw is None or str(raw).strip() == "":
        return ""
    text = _check_path_value(f"{owner} 的 ca", raw)
    try:
        _ssl_context(_resolve(text))
    except (ValueError, ConfigError) as exc:
        raise ConfigError(f"{owner} 的 ca：{exc}") from None
    return text


def _check_external(owner, raw):
    if raw is None:
        return None
    if not isinstance(raw, bool):
        raise ConfigError(f"{owner} 的 external 只能写 true 或 false")
    return raw


def _bounded_int(owner, raw, field, bounds):
    default, low, high = bounds
    value = raw.get(field, default)
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise ConfigError(f"{owner} 的 {field} 要是 {low}..{high} 之间的整数")
    return value


def _check_http_connection(name, entry):
    owner = f"连接 {name}"
    base = _check_conn_base(name, str(entry.get("base", "")).strip())
    headers = entry.get("headers") or {}
    if not isinstance(headers, dict):
        raise ConfigError(f"{owner} 的 headers 必须是映射")
    clean = {}
    for key, value in headers.items():
        key, value = str(key), str(value)
        if not HEADER_NAME.match(key):
            raise ConfigError(f"{owner} 的请求头名字不合法：{key[:40]!r}")
        if URL_PARAM.search(SECRET_REF.sub("", value)):
            raise ConfigError(f"{owner} 的请求头 {key} 只能写固定值或凭据引用 ${{名字}}")
        _check_secret_refs(f"{owner} 的请求头 {key}", value)
        clean[key] = value
    bearer = entry.get("bearer")
    bearer = "" if bearer in (None, "") else _ref_or_literal(f"{owner} 的 bearer", bearer, None, "令牌")
    bearer_file = entry.get("bearer_file")
    bearer_file = "" if bearer_file in (None, "") else _check_path_value(f"{owner} 的 bearer_file", bearer_file)
    if bearer and bearer_file:
        raise ConfigError(f"{owner} 的 bearer 和 bearer_file 只能写一个")
    if (bearer or bearer_file) and any(key.lower() == "authorization" for key in clean):
        raise ConfigError(f"{owner} 写了 bearer，就不能再写 Authorization 请求头")
    return {"base": base, "headers": clean, "ca": _check_ca(owner, entry.get("ca")),
            "bearer": bearer, "bearer_file": bearer_file}


def _check_db_connection(name, kind, entry):
    owner = f"连接 {name}"
    if kind == "sqlite":
        if entry.get("path") in (None, ""):
            raise ConfigError(f"{owner} 缺少 path：sqlite 数据库文件的绝对路径，或 ${{名字}}")
        return {"path": _check_path_value(f"{owner} 的 path", entry["path"]),
                "timeout": _bounded_int(owner, entry, "timeout", SQL_TIMEOUT)}
    port = entry.get("port", DB_PORTS[kind])
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise ConfigError(f"{owner} 的 port 要是 1..65535 的整数")
    password = entry.get("password")
    tls = str(entry.get("tls") or DB_TLS[kind][0 if kind == "mysql" else 1]).strip()
    if tls not in DB_TLS[kind]:
        raise ConfigError(f"{owner} 的 tls 只能是 {'、'.join(DB_TLS[kind])}")
    out = {"host": _ref_or_literal(f"{owner} 的 host", entry.get("host"), HOST_ADDRESS, "地址"), "port": port,
           "database": _ref_or_literal(f"{owner} 的 database", entry.get("database"), DB_IDENT, "库名"),
           "user": _ref_or_literal(f"{owner} 的 user", entry.get("user"), DB_IDENT, "账号"),
           "password": "" if password in (None, "") else _ref_or_literal(f"{owner} 的 password", password, None, "密码"),
           "tls": tls, "ca": _check_ca(owner, entry.get("ca")),
           "timeout": _bounded_int(owner, entry, "timeout", SQL_TIMEOUT)}
    if out["ca"] and tls == "disable":
        raise ConfigError(f"{owner} 写了 ca，tls 就不能是 disable")
    return out


def _check_connections(document, problems, broken=None):
    """主文件顶层 connections → {name: 连接}。坏条目跳过并记 problem，不拖垮别的连接和工具。

    broken 收集写坏了的连接名 → 原因：引用它们的工具报「连接写错了」，而不是「引用了未声明的连接」。
    """
    raw = document.get("connections")
    if raw is None:
        return {}
    if not isinstance(raw, list):
        problems.append("connections 必须是列表：- {name, type: http | postgres | mysql | sqlite, …}")
        return {}
    out = {}
    for entry in raw:
        name = ""
        try:
            if not isinstance(entry, dict):
                raise ConfigError("connections 的每一项必须是映射")
            name = str(entry.get("name", "")).strip()
            if not CONN_NAME.match(name):
                raise ConfigError(f"连接名不合法：{name[:40]!r}，只能用小写字母、数字、下划线")
            if name in out:
                raise ConfigError(f"连接名重复：{name}")
            kind = str(entry.get("type", "")).strip()
            if kind not in CONN_TYPES:
                raise ConfigError(f"连接 {name} 的 type 必须是 {'、'.join(CONN_TYPES)}")
            unknown = sorted(str(key) for key in entry if key not in CONN_FIELDS[kind])
            if unknown:
                raise ConfigError(f"连接 {name} 里有不认识的字段 {'、'.join(unknown)}"
                                  f"（{kind} 连接只认 {'、'.join(CONN_FIELDS[kind])}）")
            body = _check_http_connection(name, entry) if kind == "http" else _check_db_connection(name, kind, entry)
            conn = {"name": name, "type": kind, "label": str(entry.get("label", "")).strip()[:MAX_LABEL], **body,
                    "declared_external": _check_external(f"连接 {name}", entry.get("external"))}
            conn["external"], conn["external_why"] = _judge_connection(conn)
            out[name] = conn
        except ConfigError as exc:
            problems.append(str(exc))
            if broken is not None and name and CONN_NAME.match(name):
                broken.setdefault(name, str(exc))
    return out


def _bind_connection(spec, connections, broken=None):
    """接口型、sql 工具用了连接：把连接挂到 spec 上，执行时从这里取地址和凭据。连接不存在、类型不对就不能用。"""
    kind = spec.get("type")
    conn = (spec.get(kind) or {}).get("conn") if kind in ("http", "sql") else ""
    if not conn:
        return spec
    if conn not in connections:
        if broken and conn in broken:
            raise ConfigError(f"{spec['name']} 用的连接 {conn} 写错了，没有加载：{broken[conn]}")
        raise ConfigError(f"{spec['name']} 引用了未声明的连接 {conn}；连接只能由管理员写在主配置文件的 connections 里")
    connection = connections[conn]
    if kind == "http" and connection["type"] != "http":
        raise ConfigError(f"{spec['name']} 是接口型工具，连接 {conn} 却是 {connection['type']} 数据库")
    if kind == "sql" and connection["type"] not in DB_TYPES:
        raise ConfigError(f"{spec['name']} 是 sql 工具，连接 {conn} 却是 {connection['type']} 连接")
    spec["connection"] = connection
    return spec


# ---- 外部：调用会把实参发到组织外面 ------------------------------------------------
# 应用侧对「外部」工具的字符串实参套用出网规则（静态拦截 + 本轮污点），返回标成外部资料。
# 判断依据只有地址：公网 IP、公网主机名是外部；回环、内网 IP、单标签名、常见内网后缀是内部。
# 地址来自 ${名字} 时按取到的值判断，但页面上不显示那个值。管理员可以在连接、MCP server、接口工具上写 external: true/false 覆盖；
# 场景包只能把自己的接口工具声明成外部（更严），写 false 会被忽略并报出来。

def _external_host(host):
    """(是不是外部, 依据)。依据给人看，带主机名。"""
    host = str(host or "").strip().lower().rstrip(".")
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    if not host:
        return False, "没有地址"
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    if address is not None:
        return (True, f"公网地址 {host}") if address.is_global else (False, f"内网地址 {host}")
    if host == "localhost" or "." not in host or host.endswith(INTERNAL_SUFFIXES):
        return False, f"内网主机名 {host}"
    return True, f"公网主机名 {host}"


def _url_host(url):
    try:
        return urllib.parse.urlsplit(str(url or "")).hostname or ""
    except ValueError:
        return ""


def _judge_address(raw, url=True):
    """地址（url=True 时是 http(s) 地址，否则是主机名）→ (是不是外部, 依据)。${名字} 按取到的值判断，依据里不写值。"""
    text = str(raw or "")
    found = ENV_BASE.match(text) if url else KEY_REF.match(text)
    if found:
        env = _secret_env(found.group(1)) or ""
        value = os.environ.get(env, "").strip()
        if not value:
            return False, f"地址 ${{{found.group(1)}}} 还没配置，按内部处理"
        external, _ = _external_host(_url_host(value) if url else value)
        return external, f"按 ${{{found.group(1)}}} 取到的地址判断：{'公网' if external else '内网'}"
    return _external_host(_url_host(text) if url else text)


def _judge_connection(conn):
    declared = conn.get("declared_external")
    if declared is not None:
        return declared, f"管理员声明为{'外部' if declared else '内部'}"
    if conn["type"] == "sqlite":
        return False, "本机的数据库文件"
    if conn["type"] == "http":
        return _judge_address(conn["base"], url=True)
    return _judge_address(conn["host"], url=False)


def _tool_external(spec, servers, problems=None, in_main=True):
    """(是不是外部, 依据)：接口型看自己的声明、连接或地址；sql 看连接；MCP 看 server；命令、内置都不是。"""
    kind = spec.get("type")
    if kind == "http":
        declared = spec["http"].get("external")
        if declared is False and not in_main:
            if problems is not None:
                problems.append(f"{spec['name']} 的 external: false 已忽略：场景包只能把工具声明成外部，"
                                f"要按内部处理请管理员在主配置里声明")
            declared = None
        if declared is not None:
            return declared, f"管理员声明为{'外部' if declared else '内部'}"
        connection = spec.get("connection")
        if connection:
            return connection["external"], f"连接 {connection['name']}：{connection['external_why']}"
        return _judge_address(spec["http"]["url"], url=True)
    if kind == "sql":
        connection = spec.get("connection") or {}
        return bool(connection.get("external")), f"连接 {connection.get('name', '')}：{connection.get('external_why', '')}"
    if kind == "mcp":
        server = servers.get(spec["mcp"]["server"]) or {}
        return bool(server.get("external")), f"MCP server {spec['mcp']['server']}：{server.get('external_why', '')}"
    return False, ""


# ---- 可选依赖：数据库驱动 ------------------------------------------------------------
# 不配数据库连接，就什么都不导入：工具服务照旧只用标准库 + PyYAML。用到哪种数据库才导入它的驱动，缺了只影响
# 用这种连接的工具（不下发、页面写明原因和装法），不影响别的。驱动可以装在系统里，也可以装在本文件旁边的 vendor/：
#     python3 -m pip install --target /opt/ops/vendor 'psycopg[binary]>=3.1,<4' 'PyMySQL>=1.1,<2'

DRIVERS = {"postgres": ("psycopg", "psycopg[binary]>=3.1,<4", "PostgreSQL"),
           "mysql": ("pymysql", "PyMySQL>=1.1,<2", "MySQL"),
           "sqlite": ("sqlite3", "", "SQLite")}
_vendor = {"path": "", "used": False, "problem": ""}
_drivers = {}
_drivers_lock = threading.Lock()


def _vendor_dir():
    return os.environ.get("OPS_VENDOR_DIR") or str(Path(__file__).resolve().parent / "vendor")


def _use_vendor():
    """vendor/ 里的代码会以工具服务的身份（通常是 root）导入，所以和白名单一样把关：是目录、不是符号链接、
    属于工具服务的运行账号、组和其他用户不能写，才加进 sys.path（加在最后，不盖住系统已经装的包）。"""
    path = _vendor_dir()
    _vendor.update(path=path, used=False, problem="")
    try:
        info = os.lstat(path)
    except OSError:
        return
    problem = ""
    if not stat.S_ISDIR(info.st_mode):
        problem = "不是目录（也不能是符号链接）"
    elif os.name == "posix" and info.st_mode & 0o022:
        problem = f"组或其他用户可写（{oct(info.st_mode & 0o777)}），chmod go-w"
    elif os.name == "posix" and info.st_uid != os.geteuid():
        problem = "不属于工具服务的运行账号"
    if problem:
        _vendor["problem"] = f"{path} {problem}：没有用它，里面的驱动不会被导入"
        return
    if path not in sys.path:
        sys.path.append(path)
    _vendor["used"] = True


_use_vendor()


def _driver(kind):
    """(驱动模块, 不可用的原因)。第一次用到时才导入；结果缓存，装好驱动后重启工具服务生效。"""
    with _drivers_lock:
        if kind in _drivers:
            return _drivers[kind]
        module, package, label = DRIVERS[kind]
        try:
            result = (importlib.import_module(module), "")
        except Exception as exc:   # ImportError，或二进制包和这台机器不匹配（OSError）
            hint = ""
            if package:
                hint = (f"；装法：python3 -m pip install --target {_vendor['path'] or _vendor_dir()} '{package}'"
                        f"（或装进系统），装好后重启工具服务")
                if _vendor["problem"]:
                    hint += f"。另外 {_vendor['problem']}"
            result = (None, f"工具服务这台机器没有 {label} 驱动 {module}（{exc.__class__.__name__}）{hint}")
        _drivers[kind] = result
        return result


# ---- 主机清单（hosts）---------------------------------------------------------------
# 命令型工具在「主机」上执行：默认是工具服务自己这台；主文件顶层写了 hosts，就可以经 SSH 在别的 Linux 主机上跑。
# 主机的地址、账号、私钥是宿主机管理员的决定：只认主文件，被 include 的文件里写了忽略并报出来，页面也碰不到。
#
#   hosts:
#     default: local            # 不填 target 时去哪：主机名或 @组名；不写就是本机（有本机的话）
#     local: true               # 工具服务自己这台算不算一台主机（隐含名为 local）；false 就不算
#     defaults: {via: ssh, user: opsread, key: ${ssh_key}, mode: guarded, os: linux}
#     list:
#       - {name: a, via: local, groups: [prod]}          # 可选：给本机起名、分组
#       - {name: b, address: 10.0.0.2, groups: [gateway, prod], tools: [list_containers, host_uptime]}
#
# 没有 hosts 段时一切照旧：命令在本机跑，工具没有 target 参数。

HOST_VIAS = ("local", "ssh")
HOST_MODES = ("guarded", "direct")
HOST_FIELDS = ("name", "address", "port", "user", "key", "os", "groups", "via", "mode", "tools")
LOCAL_FIELDS = ("name", "via", "groups", "tools")
HOST_SETTINGS = ("default", "local", "enum_max", "parallel", "max_targets", "defaults", "list")
# 主机名或 IP（v4/v6）。不能以 - 开头：地址会作为 ssh 的参数，挡住「-oProxyCommand=…」这类选项注入
HOST_ADDRESS = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.:_-]{0,252}$")
HOST_USER = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
HOST_REF = re.compile(r"^@?[a-z0-9][a-z0-9._-]{0,62}$")
KEY_REF = re.compile(r"^\$\{([A-Za-z_][A-Za-z0-9_]*)\}$")
LOCAL_HOST = "local"
TARGET = "target"
LIST_TARGETS = "list_targets"
# 主机不超过 enum_max 台时 target 下发成枚举，超过改成字符串，再提供 list_targets；@组展开后的并发和单次上限
HOST_LIMITS = {"enum_max": (30, 1, 1000), "parallel": (5, 1, 32), "max_targets": (20, 1, 500)}


def _host_setting(raw, key, problems):
    default, low, high = HOST_LIMITS[key]
    value = raw.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        problems.append(f"hosts.{key} 要是 {low}..{high} 之间的整数，已按 {default} 处理")
        return default
    return value


def _host_names(owner, field, raw, pattern=HOST_NAME, reserved=()):
    if raw is None:
        return None
    items = raw if isinstance(raw, list) else [raw]
    out = []
    for value in items:
        text = str(value).strip()
        if not pattern.match(text) or text in reserved:
            raise ConfigError(f"{owner} 的 {field} 里有不合法的名字：{text[:40]!r}")
        if text not in out:
            out.append(text)
    return out


def _check_host(entry, defaults):
    """hosts.list 的一项。不认识的字段、写错的值整条拒绝：主机写错了宁可用不了，也不能连到别处去。"""
    if not isinstance(entry, dict):
        raise ConfigError("hosts.list 的每一项必须是映射：{name, address, …}")
    name = str(entry.get("name", "")).strip()
    if not HOST_NAME.match(name):
        raise ConfigError(f"主机名不合法：{name[:40]!r}（小写字母或数字开头，可含 . _ -，最长 63）")
    unknown = sorted(str(key) for key in entry if key not in HOST_FIELDS)
    if unknown:
        raise ConfigError(f"主机 {name} 里有不认识的字段 {'、'.join(unknown)}（只认 {'、'.join(HOST_FIELDS)}）")
    via = str(entry.get("via") or defaults.get("via") or "ssh").strip()
    if via not in HOST_VIAS:
        raise ConfigError(f"主机 {name} 的 via 只能是 local 或 ssh（WinRM、runner 在后续版本），不是 {via[:20]!r}")
    if via == "local":
        # 本机：defaults 只管远程主机；本机条目只能起名、分组、限定开放哪些工具，系统自动识别
        extra = sorted(str(key) for key in entry if key not in LOCAL_FIELDS)
        if extra:
            raise ConfigError(f"主机 {name} 是本机（via: local），不能写 {'、'.join(extra)}")
        return {"name": name, "via": "local",
                "groups": _host_names(f"主机 {name}", "groups", entry.get("groups"), reserved=("all",)) or [],
                "tools": _host_names(f"主机 {name}", "tools", entry.get("tools"), TOOL_NAME)}
    if name == LOCAL_HOST:
        raise ConfigError("主机名 local 留给本机（via: local）")
    merged = {**defaults, **entry}
    address = str(merged.get("address") or "").strip()
    if not HOST_ADDRESS.match(address):
        raise ConfigError(f"主机 {name} 的 address 不合法：{address[:60]!r}（主机名或 IP，不带用户名、端口和空格）")
    port = merged.get("port", 22)
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise ConfigError(f"主机 {name} 的 port 要是 1..65535 的整数")
    user = str(merged.get("user") or "").strip()
    if not HOST_USER.match(user):
        raise ConfigError(f"主机 {name} 缺少 user，或账号名不合法：{user[:40]!r}")
    found = KEY_REF.match(str(merged.get("key") or "").strip())
    if not found or _secret_env(found.group(1)) is None:
        raise ConfigError(f"主机 {name} 的 key 要写成凭据引用 ${{名字}}（环境变量 {SECRET_PREFIX}名字 里放私钥文件的路径），"
                          f"不能直接写路径或私钥")
    system = str(merged.get("os") or "").strip().lower()
    if system not in OS_NAMES:
        raise ConfigError(f"主机 {name} 要写 os（{'、'.join(OS_NAMES)}）：工具按它判断能不能在这台主机上跑")
    if system == "windows":
        raise ConfigError(f"主机 {name}：Windows 主机还不支持（WinRM 在后续版本）")
    mode = str(merged.get("mode") or "guarded").strip()
    if mode not in HOST_MODES:
        raise ConfigError(f"主机 {name} 的 mode 只能是 guarded（受控，默认）或 direct（直连），不是 {mode[:20]!r}")
    return {"name": name, "via": "ssh", "address": address, "port": port, "user": user, "key": found.group(1),
            "os": system, "mode": mode,
            "groups": _host_names(f"主机 {name}", "groups", merged.get("groups"), reserved=("all",)) or [],
            "tools": _host_names(f"主机 {name}", "tools", merged.get("tools"), TOOL_NAME)}


def _check_hosts(document, problems):
    """主文件顶层 hosts → 主机清单；没写 hosts 返回 None（老行为）。坏条目跳过并记 problem，不拖垮别的主机。

    写了 hosts（哪怕是空的）就进入主机模式：命令型工具多一个 target 参数。整段写坏时按「只有本机」处理——
    模型能指定的 target 只有本机，一个本来要发去别的主机的调用不会被悄悄当成本机执行。
    """
    if "hosts" not in document:
        return None
    raw = document.get("hosts")
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        problems.append("hosts 必须是映射：{defaults: {…}, list: [{name, address, …}]}，已按只有本机处理")
        raw = {}
    unknown = sorted(str(key) for key in raw if key not in HOST_SETTINGS)
    if unknown:
        problems.append(f"hosts 里有不认识的字段 {'、'.join(unknown)}（只认 {'、'.join(HOST_SETTINGS)}），已忽略")
    settings = {key: _host_setting(raw, key, problems) for key in HOST_LIMITS}
    defaults = raw.get("defaults") or {}
    if not isinstance(defaults, dict):
        problems.append("hosts.defaults 必须是映射，已忽略")
        defaults = {}
    wrong = sorted(str(key) for key in defaults if key not in HOST_FIELDS or key in ("name", "address"))
    if wrong:
        problems.append(f"hosts.defaults 里不能写 {'、'.join(wrong)}，整个 defaults 已忽略")
        defaults = {}
    entries = raw.get("list") or []
    if not isinstance(entries, list):
        problems.append("hosts.list 必须是列表")
        entries = []

    hosts = {}
    for entry in entries:
        try:
            host = _check_host(entry, defaults)
        except ConfigError as exc:
            problems.append(str(exc))
            continue
        if host["name"] in hosts:
            problems.append(f"主机名重复：{host['name']}")
            continue
        if host["via"] == "local" and any(h["via"] == "local" for h in hosts.values()):
            problems.append(f"主机 {host['name']}：本机（via: local）只能有一台，已忽略")
            continue
        hosts[host["name"]] = host

    keep_local = raw.get("local", True)
    if not isinstance(keep_local, bool):
        problems.append("hosts.local 只能是 true 或 false，已按 true 处理")
        keep_local = True
    local = next((h["name"] for h in hosts.values() if h["via"] == "local"), None)
    if local is None and keep_local:
        hosts = {LOCAL_HOST: {"name": LOCAL_HOST, "via": "local", "groups": [], "tools": None, "implicit": True},
                 **hosts}
        local = LOCAL_HOST
    elif local is not None and not keep_local:
        problems.append(f"hosts.local: false 和本机条目 {local} 矛盾，已按有本机处理")

    groups = {}
    for host in hosts.values():
        for group in host["groups"]:
            groups.setdefault(group, []).append(host["name"])
    groups["all"] = list(hosts)

    default = local or ""
    if raw.get("default") is not None:
        wanted = str(raw.get("default")).strip()
        if wanted.startswith("@") and wanted[1:] in groups or wanted in hosts:
            default = wanted
        else:
            problems.append(f"hosts.default 不是已声明的主机或 @组：{wanted[:40]!r}，"
                            f"已按{'本机 ' + local if local else '没有默认主机'}处理")
    return {"hosts": hosts, "groups": groups, "default": default, "local": local, **settings}


def _bind_hosts(hosts, tools, problems):
    """主机模式下的两条加载期规则：target 是保留参数名；主机的 tools 只能列已有的工具。"""
    for name, spec in list(tools.items()):
        if spec.get("type") == "command" and TARGET in spec["params"]:
            problems.append(f"{name} 有参数 target：配了主机清单后，命令型工具自动多一个 target 参数（在哪台主机上跑），"
                            f"这个名字是保留的，已跳过这个工具")
            del tools[name]
    for host in hosts["hosts"].values():
        unknown = [tool for tool in host.get("tools") or [] if tool not in tools]
        if unknown:
            problems.append(f"主机 {host['name']} 的 tools 里有不存在的工具：{'、'.join(unknown)}")
    if len(hosts["hosts"]) > hosts["enum_max"] and LIST_TARGETS in tools:
        problems.append(f"{LIST_TARGETS} 是保留名（主机多于 {hosts['enum_max']} 台时由工具服务提供），配置里的同名工具已跳过")
        del tools[LIST_TARGETS]


def _yaml():
    try:
        import yaml
    except ImportError:
        raise ConfigError("需要 PyYAML：apt install python3-yaml") from None
    return yaml


def _read_yaml(path, text=None):
    """Read a yaml mapping. A missing file is simply empty.

    text：已经拿到手的内容（批准前验证插入结果时用），按 path 那个文件来解析，不再读盘。
    """
    try:
        if text is None:
            with open(path, encoding="utf-8") as handle:
                document = _yaml().safe_load(handle) or {}
        else:
            document = _yaml().safe_load(text) or {}
    except FileNotFoundError:
        return {}
    except Exception as exc:
        raise ConfigError(f"读取失败 {path}：{exc}") from None
    if not isinstance(document, dict):
        raise ConfigError(f"{path} 的顶层必须是映射")
    return document


def _write_yaml(path, document):
    """Write atomically, so an interrupted write can't leave half a file."""
    # 临时文件名带随机后缀：后台发现线程和页面请求可能同时写同一个文件
    temporary = f"{path}.{secrets.token_hex(3)}.tmp"
    with open(temporary, "w", encoding="utf-8") as handle:
        _yaml().safe_dump(document, handle, allow_unicode=True, sort_keys=False)
    os.replace(temporary, path)


# 待审文件的读-改-写要串行：后台线程写发现结果，页面线程写申请，谁都不能把对方刚写的覆盖掉。
_pending_lock = threading.RLock()


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


def _mcp_file():
    """批准过的 MCP 工具条目。由 approve 命令写、机器维护；root 只读它，不手改。

    不追加进手写主文件，是因为 schema 漂移后重新批准要**替换**同名旧条目——整体重写一个
    没有注释需要保留的文件最干净。手写 allowlist 仍然可以放在主文件或场景包里。
    """
    return _sibling("mcp")


def load_tools(path):
    """Parse the definition file. A bad entry is skipped; a bad file raises."""
    tools, problems, _, _, _ = _load_all(path)
    return tools, problems


def _load_all(path, text=None):
    """load_tools 的完整版：多返回主文件声明的 MCP server 配置、连接和主机清单。

    text：主文件的内容（不给就读 path）。批准申请时用它加载「插入之后」的内容，和服务是同一套逻辑。

    除了自己的 `tools:`，主文件还可以用顶层 `include:` 引入别的定义文件（例如一个场景包的
    tools.yaml）。被包含的文件和主文件同等可信——它们是管理员亲手写进主文件的路径，所以同样
    只能由宿主机 root 维护；它们自己不能再 include，避免链条越拉越长看不清。

    MCP server 只认主文件顶层的 `mcp_servers:`：它是宿主机上要跑的一段代码，必须是 root 在
    主文件里亲手写下的。被包含的文件里出现 mcp_servers 会被忽略并报出来。连接（connections）、主机清单（hosts）
    同理只认主文件：被包含的文件里的工具只能用 conn: 引用主文件的连接，不能自己新建；要在哪些主机上跑由主文件决定。

    对外开放（export）也只认主文件：主文件里工具条目上的 `export: true`，或主文件顶层的 `export: [工具名…]`
    （场景包、批准过的 MCP 工具不在主文件里，用这个列表开放）。被包含的文件和 MCP 批准文件里写的 export 一律忽略并报出来：
    对外开放等于扩大了谁能触发这个工具，属于权限变更，归宿主机管理员。

    凭据同理：不来自主文件的接口型工具，只能经主文件的连接、或发往宿主机环境决定的地址（${…} 开头）用到凭据，
    见 _check_pack_credentials。主文件里写和场景包工具同名的工具，就是替换它的实现（参数要兼容，见 _incompatible）。
    """
    document = _read_yaml(path, text)
    entries = document.get("tools")
    if not isinstance(entries, list):
        raise ConfigError("配置里缺少 tools 列表")
    main = str(path)
    patterns = _include_patterns(document)
    files, problems = _expand_includes(patterns, os.path.dirname(os.path.abspath(main)))
    servers = _check_mcp_servers(document, problems)
    broken = {}
    connections = _check_connections(document, problems, broken)
    exported = _check_export_list(document, problems)
    hosts = _check_hosts(document, problems)

    # 批准文件最先读：同名时它说了算（漂移后重新批准的条目要盖过主文件里的旧条目）。
    sources = []
    mcp_path = str(_mcp_file())
    try:
        approved = _read_yaml(mcp_path).get("tools")
        if isinstance(approved, list):
            sources.append((mcp_path, approved))
    except ConfigError as exc:
        problems.append(str(exc))
    first_include = len(sources) + 1
    sources.append((main, entries))
    for included in files:
        try:
            sub = _read_yaml(included)
        except ConfigError as exc:
            problems.append(str(exc))
            continue
        if sub.get("include"):
            problems.append(f"{included} 里的 include 已忽略：被包含的文件不能再包含别的文件")
        if sub.get("mcp_servers"):
            problems.append(f"{included} 里的 mcp_servers 已忽略：MCP server 只能在主文件里声明")
        if sub.get("connections"):
            problems.append(f"{included} 里的 connections 已忽略：连接（地址和凭据）只能在主文件里声明")
        if sub.get("export") is not None:
            problems.append(f"{included} 里的 export 已忽略：对外开放只能由管理员在主配置文件里标")
        if sub.get("hosts") is not None:
            problems.append(f"{included} 里的 hosts 已忽略：主机清单（地址和私钥）只能在主文件里声明")
        sub_entries = sub.get("tools")
        if not isinstance(sub_entries, list):
            problems.append(f"{included} 缺少 tools 列表")
            continue
        sources.append((included, sub_entries))

    # 场景包（被包含的文件）里各工具的原始条目：主文件写同名工具就是替换它的实现，没写的说明、参数从这里继承
    defaults = {}
    for origin, items in sources[first_include:]:
        for entry in items:
            if isinstance(entry, dict):
                defaults.setdefault(str(entry.get("name", "")).strip(), entry)

    def where(origin):
        return "" if origin == main else f"（{origin}）"

    def admit(entry, origin):
        """一个条目 → 校验、绑定都通过的 spec；不通过返回 None，原因记进 problems。"""
        if origin == main and isinstance(entry, dict):
            entry = _inherit(entry, defaults)
        try:
            spec = _check_tool(entry)
            if origin != main:
                _check_pack_credentials(spec)
        except ConfigError as exc:
            problems.append(f"{exc}{where(origin)}")
            return None
        if spec.get("type") == "script":
            reason = _script_untrusted_reason(spec)
            if reason:
                problems.append(reason)
                return None
        if spec.get("type") == "mcp":
            server = servers.get(spec["mcp"]["server"])
            if server is None:
                problems.append(f"{spec['name']} 引用了未声明的 MCP server {spec['mcp']['server']}{where(origin)}")
                return None
            if spec["group"] == spec["mcp"]["server"]:
                spec["group"] = server["label"]
        try:
            _bind_connection(spec, connections, broken)
        except ConfigError as exc:
            problems.append(f"{exc}{where(origin)}")
            return None
        spec["origin"] = origin
        spec["export"] = _entry_export(entry, spec["name"], origin == main, origin, problems)
        spec["external"], spec["external_why"] = _tool_external(spec, servers, problems, origin == main)
        return spec

    tools = {}

    def replace(existing, entry, origin):
        """主文件里的同名工具替换场景包的默认实现：只比参数，参数兼容就替换（场景包那份不再加载，它的连接也不用存在）；
        不兼容就不替换，仍用场景包的实现，并报出原因。"""
        name = existing["name"]
        try:
            default = _check_tool(entry)
        except ConfigError as exc:
            problems.append(f"{exc}{where(origin)}")
            return
        reason = _incompatible(existing, default)
        if not reason:
            existing["replaces"] = {"pack": _pack_label(origin), "origin": origin, "impl": default["type"]}
            return
        spec = admit(entry, origin)
        problems.append(f"{name}：主配置里的同名工具和场景包 {_pack_label(origin)} 的参数不兼容（{reason}），没有替换"
                        + (f"，仍用场景包的实现（{origin}）" if spec is not None else ""))
        if spec is not None:
            tools[name] = spec

    for origin, items in sources:
        for entry in items:
            name = str(entry.get("name", "")).strip() if isinstance(entry, dict) else ""
            existing = tools.get(name)
            if existing is not None and existing["origin"] == main and origin not in (main, mcp_path):
                replace(existing, entry, origin)
                continue
            spec = admit(entry, origin)
            if spec is None:
                continue
            existing = tools.get(spec["name"])
            if existing is None:
                tools[spec["name"]] = spec
            elif existing["origin"] == mcp_path and origin != mcp_path:
                problems.append(f"{spec['name']} 已被 {os.path.basename(mcp_path)} 里批准的条目覆盖{where(origin)}")
            else:
                problems.append(f"工具名重复：{spec['name']}" + ("" if origin == main else f"（{origin}，已忽略）"))
    for name in sorted(exported):
        if name in tools:
            tools[name]["export"] = True
        else:
            problems.append(f"顶层 export 里的 {name} 不是已加载的工具，已忽略")
    if hosts is not None:
        _bind_hosts(hosts, tools, problems)
    return tools, problems, servers, connections, hosts


# ---- 场景包的凭据只能发往管理员定的地址；主文件写同名工具替换场景包的实现 ---------------------------

def _secret_family(env):
    """OPS_SECRET_GATEWAY_URL → OPS_SECRET_GATEWAY：同一组凭据的前缀（去掉最后一段）。"""
    rest = env[len(SECRET_PREFIX):]
    parts = rest.split("_")
    return SECRET_PREFIX + ("_".join(parts[:-1]) if len(parts) > 1 else rest)


def _check_pack_credentials(spec):
    """不来自主配置文件的接口型工具，凭据只能：

    - 经主文件里管理员建的连接（conn:）——这时工具自己不能再引用任何凭据：连接里「哪个凭据发往哪个地址」是管理员配好的，
      包再加一个别的凭据发过去，就把这层配对拆了；
    - 或者发往地址本身来自 ${…} 的主机（主机由宿主机环境决定）——这时只能引用和地址同一组的凭据：地址是
      ${GATEWAY_URL}，就只能引用 ${GATEWAY_…}，不能把 ${DB_PASSWORD} 发给模型网关；
    - 「字面主机 + 凭据」一律不加载：包作者写一个自己的地址，就能把宿主机上的凭据带走。
    """
    if spec.get("type") != "http":
        return
    http, name = spec["http"], spec["name"]
    texts = [http["url"], *http["query"].values(), *http["headers"].values()]
    refs = [ref for text in texts for ref in SECRET_REF.findall(text)]
    if http.get("conn"):
        if refs:
            raise ConfigError(f"{name} 用了连接 {http['conn']}，又自己引用了凭据 ${{{refs[0]}}}："
                              f"场景包里的工具只能用连接里管理员配好的凭据")
        return
    base = ENV_BASE.match(http["url"])
    if base is None:
        if refs:
            raise ConfigError(f"{name} 的地址是写死的主机，又引用了凭据 ${{{refs[0]}}}：场景包里的工具不能把凭据发往"
                              f"自己写的地址，只能经主配置里的连接，或者地址本身来自 ${{…}}（由宿主机环境决定）")
        return
    home = _secret_env(base.group(1))
    family = _secret_family(home)
    for ref in refs:
        env = _secret_env(ref)
        if env != home and not env.startswith(family + "_"):
            raise ConfigError(f"{name} 的地址来自 ${{{base.group(1)}}}，只能引用同一组的凭据（{family[len(SECRET_PREFIX):]}_…），"
                              f"不能引用 ${{{ref}}}：哪个凭据发往哪个地址要由管理员决定；需要的话把这个工具写进主配置，"
                              f"或者在主配置里建一个连接")


INHERITED = ("params", "label", "desc", "group")


def _inherit(entry, defaults):
    """主文件里替换场景包工具的条目：没写的参数、说明、显示名、分组沿用场景包的（能力不变，只换实现）。"""
    raw = defaults.get(str(entry.get("name", "")).strip())
    if raw is None:
        return entry
    merged = dict(entry)
    for key in INHERITED:
        if key not in merged and key in raw:
            merged[key] = raw[key]
    return merged


def _incompatible(new, old):
    """替换实现的参数和场景包的是否兼容：名字、类型、必填一致，pattern、范围、枚举不能放宽。返回原因，兼容时是空串。

    target 由系统处理（命令型工具在主机模式下自动多出来），两边都不比。SOP 引用的是工具名和参数，兼容就照常能跑。
    """
    mine = {k: v for k, v in (new.get("params") or {}).items() if k != TARGET}
    theirs = {k: v for k, v in (old.get("params") or {}).items() if k != TARGET}
    if sorted(mine) != sorted(theirs):
        return (f"参数名不一致：场景包是 {'、'.join(sorted(theirs)) or '（无参数）'}，"
                f"这里是 {'、'.join(sorted(mine)) or '（无参数）'}")
    for key in sorted(theirs):
        a, b = mine[key], theirs[key]
        if a.get("type") != b.get("type"):
            return f"参数 {key} 的类型不一致：场景包是 {b.get('type')}，这里是 {a.get('type')}"
        if bool(a.get("required")) != bool(b.get("required")):
            return (f"参数 {key} 的必填不一致：场景包{'必填' if b.get('required') else '可选'}，"
                    f"这里{'必填' if a.get('required') else '可选'}")
        if b.get("pattern") and a.get("pattern") not in PATTERN_WITHIN.get(b["pattern"], (b["pattern"],)):
            return f"参数 {key} 的格式放宽了：场景包是 {b['pattern']}，这里是 {a.get('pattern') or '不限'}"
        if a.get("type") == "int" and (a.get("min", 0) < b.get("min", 0) or a.get("max", 0) > b.get("max", 0)):
            return (f"参数 {key} 的范围放宽了：场景包是 {b.get('min')}..{b.get('max')}，"
                    f"这里是 {a.get('min')}..{a.get('max')}")
        if b.get("enum") is not None and not {str(v) for v in a.get("enum") or []} <= {str(v) for v in b["enum"]}:
            return f"参数 {key} 的可选值放宽了"
    return ""


def _pack_label(origin):
    """被包含的文件 → 给人看的名字：packs/<id>/tools.yaml 是场景包 <id>，别的用文件名。"""
    path = Path(origin)
    return path.parent.name if path.name == "tools.yaml" and path.parent.name else path.name


def _check_export_list(document, problems):
    """主文件顶层 export：要对外开放的工具名。场景包、批准过的 MCP 工具不在主文件里，靠它开放。"""
    raw = document.get("export")
    if raw is None:
        return set()
    if not isinstance(raw, list) or not all(isinstance(item, str) for item in raw):
        problems.append("顶层 export 必须是工具名列表：export: [holiday_calendar, …]，已忽略")
        return set()
    return {item.strip() for item in raw if item.strip()}


def _entry_export(entry, name, in_main, origin, problems):
    """工具条目上的 export：只有主文件里的 true 算数；别处写了报出来，当作 false。"""
    flag = entry.get("export") if isinstance(entry, dict) else None
    if flag is None or flag is False:
        return False
    if not in_main:
        problems.append(f"{name} 的 export 已忽略：对外开放只能在主配置文件里标，"
                        f"可以在主文件顶层 export: 里列出它（{origin}）")
        return False
    if flag is not True:
        problems.append(f"{name} 的 export 只能写 true 或 false，已当作 false")
        return False
    return True


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
          "mmtime": None, "includes": [], "tools": {}, "problems": [], "mcp_servers": {},
          "connections": {}, "hosts": None}


def _mtimes():
    def stamp(path):
        try:
            return os.stat(path).st_mtime
        except OSError:
            return None

    # 被包含的文件按上一次加载记下的模式重新展开：新增一个匹配文件、改动任何一个，都算变化。
    files, _ = _expand_includes(_state["includes"], os.path.dirname(os.path.abspath(str(_state["path"]))))
    return (stamp(_state["path"]), stamp(_sibling("overrides")),
            stamp(_trust_file()), tuple((f, stamp(f)) for f in files), stamp(_mcp_file()))


def refresh(force=False):
    """Reload when any of the files changed, so changes need no restart.

    A broken edit must not take the service down: we keep the last good set.
    """
    mtime, omtime, tmtime, imtime, mmtime = _mtimes()
    if mtime is None:
        if not _state["tools"]:
            _state["problems"] = [f"读不到配置文件 {_state['path']}"]
        return _state["tools"]
    if not force and (mtime, omtime, tmtime, imtime, mmtime) == (
            _state["mtime"], _state["omtime"], _state["tmtime"], _state["imtime"],
            _state.get("mmtime")):
        return _state["tools"]

    try:
        tools, problems, servers, connections, hosts = _load_all(_state["path"])
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

    hosts_changed = hosts != _state.get("hosts")
    _state.update(mtime=mtime, omtime=omtime, tmtime=tmtime, mmtime=mmtime, includes=includes,
                  problems=problems, tools=_apply_overrides(tools, overrides), mcp_servers=servers,
                  connections=connections, hosts=hosts)
    # 模式列表可能刚变，用它重新算一次被包含文件的印章，下一次请求才不会白白重载
    _state["imtime"] = _mtimes()[3]
    # server 配置变了就启停对应子进程；这里只换对象，真正拉进程的是后台线程或下一次调用
    _mcp.configure(servers)
    if hosts_changed:
        _monitor.wake()   # 主机清单变了，后台马上重新检查一遍
    for problem in problems:
        print(f"[config] {problem}", flush=True)
    print(f"[config] 已加载 {len(tools)} 个工具定义，"
          f"{len(overrides)} 个被页面覆盖"
          + (f"；主机 {len(hosts['hosts'])} 台：{', '.join(hosts['hosts'])}" if hosts else ""), flush=True)
    return _state["tools"]


def all_tools():
    return refresh()


def _mcp_state(spec):
    """一个已批准 MCP 工具此刻能不能用：(runnable, 原因, server 上的实时定义)。"""
    ident, raw_name = spec["mcp"]["server"], spec["mcp"]["tool"]
    server = _mcp.get(ident)
    if server is None:
        return False, f"配置里没有声明 MCP server {ident}", None
    if not (server.online and server.alive()):
        return False, f"MCP server {ident} 离线" + (f"：{server.reason}" if server.reason else ""), None
    live = server.tools.get(raw_name)
    if live is None:
        return False, f"MCP server {ident} 上已经没有 {raw_name} 这个工具", None
    if (live.get("annotations") or {}).get("destructiveHint") is True:
        return False, f"server 把 {raw_name} 标成了破坏性操作，拒绝提供", live
    if spec["schema_hash"] and _mcp_hash(live) != spec["schema_hash"]:
        return False, "schema 已变更，需重新批准", live
    return True, "", live


def _mcp_readonly(spec, live=None):
    """只读依据：declared（server 声明）/ attested（管理员确认）/ none。执行期靠它拒绝。"""
    declared = spec.get("readonly_declared") or (
        live is not None and (live.get("annotations") or {}).get("readOnlyHint") is True)
    if declared:
        return "declared"
    if spec.get("readonly_attested"):
        return "attested"
    return "none"


def _not_here(spec):
    """工具声明的系统和工具服务所在机器不符时的原因（给人看）；相符或没声明时是空串。"""
    wanted = spec.get("os") or []
    if not wanted or HOST_OS in wanted:
        return ""
    return f"不适用于这台机器：工具声明 os: {', '.join(wanted)}，工具服务运行在 {HOST_OS} 上"


def _runnable(spec):
    """Command/script tools need the right OS and their binary here; HTTP and builtin tools need nothing local.

    配了主机清单时，命令型工具只要有一台主机（本机或远程）能跑就算可用；脚本型工具只能在本机跑。
    """
    if spec.get("type") in ("http", "builtin"):
        return True
    if spec.get("type") == "sql":
        return _driver(spec["connection"]["type"])[0] is not None
    if spec.get("type") == "mcp":
        return _mcp_state(spec)[0]
    if _hosts() is not None:
        if spec.get("type") == "command":
            return _target_info(spec) is not None
        local = _local_host()
        if local is None or not _applicable(spec, local)[0]:
            return False
    if _not_here(spec):
        return False
    return bool(spec.get("binary") and shutil.which(spec["binary"]))


def _unusable_reason(spec):
    """不能用的原因，给页面看。系统不符排在缺命令前面：linux 的工具在 Windows 上是不适用，不是缺 df。"""
    if spec.get("type") in ("http", "builtin"):
        return ""
    if spec.get("type") == "sql":
        return _driver(spec["connection"]["type"])[1]
    if spec.get("type") == "mcp":
        return _mcp_state(spec)[1]
    cfg = _hosts()
    if cfg is not None:
        if spec.get("type") == "command":
            states = [(name, _host_tool_state(spec, host)) for name, host in cfg["hosts"].items()]
            if any(state != "no" for _, (state, _) in states):
                return ""
            return "没有能运行它的主机：" + "；".join(f"{name} {reason}" for name, (_, reason) in states)
        local = _local_host()
        if local is None:
            return "脚本型工具只能在本机跑，而主机清单里没有本机（hosts.local: false）"
        ok, reason = _applicable(spec, local)
        if not ok:
            return reason
    reason = _not_here(spec)
    if reason:
        return reason
    if not (spec.get("binary") and shutil.which(spec["binary"])):
        return f"本机没有 {spec['binary']}，该工具不可用"
    return ""


def _http_display(spec):
    """What the UI and logs show for an HTTP tool. Never includes secret values.

    用了连接的显示连接的地址前缀（字面量或 ${名字}，不是取出来的值）和它带的请求头的名字。
    """
    http = spec["http"]
    connection = spec.get("connection")
    if connection:
        prefix = connection["base"]
    elif http.get("conn"):
        prefix = f"[连接 {http['conn']}]"
    else:
        prefix = ""
    text = "GET " + prefix + http["url"]
    if http["query"]:
        text += "?" + "&".join(f"{k}={v}" for k, v in http["query"].items())
    headers = list((connection or {}).get("headers") or {})
    if (connection or {}).get("bearer") or (connection or {}).get("bearer_file"):
        headers.append("Authorization")
    headers += [h for h in http["headers"] if h not in headers]
    if headers:
        text += f"  （请求头：{'、'.join(headers)}）"
    if http.get("conn"):
        text += f"  （连接 {http['conn']}）"
    return text


def _display(spec):
    if spec.get("type") == "script":
        return "脚本：" + spec["binary"]
    if spec.get("type") == "http":
        return _http_display(spec)
    if spec.get("type") == "sql":
        return f"SQL [连接 {spec['sql']['conn']}] {spec['sql']['query']}"
    if spec.get("type") == "mcp":
        return f"MCP {spec['mcp']['server']} / {spec['mcp']['tool']}"
    if spec.get("type") == "builtin":
        return f"内置函数 {spec['builtin']}"
    return " ".join(spec["argv"])


def _live_schema(spec):
    """给模型看的参数 schema：server 在线且指纹一致时用它那份（文案更新），否则用批准时的快照。"""
    _, _, live = _mcp_state(spec)
    if live is not None and isinstance(live.get("inputSchema"), dict):
        return live["inputSchema"]
    return spec.get("input_schema") or {"type": "object", "properties": {}}


def _mcp_params(spec):
    """手写的 allowlist 条目没有 schema 快照，参数表要从 server 的实时定义上算。"""
    return _params_from_schema(_live_schema(spec), spec["restrict"])


# ---- 统一工具契约 -------------------------------------------------------------
# /tools 只增不改：每个工具在 desc、params（MCP 工具还有 input_schema）之外，按 MCP 的 Tool 格式多回
# title、inputSchema、annotations、_meta（项目扩展 _meta.doc2sop）。新应用按 inputSchema 生成签名，
# 老应用不认识这些字段，照旧用 params。这里下发的工具全是「数据类」：观察真实系统，可以写进 SOP。
#
# 老写法的参数在这里转成 JSON Schema：正则按预置名填进 pattern（配置文件里仍然只能写预置名），
# 预置名本身放在 x-pattern；参数值是哪类对象的名字放在 x-entity，图谱据此播种实体。
ENTITY_PATTERNS = ("name", "k8s_name")


def _entity_of(key, pattern):
    """参数值是哪类对象的名字（x-entity）。只认这两种预置正则，再按参数名分：

    namespace 一律是命名空间；其余 K8s 名字统一算 k8s_object（Pod 日志和 describe 看到的是同一个对象）；
    容器名一类的 name 就是容器，别的参数名（pod、service……）本身就是类别。
    应用侧 app/agent/registry.py 的 entity_of 是同一条规则，给只回 params 的老工具服务兜底，要改两边一起改。
    """
    if pattern not in ENTITY_PATTERNS:
        return None
    if key == "namespace":
        return "namespace"
    if pattern == "k8s_name":
        return "k8s_object"
    return "container" if key == "name" else key


def _mark_pattern(prop, key, pattern):
    prop["x-pattern"] = pattern
    entity = _entity_of(key, pattern)
    if entity:
        prop["x-entity"] = entity


def _param_schema(key, spec):
    """老写法的一个参数 → (JSON Schema 属性, 是否必填)。

    必填与默认值照应用侧老签名的规则：带默认值的 int 即使标了 required 也按非必填处理（缺参时应用把
    默认值发过来）。这样新旧两条路生成的签名、发给 /exec 的参数都一模一样。
    """
    prop = {"type": "integer" if spec["type"] == "int" else "string", "description": spec.get("desc", "")}
    if spec["type"] == "int":
        prop["minimum"], prop["maximum"] = spec["min"], spec["max"]
    else:
        prop["pattern"] = PATTERNS[spec["pattern"]].pattern
        _mark_pattern(prop, key, spec["pattern"])
    if "default" in spec:
        prop["default"] = spec["default"]
    return prop, spec["required"] and "default" not in spec


def _input_schema(spec, target=None):
    if spec.get("type") == "mcp":
        # server 的 schema 原样下发（拷一份，不改 server 那份）；管理员收紧项里的预置正则同样标出来
        schema = json.loads(json.dumps(_live_schema(spec)))
        properties = schema.get("properties") if isinstance(schema.get("properties"), dict) else {}
        for key, rule in spec["restrict"].items():
            if "pattern" in rule and isinstance(properties.get(key), dict):
                _mark_pattern(properties[key], key, rule["pattern"])
        return schema
    properties, required = {}, []
    for key, param in spec["params"].items():
        properties[key], needed = _param_schema(key, param)
        if needed:
            required.append(key)
    if target is not None:
        # 主机模式下命令型工具多出来的 target：值是主机名，声明 x-entity: host，图谱和出网规则都按它认
        properties[TARGET] = target[1]
        if target[2]:
            required.append(TARGET)
    schema = {"type": "object", "properties": properties}
    if required:
        schema["required"] = required
    return schema


def _contract(name, spec, target=None, schema=None):
    """一个工具在 MCP Tool 格式里多出来的字段（name、description 就是 /tools 的键和 desc）。"""
    open_world = False
    if spec.get("type") == "mcp":
        live = _mcp_state(spec)[2] or {}
        open_world = (live.get("annotations") or {}).get("openWorldHint") is True
    doc2sop = {"category": "data", "provider": "ops", "export": bool(spec.get("export")), "group": spec.get("group", "")}
    if spec.get("external"):
        doc2sop["external"] = True   # 只在外部工具上出现：内部工具的 /tools 一个字节都不变
    return {
        "title": spec.get("label") or name,
        "inputSchema": schema if schema is not None else _input_schema(spec, target),
        # 这里下发的都是只读工具：命令有写动词黑名单，接口只许 GET，sql 只读事务 + 只许 SELECT，MCP 工具执行前要有只读依据。
        # 外部工具（实参会发到组织外面，见 _tool_external）标 openWorldHint，应用侧据此对字符串实参套用出网规则
        "annotations": {"readOnlyHint": True, "destructiveHint": False,
                        "openWorldHint": open_world or bool(spec.get("external"))},
        # export：能否出现在对外 MCP。只认主配置文件（见 _load_all），场景包和 MCP 批准文件里写了不算
        "_meta": {"doc2sop": doc2sop},
    }


def _host_target(spec):
    """主机模式下命令型工具的 target 参数 (params 写法, schema 属性, 是否必填)；别的情况是 None。"""
    if _hosts() is None or spec.get("type") != "command":
        return None
    info = _target_info(spec)
    return _target_param(spec, info) if info else None


def _list_targets_entry():
    """主机多于 enum_max 台时由工具服务提供的 list_targets（数据类，和别的工具一样走 /exec）。"""
    spec = _list_targets_spec()
    schema = {"type": "object", "properties": {"group": {
        "type": "string", "description": spec["params"]["group"]["desc"], "default": ""}}}
    return spec, {"desc": spec["desc"], "params": spec["params"], **_contract(LIST_TARGETS, spec, schema=schema)}


def available_tools():
    """Only advertise enabled tools that can actually run on this host (or, with a host list, on some host)."""
    out = {}
    for name, spec in all_tools().items():
        if not (spec["enabled"] and _runnable(spec)):
            continue
        target = _host_target(spec)
        params = spec["params"] if target is None else {**spec["params"], TARGET: target[0]}
        entry = {"desc": spec["desc"], "params": params}
        if spec.get("type") == "mcp":
            # 应用侧有 input_schema 就按它生成完整的 pydantic 模型（嵌套、枚举、必填都在）
            entry["input_schema"] = _live_schema(spec)
            entry["params"] = _mcp_params(spec)
        entry.update(_contract(name, spec, target))
        if spec.get("replaces"):
            # 主配置里的同名工具替换了场景包的默认实现：能力（名字、参数）不变，SOP 照常能用
            entry["replaces"] = spec["replaces"]["pack"]
        out[name] = entry
    if _list_targets_active():
        out[LIST_TARGETS] = _list_targets_entry()[1]
    return out


def _approved_counts():
    counts = {}
    for spec in _state["tools"].values():
        if spec.get("type") == "mcp":
            counts[spec["mcp"]["server"]] = counts.get(spec["mcp"]["server"], 0) + 1
    return counts


def mcp_status():
    all_tools()
    return _mcp.status(_approved_counts())


def describe_tools():
    """Everything the UI needs in order to show what the agent can really run."""
    out = {}
    cfg = _hosts()
    for name, spec in all_tools().items():
        target = _host_target(spec) if spec["enabled"] else None
        item = {"desc": spec["desc"],
                "params": spec["params"] if target is None else {**spec["params"], TARGET: target[0]},
                "label": spec.get("label", ""),
                "group": spec.get("group", ""),
                "binary": spec["binary"],
                "command": _display(spec),
                "type": spec.get("type", "command"),
                "script": spec.get("script", ""),
                "enabled": spec["enabled"],
                "runnable": _runnable(spec),
                "overridden": spec.get("overridden", []),
                # 系统不符和缺命令分开报：前者是「不适用于这台机器」，不是坏了
                "os": list(spec.get("os") or []),
                "applicable": not _not_here(spec),
                "export": bool(spec.get("export"))}
        if cfg is not None and spec.get("type") == "command":
            # 主机模式：逐台列出能不能跑（ok / unknown / no）和原因；有一台适用就不算「不适用」
            states = {host_name: _host_tool_state(spec, host) for host_name, host in cfg["hosts"].items()}
            item["hosts"] = {host_name: {"state": state, "reason": reason}
                             for host_name, (state, reason) in states.items()}
            item["groups"] = list(spec.get("groups") or [])
            item["applicable"] = any(_applicable(spec, host)[0] for host in cfg["hosts"].values())
        elif spec.get("type") == "command" and spec.get("groups"):
            item["groups"] = list(spec["groups"])
        if not item["runnable"] and spec.get("type") != "mcp":
            item["reason"] = _unusable_reason(spec)
        if spec.get("type") == "builtin":
            item["builtin"] = spec["builtin"]
        if spec.get("type") == "http":
            item["conn"] = spec["http"].get("conn", "")
        if spec.get("type") == "sql":
            item.update(conn=spec["sql"]["conn"], max_rows=spec["sql"]["max_rows"],
                        db=spec["connection"]["type"])
        if spec.get("external"):
            item["external"] = True
            item["external_why"] = spec.get("external_why", "")
        if spec.get("replaces"):
            item["replaces"] = {"pack": spec["replaces"]["pack"], "impl": spec["replaces"]["impl"]}
        if spec.get("type") == "mcp":
            runnable, reason, live = _mcp_state(spec)
            item.update(mcp=spec["mcp"], reason=reason, readonly=_mcp_readonly(spec, live),
                        schema_locked=bool(spec["schema_hash"]), restrict=spec["restrict"],
                        input_schema=_live_schema(spec), params=_mcp_params(spec))
        out[name] = item
    if _list_targets_active():
        spec, entry = _list_targets_entry()
        out[LIST_TARGETS] = {"desc": spec["desc"], "params": spec["params"], "label": spec["label"],
                             "group": spec["group"], "binary": "", "command": "内置函数 list_targets",
                             "type": "builtin", "builtin": LIST_TARGETS, "script": "", "enabled": True,
                             "runnable": True, "overridden": [], "os": [], "applicable": True, "export": False}
    return out


def _conn_address(conn):
    """连接的地址，给人看：字面量或 ${名字} 原样（不是取出来的值），不带账号和密码。"""
    if conn["type"] == "http":
        return conn["base"]
    if conn["type"] == "sqlite":
        return conn["path"]
    return f"{conn['host']}:{conn['port']}/{conn['database']}"


def describe_connections():
    """页面上看得到的连接：名字、类型、地址（字面量或 ${名字}）、请求头的名字、谁在用。永远没有凭据的值。"""
    tools = all_tools()
    out = {}
    for name, conn in sorted(_state.get("connections", {}).items()):
        item = {"type": conn["type"], "label": conn["label"], "base": _conn_address(conn),
                "headers": sorted(conn.get("headers") or {}),
                "external": bool(conn.get("external")), "external_why": conn.get("external_why", ""),
                "used_by": sorted(n for n, spec in tools.items()
                                  if (spec.get("connection") or {}).get("name") == name)}
        if conn["type"] == "http":
            if conn.get("bearer") or conn.get("bearer_file"):
                item["headers"] = sorted(set(item["headers"]) | {"Authorization"})
            item["ca"] = bool(conn.get("ca"))
        else:
            item["driver"] = _driver(conn["type"])[1]   # 空串表示驱动在；否则是缺什么、怎么装
            item["timeout"] = conn["timeout"]
        out[name] = item
    return out


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
        (re.compile(rf"^{re.escape(name)}\.os 只能是 (.+?)（可以写成列表），不是 (.+)$"),
         r"适用系统只能是 \1，不是 \2"),
        (re.compile(rf"^{re.escape(name)}\.impl\.query 用到了未声明的参数 (\S+)$"),
         r"查询里用了参数 :\1，请在下方「参数」里把它的类型填好"),
        (re.compile(rf"^{re.escape(name)}\.impl\.query 没有用到参数 (\S+?)：.*$"),
         r"参数 \1 没有在查询里用到（写成 :\1）"),
    ]
    for pattern, repl in swaps:
        if pattern.match(message):
            return pattern.sub(repl, message)
    return (message.replace(f"{name}.argv", "命令").replace(f"{name}.params.", "参数 ")
            .replace(f"{name}.impl.query", "查询").replace(f"{name}.impl.max_rows", "最多行数")
            .replace(f"{name}.impl.conn", "连接"))


def _proposal_kind(raw):
    """申请的实现类型：新写法看 impl.type，老写法看写了哪个字段。"""
    impl = raw.get("impl")
    if impl is not None:
        return str(impl.get("type", "")).strip() if isinstance(impl, dict) else ""
    if raw.get("mcp") is not None:
        return "mcp"
    if raw.get("script"):
        return "script"
    if raw.get("http") is not None:
        return "http"
    return "command"


def propose_tool(raw, author="web"):
    """Queue a new tool for review. Proposals are never loaded as usable tools.

    按实现类型申请，不查工具服务这台机器的 PATH：命令在哪种系统上跑由 os 声明；批准后系统不符的
    显示「不适用于这台机器」，缺命令的显示「本机没有 …」，都不挡申请。builtin 随代码发布、MCP 工具
    来自 server 的发现，都不能申请。措辞用表单上的栏目名，而不是配置文件里的字段名。
    """
    raw = raw if isinstance(raw, dict) else {}
    name = str(raw.get("name", "")).strip()
    if not TOOL_NAME.match(name):
        raise ConfigError(
            f"工具名「{name[:40]}」不能用：它会作为函数名发给模型，只能用小写英文字母、"
            f"数字和下划线，例如 host_time。中文请填在「中文显示名」那一栏。")

    kind = _proposal_kind(raw)
    if raw.get("export") is not None:
        # 批准时申请原样追加进主配置文件：带着 export 就成了页面绕过管理员开放工具的口子
        raise ConfigError("申请里不能带 export：工具要不要对外开放，只能由管理员在宿主机主配置文件里标")
    if kind == "mcp":
        # MCP 工具不由页面申请：它来自 server 的发现，而 server 只能由管理员在宿主机声明。
        raise ConfigError("页面不能申请 MCP 工具；在宿主机配置 mcp_servers 后，发现到的工具会自动进入待审列表")
    if kind == "builtin":
        raise ConfigError("页面不能申请内置函数：内置函数随工具服务的代码发布，管理员在配置里按名字引用即可")
    if kind == "http":
        # 页面申请的接口工具不能带凭据：否则一条申请就能把宿主机上的密钥发到任意地址，
        # 只差审批时的一次疏忽。要鉴权就选一个管理员建好的连接，凭据留在连接里。
        http = raw.get("impl") if raw.get("impl") is not None else raw.get("http")
        http = http if isinstance(http, dict) else {}
        if http.get("headers"):
            raise ConfigError("页面申请的接口工具不能设置请求头；需要鉴权的接口请选一个已有连接，或让管理员在宿主机配置")
        if http.get("notes"):
            raise ConfigError("页面申请的接口工具不能附带 notes 说明；请让管理员在宿主机配置")
        if "${" in json.dumps(http, ensure_ascii=False):
            raise ConfigError("页面申请的接口工具不能引用宿主机环境变量或凭据；要带凭据请选一个已有连接")
    if kind == "sql":
        # 地址、账号、密码都在管理员建好的数据库连接里；申请只能选一个连接、写查询模板和参数
        impl = raw.get("impl") if isinstance(raw.get("impl"), dict) else {}
        if not str(impl.get("conn") or "").strip():
            raise ConfigError("SQL 工具要选一个已有的数据库连接；连接只能由管理员在宿主机配置")
        if "${" in json.dumps(impl, ensure_ascii=False):
            raise ConfigError("页面申请的 SQL 工具不能引用凭据：地址和账号都在连接里")

    tools = all_tools()   # 顺带把连接刷新到最新
    try:
        # 其余规则（argv 首项、写动词、占位符、连接是否存在）与正式配置一致
        spec = _bind_connection(_check_tool(raw), _state.get("connections", {}))
    except ConfigError as exc:
        raise ConfigError(_form_wording(str(exc), name)) from None
    if spec["name"] in tools:
        raise ConfigError(f"已存在同名工具：{spec['name']}")
    with _pending_lock:
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
    with _pending_lock:
        item = _find_pending(ident)
        _write_yaml(_sibling("pending"),
                    {"pending": [i for i in list_pending() if i.get("id") != item["id"]]})
    return item


def approve_pending(ident, attest_readonly=False):
    """Approve a pending proposal. Only runs on the host.

    MCP 条目走另一条路：写进 ops_tools.mcp.yaml（同名替换），并且必须有只读依据——
    server 声明了 readOnlyHint，或者审批人加 --attest-readonly 亲口确认。

    其余（命令、脚本、接口、SQL）写进手写的主配置文件：插到顶层 tools 列表的末尾（见 _insert_tool_text），
    其余内容一个字节都不动。写之前用和服务同一套加载逻辑加载插入后的内容，必须正好多出这一个工具、
    别的都不变（见 _check_insertion）；认不出写法或验证不过就不写，申请留在待审。写入是原子的，
    保留属主和权限，写之前在同一目录留一份带时间戳的备份（见 _replace_config）。写成了才删待审。
    """
    item = _find_pending(ident)
    spec = _check_tool(item.get("tool") or {})  # 再校验一次，文件可能被改过
    if spec.get("type") == "mcp":
        return _approve_mcp(item, spec, attest_readonly)
    if spec["name"] in all_tools():
        raise ConfigError(f"已存在同名工具：{spec['name']}")
    _bind_connection(spec, _state.get("connections", {}))   # 连接可能在申请之后被删了
    path = Path(_state["path"])
    try:
        original = path.read_bytes()
        text = original.decode("utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise ConfigError(f"读不了主配置 {path}（{exc}）：没有改主配置，申请仍在待审") from None
    new_text, line = _insert_tool_text(text, item["tool"])
    try:
        before = _load_all(path, text)
    except ConfigError as exc:
        raise ConfigError(f"主配置现在就加载不了（{exc}）：没有改主配置，申请仍在待审") from None
    script = spec.get("type") == "script"
    trusted_before = _file_bytes(_trust_file()) if script else None
    try:
        if script:
            # 批准脚本 = 认可此刻的脚本内容，把它的哈希登记为可信（没写成主配置就恢复原来的登记）。
            trust_script(spec["script"])
        _check_insertion(path, new_text, before, spec["name"])
        backup = _replace_config(path, original, new_text.encode("utf-8"))
    except BaseException:
        if script:
            _restore_bytes(_trust_file(), trusted_before)
        raise
    try:
        drop_pending(item["id"])
    except (OSError, ConfigError) as exc:
        raise ConfigError(f"已写入主配置（改之前的备份：{backup}），但没能从待审里删掉这条申请（{exc}）："
                          f"用 ops_readonly.py reject {item['id']} 清掉") from None
    refresh(force=True)
    spec["written"] = {"path": str(path), "line": line, "backup": backup}
    return spec


# ---- 批准写进主配置：插到顶层 tools 列表末尾，其余内容一个字节都不动 ---------------------------------------

_TOOLS_KEY = re.compile(r"tools[ \t]*:")
_TOOLS_BLOCK = re.compile(r"tools[ \t]*:[ \t]*(?:#.*)?")
_TOOLS_EMPTY = re.compile(r"(tools[ \t]*:)[ \t]*\[[ \t]*\]([ \t]*(?:#.*)?)")
_SEQ_ITEM = re.compile(r"( *)-(?: |$)")


def _insert_tool_text(text, tool):
    """把一个工具条目插到主配置顶层 tools: 列表的末尾，返回 (新内容, 新条目从第几行开始)。

    tools 后面还有别的顶层段（hosts、connections、export…）时，插在那一段前面——它上方顶格的注释算那一段的；
    文件末尾只剩顶格注释时，插在这些注释前面。其余内容一个字节都不动：注释、空行、缩进、换行符（LF / CRLF）、
    有没有结尾换行都保持原样；只有 tools: [] 这一行会去掉 []（空的流式列表没法往里追加块列表项）。
    认不出写法——找不到或有多个顶层 tools:、非空的流式写法、第一项不是「- 」开头——就抛 ConfigError，
    并附上要手工加的那段 YAML。
    """
    entry = _yaml().safe_dump([tool], allow_unicode=True, sort_keys=False, default_flow_style=None)

    def manual(reason):
        return ConfigError(f"{reason}，没法只插入一段而不动别的内容：没有改主配置，申请仍在待审。"
                           f"请手工把下面这段加到 tools 列表末尾，确认加载正常后用 ops_readonly.py reject <id> "
                           f"清掉这条申请：\n{textwrap.indent(entry, '  ')}")

    lines = re.findall(r"[^\n]*\n|[^\n]+\Z", text)   # 每行带着自己的换行符，最后一行可能没有
    bodies = []
    for index, raw in enumerate(lines):
        body = raw[:-1] if raw.endswith("\n") else raw
        body = body[:-1] if body.endswith("\r") else body
        if index == 0 and body.startswith("\ufeff"):
            body = body[1:]
        bodies.append(body)
    found = [i for i, body in enumerate(bodies) if _TOOLS_KEY.match(body)]
    if len(found) != 1:
        raise manual("主配置里找不到顶层的 tools:" if not found else "主配置里有不止一个顶层的 tools:")
    start = found[0]
    ending = re.search(r"\r?\n\Z", lines[start])
    eol = ending.group(0) if ending else ("\r\n" if "\r\n" in text else "\n")

    def blank(index):
        return not bodies[index].strip()

    empty = _TOOLS_EMPTY.fullmatch(bodies[start])
    if empty:
        offset = sum(len(raw) for raw in lines[:start])
        bom = "\ufeff" if start == 0 and lines[0].startswith("\ufeff") else ""
        tail = lines[start][len(bom) + len(bodies[start]):]      # 这一行原来的换行符；文件最后一行没有换行时是空串
        block = textwrap.indent(entry, "  ").split("\n")[:-1]
        head = bom + empty.group(1) + empty.group(2)
        if tail:
            after = eol if start + 1 < len(lines) and not blank(start + 1) else ""
            inserted = head + tail + eol.join(block) + eol + after
        else:
            inserted = head + eol + eol.join(block)
        return text[:offset] + inserted + text[offset + len(lines[start]):], start + 2
    if not _TOOLS_BLOCK.fullmatch(bodies[start]):
        raise manual("主配置里的 tools 是流式写法（tools: [...]），或者在同一行写了别的值")
    first = next((i for i in range(start + 1, len(lines))
                  if not blank(i) and not bodies[i].lstrip().startswith("#")), None)
    item = _SEQ_ITEM.match(bodies[first]) if first is not None else None
    if item is None:
        raise manual("认不出主配置里 tools 列表的写法（tools: 下面第一项不是「- 」开头的块列表项）")
    indent = len(item.group(1))
    # 列表到哪一行为止：下一个顶格、不是注释、也不是列表项的行（下一个顶层段，或 --- 之类）
    end = len(lines)
    for i in range(first + 1, len(lines)):
        body = bodies[i]
        if blank(i) or body[0] in " \t" or body.startswith("#") or (indent == 0 and _SEQ_ITEM.match(body)):
            continue
        end = i
        break
    # 列表末尾的空行和顶格注释：顶格注释算下一段（或文件末尾的说明），条目插在第一行顶格注释前面
    stop = end
    while stop - 1 > first and (blank(stop - 1) or bodies[stop - 1].startswith("#")):
        stop -= 1
    at = next((i for i in range(stop, end) if bodies[i].startswith("#")), end)
    offset = sum(len(raw) for raw in lines[:at])
    block = textwrap.indent(entry, " " * indent).split("\n")[:-1]
    lead = "" if blank(at - 1) else eol               # 紧挨着的上一行有内容：先空一行
    if at == len(lines) and not text.endswith("\n"):
        inserted = eol + lead + eol.join(block)        # 原文件没有结尾换行：补上上一行的换行，新内容末尾也不加
        line = text.count("\n") + 2 + (1 if lead else 0)
    else:
        after = eol if at < len(lines) and not blank(at) else ""   # 下一行是注释或下一段：再空一行
        inserted = lead + eol.join(block) + eol + after
        line = text[:offset].count("\n") + 1 + (1 if lead else 0)
    return text[:offset] + inserted + text[offset:], line


def _check_insertion(path, new_text, before, name):
    """用和服务同一套加载逻辑加载插入后的完整内容：必须正好多出 name 这一个工具，
    其余工具、加载问题、MCP server、连接、主机清单都和现在一样。不满足就抛 ConfigError，说清哪里不一样。"""
    try:
        after = _load_all(path, new_text)
    except ConfigError as exc:
        raise ConfigError(f"插入后的主配置加载失败（{exc}）：没有改主配置，申请仍在待审") from None
    tools, problems, servers, connections, hosts = before
    new_tools, new_problems, new_servers, new_connections, new_hosts = after
    reasons = []
    added = sorted(set(new_tools) - set(tools))
    removed = sorted(set(tools) - set(new_tools))
    if added != [name] or removed:
        reasons.append(f"工具的变化不是正好多出 {name}（多出：{'、'.join(added) or '无'}；少了：{'、'.join(removed) or '无'}）")
    changed = sorted(n for n in tools if n in new_tools and new_tools[n] != tools[n])
    if changed:
        reasons.append(f"别的工具变了：{'、'.join(changed)}")
    if new_problems != problems:
        diff = [p for p in new_problems if p not in problems] or [p for p in problems if p not in new_problems]
        reasons.append(f"加载问题变了：{diff[0][:200] if diff else '顺序不同'}")
    for label, old, new in (("MCP server", servers, new_servers), ("连接", connections, new_connections),
                            ("主机清单", hosts, new_hosts)):
        if old != new:
            reasons.append(f"{label}变了")
    if reasons:
        raise ConfigError("插入后的加载结果不对：" + "；".join(reasons) + "。没有改主配置，申请仍在待审")


def _replace_config(path, original, data):
    """主配置的原子写入：先确认文件还是读到时的样子，在同一目录留一份带时间戳的备份，
    再写临时文件（属主、权限和原文件一样）、rename 过去。返回备份路径。"""
    real = os.path.realpath(path)
    with open(real, "rb") as handle:
        if handle.read() != original:
            raise ConfigError("主配置在批准过程中被改过：没有改主配置，申请仍在待审，请重新执行")
    info = os.stat(real)
    stamp = time.strftime("%Y%m%d%H%M%S")
    backup, serial = f"{real}.bak-{stamp}", 1
    while os.path.exists(backup):
        backup, serial = f"{real}.bak-{stamp}-{serial}", serial + 1
    shutil.copy2(real, backup)
    _keep_owner(backup, info, strict=False)
    folder, base = os.path.split(real)
    temporary = os.path.join(folder, f".{base}.{secrets.token_hex(3)}.tmp")
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, stat.S_IMODE(info.st_mode))
        _keep_owner(temporary, info, strict=True)
        os.replace(temporary, real)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise
    return backup


def _keep_owner(path, info, strict):
    """让 path 的属主和 info 一样（POSIX）。strict：做不到就不写，抛 ConfigError。"""
    if not hasattr(os, "chown"):
        return
    current = os.stat(path)
    if (current.st_uid, current.st_gid) == (info.st_uid, info.st_gid):
        return
    try:
        os.chown(path, info.st_uid, info.st_gid)
    except OSError as exc:
        if strict:
            raise ConfigError(f"新文件没法保留原来的属主 {info.st_uid}:{info.st_gid}（{exc}）：没有改主配置，"
                              f"申请仍在待审；请用主配置文件的属主（通常是 root）执行") from None


def _file_bytes(path):
    """文件内容；文件不存在时是 None。"""
    try:
        return Path(path).read_bytes()
    except FileNotFoundError:
        return None


def _restore_bytes(path, saved):
    """把文件恢复成 _file_bytes 拿到的样子（原来不存在就删掉）。"""
    if saved is None:
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
        return
    temporary = f"{path}.{secrets.token_hex(3)}.tmp"
    with open(temporary, "wb") as handle:
        handle.write(saved)
    os.replace(temporary, path)


def _approve_mcp(item, spec, attest_readonly):
    raw = dict(item["tool"])
    if attest_readonly:
        raw["readonly_attested"] = True
    if not raw.get("readonly_declared") and not raw.get("readonly_attested"):
        raise ConfigError(
            f"{spec['name']} 没有被 server 声明为只读（readOnlyHint）。请先确认它确实不会改任何东西，"
            f"再用 --attest-readonly 批准：ops_readonly.py approve {item.get('id')} --attest-readonly")
    existing = all_tools().get(spec["name"])
    if existing is not None and (existing.get("type") != "mcp" or existing["mcp"] != spec["mcp"]):
        raise ConfigError(f"已存在同名工具：{spec['name']}")
    raw["approved_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
    document = _read_yaml(_mcp_file())
    entries = [e for e in (document.get("tools") or [])
               if not (isinstance(e, dict) and e.get("name") == spec["name"])]
    _write_yaml(_mcp_file(), {**document, "tools": entries + [raw]})
    drop_pending(item["id"])
    refresh(force=True)
    return _check_tool(raw)


def _mcp_tool_name(server_id, raw_name):
    """server 上的原名 → 发给模型的函数名：server__原名，原名按确定性规则转小写下划线。"""
    slug = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", str(raw_name)).lower()
    slug = re.sub(r"[^a-z0-9_]+", "_", slug)
    slug = re.sub(r"_+", "_", slug).strip("_") or "tool"
    if not slug[0].isalpha():
        slug = "t_" + slug
    return f"{server_id}__{slug}"[:64]


def _suspicious_name(raw_name):
    words = set(re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", str(raw_name)).lower()
                .replace("-", "_").split("_"))
    return bool(words & MCP_WRITE_WORDS)


def _mcp_candidate(server, raw_name, tool, name):
    """发现到的一个 MCP 工具 → 待审条目（批准后原样落盘）。"""
    annotations = tool.get("annotations") or {}
    label = str(tool.get("title") or annotations.get("title") or raw_name).strip()[:MAX_LABEL]
    return {"name": name, "label": label, "group": server.label,
            "desc": str(tool.get("description") or "").strip()[:MAX_MCP_DESC],
            "mcp": {"server": server.id, "tool": raw_name},
            "input_schema": tool.get("inputSchema") if isinstance(tool.get("inputSchema"), dict)
            else {"type": "object", "properties": {}},
            "schema_hash": _mcp_hash(tool),
            "readonly_declared": annotations.get("readOnlyHint") is True}


def _mcp_discovered(server):
    """tools/list 之后：没批准过的进 pending，批准过但指纹变了的也重新进 pending。

    默认拒绝的落实点就在这里——发现 ≠ 可用。破坏性工具连 pending 都不进，只记一行日志；
    其余按 server 有没有声明只读、名字像不像写操作打标签，给审批人看。
    """
    with _pending_lock:
        _reconcile_pending(server)


def _reconcile_pending(server):
    tools = all_tools()
    approved = {spec["mcp"]["tool"]: spec for spec in tools.values()
                if spec.get("type") == "mcp" and spec["mcp"]["server"] == server.id}
    pending = list_pending()
    by_name = {(item.get("tool") or {}).get("name"): item for item in pending}
    notes, changed, taken = [], False, set()
    for raw_name in sorted(server.tools):
        tool = server.tools[raw_name]
        annotations = tool.get("annotations") or {}
        if annotations.get("destructiveHint") is True:
            notes.append(f"{raw_name}：server 标为破坏性操作，不列出")
            continue
        digest = _mcp_hash(tool)
        existing = approved.get(raw_name)
        if existing is not None and (not existing["schema_hash"] or existing["schema_hash"] == digest):
            continue
        name = existing["name"] if existing is not None else _mcp_tool_name(server.id, raw_name)
        if name in taken or (existing is None and name in tools):
            notes.append(f"{raw_name}：转换后的工具名 {name} 已被占用，未列出")
            continue
        taken.add(name)
        reason = "schema 已变更，需重新批准" if existing is not None else "新发现"
        previous = by_name.get(name)
        if previous is not None and (previous.get("tool") or {}).get("schema_hash") == digest:
            continue
        if previous is not None:
            pending = [item for item in pending if item is not previous]
        candidate = _mcp_candidate(server, raw_name, tool, name)
        pending.append({"id": secrets.token_hex(4),
                        "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                        "author": f"mcp:{server.id}", "tool": candidate,
                        "review": {"readonly": "declared" if candidate["readonly_declared"] else "undeclared",
                                   "suspicious_name": _suspicious_name(raw_name),
                                   "reason": reason}})
        changed = True
        print(f"[mcp:{server.id}] {raw_name} → 待审 {name}（{reason}）", flush=True)
    # server 上已经没有的工具，它的待审申请也没意义了
    live_names = {_mcp_tool_name(server.id, raw) for raw in server.tools} | {s["name"] for s in approved.values()}
    kept = [item for item in pending
            if not (str(item.get("author", "")) == f"mcp:{server.id}"
                    and (item.get("tool") or {}).get("name") not in live_names)]
    if len(kept) != len(pending):
        pending, changed = kept, True
    server.notes = notes
    if changed:
        _write_yaml(_sibling("pending"), {"pending": pending})


# 参数校验与 argv 拼装：本机执行、发给主机上的执行器之前、执行器自己，用的都是 ops_exec.py 里这一份。
_value = ops_exec.value
build_argv = ops_exec.build_argv


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """接口返回 3xx 时不跟随：主机名是审过的，不能被一次跳转带去别处。"""

    def redirect_request(self, *args, **kwargs):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)
_openers = {}


def _opener(context=None):
    """不跟随跳转的 opener；连接配了自己的 CA 时，用只信那个 CA 的 TLS 上下文。"""
    if context is None:
        return _OPENER
    cached = _openers.get(id(context))
    if cached is None or cached[0] is not context:
        if len(_openers) > 64:
            _openers.clear()
        cached = (context, urllib.request.build_opener(_NoRedirect, urllib.request.HTTPSHandler(context=context)))
        _openers[id(context)] = cached
    return cached[1]


def _http_get(url, headers, context=None):
    """One GET. Returns (status, body_bytes). Isolated so tests can replace it."""
    request = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with _opener(context).open(request, timeout=HTTP_TIMEOUT) as response:
            return response.status, response.read(MAX_HTTP_BYTES + 1)
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(MAX_HTTP_BYTES + 1) if exc.fp else b""


def _secret(ref):
    """取一个凭据的值：${prom_token} 读 OPS_SECRET_PROM_TOKEN，${OPS_SECRET_X} 读它自己。没配就不能用。"""
    env = _secret_env(ref)
    value = os.environ.get(env, "") if env else ""
    if not value:
        shown = ref if env in (None, ref) else f"{ref}（环境变量 {env}）"
        raise ValueError(f"宿主机没有配置 {shown}，该工具暂不可用")
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
    connection = spec.get("connection")
    if http.get("conn") and not connection:
        raise ValueError(f"连接 {http['conn']} 不存在，该工具暂不可用")
    env_base = None if connection else ENV_BASE.match(url)
    if connection:
        base, rest = _connection_base(connection, secrets_used), url
    elif env_base:
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
        if found:
            value = values[found.group(1)]
        elif "$" not in raw and URL_PARAM.search(raw):
            # 嵌在查询值里的参数（只有 EMBED_SAFE 的预置正则和整数，加载时查过）：原样嵌进去，整个值再做 URL 编码
            value = URL_PARAM.sub(lambda m: values[m.group(1)], raw)
        else:
            value = _fill_secrets(raw, secrets_used)
        query.append((key, value))
    if query:
        full += "?" + urllib.parse.urlencode(query)

    headers = {"User-Agent": "ops-readonly/1", "Accept": "application/json, */*"}
    # 连接的请求头（含 bearer 令牌）在前，工具自己写的同名请求头覆盖它
    for key, raw in ((connection or {}).get("headers") or {}).items():
        headers[key] = _fill_secrets(raw, secrets_used)
    token = _bearer(connection, secrets_used) if connection else ""
    if token:
        headers["Authorization"] = f"Bearer {token}"
    for key, raw in http["headers"].items():
        headers[key] = _fill_secrets(raw, secrets_used)
    return full, headers, [s for s in secrets_used if s]


def _bearer(connection, used):
    """连接的 bearer 令牌：bearer 取凭据的值；bearer_file 每次现读文件（令牌轮换后不用重启）。没配返回空串。"""
    if connection.get("bearer"):
        token = _resolve(connection["bearer"], used)
    elif connection.get("bearer_file"):
        token = _read_token_file(connection, _resolve(connection["bearer_file"], used))
        used.append(token)
    else:
        return ""
    if not re.fullmatch(r"[\x21-\x7e]{1,8192}", token):
        raise ValueError(f"连接 {connection['name']} 的令牌不合法：只能是可见的 ASCII 字符，不能有空白")
    return token


def _read_token_file(connection, path):
    """令牌文件：普通文件（不能是符号链接）、只有工具服务账号能读写、不超过 16 KB。报错里不写路径。"""
    shown = f"连接 {connection['name']} 的 bearer_file"
    try:
        info = os.lstat(path)
    except OSError:
        raise ValueError(f"{shown} 读不到") from None
    if not stat.S_ISREG(info.st_mode):
        raise ValueError(f"{shown} 不是普通文件（不能是符号链接或目录）")
    if os.name == "posix":
        if info.st_mode & 0o077:
            raise ValueError(f"{shown} 权限过宽（{oct(info.st_mode & 0o777)}），只能由工具服务账号读写：chmod 600")
        if info.st_uid != os.geteuid():
            raise ValueError(f"{shown} 不属于工具服务的运行账号")
    with open(path, "rb") as handle:
        data = handle.read(16385)
    if len(data) > 16384:
        raise ValueError(f"{shown} 太大，不像一个令牌")
    return data.decode("ascii", "replace").strip()


def _http_context(spec):
    """连接配了 ca：只信那个 CA 的 TLS 上下文；没配返回 None（用系统的根证书）。"""
    connection = spec.get("connection") or {}
    if not connection.get("ca"):
        return None
    try:
        return _ssl_context(_resolve(connection["ca"]))
    except ConfigError as exc:
        raise ValueError(f"连接 {connection['name']} 的 ca：{exc}") from None


def _connection_base(connection, secrets_used):
    """连接的地址前缀：字面量原样；${名字} 开头的取凭据的值——地址本身也当敏感信息，输出里脱敏。"""
    base = connection["base"]
    env_base = ENV_BASE.match(base)
    if not env_base:
        return base
    value = _secret(env_base.group(1)).rstrip("/")
    secrets_used.append(value)
    if not re.match(r"^https?://[^/?#@]+(/[^?#]*)?$", value):
        raise ValueError(f"连接 {connection['name']} 的地址 {env_base.group(1)} 不是合法的 http(s) 地址")
    return value + env_base.group(2)


def _scrub(text, secrets_used):
    """Never hand a secret back to the model, even if the API echoes it.

    放进查询串的凭据在 URL 里是编码过的（+ / = 会变成 %2B %2F %3D），回显的也可能是编码后的样子，两种都换掉。
    """
    forms = set()
    for secret in set(secrets_used):
        if len(secret) >= 6:
            forms.update((secret, urllib.parse.quote(secret, safe=""), urllib.parse.quote_plus(secret)))
    for secret in sorted(forms, key=len, reverse=True):
        text = text.replace(secret, "***")
    return text


def _run_http(spec, args):
    try:
        url, headers, secrets_used = build_request(spec, args)
        context = _http_context(spec)
    except ValueError as exc:
        return {"ok": False, "error": str(exc)}
    shown = _scrub(url, secrets_used)
    try:
        status, body = _http_get(url, headers, **({"context": context} if context is not None else {}))
    except Exception as exc:
        return {"ok": False, "error": _scrub(f"请求失败：{exc.__class__.__name__}: {exc}",
                                             secrets_used), "command": "GET " + shown}

    text = body[:MAX_HTTP_BYTES].decode("utf-8", errors="replace")
    ok = 200 <= status < 300
    notes = spec["http"].get("notes") or {}
    remarks = []
    # 只在成功时摘字段；出错时原样保留厂商的报错正文（Invalid token、404 page not found……），
    # 否则模型看到的是一串 null，解释不了为什么失败。
    if ok and spec["http"]["pick"]:
        try:
            data = json.loads(text)
            picked = {path: _pick(data, path) for path in spec["http"]["pick"]}
            text = json.dumps(picked, ensure_ascii=False, indent=1)
            remarks += [note for path, note in (notes.get("empty") or {}).items()
                        if picked.get(path) in (None, [], {}, "")]
        except ValueError:
            pass
    text = _scrub(text.strip(), secrets_used)
    if not ok:
        text = f"接口返回 {status}：{text or '（无正文）'}"
        if str(status) in (notes.get("status") or {}):
            remarks.append(notes["status"][str(status)])
    if remarks:
        # 管理员写的解释跟在数据后面：空数组、404 对这个接口意味着什么，模型不用猜
        text += "\n" + "\n".join(remarks)
    truncated = len(text) > MAX_OUTPUT
    if 300 <= status < 400:
        text = f"接口返回 {status} 跳转，已拒绝跟随（只允许访问配置里写明的主机）"
    return {"ok": ok, "command": "GET " + shown, "status": status,
            "output": text[:MAX_OUTPUT] + ("\n…（输出已截断）" if truncated else "")}


# ---- sql 的执行 ------------------------------------------------------------------------

class SqlError(RuntimeError):
    """连不上数据库、查询失败、超时：给人和模型看的原因（还没脱敏）。"""


def _sql_render(segments, style):
    """模板片段 → 驱动要的 SQL 文本。参数一律是驱动的占位符：sqlite 用原生的 :名字，psycopg、PyMySQL 用
    %(名字)s（这两家会把文本里的 % 当格式符，原文的 % 写成 %%）。参数值从来不进 SQL 文本。"""
    out = []
    for kind, value in segments:
        if kind == "param":
            out.append(f":{value}" if style == "named" else f"%({value})s")
        else:
            out.append(value if style == "named" else value.replace("%", "%%"))
    return "".join(out)


def _sql_cell(value):
    if value is None:
        return "NULL"
    if isinstance(value, (bytes, bytearray, memoryview)):
        return f"<二进制 {len(bytes(value))} 字节>"
    text = value.isoformat() if isinstance(value, (datetime.datetime, datetime.date, datetime.time)) else str(value)
    text = text.replace("\r\n", "\n").replace("\n", "⏎").replace("\t", " ").replace("|", "¦")
    return text[:SQL_CELL] + ("…" if len(text) > SQL_CELL else "")


def _sql_table(columns, rows, more, max_rows):
    """查询结果 → 给模型看的表：表头一行，每行用 | 分隔；末尾说明行数，取不完时明说。"""
    lines = [" | ".join(str(column) for column in columns)] if columns else []
    lines += [" | ".join(_sql_cell(value) for value in row) for row in rows]
    if not rows:
        lines.append("（没有查到数据）")
    elif more:
        lines.append(f"（只取了前 {max_rows} 行，后面还有：缩小查询范围再查）")
    else:
        lines.append(f"（共 {len(rows)} 行）")
    return "\n".join(lines)


def _sql_first_line(exc):
    text = str(exc).strip() or exc.__class__.__name__
    return text.splitlines()[0][:300]


def _sql_timeout(conn):
    return SqlError(f"查询超时（{conn['timeout']} 秒）：缩小查询范围，或请管理员优化这条查询")


def _sqlite_authorizer(module):
    """sqlite 的第二层：授权回调只放行读（SELECT、读表、调函数、递归 CTE），副作用函数也拒绝。"""
    allowed = {module.SQLITE_SELECT, module.SQLITE_READ, module.SQLITE_FUNCTION, getattr(module, "SQLITE_RECURSIVE", 33)}

    def authorize(action, arg1, arg2, database, source):
        if action == module.SQLITE_FUNCTION and str(arg2 or "").lower() in SQL_DENY_FUNCS:
            return module.SQLITE_DENY
        return module.SQLITE_OK if action in allowed else module.SQLITE_DENY
    return authorize


def _sqlite_query(conn, module, segments, params, max_rows, used):
    path = _resolve(conn["path"], used)
    if not os.path.isfile(path):
        raise SqlError(f"连接 {conn['name']} 的数据库文件不存在")
    deadline = time.monotonic() + conn["timeout"]
    late = []

    def progress():
        if time.monotonic() > deadline:
            late.append(True)
            return 1
        return 0

    try:
        # 只读打开（mode=ro）+ query_only + 授权回调：三重保证写不进去
        db = module.connect(Path(path).resolve().as_uri() + "?mode=ro", uri=True, timeout=conn["timeout"],
                            check_same_thread=False)
    except module.Error as exc:
        raise SqlError(f"打不开数据库：{_sql_first_line(exc)}") from None
    try:
        db.execute("PRAGMA query_only = ON")
        db.set_authorizer(_sqlite_authorizer(module))
        db.set_progress_handler(progress, 1000)
        cursor = db.execute(_sql_render(segments, "named"), params)
        columns = [item[0] for item in cursor.description or []]
        rows = cursor.fetchmany(max_rows + 1)
    except module.Error as exc:
        if late:
            raise _sql_timeout(conn) from None
        raise SqlError(f"查询失败：{_sql_first_line(exc)}") from None
    finally:
        db.close()
    return columns, rows[:max_rows], len(rows) > max_rows


def _postgres_query(conn, module, segments, params, max_rows, used):
    millis = conn["timeout"] * 1000
    kwargs = {"host": _resolve(conn["host"], used), "port": conn["port"],
              "dbname": _resolve(conn["database"], used), "user": _resolve(conn["user"], used),
              "connect_timeout": min(10, conn["timeout"] + 3), "application_name": "doc2sop-ops-readonly",
              "sslmode": {"disable": "disable", "prefer": "prefer", "require": "require",
                          "verify": "verify-full"}[conn["tls"]],
              # 第二层：这条连接上的事务默认只读；语句超时由数据库自己掐
              "options": f"-c default_transaction_read_only=on -c statement_timeout={millis} "
                         f"-c idle_in_transaction_session_timeout={millis * 2}"}
    if conn["password"]:
        kwargs["password"] = _resolve(conn["password"], used)
    if conn["ca"]:
        kwargs["sslrootcert"] = _resolve(conn["ca"], used)
    try:
        db = module.connect(autocommit=False, **kwargs)
    except Exception as exc:
        raise SqlError(f"连不上数据库：{_sql_first_line(exc)}") from None
    canceled = getattr(getattr(module, "errors", None), "QueryCanceled", ())
    try:
        db.read_only = True   # 再加一道：事务以 BEGIN READ ONLY 开始
        # 服务端游标：只取要的那几行，结果集再大也不会整个搬进工具服务
        cursor = db.cursor(name="doc2sop_ops_readonly")
        cursor.execute(_sql_render(segments, "pyformat"), params)
        columns = [getattr(item, "name", None) or item[0] for item in cursor.description or []]
        rows = cursor.fetchmany(max_rows + 1)
        db.rollback()
    except Exception as exc:
        if canceled and isinstance(exc, canceled):
            raise _sql_timeout(conn) from None
        raise SqlError(f"查询失败：{_sql_first_line(exc)}") from None
    finally:
        try:
            db.close()
        except Exception:
            pass
    return columns, rows[:max_rows], len(rows) > max_rows


def _mysql_query(conn, module, segments, params, max_rows, used):
    kwargs = {"host": _resolve(conn["host"], used), "port": conn["port"], "user": _resolve(conn["user"], used),
              "password": _resolve(conn["password"], used) if conn["password"] else "",
              "database": _resolve(conn["database"], used), "connect_timeout": min(10, conn["timeout"] + 3),
              "read_timeout": conn["timeout"] + 5, "write_timeout": 10, "charset": "utf8mb4",
              "autocommit": False, "local_infile": False,
              # 不缓冲的游标：只取要的那几行，不把整个结果集读进工具服务
              "cursorclass": module.cursors.SSCursor}
    if conn["tls"] != "disable":
        kwargs.update(ssl_verify_cert=conn["tls"] == "verify", ssl_verify_identity=conn["tls"] == "verify")
        if conn["ca"]:
            kwargs["ssl_ca"] = _resolve(conn["ca"], used)
    try:
        db = module.connect(**kwargs)
    except Exception as exc:
        raise SqlError(f"连不上数据库：{_sql_first_line(exc)}") from None
    try:
        cursor = db.cursor()
        try:
            cursor.execute(f"SET SESSION max_execution_time = {conn['timeout'] * 1000}")   # MySQL 5.7.8+
        except module.Error:
            try:
                cursor.execute(f"SET SESSION max_statement_time = {conn['timeout']}")       # MariaDB 10.1+
            except module.Error:
                pass
        cursor.execute("START TRANSACTION READ ONLY")   # 第二层：只读事务
        cursor.execute(_sql_render(segments, "pyformat"), params)
        columns = [item[0] for item in cursor.description or []]
        rows = cursor.fetchmany(max_rows + 1)
    except Exception as exc:
        text = _sql_first_line(exc)
        code = exc.args[0] if getattr(exc, "args", None) else None
        if code in (3024, 1969) or "timed out" in text.lower():
            raise _sql_timeout(conn) from None
        raise SqlError(f"查询失败：{text}") from None
    finally:
        try:
            db.close()   # 不读完剩下的行、不回滚：直接断开，服务器那边的只读事务随连接结束
        except Exception:
            pass
    return columns, rows[:max_rows], len(rows) > max_rows


SQL_RUNNERS = {"sqlite": _sqlite_query, "postgres": _postgres_query, "mysql": _mysql_query}


def _run_sql(spec, args):
    sql = spec["sql"]
    connection = spec.get("connection")
    if connection is None:
        return {"ok": False, "error": f"连接 {sql['conn']} 不存在，该工具暂不可用"}
    module, reason = _driver(connection["type"])
    if module is None:
        return {"ok": False, "error": reason}
    try:
        values = {key: _value(key, param, args or {}) for key, param in spec["params"].items()}
    except ValueError as exc:
        return {"ok": False, "error": str(exc)}
    params = {key: int(value) if spec["params"][key]["type"] == "int" else value for key, value in values.items()}
    used = []
    shown = _display(spec)
    try:
        columns, rows, more = SQL_RUNNERS[connection["type"]](connection, module, sql["segments"], params,
                                                              sql["max_rows"], used)
    except ValueError as exc:   # 凭据没配置
        return {"ok": False, "error": str(exc), "command": shown}
    except SqlError as exc:
        return {"ok": False, "error": _scrub(str(exc), used), "command": shown}
    output = _scrub(_sql_table(columns, rows, more, sql["max_rows"]), used)
    return {"ok": True, "command": shown, "output": _cut(output), "rows": len(rows)}


# ---- MCP 客户端 ------------------------------------------------------------

class McpError(RuntimeError):
    """和某个 MCP server 打交道失败：没连上、超时、server 返回 JSON-RPC 错误。"""


def _check_mcp_servers(document, problems):
    """主文件顶层 mcp_servers → {id: 配置}。坏条目跳过并记 problem，不拖垮其他 server。

    两种：command（宿主机上的 stdio 子进程）或 url（远程 Streamable HTTP server），只能写一种。
    command 不受 INTERPRETERS 限制：MCP server 本来就是 python/node 跑的一段程序。这不是放宽，
    而是把「允许宿主机跑哪段代码」这个决定完整交给手写主文件的 root——和脚本型工具的 trust 同一个意思。
    url 同理：「允许把实参发给哪个远程服务」也只能由 root 写在主文件里；请求头只能是固定值或凭据引用，只做静态鉴权。
    """
    raw = document.get("mcp_servers")
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        problems.append("mcp_servers 必须是映射：server id → {command, args, env, cwd} 或 {url, headers}")
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
            remote = entry.get("url") not in (None, "")
            if remote == (entry.get("command") not in (None, "")):
                raise ConfigError(f"mcp_servers.{ident} 要么写 command（宿主机上的 stdio 子进程），"
                                  f"要么写 url（远程 Streamable HTTP server），只能写一种")
            fields = MCP_HTTP_FIELDS if remote else MCP_STDIO_FIELDS
            unknown = sorted(str(key) for key in entry if key not in fields)
            if unknown:
                raise ConfigError(f"mcp_servers.{ident} 里有不认识的字段 {'、'.join(unknown)}"
                                  f"（{'远程' if remote else 'stdio'} server 只认 {'、'.join(fields)}）")
            config = _check_mcp_http(ident, entry) if remote else _check_mcp_stdio(ident, entry)
            config["label"] = str(entry.get("label", "")).strip()[:GROUP_MAX] or ident
            declared = _check_external(f"mcp_servers.{ident}", entry.get("external"))
            config["declared_external"] = declared
            if declared is not None:
                config["external"], config["external_why"] = declared, f"管理员声明为{'外部' if declared else '内部'}"
            elif remote:
                config["external"], config["external_why"] = _judge_address(config["url"], url=True)
            else:
                config["external"], config["external_why"] = (
                    False, "本机的子进程（它自己会访问哪里，工具服务看不到；需要时管理员声明 external: true）")
            servers[ident] = config
        except ConfigError as exc:
            problems.append(str(exc))
    return servers


def _check_mcp_stdio(ident, entry):
    command = str(entry.get("command", "")).strip()
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
            raise ConfigError(f"mcp_servers.{ident}.env 不能把 {key} 交给 server：那是工具服务自己的凭据")
        _check_secret_refs(f"mcp_servers.{ident}.env.{key}", str(value))
    cwd = entry.get("cwd")
    return {"transport": "stdio", "command": command, "args": [str(a) for a in args],
            "env": {str(k): str(v) for k, v in env.items()}, "cwd": str(cwd).strip() if cwd else ""}


# 远程 server 的请求头里这些由协议和传输层管，管理员不能写
MCP_RESERVED_HEADERS = ("content-type", "content-length", "accept", "host", "mcp-session-id", "mcp-protocol-version",
                        "mcp-method", "mcp-name", "last-event-id")


def _check_mcp_http(ident, entry):
    owner = f"mcp_servers.{ident}"
    url = str(entry.get("url", "")).strip()
    env = ENV_BASE.match(url)
    if env:
        _check_secret_refs(owner, url)
        rest = env.group(2)
    else:
        literal = re.match(r"^https?://([^/?#]+)(.*)$", url)
        if not literal:
            raise ConfigError(f"{owner}.url 必须以 http:// 或 https:// 开头，或者以 ${{名字}} 开头")
        if re.search(r"[{}$@]", literal.group(1)):
            raise ConfigError(f"{owner}.url 的主机名部分不能有参数、变量或用户名密码（凭据写在 headers 里）")
        rest = literal.group(2)
    if rest and not rest.startswith("/"):
        raise ConfigError(f"{owner}.url 主机名后面必须直接是路径（以 / 开头）")
    if re.search(r"[{}$?#]", rest):
        raise ConfigError(f"{owner}.url 不能带查询串或变量：凭据请写在 headers 里")
    headers = entry.get("headers") or {}
    if not isinstance(headers, dict):
        raise ConfigError(f"{owner}.headers 必须是映射")
    clean = {}
    for key, value in headers.items():
        key, value = str(key), str(value)
        if not HEADER_NAME.match(key):
            raise ConfigError(f"{owner}.headers 的名字不合法：{key[:40]!r}")
        if key.lower() in MCP_RESERVED_HEADERS or key.lower().startswith("mcp-param-"):
            raise ConfigError(f"{owner}.headers 不能写 {key}：它由 MCP 协议和传输层管")
        if URL_PARAM.search(SECRET_REF.sub("", value)):
            raise ConfigError(f"{owner}.headers.{key} 只能写固定值或凭据引用 ${{名字}}")
        _check_secret_refs(f"{owner}.headers.{key}", value)
        clean[key] = value
    protocol = str(entry.get("protocol") or "auto").strip()
    if protocol not in MCP_HTTP_PROTOCOLS:
        raise ConfigError(f"{owner}.protocol 只能是 {'、'.join(MCP_HTTP_PROTOCOLS)}")
    return {"transport": "http", "url": url, "headers": clean, "protocol": protocol,
            "timeout": _bounded_int(owner, entry, "timeout", (TIMEOUT, 1, 120)),
            "ca": _check_ca(owner, entry.get("ca"))}


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
        self.notes = []             # 审批层对这个 server 的备注：哪些工具没列出、为什么
        self._send_lock = threading.Lock()
        self._state_lock = threading.Lock()
        # 握手期间不许别的线程再来 start/stop：后台线程在连，/exec 同时到来就会把它刚拉起的进程杀掉
        self._life_lock = threading.RLock()
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
        with self._life_lock:
            if self.alive() and self.online:
                return   # 等锁期间别的线程已经连好了
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
        with self._life_lock:
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
        with self._life_lock:
            self._go_offline(reason)
            self._kill()

    def status(self, approved=0):
        return {"label": self.label, "online": bool(self.online and self.alive()),
                "reason": "" if self.online else self.reason,
                "discovered": len(self.tools), "approved": approved,
                "notes": list(self.notes),
                "server": self.server_info, "protocol": self.protocol, "transport": "stdio",
                "external": bool(self.config.get("external"))}


class _McpRefused(McpError):
    """server 连上了，但拒绝了这个请求（HTTP 4xx/5xx 或 JSON-RPC 错误）。auto 协商据此退回 initialize。"""

    def __init__(self, message, code=None, data=None):
        super().__init__(message)
        self.code, self.data = code, data


class _McpSessionGone(McpError):
    """带着会话 id 的请求收到 404：会话过期了，重新 initialize 再发一次。"""


MCP_CLIENT_INFO = {"name": "doc2sop-ops-readonly", "version": "1"}
_HEADER_SAFE = re.compile(r"^[\x20-\x7E]*$")
_HEADER_TOKEN = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")


def _mcp_header_value(text):
    """请求头的值：可见 ASCII 原样；中文、首尾空白、控制字符等包成 =?base64?…?=（和官方 SDK 一致）。"""
    if _HEADER_SAFE.fullmatch(text) and text == text.strip() and not re.fullmatch(r"=\?base64\?.*\?=", text):
        return text
    return "=?base64?" + base64.b64encode(text.encode("utf-8")).decode("ascii") + "?="


def _mcp_param_paths(schema):
    """2026-07-28：inputSchema 里标了 x-mcp-header 的参数（沿 properties 一路走下去）→ {路径: 请求头名}。

    tools/call 要把这些参数的值同时放进 Mcp-Param-<名> 请求头（给中间的网关路由用），server 会核对两边一致。
    """
    out = {}

    def walk(node, path):
        properties = node.get("properties") if isinstance(node, dict) else None
        for key, sub in (properties or {}).items():
            if not isinstance(sub, dict):
                continue
            token = sub.get("x-mcp-header")
            if isinstance(token, str) and _HEADER_TOKEN.fullmatch(token):
                out[path + (str(key),)] = token
            walk(sub, path + (str(key),))

    walk(schema, ())
    return out


class McpHttpServer:
    """远程 MCP server（Streamable HTTP）。对外的接口和 McpServer 一样：发现、待审、批准、只读确认、schema 指纹走同一套。

    两个协议时代（见 MCP_MODERN 上面的说明）：
      2025-11-25 及以前  initialize → notifications/initialized；server 可能给 Mcp-Session-Id，之后的请求都带它和
                         MCP-Protocol-Version。带着会话 id 收到 404 是会话过期：重新 initialize，把请求再发一次。
      2026-07-28         没有握手和会话：server/discover 问能力；每个请求的 params._meta 带协议版本、客户端信息和能力，
                         请求头带 MCP-Protocol-Version、Mcp-Method（tools/call 还有 Mcp-Name 和 Mcp-Param-*）。
    每个请求一次 POST，回应是 JSON 或 SSE 流（中途可能夹着通知、server 发来的请求，一直读到我们这条的回应）。
    不跟随任何跳转；回应超过 MCP_HTTP_MAX 字节、超过时限都断开报错；请求头里的凭据、来自凭据的地址在输出里脱敏。
    """

    def __init__(self, ident, config):
        self.id = ident
        self.config = config
        self.label = config.get("label") or ident
        self.online = False
        self.reason = "尚未连接"
        self.tools = {}
        self.failures = 0
        self.next_retry = 0.0
        self.list_changed = False
        self.last_discovery = 0.0
        self.secrets = []
        self.server_info = {}
        self.protocol = ""
        self.notes = []
        self.mode = ""              # legacy（initialize 握手）| modern（2026-07-28）
        self.session = None         # Mcp-Session-Id（legacy，server 给了才有）
        self.param_paths = {}       # 工具原名 -> x-mcp-header 的 {路径: 请求头名}（modern）
        self._life_lock = threading.RLock()
        self._id_lock = threading.Lock()
        self._next_id = 0

    def alive(self):
        return self.online   # 没有子进程：握手（或 discover）成功就算活着

    # --- 一次 POST ------------------------------------------------------------------

    def _endpoint(self):
        """(地址, 管理员配的请求头, TLS 上下文)。凭据现取，取出来的值记进 self.secrets（输出脱敏）。"""
        used = []
        try:
            url = self.config["url"]
            env = ENV_BASE.match(url)
            if env:
                base = _secret(env.group(1)).rstrip("/")
                used.append(base)
                if not re.match(r"^https?://[^/?#@]+(/[^?#]*)?$", base):
                    raise ValueError(f"{env.group(1)} 不是合法的 http(s) 地址")
                url = base + env.group(2)
            headers = {key: _fill_secrets(value, used) for key, value in self.config["headers"].items()}
            context = _ssl_context(_resolve(self.config["ca"])) if self.config["ca"] else None
        except (ValueError, ConfigError) as exc:
            raise McpError(str(exc)) from None
        self.secrets = [s for s in used if s]
        return url, headers, context

    def _post(self, message, extra, timeout, capture_session=False):
        """发一条 JSON-RPC 消息。请求返回回应（dict），通知、回应返回 None（server 应答 202）。"""
        url, headers, context = self._endpoint()
        headers.update({"Content-Type": "application/json", "Accept": "application/json, text/event-stream",
                        "User-Agent": "doc2sop-ops-readonly/1"})
        headers.update(extra)
        body = json.dumps(message, ensure_ascii=False).encode("utf-8")
        deadline = time.monotonic() + timeout
        request = urllib.request.Request(url, data=body, headers=headers, method="POST")
        try:
            response = _opener(context).open(request, timeout=timeout)
        except urllib.error.HTTPError as exc:
            self._refused(exc, url)
        except Exception as exc:
            raise McpError(_scrub(f"请求失败：{exc.__class__.__name__}: {exc}", self.secrets)) from None
        with response:
            if capture_session:
                self.session = response.headers.get("Mcp-Session-Id") or None
            if response.status == 202 or "id" not in message or "method" not in message:
                return None
            kind = (response.headers.get("Content-Type") or "").split(";")[0].strip().lower()
            if kind == "application/json":
                data = response.read(MCP_HTTP_MAX + 1)
                if len(data) > MCP_HTTP_MAX:
                    raise McpError(f"回应超过 {MCP_HTTP_MAX // 1024 // 1024} MB，已断开")
                try:
                    reply = json.loads(data.decode("utf-8"))
                except ValueError:
                    raise McpError("回应不是合法的 JSON") from None
                found = self._pick(reply, message["id"])
                if found is None:
                    raise McpError("回应里没有这个请求的结果")
                return found
            if kind == "text/event-stream":
                return self._read_sse(response, message["id"], deadline)
            raise McpError(f"不认识的回应类型 {kind or '（没有 Content-Type）'}")

    def _refused(self, exc, url):
        """HTTP 错误 → 抛出合适的 McpError。跳转一律不跟随，只说明它想跳到哪（同一主机时给路径）。"""
        status = exc.code
        if 300 <= status < 400:
            target = exc.headers.get("Location", "") if exc.headers else ""
            same = urllib.parse.urlsplit(urllib.parse.urljoin(url, target))
            here = urllib.parse.urlsplit(url)
            where = f"（同一主机的 {same.path}，请把配置里的 url 改成它）" \
                if (same.scheme, same.netloc) == (here.scheme, here.netloc) else "（别的地址）"
            raise _McpRefused(f"server 返回 {status} 跳转{where}，已拒绝跟随：只访问配置里写明的地址")
        if status == 404 and self.session:
            raise _McpSessionGone("会话已过期")
        data = b""
        try:
            data = exc.read(64 * 1024) if exc.fp else b""
        except Exception:
            pass
        try:
            reply = json.loads(data.decode("utf-8"))
        except ValueError:
            reply = None
        error = reply.get("error") if isinstance(reply, dict) else None
        if isinstance(error, dict):
            raise _McpRefused(_scrub(f"server 返回错误 {error.get('code', '')}：{error.get('message', '')}",
                                     self.secrets), error.get("code"), error.get("data"))
        raise _McpRefused(f"server 返回 HTTP {status}", status)

    def _pick(self, reply, request_id):
        """回应体（一条或一批）里找这个请求的结果；顺手处理夹在里面的通知和 server 发来的请求。"""
        for item in reply if isinstance(reply, list) else [reply]:
            if not isinstance(item, dict):
                continue
            if "method" in item:
                self._incoming(item)
            elif item.get("id") == request_id and ("result" in item or "error" in item):
                return item
        return None

    def _incoming(self, message):
        """server 发来的通知只认 tools/list_changed；发来的请求（sampling、elicitation……）一律回「不支持」。"""
        if message.get("id") is None:
            if message.get("method") == "notifications/tools/list_changed":
                self.list_changed = True
            return
        if self.mode != "legacy":
            return   # 2026-07-28 的 HTTP 上没有客户端发给 server 的回应通道；server 拿不到回应自然超时
        try:
            self._post({"jsonrpc": "2.0", "id": message["id"],
                        "error": {"code": -32601, "message": "doc2sop 工具服务不支持该方法"}},
                       self._headers(None), 5)
        except McpError:
            pass

    def _read_sse(self, response, request_id, deadline):
        """读 SSE 流，直到这个请求的回应出现。注释行（:）是保活；event 不是 message 的忽略。

        流在回应之前断了：server 给过事件 id，就按 Last-Event-ID 用 GET 重连接着读（2025-11-25 起的 SSE 轮询），最多 3 次。
        """
        total, lines, event, last_id, attempts, resumed = 0, [], "message", None, 0, None
        try:
            while True:
                if time.monotonic() > deadline:
                    raise McpError(f"等回应超时（{self.config['timeout']}s）")
                try:
                    raw = response.readline(MCP_HTTP_MAX + 1)
                except Exception as exc:
                    raise McpError(f"读回应失败：{exc.__class__.__name__}") from None
                if not raw:
                    if last_id is None or attempts >= 3:
                        raise McpError("server 在给出结果之前关闭了连接")
                    attempts += 1
                    if resumed is not None:
                        resumed.close()
                    response = resumed = self._resume(last_id, deadline)
                    lines, event = [], "message"
                    continue
                total += len(raw)
                if total > MCP_HTTP_MAX:
                    raise McpError(f"回应超过 {MCP_HTTP_MAX // 1024 // 1024} MB，已断开")
                line = raw.decode("utf-8", "replace").rstrip("\r\n")
                if line:
                    if line.startswith(":"):
                        continue
                    field, _, value = line.partition(":")
                    value = value[1:] if value.startswith(" ") else value
                    if field == "data":
                        lines.append(value)
                    elif field == "event":
                        event = value or "message"
                    elif field == "id" and value and "\x00" not in value:
                        last_id = value
                    continue
                if lines and event == "message":
                    try:
                        reply = json.loads("\n".join(lines))
                    except ValueError:
                        reply = None
                    found = self._pick(reply, request_id) if reply is not None else None
                    if found is not None:
                        return found
                lines, event = [], "message"
        finally:
            if resumed is not None:
                resumed.close()

    def _resume(self, last_id, deadline):
        url, headers, context = self._endpoint()
        headers.update({"Accept": "text/event-stream", "Last-Event-ID": last_id,
                        "User-Agent": "doc2sop-ops-readonly/1"})
        headers.update(self._headers(None))
        request = urllib.request.Request(url, headers=headers, method="GET")
        try:
            return _opener(context).open(request, timeout=max(1.0, deadline - time.monotonic()))
        except urllib.error.HTTPError as exc:
            self._refused(exc, url)
        except Exception as exc:
            raise McpError(_scrub(f"重连失败：{exc.__class__.__name__}: {exc}", self.secrets)) from None

    # --- JSON-RPC ---------------------------------------------------------------------

    def _headers(self, method, params=None):
        """这个请求要带的协议请求头。"""
        if self.mode == "modern":
            headers = {"MCP-Protocol-Version": MCP_MODERN}
            if method:
                headers["Mcp-Method"] = method
            if method == "tools/call" and isinstance((params or {}).get("name"), str):
                headers["Mcp-Name"] = _mcp_header_value(params["name"])
                arguments = params.get("arguments") if isinstance(params.get("arguments"), dict) else {}
                for path, token in self.param_paths.get(params["name"], {}).items():
                    value = arguments
                    for key in path:
                        value = value.get(key) if isinstance(value, dict) else None
                    if isinstance(value, bool):
                        headers["Mcp-Param-" + token] = "true" if value else "false"
                    elif isinstance(value, (str, int, float)):
                        headers["Mcp-Param-" + token] = _mcp_header_value(str(value))
            return headers
        headers = {}
        if self.protocol:
            headers["MCP-Protocol-Version"] = self.protocol
        if self.session:
            headers["Mcp-Session-Id"] = self.session
        return headers

    def request(self, method, params=None, timeout=None, _again=True):
        timeout = timeout or self.config["timeout"]
        with self._id_lock:
            self._next_id += 1
            ident = self._next_id
        body = dict(params or {})
        if self.mode == "modern":
            body["_meta"] = {**(body.get("_meta") or {}), MCP_META + "protocolVersion": MCP_MODERN,
                             MCP_META + "clientInfo": MCP_CLIENT_INFO, MCP_META + "clientCapabilities": {}}
        message = {"jsonrpc": "2.0", "id": ident, "method": method}
        if body or self.mode == "modern":
            message["params"] = body
        try:
            reply = self._post(message, self._headers(method, body), timeout, capture_session=method == "initialize")
        except _McpSessionGone:
            if not _again:
                raise McpError("会话过期，重新连接后仍然失败") from None
            with self._life_lock:
                self._initialize()
            return self.request(method, params, timeout, _again=False)
        if reply is None:
            raise McpError(f"server 对 {method} 回了 202，没有给出结果")
        error = reply.get("error")
        if isinstance(error, dict):
            raise _McpRefused(_scrub(f"server 返回错误 {error.get('code', '')}：{error.get('message', '')}",
                                     self.secrets).strip(), error.get("code"), error.get("data"))
        result = reply.get("result")
        if isinstance(result, dict) and result.get("resultType") not in (None, "complete"):
            raise McpError(f"server 要求客户端交互（resultType={str(result.get('resultType'))[:30]}），工具服务不支持")
        return result

    def notify(self, method, params=None):
        message = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            message["params"] = params
        self._post(message, self._headers(method), self.config["timeout"])

    # --- 连接：协商协议版本 ---------------------------------------------------------------

    def _discover(self):
        """2026-07-28：server/discover。server 不认（任何 HTTP 或 JSON-RPC 错误）抛 _McpRefused，auto 时退回 initialize。"""
        self.mode, self.session, self.protocol = "modern", None, ""
        result = self.request("server/discover", {}, timeout=min(MCP_INIT_TIMEOUT, self.config["timeout"]))
        if not isinstance(result, dict):
            raise _McpRefused("server/discover 的结果不是对象")
        versions = result.get("supportedVersions") if isinstance(result.get("supportedVersions"), list) else []
        if MCP_MODERN not in versions:
            raise _McpRefused(f"server 只支持 {', '.join(map(str, versions[:6])) or '（没说）'}")
        self.protocol = MCP_MODERN
        info = (result.get("_meta") or {}).get(MCP_META + "serverInfo") if isinstance(result.get("_meta"), dict) else None
        self.server_info = info if isinstance(info, dict) else {}

    def _initialize(self):
        """2025-11-25 及以前：initialize → notifications/initialized。server 给了会话 id 就记下，之后每个请求都带。"""
        self.mode, self.session, self.protocol = "legacy", None, ""
        offer = MCP_HANDSHAKE if self.config["protocol"] in ("auto", MCP_HANDSHAKE) else self.config["protocol"]
        result = self.request("initialize", {"protocolVersion": offer, "capabilities": {},
                                             "clientInfo": MCP_CLIENT_INFO},
                              timeout=min(MCP_INIT_TIMEOUT, self.config["timeout"]), _again=False) or {}
        version = str(result.get("protocolVersion", ""))
        if version not in MCP_HANDSHAKE_VERSIONS:
            raise McpError(f"server 回的协议版本 {version[:30] or '（空）'} 不认识")
        self.protocol = version
        self.server_info = result.get("serverInfo") if isinstance(result.get("serverInfo"), dict) else {}
        self.notify("notifications/initialized")

    def _connect(self):
        wanted = self.config["protocol"]
        if wanted in ("auto", MCP_MODERN):
            try:
                self._discover()
                return
            except _McpRefused as exc:
                if wanted == MCP_MODERN:
                    raise McpError(f"server 不支持 {MCP_MODERN}：{exc}") from None
        self._initialize()

    # --- 生命周期（和 McpServer 一样）--------------------------------------------------------

    def start(self):
        with self._life_lock:
            if self.online:
                return
            if time.monotonic() < self.next_retry:
                raise McpError(self.reason)
            try:
                self._connect()
                self.online = True
                self.reason = ""
                self.list_tools()
            except McpError as exc:
                self.failures += 1
                delay = MCP_BACKOFF[min(self.failures, len(MCP_BACKOFF)) - 1]
                self.next_retry = time.monotonic() + delay
                self.online = False
                self.reason = f"连接失败（第 {self.failures} 次）：{exc}；{delay}s 后重试"
                raise McpError(self.reason) from None
            self.failures = 0
            self.next_retry = 0.0
        print(f"[mcp:{self.id}] 已连接 {self.server_info.get('name', '')} {self.server_info.get('version', '')}"
              f"（Streamable HTTP，协议 {self.protocol}{'，有会话' if self.session else ''}），"
              f"发现 {len(self.tools)} 个工具", flush=True)

    def ensure(self):
        with self._life_lock:
            if not self.online:
                self.start()

    def list_tools(self):
        found, cursor = {}, None
        for _ in range(100):
            result = self.request("tools/list", {"cursor": cursor} if cursor else None) or {}
            for tool in result.get("tools") or []:
                if isinstance(tool, dict) and str(tool.get("name", "")).strip():
                    found[str(tool["name"])] = tool
            cursor = result.get("nextCursor")
            if not cursor:
                break
        self.tools = found
        self.param_paths = {name: _mcp_param_paths(tool.get("inputSchema")) for name, tool in found.items()}
        self.list_changed = False
        self.last_discovery = time.monotonic()
        return found

    def call(self, tool, arguments, timeout=None):
        self.ensure()
        try:
            return self.request("tools/call", {"name": tool, "arguments": arguments or {}}, timeout=timeout) or {}
        except McpError as exc:
            if not isinstance(exc, _McpRefused):
                self.online = False   # 连不上、超时：下一次调用重新握手
                self.reason = str(exc)
            raise

    def stop(self, reason="已停止"):
        with self._life_lock:
            session, self.session = self.session, None
            if session and self.mode == "legacy":
                # 有会话就告诉 server 可以收了（DELETE）；失败无所谓，server 自己会过期
                try:
                    url, headers, context = self._endpoint()
                    headers.update({"Mcp-Session-Id": session, "MCP-Protocol-Version": self.protocol})
                    with _opener(context).open(urllib.request.Request(url, headers=headers, method="DELETE"),
                                               timeout=3):
                        pass
                except Exception:
                    pass
            self.online = False
            self.reason = reason

    def status(self, approved=0):
        url = self.config["url"]
        return {"label": self.label, "online": bool(self.online), "reason": "" if self.online else self.reason,
                "discovered": len(self.tools), "approved": approved, "notes": list(self.notes),
                "server": self.server_info, "protocol": self.protocol, "transport": "http",
                "url": url if ENV_BASE.match(url) else _url_prefix(url),
                "external": bool(self.config.get("external"))}


def _url_prefix(url):
    """给人看的地址：协议、主机、端口和路径，不带查询串。"""
    parts = urllib.parse.urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}{parts.path}"


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
                    kind = McpHttpServer if config.get("transport") == "http" else McpServer
                    self.servers[ident] = kind(ident, config)
        self._wake.set()

    def get(self, ident):
        return self.servers.get(ident)

    def sync(self, ident=None, force=False):
        """同步地把（某个/所有）server 连上并刷新工具列表，再交给审批层。测试与后台线程都走这里。"""
        for server in ([self.servers[ident]] if ident in self.servers else list(self.servers.values())):
            try:
                if not (server.alive() and server.online):
                    if time.monotonic() < server.next_retry:
                        continue   # 退避期内不反复尝试，也不反复刷日志
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
_mcp.on_discovered = _mcp_discovered


# ---- MCP 执行：形状校验 → 收紧项 → tools/call → 拍平输出 ------------------------

def _is_type(value, kind):
    if kind == "string":
        return isinstance(value, str)
    if kind == "boolean":
        return isinstance(value, bool)
    if kind == "integer":
        return (isinstance(value, int) and not isinstance(value, bool)) or \
               (isinstance(value, float) and value.is_integer())
    if kind == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if kind == "object":
        return isinstance(value, dict)
    if kind == "array":
        return isinstance(value, list)
    if kind == "null":
        return value is None
    return True   # 不认识的 type 放行，server 自己还会校一次


def _check_shape(value, schema, path="参数"):
    """按 JSON Schema 的常用子集校验，返回错误列表（空表示通过）。

    标准库手写而不引入 jsonschema：覆盖 type/required/properties/items/enum/const/
    anyOf/oneOf/allOf/additionalProperties/数值范围/长度范围/pattern。不认识的关键字放行——
    这一层的目的是把明显填错的参数在进 server 之前挡掉并给出中文原因，不是替 server 做完整校验。
    """
    if not isinstance(schema, dict):
        return []
    errors = []
    kinds = schema.get("type")
    if kinds:
        kinds = kinds if isinstance(kinds, list) else [kinds]
        if not any(_is_type(value, k) for k in kinds):
            return [f"{path} 应为 {'/'.join(str(k) for k in kinds)}，实际是 {type(value).__name__}"]
    if "enum" in schema and isinstance(schema["enum"], list) and value not in schema["enum"]:
        errors.append(f"{path} 只能是 {schema['enum']} 之一")
    if "const" in schema and value != schema["const"]:
        errors.append(f"{path} 只能是 {schema['const']!r}")
    for key in ("anyOf", "oneOf"):
        options = schema.get(key)
        if isinstance(options, list) and options and \
                not any(not _check_shape(value, option, path) for option in options):
            errors.append(f"{path} 不符合任一候选形状")
    if isinstance(schema.get("allOf"), list):
        for option in schema["allOf"]:
            errors.extend(_check_shape(value, option, path))

    if isinstance(value, str):
        if isinstance(schema.get("minLength"), int) and len(value) < schema["minLength"]:
            errors.append(f"{path} 至少 {schema['minLength']} 个字符")
        if isinstance(schema.get("maxLength"), int) and len(value) > schema["maxLength"]:
            errors.append(f"{path} 最多 {schema['maxLength']} 个字符")
        if isinstance(schema.get("pattern"), str):
            try:
                if not re.search(schema["pattern"], value):
                    errors.append(f"{path} 不符合要求的格式")
            except re.error:
                pass   # ECMAScript 正则 Python 可能不认，放行
    elif isinstance(value, (int, float)) and not isinstance(value, bool):
        bounds = {key: schema[key] for key in ("minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum")
                  if isinstance(schema.get(key), (int, float)) and not isinstance(schema.get(key), bool)}
        if "minimum" in bounds and value < bounds["minimum"]:
            errors.append(f"{path} 不能小于 {bounds['minimum']}")
        if "maximum" in bounds and value > bounds["maximum"]:
            errors.append(f"{path} 不能大于 {bounds['maximum']}")
        if "exclusiveMinimum" in bounds and value <= bounds["exclusiveMinimum"]:
            errors.append(f"{path} 必须大于 {bounds['exclusiveMinimum']}")
        if "exclusiveMaximum" in bounds and value >= bounds["exclusiveMaximum"]:
            errors.append(f"{path} 必须小于 {bounds['exclusiveMaximum']}")
    elif isinstance(value, list):
        if isinstance(schema.get("minItems"), int) and len(value) < schema["minItems"]:
            errors.append(f"{path} 至少 {schema['minItems']} 项")
        if isinstance(schema.get("maxItems"), int) and len(value) > schema["maxItems"]:
            errors.append(f"{path} 最多 {schema['maxItems']} 项")
        items = schema.get("items")
        if isinstance(items, dict):
            for index, item in enumerate(value):
                errors.extend(_check_shape(item, items, f"{path}[{index}]"))
        elif isinstance(items, list):
            for index, (item, sub) in enumerate(zip(value, items)):
                errors.extend(_check_shape(item, sub, f"{path}[{index}]"))
    elif isinstance(value, dict):
        properties = schema.get("properties") if isinstance(schema.get("properties"), dict) else {}
        required = schema.get("required") if isinstance(schema.get("required"), list) else []
        for key in required:
            if str(key) not in value:
                inner = path[len("参数 "):] + "." if path.startswith("参数 ") else ""
                errors.append(f"缺少必填参数：{inner}{key}")
        for key, item in value.items():
            sub = properties.get(key)
            label = f"{path}.{key}" if path != "参数" else f"参数 {key}"
            if sub is not None:
                errors.extend(_check_shape(item, sub, label))
            elif schema.get("additionalProperties") is False:
                errors.append(f"多余的参数：{key}")
            elif isinstance(schema.get("additionalProperties"), dict):
                errors.extend(_check_shape(item, schema["additionalProperties"], label))
    return errors


def _coerce_top(value, prop):
    """顶层参数的宽松转换：模型常把数字发成 "2026"、布尔发成 "true"，这些不该算填错。"""
    kind = prop.get("type") if isinstance(prop, dict) else None
    if isinstance(kind, list):
        kind = next((k for k in kind if k != "null"), None)
    if isinstance(value, str):
        text = value.strip()
        if kind == "integer" and re.fullmatch(r"[+-]?\d+", text):
            return int(text)
        if kind == "number" and re.fullmatch(r"[+-]?\d+(\.\d+)?", text):
            return float(text) if "." in text else int(text)
        if kind == "boolean" and text.lower() in ("true", "false"):
            return text.lower() == "true"
    elif kind == "string" and isinstance(value, (int, float)) and not isinstance(value, bool):
        return str(value)
    return value


def _apply_restrict(args, restrict):
    errors = []
    for key, rule in restrict.items():
        if key not in args or args[key] is None:
            continue
        value = args[key]
        if "pattern" in rule and not PATTERNS[rule["pattern"]].match(str(value)):
            errors.append(f"参数 {key} 不合法：{str(value)[:40]!r}")
        if "enum" in rule and value not in rule["enum"]:
            errors.append(f"参数 {key} 只能是 {rule['enum']} 之一")
        if "max_len" in rule and len(str(value)) > rule["max_len"]:
            errors.append(f"参数 {key} 最多 {rule['max_len']} 个字符")
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            if "min" in rule and value < rule["min"]:
                errors.append(f"参数 {key} 不能小于 {rule['min']:g}")
            if "max" in rule and value > rule["max"]:
                errors.append(f"参数 {key} 不能大于 {rule['max']:g}")
    return errors


def prepare_mcp_args(args, schema, restrict=None):
    """校验并整理要发给 server 的参数：(清洗后的 args, 错误列表)。"""
    args = dict(args) if isinstance(args, dict) else {}
    properties = schema.get("properties") if isinstance(schema.get("properties"), dict) else {}
    clean = {}
    for key, value in args.items():
        if value is None:
            continue   # 应用侧没填的参数是 None，不要当成「传了 null」；必填的留给 required 去报
        clean[key] = _coerce_top(value, properties.get(key))
    errors = _check_shape(clean, schema)
    errors.extend(_apply_restrict(clean, restrict or {}))
    return clean, errors


def _flatten_content(result):
    """tools/call 的 content 块拍成一段文字；二进制块只留一句说明，不把 base64 喂给模型。"""
    parts = []
    for block in result.get("content") or []:
        if not isinstance(block, dict):
            continue
        kind = block.get("type")
        if kind == "text":
            parts.append(str(block.get("text", "")))
        elif kind == "resource":
            resource = block.get("resource") if isinstance(block.get("resource"), dict) else {}
            parts.append(str(resource["text"]) if "text" in resource
                         else f"[资源 {resource.get('uri', '')}，二进制内容已省略]")
        elif kind == "resource_link":
            parts.append(f"[资源链接 {block.get('uri', '')}]")
        elif kind in ("image", "audio"):
            parts.append(f"[{'图片' if kind == 'image' else '音频'} {block.get('mimeType', '')}，已省略]")
        else:
            parts.append(f"[{kind} 内容已省略]")
    structured = result.get("structuredContent")
    if structured is not None:
        try:
            dumped = json.dumps(structured, ensure_ascii=False, indent=1)
        except (TypeError, ValueError):
            dumped = ""
        # 很多 server 的 structuredContent 只是把文本再包一层（{"content": 同一段话}），重复的不附
        texts = [p for p in parts if p]
        duplicate = dumped and ("\n".join(texts) == dumped or
                                (isinstance(structured, dict) and list(structured.values()) == texts))
        if dumped and not duplicate:
            parts.append(dumped)
    return "\n".join(p for p in parts if p).strip()


def _run_mcp(spec, args):
    server = _mcp.get(spec["mcp"]["server"])
    if server is not None and not (server.online and server.alive()):
        try:
            server.ensure()   # 崩过的 server 在这里重拉；退避期内会直接报原因
        except McpError:
            pass
    runnable, reason, live = _mcp_state(spec)
    if not runnable:
        return {"ok": False, "error": f"该工具暂不可用：{reason}"}
    # 执行期再校一次只读依据：条目可能是手写的，批准时的检查它没经过
    if _mcp_readonly(spec, live) == "none":
        return {"ok": False, "error": "拒绝执行：server 没有声明该工具只读，管理员也没有确认过"
                                      "（批准时加 --attest-readonly，或在条目里写 readonly_attested: true）"}
    schema = live.get("inputSchema") if isinstance(live.get("inputSchema"), dict) else spec["input_schema"]
    clean, errors = prepare_mcp_args(args, schema or {}, spec["restrict"])
    if errors:
        return {"ok": False, "error": "参数不合法：" + "；".join(errors[:5])}
    command = _display(spec)
    try:
        result = server.call(spec["mcp"]["tool"], clean, timeout=TIMEOUT)
    except McpError as exc:
        return {"ok": False, "error": _scrub(str(exc), server.secrets), "command": command}
    if not isinstance(result, dict):
        return {"ok": False, "error": "server 返回的结果不符合 MCP 规范（不是对象）", "command": command}
    text = _scrub(_flatten_content(result), server.secrets)
    truncated = len(text) > MAX_OUTPUT
    return {"ok": not result.get("isError"), "command": command,
            "output": text[:MAX_OUTPUT] + ("\n…（输出已截断）" if truncated else "")}


# ---- 在主机上执行 -----------------------------------------------------------------------
# 传输层用系统的 OpenSSH 客户端（subprocess，argv 列表，不经过 shell）：工具服务仍然只依赖标准库，systemd 单元不用改。
# 以后要支持 Windows 主机或不想依赖 ssh 程序时，可以再写一个同样接口（run）的实现，比如基于 paramiko。
#
# 两种模式：
#   guarded（受控，默认）  只发「工具名 + 参数」，主机上的 ops_exec.py（强制命令）按它自己的白名单校验后执行
#   direct（直连）         这边按 argv 模板校验、查黑名单，每个参数做 shell 转义后拼成一条命令发过去；只读靠账号权限

GUARDED_COMMAND = "doc2sop-ops-exec"   # 受控模式发的远程命令：强制命令会忽略它；没配强制命令的主机上它不存在，只会报错
SSH_CONNECT_TIMEOUT = 5
SSH_SLACK = 8                           # 远程调用的总时限 = TIMEOUT + 建连、起 python 的余量，要小于应用等 /exec 的 30 秒
SSH_OUTPUT_MAX = 1024 * 1024            # 从主机读回来的输出上限（字节），再多就丢掉，不让一台主机撑爆工具服务
SSH_PASS_ENV = ("PATH", "HOME", "LANG", "LC_ALL", "SYSTEMROOT", "TMPDIR")
HOST_REFRESH = 300                      # 后台每隔多久检查一遍各主机（list / probe），结果用来标可用性
EXEC_DIR = "/opt/ops-readonly"          # 主机上执行器和白名单的位置（push 装到这里，强制命令指向这里）


class HostError(RuntimeError):
    """连主机这一步失败了：没有 ssh 客户端、凭据不对、host key 不认识、连不上、超时。"""


def _known_hosts():
    """工具服务自己的 known_hosts，和主配置放在一起；按主机名（HostKeyAlias）登记，由 enroll 写入。"""
    path = Path(_state["path"])
    return path.with_name(f"{path.stem}.known_hosts")


def _pinned_keys(alias):
    """known_hosts 里登记给这台主机的 host key：[(类型, base64)]。"""
    try:
        lines = _known_hosts().read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    found = []
    for line in lines:
        parts = line.split()
        if len(parts) >= 3 and not line.startswith(("#", "@")) and alias in parts[0].split(","):
            found.append((parts[1], parts[2]))
    return found


def _check_known_hosts(host):
    """连之前先确认登记过 host key，而且文件没被放宽权限：从不自动接受，也不让别人往里塞。"""
    path = _known_hosts()
    if not _pinned_keys(host["name"]):
        raise HostError(f"主机 {host['name']} 的 host key 还没登记：先在工具服务所在机器上执行 "
                        f"ops_readonly.py enroll {host['name']}，核对指纹后登记")
    if os.name == "posix" and os.stat(path).st_mode & 0o022:
        raise HostError(f"{path.name} 的权限过宽（组或其他用户可写），拒绝使用：chmod 644 {path}")
    return path


def _key_file(host):
    """私钥文件的路径（凭据的值）。不是普通文件、是符号链接、组或其他用户能读写、不属于工具服务账号，都拒绝。

    报错里只写凭据的名字，不写路径：路径也是凭据的一部分，不进日志和页面。
    """
    shown = "${" + host["key"] + "}"
    try:
        path = _secret(host["key"])
    except ValueError:
        raise HostError(f"主机 {host['name']} 的私钥 {shown} 没有配置（环境变量 {_secret_env(host['key'])}，"
                        f"值是私钥文件的路径）") from None
    try:
        info = os.lstat(path)
    except OSError:
        raise HostError(f"主机 {host['name']} 的私钥 {shown} 指向的文件读不到") from None
    if not stat.S_ISREG(info.st_mode):
        raise HostError(f"主机 {host['name']} 的私钥 {shown} 不是普通文件（不能是符号链接或目录）")
    if os.name == "posix":
        if info.st_mode & 0o077:
            raise HostError(f"主机 {host['name']} 的私钥 {shown} 权限过宽（{oct(info.st_mode & 0o777)}），"
                            f"拒绝使用：只能由工具服务账号读写，chmod 600")
        if info.st_uid != os.geteuid():
            raise HostError(f"主机 {host['name']} 的私钥 {shown} 不属于工具服务的运行账号，拒绝使用")
    return path


def _communicate(argv, data, timeout, limit, env=None):
    """起一个子进程，喂 stdin、收 stdout/stderr（各最多 limit 字节），超时就杀掉。返回 (退出码, stdout, stderr)。"""
    kwargs = {"creationflags": subprocess.CREATE_NO_WINDOW} if hasattr(subprocess, "CREATE_NO_WINDOW") else {}
    proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            env=env, shell=False, **kwargs)
    buffers = (bytearray(), bytearray())

    def pump(stream, buffer):
        try:
            while True:
                block = stream.read1(65536)
                if not block:
                    return
                room = limit - len(buffer)
                if room > 0:
                    buffer.extend(block[:room])
        except (OSError, ValueError):
            return

    def feed():
        try:
            if data:
                proc.stdin.write(data)
            proc.stdin.close()
        except (OSError, ValueError):
            pass

    workers = [threading.Thread(target=pump, args=(proc.stdout, buffers[0]), daemon=True),
               threading.Thread(target=pump, args=(proc.stderr, buffers[1]), daemon=True),
               threading.Thread(target=feed, daemon=True)]
    for worker in workers:
        worker.start()
    try:
        code = proc.wait(timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(5)
        raise HostError(f"执行超时（{timeout}s，含建立连接）") from None
    finally:
        for worker in workers:
            worker.join(5)
        for stream in (proc.stdin, proc.stdout, proc.stderr):
            try:
                stream.close()
            except OSError:
                pass
    return code, bytes(buffers[0]), bytes(buffers[1])


class SshTransport:
    """系统的 OpenSSH 客户端。只用命令行选项，不读任何 ssh_config（-F 指向空设备）：

    host key 只认工具服务自己的 known_hosts（按主机名登记），不认识或变了一律失败，不会自动接受；
    只用指定的私钥（不用 agent、不试别的密钥、不问密码）；不转发 agent/X11/端口，不复用连接，不走跳板。
    """

    def argv(self, binary, host, key, known_hosts, command):
        options = {
            "BatchMode": "yes", "StrictHostKeyChecking": "yes", "UserKnownHostsFile": str(known_hosts),
            "GlobalKnownHostsFile": os.devnull, "HostKeyAlias": host["name"], "CheckHostIP": "no",
            "UpdateHostKeys": "no", "VerifyHostKeyDNS": "no", "IdentitiesOnly": "yes", "IdentityAgent": "none",
            "PreferredAuthentications": "publickey", "PasswordAuthentication": "no",
            "KbdInteractiveAuthentication": "no", "ConnectTimeout": str(SSH_CONNECT_TIMEOUT),
            "ServerAliveInterval": "10", "ServerAliveCountMax": "2", "ControlMaster": "no", "ControlPath": "none",
            "ClearAllForwardings": "yes", "ForwardAgent": "no", "ForwardX11": "no", "PermitLocalCommand": "no",
            "ProxyCommand": "none", "RequestTTY": "no", "LogLevel": "ERROR"}
        out = [binary, "-F", os.devnull, "-T", "-i", key]
        for name, value in options.items():
            out += ["-o", f"{name}={value}"]
        return out + ["-p", str(host["port"]), "-l", host["user"], "--", host["address"], command]

    def run(self, host, command, data=b"", timeout=TIMEOUT + SSH_SLACK):
        """在主机上执行一条远程命令：(退出码, stdout 字节, stderr 文字)。连不上之类的问题抛 HostError。"""
        binary = shutil.which("ssh")
        if not binary:
            raise HostError("工具服务这台机器没有 ssh 客户端（OpenSSH），连不了远程主机")
        known_hosts = _check_known_hosts(host)
        key = _key_file(host)
        env = {name: os.environ[name] for name in SSH_PASS_ENV if name in os.environ}
        try:
            code, out, err = _communicate(self.argv(binary, host, key, known_hosts, command), data,
                                          timeout, SSH_OUTPUT_MAX, env)
        except OSError as exc:
            raise HostError(f"起 ssh 失败：{exc}") from None
        return code, out, _scrub(err.decode("utf-8", "replace"), [key]).strip()


_transport = SshTransport()


def _ssh_failure(host, err):
    """ssh 自己失败（退出码 255）时给人看的原因。host key 的问题单独说清楚：这时绝不能「先连上再说」。"""
    text = err or ""
    first = next((line for line in text.splitlines() if line.strip()), "")[:200]
    name = host["name"]
    if "IDENTIFICATION HAS CHANGED" in text or "Host key verification failed" in text or "host key is known" in text:
        return (f"主机 {name} 的 host key 和登记的不一致（或没登记），拒绝连接：可能是主机重装了，也可能有人在中间冒充。"
                f"先在主机上核对指纹，确认无误再 enroll {name} --replace")
    if "Permission denied" in text:
        return f"主机 {name} 拒绝登录：账号 {host['user']} 上没有放工具服务的公钥，或账号不对（{first}）"
    return f"连不上主机 {name}：{first or 'ssh 退出码 255'}"


def _decode(data):
    return (data or b"").decode("utf-8", "replace").replace("\r\n", "\n")


def _call_executor(host, request):
    """受控模式：把一条请求发给主机上的执行器，返回 (回应, 错误)。回应一定是执行器写的那条 JSON。"""
    payload = json.dumps(request, ensure_ascii=True).encode("ascii")
    try:
        code, out, err = _transport.run(host, GUARDED_COMMAND, payload)
    except HostError as exc:
        return None, f"主机 {host['name']}：{exc}"
    lines = [line for line in _decode(out).splitlines() if line.strip()]
    try:
        response = json.loads(lines[-1]) if lines else None
    except ValueError:
        response = None
    if isinstance(response, dict) and "ops_exec" in response:
        return response, None
    if code == 255:
        return None, _ssh_failure(host, err)
    detail = (err or (lines[-1] if lines else ""))[:200]
    return None, (f"主机 {host['name']} 没有按受控模式回应（退出码 {code}）：authorized_keys 里要用强制命令启动执行器，"
                  f"见 enroll 打印的安装步骤" + (f"；{detail}" if detail else ""))


def _quote_argv(argv):
    """直连模式：每一项单独做 POSIX shell 转义再拼起来。; $() 反引号 换行 通配符 在远端都只是字面字符。"""
    return " ".join(shlex.quote(part) for part in argv)


def _cut(text, limit=MAX_OUTPUT):
    return text[:limit] + ("\n…（输出已截断）" if len(text) > limit else "")


def _run_guarded(host, spec, args):
    try:
        filled = ops_exec.values(spec, args)
        argv = build_argv(spec, args)
    except ValueError as exc:
        return {"ok": False, "error": str(exc)}
    if ops_exec.forbidden(argv):
        return {"ok": False, "error": "拒绝执行：命中写操作黑名单"}
    shown = f"{host['name']}: {' '.join(argv)}"
    response, error = _call_executor(host, {"v": ops_exec.PROTOCOL, "op": "exec", "tool": spec["name"],
                                            "args": filled, "fp": _fingerprint(spec)})
    if error:
        return {"ok": False, "error": error, "command": shown}
    if response.get("code") in ("fp_mismatch", "not_allowed", "guard", "allowlist"):
        _monitor.wake()   # 主机上的白名单和这边对不上：马上重新检查，页面和枚举跟着更新
    result = {"ok": response.get("ok") is True, "command": shown}
    if "output" in response:
        result["output"] = _cut(str(response["output"]))
    if isinstance(response.get("exit_code"), int):
        result["exit_code"] = response["exit_code"]
    if not result["ok"] and response.get("error"):
        result["error"] = f"主机 {host['name']}：{str(response['error'])[:500]}"
    elif not result["ok"] and "output" not in result:
        result["error"] = f"主机 {host['name']} 的执行器没有给出结果"
    return result


def _run_direct(host, spec, args):
    try:
        argv = build_argv(spec, args)
    except ValueError as exc:
        return {"ok": False, "error": str(exc)}
    if ops_exec.forbidden(argv):
        return {"ok": False, "error": "拒绝执行：命中写操作黑名单"}
    shown = f"{host['name']}: {' '.join(argv)}"
    try:
        code, out, err = _transport.run(host, _quote_argv(argv))
    except HostError as exc:
        return {"ok": False, "error": f"主机 {host['name']}：{exc}", "command": shown}
    output = (_decode(out) or err or "").strip()
    if code == 255 and not out:
        return {"ok": False, "error": _ssh_failure(host, err), "command": shown}
    if code == 127 and not out:
        return {"ok": False, "error": f"主机 {host['name']} 上没有 {spec['binary']}（{err[:120]}）", "command": shown}
    return {"ok": code == 0, "command": shown, "output": _cut(output), "exit_code": code}


def _fingerprint(spec):
    return ops_exec.fingerprint(spec["argv"], spec["params"])


def _hosts():
    return _state.get("hosts")


def _host_os_of(host):
    return HOST_OS if host["via"] == "local" else host["os"]


def _local_host():
    cfg = _hosts()
    return cfg["hosts"].get(cfg["local"]) if cfg and cfg["local"] else None


def _applicable(spec, host):
    """静态规则：系统、适用分组、主机开放的工具。(能不能, 原因)。不连主机。"""
    wanted = spec.get("os") or []
    system = _host_os_of(host)
    if wanted and system not in wanted:
        return False, f"不适用：工具声明 os: {', '.join(wanted)}，主机是 {system}"
    groups = spec.get("groups") or []
    if groups and not set(groups) & set(host["groups"]):
        return False, f"不适用：工具只在分组 {', '.join(groups)} 的主机上跑"
    if host.get("tools") is not None and spec["name"] not in host["tools"]:
        return False, "这台主机没有开放这个工具（主机的 tools 里没有它）"
    return True, ""


# 各主机最近一次检查的结果：主机名 → {sig, checked_at, reachable, error, executor, allowlist, tools, binaries}
_host_status = {}
_host_status_lock = threading.Lock()


def _host_sig(host):
    return tuple(host.get(key) for key in ("via", "address", "port", "user", "mode", "key"))


def _cached_status(host):
    with _host_status_lock:
        status = _host_status.get(host["name"])
    return status if status and status.get("sig") == _host_sig(host) else None


def _host_tool_state(spec, host):
    """这个工具在这台主机上：("ok" | "unknown" | "no", 原因)。

    unknown（没检查过、暂时连不上）照样算候选：调用时会拿到具体原因；no 是确定不行（不适用、没开放、没装、版本不一致）。
    """
    ok, reason = _applicable(spec, host)
    if not ok:
        return "no", reason
    if host["via"] == "local":
        if not (spec.get("binary") and shutil.which(spec["binary"])):
            return "no", f"本机没有 {spec['binary']}"
        return "ok", ""
    status = _cached_status(host)
    if status is None:
        return "unknown", "还没检查过这台主机"
    if not status.get("reachable"):
        return "unknown", status.get("error") or "连不上"
    if host["mode"] == "guarded":
        if status.get("tools") is None:
            return "no", status.get("error") or "执行器不可用"
        listed = status["tools"].get(spec["name"])
        if listed is None:
            have = (status.get("binaries") or {}).get(spec["binary"])
            return "no", "白名单里没有，需要 push" + ("（主机上有这个命令）" if have else "")
        if listed.get("fp") != _fingerprint(spec):
            return "no", "主机白名单里的定义和这边不一致，需要 push"
        if not listed.get("runnable"):
            return "no", f"主机上没有 {spec['binary']}"
        return "ok", ""
    have = (status.get("binaries") or {}).get(spec["binary"])
    if have is None:
        return "unknown", "还没检查过这个命令"
    return ("ok", "") if have else ("no", f"主机上没有 {spec['binary']}")


def _default_candidate(spec, host):
    """能不能当这个工具的默认主机：只看配置（系统、分组、开放的工具），本机再现查命令在不在。

    不看后台检查的缓存：缓存随时会变，默认主机要是跟着它变，模型以为查的是 b、实际跑在了别处，结果还当成 b 的报出来。
    默认主机跑不了，就让调用带着它自己的原因失败。
    """
    if not _applicable(spec, host)[0]:
        return False
    return host["via"] != "local" or bool(spec.get("binary") and shutil.which(spec["binary"]))


def _target_info(spec):
    """命令型工具在主机模式下的 target：(可选的主机, 可选的组, 默认值或 None)；没有能跑它的主机返回 None。

    默认值的规则（文档和测试都按这条）：hosts.default（主机或 @组，不写就是本机）能跑这个工具就用它；
    不能的话，只剩一台主机能跑就用那一台；否则 target 必填。「能跑」只看配置和本机的命令（见 _default_candidate），
    所以默认值是确定的；可选的主机还要去掉后台检查确定跑不了的，但默认主机总在里面。
    """
    cfg = _hosts()
    usable = [name for name, host in cfg["hosts"].items() if _host_tool_state(spec, host)[0] != "no"]
    if not usable:
        return None
    candidates = [name for name, host in cfg["hosts"].items() if _default_candidate(spec, host)]
    wanted, default = cfg["default"], None
    if wanted.startswith("@") and any(name in candidates for name in cfg["groups"].get(wanted[1:], [])):
        default = wanted
    elif wanted in candidates:
        default = wanted
    if default is None and len(candidates) == 1:
        default = candidates[0]
    if default and not default.startswith("@") and default not in usable:
        usable = [name for name in cfg["hosts"] if name in usable or name == default]
    groups = [group for group, members in sorted(cfg["groups"].items())
              if group != "all" and any(member in usable for member in members)]
    if len(usable) > 1:
        groups.append("all")
    if default and default.startswith("@") and default[1:] not in groups:
        groups.append(default[1:])
    return usable, groups, default


def _target_param(spec, info):
    """target 参数：(params 里的写法, inputSchema 里的属性, 是否必填)。主机不多时是枚举，多了是字符串 + list_targets。

    默认主机只写在说明里，不放进 schema 的 default：应用侧按签名会把 default 填进每次调用，target 又是出网污点，
    那样每轮都会把 local 这种常见词记成污点，联网搜索平白被拦。不填时由这边按默认规则补上。
    """
    cfg = _hosts()
    usable, groups, default = info
    desc = "在哪台主机上执行：主机名，或 @组名（组内每台主机都执行一遍，结果按主机分段）。"
    desc += f"不填就是 {default}。" if default else "必须指定。"
    param = {"type": "str", "desc": desc, "required": default is None}
    prop = {"type": "string", "description": desc, "x-entity": "host"}
    if len(cfg["hosts"]) <= cfg["enum_max"]:
        choices = usable + ["@" + group for group in groups]
        param.update(type="enum", enum=choices)
        prop["enum"] = choices
    else:
        prop["pattern"] = HOST_REF.pattern
        param["desc"] = prop["description"] = desc + f"主机名先用 {LIST_TARGETS} 查。"
    if default:
        prop["x-default"] = default     # 项目扩展：给人和测试看；应用不拿它生成签名，对外下发时剥掉
    return param, prop, default is None


def _choices(spec):
    info = _target_info(spec)
    if not info:
        return "（没有）"
    return "、".join(info[0] + ["@" + group for group in info[1]])


def _resolve_target(spec, raw):
    """target 实参 → (主机列表, 组名或 None)。不认识的、不填又没有默认值的，直接报错。"""
    cfg = _hosts()
    text = "" if raw is None else str(raw).strip()
    if not text:
        info = _target_info(spec)
        if info is None:
            raise ValueError(f"{spec['name']} 现在没有能运行它的主机")
        if info[2] is None:
            raise ValueError(f"缺少必填参数：target（在哪台主机上执行；可选：{_choices(spec)}）")
        text = info[2]
    if not HOST_REF.match(text):
        raise ValueError(f"参数 target 不合法：{text[:40]!r}")
    if text.startswith("@"):
        members = cfg["groups"].get(text[1:])
        if members is None:
            raise ValueError(f"没有主机分组 {text}；可选：{_choices(spec)}")
        return [cfg["hosts"][name] for name in members], text[1:]
    host = cfg["hosts"].get(text)
    if host is None:
        raise ValueError(f"没有主机 {text}；可选：{_choices(spec)}")
    return [host], None


def _run_on(host, spec, args):
    ok, reason = _applicable(spec, host)
    if not ok:
        return {"ok": False, "error": f"{spec['name']} 不能在主机 {host['name']} 上跑：{reason}", "host": host["name"]}
    if host["via"] == "local":
        result = _run_local(spec, args)
    elif host["mode"] == "guarded":
        result = _run_guarded(host, spec, args)
    else:
        result = _run_direct(host, spec, args)
    result["host"] = host["name"]
    return result


GROUP_DEADLINE = 25    # @组 最多等多少秒：应用等 /exec 30 秒，到点没回来的主机记成超时，已经回来的照常返回
SKIPPED_SHOWN = 10     # 汇总里最多列出几台不适用、跳过的主机


def _run_group(group, members, spec, args):
    """@组：组内每台能跑的主机并发执行，输出按主机分段，末尾汇总。总长仍不超过 MAX_OUTPUT，总时长不超过 GROUP_DEADLINE。"""
    cfg = _hosts()
    runnable, skipped = [], []
    for host in members:
        (runnable if _applicable(spec, host)[0] else skipped).append(host)
    if not runnable:
        return {"ok": False, "error": f"分组 @{group} 里没有能运行 {spec['name']} 的主机"}
    if len(runnable) > cfg["max_targets"]:
        return {"ok": False, "error": f"分组 @{group} 里有 {len(runnable)} 台主机能运行 {spec['name']}，"
                                      f"超过单次上限 {cfg['max_targets']} 台；请换一个小一点的分组，或指定单台主机"}
    try:
        build_argv(spec, args)   # 参数对所有主机都一样，先校验一次，填错了不用连任何主机
    except ValueError as exc:
        return {"ok": False, "error": str(exc)}
    pool = ThreadPoolExecutor(max_workers=min(cfg["parallel"], len(runnable)))
    futures = [pool.submit(_run_on, host, spec, args) for host in runnable]
    wait(futures, timeout=GROUP_DEADLINE)
    # 没等到的不再等：还没开始的取消，正在跑的到它自己的超时为止，结果丢掉
    pool.shutdown(wait=False, cancel_futures=True)
    results = [future.result() if future.done() and not future.cancelled() else
               {"ok": False, "error": f"超过 {GROUP_DEADLINE} 秒没有结果，没再等它"} for future in futures]

    succeeded = sum(1 for result in results if result.get("ok"))
    shown = "、".join(host["name"] for host in skipped[:SKIPPED_SHOWN])
    if len(skipped) > SKIPPED_SHOWN:
        shown += f" 等 {len(skipped)} 台"
    summary = (f"（@{group}：共 {len(results)} 台，成功 {succeeded} 台，失败 {len(results) - succeeded} 台"
               + (f"；不适用、已跳过 {len(skipped)} 台：{shown}" if skipped else "") + "）")
    heads = [f"== {host['name']}（{'成功' if result.get('ok') else '失败'}）==" for host, result in zip(runnable, results)]
    budget = max(0, (MAX_OUTPUT - len(summary) - sum(len(head) + 4 for head in heads)) // len(results) - 20)
    parts = []
    for head, result in zip(heads, results):
        body = str(result.get("output") or "").strip()
        if not result.get("ok"):
            error = str(result.get("error") or "").strip()
            code = result.get("exit_code")
            body = "\n".join(part for part in (error, body, f"（退出码 {code}）" if code not in (None, 0) else "")
                             if part)
        body = body or "（没有输出）"
        if len(body) > budget:
            body = body[:budget] + "\n…（这台的输出已截断）"
        parts.append(f"{head}\n{body}")
    output = "\n\n".join(parts + [summary])
    if len(output) > MAX_OUTPUT:
        output = output[:max(0, MAX_OUTPUT - len(summary) - 20)] + "\n…（输出已截断）\n\n" + summary
    return {"ok": succeeded > 0, "command": f"@{group}: {' '.join(spec['argv'])}", "output": output,
            "hosts": {host["name"]: bool(result.get("ok")) for host, result in zip(runnable, results)}}


def _stray_target(spec, args):
    """没配主机清单，却带了 target：多半是配置刚改坏、或者 SOP 里写死了主机。绝不能悄悄在本机执行。"""
    return (isinstance(args, dict) and TARGET not in spec.get("params", {})
            and str(args.get(TARGET) or "").strip() != "")


def _run_local(spec, args):
    """在工具服务这台机器上执行命令型、脚本型工具（主机模式下就是本机那台）。和改造前逐字一致。"""
    # 先校验参数再看本机有没有这个命令：不可信输入是安全边界，要最先挡掉。
    try:
        argv = build_argv(spec, args)
    except ValueError as exc:
        return {"ok": False, "error": str(exc)}

    if ops_exec.forbidden(argv):
        return {"ok": False, "error": "拒绝执行：命中写操作黑名单"}

    # 声明了别的系统：同名命令在这台机器上即使存在，参数和输出也未必是那个意思，不跑
    reason = _not_here(spec)
    if reason:
        return {"ok": False, "error": reason}

    # 脚本型工具：执行前再比一次哈希。配置 mtime 不变也挡得住"脚本被偷换内容"。
    if spec.get("type") == "script":
        reason = _script_untrusted_reason(spec)
        if reason:
            return {"ok": False, "error": reason}

    if not shutil.which(spec["binary"]):
        return {"ok": False, "error": f"本机没有 {spec['binary']}，该工具不可用"}
    return ops_exec.run_argv(argv, timeout=TIMEOUT, max_output=MAX_OUTPUT)


def _run_command(spec, args):
    """命令型、脚本型工具：没配主机清单就在本机跑（老行为）；配了就按 target 选主机。"""
    cfg = _hosts()
    if cfg is None:
        if _stray_target(spec, args):
            return {"ok": False, "error": "没有配置主机清单（hosts），不能指定 target：拒绝执行，以免在本机跑了本该去别处的命令"}
        return _run_local(spec, args)
    args = dict(args or {})
    raw = args.pop(TARGET, None)
    if spec.get("type") == "script":
        # 脚本在工具服务的 scripts 目录里，只能在本机跑，不加 target
        local = _local_host()
        if local is None:
            return {"ok": False, "error": "脚本型工具只能在本机跑，而主机清单里没有本机（hosts.local: false）"}
        if str(raw or "").strip() not in ("", local["name"]):
            return {"ok": False, "error": f"脚本型工具只能在本机（{local['name']}）上跑"}
        ok, reason = _applicable(spec, local)
        return _run_local(spec, args) if ok else {"ok": False, "error": reason}
    try:
        members, group = _resolve_target(spec, raw)
    except ValueError as exc:
        return {"ok": False, "error": str(exc)}
    if group is None:
        return _run_on(members[0], spec, args)
    return _run_group(group, members, spec, args)


# ---- 主机检查：list / probe，后台定期跑，status 命令现跑 -------------------------------------

def _command_tools():
    return {name: spec for name, spec in all_tools().items() if spec.get("type") == "command"}


def _probe_direct(host, binaries):
    """直连模式的探测：在登录 shell 里逐个 command -v（命令名都转义过），顺带确认是 POSIX shell。"""
    script = ("for b in " + " ".join(shlex.quote(b) for b in binaries) + "; do "
              "if command -v \"$b\" >/dev/null 2>&1; then printf 'have:%s\\n' \"$b\"; fi; done; "
              "printf 'posix:%s\\n' \"$((6*7))\"") if binaries else "printf 'posix:%s\\n' \"$((6*7))\""
    code, out, err = _transport.run(host, script)
    lines = _decode(out).splitlines()
    if code == 255 and not lines:
        raise HostError(_ssh_failure(host, err))
    if "posix:42" not in lines:
        raise HostError(f"主机 {host['name']} 的登录 shell 不是 POSIX shell（直连模式要求 sh / bash 这一类）")
    have = {line[5:] for line in lines if line.startswith("have:")}
    return {binary: binary in have for binary in binaries}


def check_host(host):
    """连一次主机，看能不能用：受控模式 list（+ 白名单外命令的 probe），直连模式 probe。返回状态，并记进缓存。"""
    status = {"sig": _host_sig(host), "checked_at": time.strftime("%Y-%m-%d %H:%M:%S"), "reachable": False,
              "error": "", "executor": "", "allowlist": {}, "tools": None, "binaries": {}}
    applicable = {name: spec for name, spec in _command_tools().items() if _applicable(spec, host)[0]}
    try:
        if host["mode"] == "guarded":
            response, error = _call_executor(host, {"v": ops_exec.PROTOCOL, "op": "list"})
            if error:
                raise HostError(error)
            status.update(reachable=True, executor=str(response.get("ops_exec", ""))[:20])
            if response.get("ok") is not True:
                status["error"] = f"执行器：{str(response.get('error') or '没有说明')[:300]}"
            else:
                allow = response.get("allowlist") if isinstance(response.get("allowlist"), dict) else {}
                status["allowlist"] = {key: allow.get(key) for key in ("version", "generated_at", "host", "problems")}
                listed = response.get("tools") if isinstance(response.get("tools"), dict) else {}
                status["tools"] = {name: {"fp": str(item.get("fp")), "runnable": item.get("runnable") is True}
                                   for name, item in listed.items() if isinstance(item, dict)}
                missing = sorted({spec["binary"] for name, spec in applicable.items() if name not in status["tools"]
                                  and ops_exec.BINARY.match(spec["binary"])})[:ops_exec.PROBE_MAX]
                if missing:
                    probed, error = _call_executor(host, {"v": ops_exec.PROTOCOL, "op": "probe", "binaries": missing})
                    if probed and probed.get("ok"):
                        status["binaries"] = {k: v is True for k, v in (probed.get("binaries") or {}).items()}
        else:
            status["binaries"] = _probe_direct(host, sorted({spec["binary"] for spec in applicable.values()}))
            status["reachable"] = True
    except HostError as exc:
        text = str(exc)
        status["error"] = text if text.startswith(("主机", "连不上")) else f"主机 {host['name']}：{text}"
    with _host_status_lock:
        _host_status[host["name"]] = status
    return status


def check_hosts(names=None):
    """并发检查各远程主机（本机不用连）。返回 {主机名: 状态}。"""
    cfg = _hosts()
    if cfg is None:
        return {}
    targets = [host for name, host in cfg["hosts"].items() if host["via"] == "ssh" and (names is None or name in names)]
    if not targets:
        return {}
    with ThreadPoolExecutor(max_workers=min(cfg["parallel"], len(targets))) as pool:
        return dict(zip((host["name"] for host in targets), pool.map(check_host, targets)))


class HostMonitor:
    """后台线程：每 HOST_REFRESH 秒（或主机清单刚变）检查一遍远程主机，结果只用来标可用性、给页面看。"""

    def __init__(self):
        self._wake = threading.Event()
        self._thread = None

    def wake(self):
        self._wake.set()

    def start_background(self):
        if self._thread is None:
            self._thread = threading.Thread(target=self._loop, daemon=True, name="host-monitor")
            self._thread.start()

    def _loop(self):
        while True:
            self._wake.clear()
            try:
                all_tools()
                checked = check_hosts()
                for name, status in checked.items():
                    if status.get("error"):
                        print(f"[hosts] {name}：{status['error']}", flush=True)
            except Exception as exc:   # 检查出错不能把后台线程弄死
                print(f"[hosts] 后台检查失败：{exc.__class__.__name__}: {exc}", flush=True)
            self._wake.wait(HOST_REFRESH)


_monitor = HostMonitor()


def _host_view(host):
    """页面和 status 看到的一台主机：没有私钥的值和路径。"""
    item = {"via": host["via"], "os": _host_os_of(host), "groups": list(host["groups"]),
            "tools": None if host.get("tools") is None else list(host["tools"])}
    if host["via"] == "ssh":
        item.update(address=host["address"], port=host["port"], user=host["user"], mode=host["mode"],
                    readonly="账号权限" if host["mode"] == "direct" else "强制命令 + 白名单")
        status = _cached_status(host)
        item["status"] = None if status is None else {
            key: status.get(key) for key in ("checked_at", "reachable", "error", "executor")}
        if status is not None:
            item["status"]["allowlist"] = (status.get("allowlist") or {}).get("version") or ""
            item["status"]["generated_at"] = (status.get("allowlist") or {}).get("generated_at") or ""
    return item


def describe_hosts():
    cfg = _hosts()
    if cfg is None:
        return {"configured": False}
    return {"configured": True, "default": cfg["default"], "local": cfg["local"], "enum_max": cfg["enum_max"],
            "groups": {group: list(members) for group, members in cfg["groups"].items()},
            "list": {name: _host_view(host) for name, host in cfg["hosts"].items()}}


def _list_targets_spec():
    return {"name": LIST_TARGETS, "label": "主机清单", "group": "主机", "type": "builtin", "builtin": LIST_TARGETS,
            "binary": "", "argv": [], "enabled": True, "export": False,
            "desc": "列出可以在上面执行命令的主机：名称、分组、系统、执行方式、最近一次检查的状态。"
                    "主机很多、记不清名字时先用它，再把主机名或 @组名填进别的工具的 target。",
            "params": {"group": {"type": "str", "desc": "只看这个分组（不带 @），不填就是全部", "required": False,
                                 "default": ""}}}


def _list_targets_active():
    cfg = _hosts()
    return bool(cfg) and len(cfg["hosts"]) > cfg["enum_max"]


def _run_list_targets(args):
    cfg = _hosts()
    group = str((args or {}).get("group") or "").strip().lstrip("@")
    if group and not HOST_NAME.match(group):
        return {"ok": False, "error": f"参数 group 不合法：{group[:40]!r}"}
    if group and group not in cfg["groups"]:
        return {"ok": False, "error": f"没有主机分组 {group}"}
    names = cfg["groups"][group] if group else list(cfg["hosts"])
    lines = [f"{'@' + group + ' 里' if group else '共'} {len(names)} 台主机（名称 | 系统 | 分组 | 方式 | 状态）："]
    for name in names:
        host = cfg["hosts"][name]
        if host["via"] == "local":
            how, state = "本机", "在线"
        else:
            how = "受控" if host["mode"] == "guarded" else "直连"
            status = _cached_status(host)
            state = "未检查" if status is None else ("在线" if status.get("reachable") and not status.get("error")
                                                    else "异常：" + str(status.get("error") or "连不上")[:60])
        lines.append(f"{name} | {_host_os_of(host)} | {','.join(host['groups']) or '-'} | {how} | {state}")
    if not group:
        lines.append("分组：" + "、".join(f"@{g}（{len(m)} 台）" for g, m in sorted(cfg["groups"].items())))
    return {"ok": True, "command": "内置函数 list_targets", "output": _cut("\n".join(lines))}


def run_tool(name, args):
    spec = all_tools().get(name)
    if spec is None and name == LIST_TARGETS and _list_targets_active():
        return _run_list_targets(args)
    if spec is None or not spec["enabled"]:
        return {"ok": False, "error": f"未知工具：{name}"}

    if spec.get("type") == "http":
        return _run_http(spec, args)
    if spec.get("type") == "sql":
        return _run_sql(spec, args)
    if spec.get("type") == "mcp":
        return _run_mcp(spec, args)
    if spec.get("type") == "builtin":
        return _run_builtin(spec, args)
    return _run_command(spec, args)


# /exec 的调用方：应用带上「谁发起的」——项目 Agent 的会话，或对外 MCP 的客户端——写进日志，两边的日志对得上。
# 只记录、不鉴权（鉴权仍是 X-Ops-Token）；值来自请求头，进日志前只留可打印的 ASCII，防止伪造日志行。
CALLER_HEADER = "X-Ops-Caller"
CALLER_MAX = 200


def _caller(raw):
    text = "".join(ch if " " <= ch <= "~" else "?" for ch in str(raw or ""))
    return " ".join(text.split())[:CALLER_MAX]


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
            return self._send(200, {"status": "ok", "tools": sorted(available_tools()),
                                    "mcp": mcp_status()})
        if not self._authorised():
            return self._send(401, {"error": "令牌无效"})
        if self.path == "/tools":
            return self._send(200, {"tools": available_tools()})
        if self.path == "/tools/full":
            return self._send(200, {"tools": describe_tools(),
                                    "pending": len(list_pending()),
                                    "mcp_servers": mcp_status(),
                                    "connections": describe_connections(),
                                    "hosts": describe_hosts(),
                                    "host": {"os": HOST_OS}})
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
        try:
            result = run_tool(name, payload.get("args"))
        except Exception as exc:   # 不能让一个 server 报回来的怪数据把连接直接掐断
            result = {"ok": False, "error": f"执行失败：{exc.__class__.__name__}: {exc}"}
        caller = _caller(self.headers.get(CALLER_HEADER, ""))
        print(f"[exec] {name} caller={caller or '-'} args={payload.get('args')} ok={result.get('ok')}", flush=True)
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


def _legacy_view(tool):
    """待审条目按老写法的字段看：分层写法把 impl 摊开，打印只认一套字段。"""
    impl = tool.get("impl")
    if not isinstance(impl, dict):
        return tool
    body = {key: value for key, value in impl.items() if key != "type"}
    view = {key: value for key, value in tool.items() if key != "impl"}
    kind = impl.get("type")
    if kind == "command":
        view.update(argv=body.get("argv") or [], os=body.get("os"), groups=body.get("groups"))
    elif kind == "script":
        view.update(script=body.get("script"), os=body.get("os"))
    elif kind in ("http", "mcp", "sql"):
        view[kind] = body
    return view


def _print_pending():
    items = list_pending()
    if not items:
        print("没有待审申请")
        return 0
    print(f"待审申请 {len(items)} 条：\n")
    for item in items:
        tool = _legacy_view(item.get("tool") or {})
        print(f"  [{item.get('id')}] {tool.get('name')}"
              f"    {item.get('author')} 于 {item.get('created_at')} 提交")
        print(f"      说明：{tool.get('desc')}")
        if tool.get("script"):
            print(f"      脚本：scripts/{tool['script']}（批准前请逐行读脚本内容）")
        elif isinstance(tool.get("mcp"), dict):
            review = item.get("review") or {}
            marks = {"declared": "只读（server 声明）", "undeclared": "未声明只读"}.get(
                review.get("readonly"), "未声明只读")
            if review.get("suspicious_name"):
                marks += "，名称疑似写操作"
            print(f"      MCP：{tool['mcp'].get('server')} / {tool['mcp'].get('tool')}    [{marks}]")
            if review.get("reason") and review["reason"] != "新发现":
                print(f"      原因：{review['reason']}")
            if review.get("readonly") != "declared":
                print(f"      批准需确认只读：ops_readonly.py approve {item.get('id')} --attest-readonly")
        elif isinstance(tool.get("http"), dict):
            http = tool["http"]
            query = "&".join(f"{k}={v}" for k, v in (http.get("query") or {}).items())
            conn = f"[连接 {http['conn']}] " if http.get("conn") else ""
            print(f"      接口：GET {conn}{http.get('url', '')}{'?' + query if query else ''}")
        elif isinstance(tool.get("sql"), dict):
            sql = tool["sql"]
            print(f"      SQL：[连接 {sql.get('conn', '')}] {sql.get('query', '')}"
                  f"（最多 {sql.get('max_rows', SQL_ROWS[0])} 行）")
        else:
            print(f"      命令：{' '.join(str(p) for p in tool.get('argv') or [])}")
        if tool.get("os"):
            print(f"      适用系统：{tool['os'] if isinstance(tool['os'], str) else ', '.join(map(str, tool['os']))}"
                  f"（工具服务运行在 {HOST_OS} 上）")
        if tool.get("groups"):
            groups = tool["groups"] if isinstance(tool["groups"], list) else [tool["groups"]]
            print(f"      适用分组：{', '.join(map(str, groups))}（只在这些分组的主机上跑）")
        params = tool.get("params") or {}
        if params:
            print(f"      参数：{', '.join(params)}")
        if item.get("reason"):
            print(f"      理由：{item['reason']}")
        print()
    print("批准：ops_readonly.py approve <id>     拒绝：ops_readonly.py reject <id>")
    print("批准前请逐字读一遍「命令」、SQL 或脚本内容——这是它唯一会执行的东西。")
    print("MCP 工具没有 server 的只读声明时，要加 --attest-readonly 表示你确认过它不改任何东西。")
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


# ---- 主机的命令行：enroll / push / status ---------------------------------------------------
# 都在工具服务所在机器上由管理员执行。enroll 只登记 host key、打印主机上的安装步骤；push 用管理员自己的 SSH 身份
# 把执行器和白名单装到主机上——工具服务进程从不持有能写主机的凭据；status 现连一遍各主机，逐台列出能跑什么。

def load_env_file(path):
    """读 systemd 的 EnvironmentFile（KEY=VALUE），只取 OPS_SECRET_ 开头的凭据放进本进程。不打印任何值。"""
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"读不到凭据文件 {path}：{exc}") from None
    loaded = 0
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        if key.startswith("export "):
            key = key[len("export "):].strip()
        if not key.startswith(SECRET_PREFIX):
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        os.environ[key] = value
        loaded += 1
    return loaded


def _cli_hosts(group=None, target=None):
    cfg = _hosts()
    if cfg is None:
        raise ConfigError("主配置里没有 hosts 段：命令型工具都在本机跑，没有要接入的主机")
    picked = []
    for name, host in cfg["hosts"].items():
        if target and name != target:
            continue
        if group and name not in cfg["groups"].get(group, []):
            continue
        picked.append(host)
    if target and not picked:
        raise ConfigError(f"主机清单里没有 {target}（有：{'、'.join(cfg['hosts'])}）")
    if group and group not in cfg["groups"]:
        raise ConfigError(f"没有主机分组 {group}（有：{'、'.join(sorted(cfg['groups']))}）")
    return picked


def key_fingerprint(blob):
    """host key（base64）的 SHA256 指纹，和 ssh-keygen -lf 显示的一样。"""
    digest = hashlib.sha256(base64.b64decode(blob)).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


def scan_host_keys(host):
    """ssh-keyscan 取 host key：[(类型, base64, 指纹)]。只是拿来给人核对，不会自动登记。"""
    binary = shutil.which("ssh-keyscan")
    if not binary:
        raise ConfigError("工具服务这台机器没有 ssh-keyscan（OpenSSH 客户端）")
    done = subprocess.run([binary, "-T", "5", "-p", str(host["port"]), "-t", "ed25519,ecdsa,rsa", "--",
                           host["address"]], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=40)
    keys = []
    for line in _decode(done.stdout).splitlines():
        parts = line.split()
        if len(parts) >= 3 and not line.startswith("#"):
            try:
                keys.append((parts[1], parts[2], key_fingerprint(parts[2])))
            except ValueError:
                continue
    return keys


def _write_known_hosts(alias, keytype, blob):
    """登记（或替换）一台主机的 host key：按主机名登记，原子写入，权限 644。"""
    path = _known_hosts()
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        lines = []
    kept = [line for line in lines if not (line.split() and alias in line.split()[0].split(","))]
    temporary = f"{path}.{secrets.token_hex(3)}.tmp"
    with open(temporary, "w", encoding="utf-8") as handle:
        handle.write("\n".join(kept + [f"{alias} {keytype} {blob}"]) + "\n")
    os.chmod(temporary, 0o644)
    os.replace(temporary, path)


def public_key(host):
    """工具服务私钥对应的公钥（一行），给主机上的 authorized_keys 用。读不出来返回 (None, 原因)。"""
    try:
        path = _key_file(host)
    except HostError as exc:
        return None, str(exc)
    keygen = shutil.which("ssh-keygen")
    if not keygen:
        return None, "没有 ssh-keygen"
    done = subprocess.run([keygen, "-y", "-f", path], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, timeout=10)
    if done.returncode != 0:
        return None, "ssh-keygen -y 读不出公钥：私钥坏了，或设了口令（工具服务用的私钥不能设口令，靠文件权限保护）"
    return _decode(done.stdout).strip().splitlines()[0], ""


def install_snippet(host, source=""):
    """主机上要执行的安装片段（给主机负责人看、照着做）。"""
    key, why = public_key(host)
    key = key or "<工具服务的公钥：" + why + ">"
    source = source or "<工具服务连过来的出口 IP>"
    user, name = host["user"], host["name"]
    if host["mode"] == "direct":
        return textwrap.dedent(f"""\
            在 {name}（{host['address']}）上以 root 执行（直连模式：只读靠账号权限，账号能做的事模型都能做，慎用）：

              # 普通账号，不进 sudo、不进 docker 组（除非你清楚后果）。家目录归 root：账号自己换不掉 ~/.ssh
              useradd -M --shell /bin/sh {user}
              install -d -o root -g root -m 0755 ~{user} ~{user}/.ssh
              printf '%s\\n' 'restrict,from="{source}" {key}' > ~{user}/.ssh/authorized_keys
              chown root:root ~{user}/.ssh/authorized_keys && chmod 0644 ~{user}/.ssh/authorized_keys

            撤销：删掉 ~{user}/.ssh/authorized_keys 里这一行；连账号一起删：rm -r ~{user} && userdel {user}。""")
    return textwrap.dedent(f"""\
        在 {name}（{host['address']}）上以 root 执行（受控模式）：

          # 1. 执行账号：普通账号，不进 sudo。登录 shell 要能启动强制命令，但它只能启动执行器。
          #    家目录也归 root、执行账号写不了：家目录的主人能给 ~/.ssh 改名、另放一把不带限制的公钥，也能往 ~/.local 里放代码
          useradd -M --shell /bin/sh {user}
          install -d -o root -g root -m 0755 ~{user} ~{user}/.ssh
          # 2. 执行器和白名单归 root 所有：目录先建好，文件由工具服务这边的管理员 push 上来
          install -d -o root -g root -m 0755 {EXEC_DIR}
          # 3. 公钥只能启动执行器；authorized_keys 也归 root，执行账号自己改不了。
          #    -I 是 Python 的隔离模式：不加载执行账号能写的 ~/.local，漏了它执行器拒绝启动
          printf '%s\\n' 'restrict,from="{source}",command="/usr/bin/python3 -I {EXEC_DIR}/ops_exec.py --stdio" {key}' \\
            > ~{user}/.ssh/authorized_keys
          chown root:root ~{user}/.ssh/authorized_keys && chmod 0644 ~{user}/.ssh/authorized_keys
          # 4. 要查容器的话，执行账号要能读 docker：见 docs/正式部署.md「接入一台主机」里的几种做法和利弊

        然后在工具服务这边：
          ops_readonly.py push --target {name}       # 用你自己的 SSH 身份装执行器和白名单
          ops_readonly.py status --target {name}     # 核对：连通、执行器版本、白名单版本、每个工具能不能跑

        撤销：rm -r ~{user} {EXEC_DIR} && userdel {user}（家目录归 root，userdel -r 不会删它）；
        工具服务这边从 hosts.list 删掉它，再从 {_known_hosts().name} 删掉 {name} 那一行。""")


def enroll(name, fingerprint=None, replace=False, source="", ask=None):
    """取 host key 让管理员核对指纹，核对上的才登记；然后打印主机上的安装片段。返回登记的指纹。"""
    host = _cli_hosts(target=name)[0]
    if host["via"] != "ssh":
        raise ConfigError(f"{name} 是本机，不用 enroll")
    keys = scan_host_keys(host)
    if not keys:
        raise ConfigError(f"从 {host['address']}:{host['port']} 取不到 host key：连不上，或者那不是 SSH 服务")
    print(f"主机 {name}（{host['address']}:{host['port']}）报上来的 host key：")
    for keytype, _, digest in keys:
        print(f"  {keytype:<22} {digest}")
    print("请在主机控制台上（不要经过这条网络）核对：for f in /etc/ssh/ssh_host_*_key.pub; do ssh-keygen -lf \"$f\"; done")
    if not fingerprint:
        if ask is None:
            if not sys.stdin.isatty():
                raise ConfigError("非交互运行时要用 --fingerprint SHA256:… 给出在主机上核对过的指纹")
            ask = input
        fingerprint = ask("把在主机上核对过的指纹粘贴到这里（SHA256:…）：")
    chosen = [key for key in keys if key[2] == str(fingerprint or "").strip()]
    if not chosen:
        raise ConfigError("指纹对不上扫描到的任何一个 host key，没有登记：核对的不是这台主机，或者中间有人冒充")
    keytype, blob, digest = chosen[0]
    pinned = _pinned_keys(name)
    if pinned and pinned != [(keytype, blob)]:
        if not replace:
            shown = "、".join(key_fingerprint(b) for _, b in pinned)
            raise ConfigError(f"{name} 已经登记过别的 host key（{shown}）。host key 变了先查清原因（重装？冒充？），"
                              f"确认无误再加 --replace")
    if pinned != [(keytype, blob)]:
        _write_known_hosts(name, keytype, blob)
        print(f"已登记 {name} 的 host key：{keytype} {digest}（{_known_hosts()}）")
    else:
        print(f"{name} 的 host key 早已登记，指纹一致，没有改动")
    print()
    print(install_snippet(host, source))
    return digest


def allowlist_for(host, generated_at=""):
    """按主机的系统、分组和开放的工具生成它的白名单（JSON 文本）。停用的工具也在里面：启停是工具服务这边的开关。"""
    entries = [(name, spec["argv"], spec["params"]) for name, spec in sorted(_command_tools().items())
               if _applicable(spec, host)[0]]
    return ops_exec.render_allowlist(host["name"], entries, generated_at=generated_at,
                                     timeout=TIMEOUT, max_output=MAX_OUTPUT)


def install_script(allowlist_text):
    """在主机上以 root 执行的安装脚本（sh）：执行器和白名单原子替换、归 root，装完用执行器自己校验一遍。"""
    executor = Path(ops_exec.__file__).read_bytes()
    lines = ["set -eu", "umask 022", f"dir={EXEC_DIR}", 'install -d -o root -g root -m 0755 "$dir"']
    for target, data, mode in (("ops_exec.py", executor, "0755"),
                               ("allowlist.json", allowlist_text.encode("utf-8"), "0644")):
        lines += ['tmp=$(mktemp "$dir/.push.XXXXXX")',
                  f"printf '%s' '{base64.b64encode(data).decode('ascii')}' | base64 -d > \"$tmp\"",
                  'chown root:root "$tmp"', f'chmod {mode} "$tmp"', f'mv -f "$tmp" "$dir/{target}"']
    lines.append('python3 "$dir/ops_exec.py" --check "$dir/allowlist.json"')
    return "\n".join(lines) + "\n"


def push(group=None, target=None, out=None, admin_user="root", identity=None, sudo=False):
    """按主机生成白名单；out 给了就只导出文件（不连主机），否则用管理员自己的 SSH 身份装到主机上。"""
    hosts = [host for host in _cli_hosts(group, target) if host["via"] == "ssh"]
    if not hosts:
        raise ConfigError("没有要 push 的远程主机（本机不用 push）")
    stamp = time.strftime("%Y-%m-%d %H:%M:%S")
    failed = 0
    for host in hosts:
        name = host["name"]
        if host["mode"] == "direct":
            print(f"{name}：直连模式，不用白名单（只读靠账号权限），跳过")
            continue
        text = allowlist_for(host, stamp)
        count = len(json.loads(text)["tools"])
        if out:
            folder = Path(out) / name
            folder.mkdir(parents=True, exist_ok=True)
            (folder / "allowlist.json").write_text(text, encoding="utf-8")
            shutil.copyfile(ops_exec.__file__, folder / "ops_exec.py")
            (folder / "install.sh").write_text(install_script(text), encoding="utf-8")
            print(f"{name}：白名单 {count} 个工具 → {folder}（allowlist.json、ops_exec.py，"
                  f"以及在主机上以 root 执行的 install.sh）")
            continue
        binary = shutil.which("ssh")
        if not binary:
            raise ConfigError("这台机器没有 ssh 客户端")
        known_hosts = _check_known_hosts(host)
        argv = [binary, "-T", "-o", "StrictHostKeyChecking=yes", "-o", f"UserKnownHostsFile={known_hosts}",
                "-o", f"GlobalKnownHostsFile={os.devnull}", "-o", f"HostKeyAlias={name}", "-o", "CheckHostIP=no",
                "-o", "UpdateHostKeys=no"]
        if identity:
            argv += ["-i", identity, "-o", "IdentitiesOnly=yes"]
        argv += ["-p", str(host["port"]), "-l", admin_user, "--", host["address"],
                 "sudo -n sh -s" if sudo else "sh -s"]
        print(f"{name}：用 {admin_user} 的身份装执行器和白名单（{count} 个工具）…")
        done = subprocess.run(argv, input=install_script(text).encode("utf-8"), stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, timeout=120)
        report = (_decode(done.stdout) + _decode(done.stderr)).strip()
        if done.returncode != 0:
            failed += 1
            print(f"{name}：失败（退出码 {done.returncode}）\n{report}")
        else:
            print(f"{name}：已装好。{report}")
    return failed


def status(group=None, target=None):
    """现连各主机，逐台列出：能否连通、执行器版本、白名单版本、每个工具能不能跑。返回连不上 / 异常的台数。"""
    hosts = _cli_hosts(group, target)
    check_hosts([host["name"] for host in hosts])
    tools = _command_tools()
    bad = 0
    for host in hosts:
        view = _host_view(host)
        name = host["name"]
        if host["via"] == "local":
            print(f"■ {name}：本机（{view['os']}）" + (f"，分组 {', '.join(host['groups'])}" if host["groups"] else ""))
        else:
            mode = "受控" if host["mode"] == "guarded" else "直连（只读靠账号权限）"
            print(f"■ {name}：{host['user']}@{host['address']}:{host['port']}，{mode}，{host['os']}"
                  + (f"，分组 {', '.join(host['groups'])}" if host["groups"] else ""))
            state = view.get("status") or {}
            if state.get("error") or not state.get("reachable"):
                bad += 1
                print(f"    ✗ {state.get('error') or '连不上'}")
            else:
                print("    ✓ 连通" + (f"；执行器 {state['executor']}；白名单 {state['allowlist'][:19]}…"
                                       f"（{state['generated_at'] or '生成时间不详'}）" if host["mode"] == "guarded" else ""))
        groups = {"ok": [], "unknown": [], "no": []}
        for tool_name, spec in sorted(tools.items()):
            if not _applicable(spec, host)[0]:
                continue
            kind, reason = _host_tool_state(spec, host)
            groups[kind].append(tool_name if kind == "ok" else f"{tool_name}（{reason}）")
        print(f"    能跑 {len(groups['ok'])} 个：{'、'.join(groups['ok']) or '无'}")
        for key, label in (("unknown", "不确定"), ("no", "不能跑")):
            if groups[key]:
                print(f"    {label} {len(groups[key])} 个：{'；'.join(groups[key])}")
    return bad


def _cli(command, ident, config, attest_readonly=False, options=None):
    """Review proposals from the host. Approving is deliberately not an API."""
    _state["path"] = Path(config)
    options = options or {}
    if command == "pending":
        return _print_pending()
    if command == "scripts":
        return _print_scripts()
    if command in ("enroll", "push", "status"):
        try:
            if options.get("env_file"):
                load_env_file(options["env_file"])
            refresh(force=True)
            if command == "enroll":
                if not ident:
                    print("用法：ops_readonly.py enroll <主机名> [--fingerprint SHA256:…] [--from 工具服务的出口IP]",
                          file=sys.stderr)
                    return 2
                enroll(ident, options.get("fingerprint"), options.get("replace", False), options.get("source", ""))
                return 0
            if command == "push":
                return 1 if push(options.get("group"), options.get("target"),
                                 options.get("out") if options.get("print") else None,
                                 options.get("admin_user") or "root", options.get("identity"),
                                 options.get("sudo", False)) else 0
            return 1 if status(options.get("group"), options.get("target")) else 0
        except (ConfigError, HostError) as exc:
            print(f"失败：{exc}", file=sys.stderr)
            return 1
    if not ident:
        print(f"用法：ops_readonly.py {command} <id>", file=sys.stderr)
        return 2
    try:
        if command == "approve":
            spec = approve_pending(ident, attest_readonly=attest_readonly)
            print(f"已批准并写入配置：{spec['name']}")
            print(f"  {_display(spec)}")
            if spec.get("type") == "mcp":
                print(f"  只读依据：{'server 声明' if spec['readonly_declared'] else '管理员确认（--attest-readonly）'}"
                      f"；条目已写入 {_mcp_file().name}")
            written = spec.get("written")
            if written:
                print(f"  写在 {written['path']} 的 tools 列表末尾（第 {written['line']} 行起）；"
                      f"改之前的备份：{written['backup']}")
            print(f"重新加载后共 {len(_state['tools'])} 个工具定义。")
            if spec["name"] not in _state["tools"]:
                print(f"注意：重新加载的结果里没有 {spec['name']}，看上面 [config] 开头的提示", file=sys.stderr)
                return 1
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
                                 "scripts", "trust", "enroll", "push", "status"],
                        help="serve 起服务；pending/approve/reject/scripts/trust 审批工具与脚本；"
                             "enroll/push/status 接入和检查远程主机")
    parser.add_argument("ident", nargs="?", help="待审申请的 id、工具名、脚本名；enroll 时是主机名")
    parser.add_argument("--port", type=int, default=8799)
    parser.add_argument("--config", default=str(DEFAULT_CONFIG),
                        help="Tool definitions; edits are picked up live.")
    parser.add_argument("--host", default="127.0.0.1",
                        help="Loopback by default; do not expose this publicly.")
    parser.add_argument("--attest-readonly", action="store_true",
                        help="approve 时使用：确认这个 MCP 工具只读（server 没有声明 readOnlyHint 时必须加）")
    hosts = parser.add_argument_group("远程主机（enroll / push / status）")
    hosts.add_argument("--target", help="push / status：只处理这一台主机")
    hosts.add_argument("--group", help="push / status：只处理这个分组里的主机")
    hosts.add_argument("--print", action="store_true", help="push：只导出文件（白名单、执行器、安装脚本），不连主机")
    hosts.add_argument("--out", default="ops-push", help="push --print 导出到哪个目录，默认 ./ops-push")
    hosts.add_argument("--admin-user", default="root", help="push：以哪个账号登录主机安装（你自己的 SSH 身份）")
    hosts.add_argument("--identity", help="push：用哪把私钥登录主机（默认按你的 ssh 配置和 agent）")
    hosts.add_argument("--sudo", action="store_true", help="push：登录账号不是 root 时，用 sudo -n 安装")
    hosts.add_argument("--fingerprint", help="enroll：在主机上核对过的 host key 指纹（SHA256:…），非交互运行时必填")
    hosts.add_argument("--replace", action="store_true", help="enroll：替换已登记的 host key（先查清它为什么变了）")
    hosts.add_argument("--from", dest="source", default="", help="enroll：安装片段里 from= 写的工具服务出口 IP")
    hosts.add_argument("--env-file", help="enroll / status：从这个文件读凭据（如 /etc/ops-readonly.env）")
    args = parser.parse_args()

    if args.command != "serve":
        options = {key: getattr(args, key) for key in ("target", "group", "print", "out", "admin_user", "identity",
                                                       "sudo", "fingerprint", "replace", "source", "env_file")}
        return _cli(args.command, args.ident, args.config, attest_readonly=args.attest_readonly, options=options)

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
    elsewhere = [name for name in missing if _not_here(all_tools()[name])]
    missing = [name for name in missing if name not in elsewhere]
    if elsewhere:
        print(f"（不适用于这台机器（声明的 os 不是 {HOST_OS}）：{', '.join(elsewhere)}）")
    if missing:
        print(f"（本机缺少对应命令或 MCP server 尚未连上，暂不可用：{', '.join(missing)}）")
    exported = sorted(name for name, spec in all_tools().items() if spec.get("export"))
    if exported:
        print(f"对外开放（export）的工具 {len(exported)} 个：{', '.join(exported)}")
    waiting = len(list_pending())
    if waiting:
        print(f"（有 {waiting} 条新工具申请待审：ops_readonly.py pending）")
    if _state["mcp_servers"]:
        print(f"MCP server {len(_state['mcp_servers'])} 个：{', '.join(sorted(_state['mcp_servers']))}，"
              f"后台连接中；发现的工具会进入待审列表")
    if _hosts() is not None:
        remote = [name for name, host in _hosts()["hosts"].items() if host["via"] == "ssh"]
        print(f"主机清单 {len(_hosts()['hosts'])} 台：{', '.join(_hosts()['hosts'])}；不填 target 时用 "
              f"{_hosts()['default'] or '（没有默认，单台可选时用那台，否则必填）'}"
              + (f"；远程 {len(remote)} 台，后台检查中" if remote else ""))
    connections = _state.get("connections") or {}
    if connections:
        print(f"连接 {len(connections)} 个：" + "，".join(
            f"{name}（{conn['type']}{'，外部' if conn.get('external') else ''}）" for name, conn in connections.items()))
    if _vendor["problem"]:
        print(f"（{_vendor['problem']}）")
    # 没声明 server 也要起这个线程：配置热加载后新加的 mcp_servers 靠它连接和发现
    _mcp.start_background()
    # 主机同理：热加载后新加的 hosts 靠它检查（没配主机时它什么都不连）
    _monitor.start_background()
    ThreadingHTTPServer((args.host, args.port), Handler).serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
