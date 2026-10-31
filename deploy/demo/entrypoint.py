#!/usr/bin/env python3
"""演示 sidecar（kb-ops）的入口：把 compose 传进来的变量整理成 ops_readonly.py 要的样子，再起服务。

做这几件事，目的都是让用户不用手工对齐任何值：

  1. 网关组工具的地址。.env 里的 LLM_BASE_URL 约定以 /v1 结尾，而工具模板写的是
     ${OPS_SECRET_GATEWAY_URL}/v1/...（根地址约定，和宿主机的 ops_tools.yaml 一致），
     所以这里把结尾的 /v1 去掉。
  2. 工具定义。生成 /ops/ops_tools.yaml，它的 include 恰好是 DEMO_PACKS 列出的那些包的
     tools.yaml——导入哪些包，就只提供哪些包的工具（运维包的 df/free 在容器里查到的只是
     容器自己，不该出现在演示里）。文件已存在时只改 include 和 hosts，保留 tools:，那里面是通过页面
     申请、在容器里批准过的工具。
  3. 演示主机（DEMO_HOST，compose 里的 kb-host）：sidecar 自己算本机，演示主机经 SSH 受控模式巡检，
     两台合成分组 demo，演示多机巡检。DEMO_HOST_PACKS 列出的场景包只取工具（不导入文档和 SOP）。
     密钥交换只走共享卷 /exchange 里的两份公钥：sidecar 的客户端公钥给演示主机写进 authorized_keys（强制命令），
     演示主机的 host 公钥由这里登记进 known_hosts——这是可信通道，不是从网络上自动接受。私钥都不出各自的容器。
  4. 演示数据库：DEMO_PACKS 里的包在 pack.yaml 写了 demo.sqlite（连接名 + 建库脚本）的，用脚本在 /ops 里建一个
     sqlite 库（每次启动重建，脚本里的日期按当天推算），在主配置里建同名连接——工具服务只读打开它。不加常驻容器。
  5. exec ops_readonly.py serve --host 0.0.0.0。容器内必须监听所有地址 kb-app 才连得上；
     端口不对外发布，只有同一 compose 网络里的容器能访问，令牌是第二道保险。
"""
import os
import re
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

PACKS_DIR = Path(os.environ.get("PACKS_DIR", "/packs"))
STATE_DIR = Path(os.environ.get("OPS_STATE_DIR", "/ops"))
EXCHANGE_DIR = Path(os.environ.get("OPS_EXCHANGE_DIR", "/exchange"))
CONFIG = STATE_DIR / "ops_tools.yaml"
HERE = Path(__file__).resolve().parent
# 镜像里两个文件并排在 /srv；源码检出里它在上一级 deploy/。两处都找，这样不装 Docker 也能直接跑这个入口。
SERVER = next((p for p in (HERE / "ops_readonly.py", HERE.parent / "ops_readonly.py") if p.is_file()),
              HERE / "ops_readonly.py")
HEADER = ("# 由 entrypoint.py 按 DEMO_PACKS / DEMO_HOST 生成，每次启动重写 include、hosts 和 connections；\n"
          "# tools: 里是通过页面申请、在本容器里批准过的工具，会保留。\n")
# 演示主机只开放这三个无害的工具（它的白名单 deploy/demo/host-allowlist.json 也只有这三个）；容器状态要读 docker，演示主机上没有
HOST_NAME = "demo-host"
HOST_TOOLS = ["host_disk", "host_resources", "host_uptime"]
HOST_KEY = "demo_host_key"          # 凭据名：${demo_host_key} → 环境变量 OPS_SECRET_DEMO_HOST_KEY，值是私钥路径
HOST_WAIT = 60                      # 等演示主机交出 host 公钥最多多少秒


def gateway_root(url):
    """'https://api.siliconflow.cn/v1/' -> 'https://api.siliconflow.cn'；空就是空。"""
    url = (url or "").strip().rstrip("/")
    if url.endswith("/v1"):
        url = url[:-3].rstrip("/")
    return url


def pack_ids(raw):
    return [p.strip() for p in (raw or "").split(",") if p.strip()]


def include_list(ids, packs_dir=None):
    """每个包的 tools.yaml 绝对路径；没有这个文件的包单独报出来（id 拼错了，或目录没挂进来）。"""
    files, missing = [], []
    for pack_id in ids:
        path = Path(packs_dir or PACKS_DIR) / pack_id / "tools.yaml"
        if path.is_file():
            files.append(str(path))
        else:
            missing.append(pack_id)
    return files, missing


def write_config(path, includes, hosts=None, connections=None):
    """写主定义文件：include、hosts、connections 按本次启动重算，tools 和其他顶层键（如 mcp_servers）原样保留。原子替换。"""
    import yaml
    path = Path(path)
    document = {}
    if path.is_file():
        try:
            document = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except Exception:
            document = {}
    document = document if isinstance(document, dict) else {}
    tools = document.get("tools") if isinstance(document.get("tools"), list) else []
    others = {k: v for k, v in document.items() if k not in ("include", "tools", "hosts", "connections")}
    if hosts:
        others["hosts"] = hosts
    if connections:
        others["connections"] = connections
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(HEADER + yaml.safe_dump({"include": list(includes), **others, "tools": tools},
                                           allow_unicode=True, sort_keys=False), encoding="utf-8")
    os.replace(tmp, path)
    return path


CONN_NAME = re.compile(r"^[a-z][a-z0-9_]{0,30}$")


def demo_databases(ids, packs_dir=None, state=None):
    """DEMO_PACKS 里在 pack.yaml 写了 demo.sqlite 的包：用包里的建库脚本在 state 目录建 sqlite 库，返回要建的连接。

    每次启动重建（先建临时文件再替换，建到一半失败不会留下半个库）：脚本里的日期按当天推算，演示什么时候跑结论都一样。
    建库用标准库 sqlite3；工具服务只读打开它（mode=ro + query_only + 授权回调）。
    """
    import yaml
    out = []
    for pack_id in ids:
        folder = Path(packs_dir or PACKS_DIR) / pack_id
        try:
            meta = yaml.safe_load((folder / "pack.yaml").read_text(encoding="utf-8")) or {}
        except Exception:
            continue
        demo = meta.get("demo") if isinstance(meta, dict) else None
        sqlite = demo.get("sqlite") if isinstance(demo, dict) else None
        if not isinstance(sqlite, dict):
            continue
        conn, script = str(sqlite.get("conn") or ""), str(sqlite.get("script") or "")
        source = (folder / script).resolve()
        if not CONN_NAME.match(conn) or not script or folder.resolve() not in source.parents or not source.is_file():
            print(f"[demo] {pack_id} 的 demo.sqlite 写得不对（连接名 {conn!r}、脚本 {script!r}），没有建演示库", flush=True)
            continue
        target = Path(state or STATE_DIR) / f"demo-{pack_id}.db"
        tmp = target.with_suffix(".tmp")
        try:
            if tmp.exists():
                tmp.unlink()
            db = sqlite3.connect(tmp)
            try:
                db.executescript(source.read_text(encoding="utf-8"))
                db.commit()
            finally:
                db.close()
            os.chmod(tmp, 0o644)
            os.replace(tmp, target)
        except Exception as exc:
            print(f"[demo] {pack_id} 的演示库建不起来：{exc.__class__.__name__}: {exc}", flush=True)
            continue
        out.append({"name": conn, "type": "sqlite", "path": str(target), "label": f"{meta.get('name') or pack_id}（演示库）"})
        print(f"[demo] 已用 {pack_id}/{script} 建演示库，连接 {conn}", flush=True)
    return out


def host_section(address):
    """演示用的主机清单：sidecar 自己（本机）和演示主机，合成分组 demo。"""
    return {"list": [{"name": "local", "via": "local", "groups": ["demo"]},
                     {"name": HOST_NAME, "address": address, "user": "opsread", "key": "${" + HOST_KEY + "}",
                      "os": "linux", "mode": "guarded", "groups": ["demo"], "tools": list(HOST_TOOLS)}]}


def _atomic(path, text, mode):
    tmp = Path(f"{path}.tmp")
    tmp.write_text(text, encoding="utf-8")
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def prepare_host(environ, address, exchange=None, state=None, wait=HOST_WAIT):
    """演示主机的密钥：生成（或沿用）客户端私钥，公钥放进交换目录；等演示主机交出 host 公钥，登记进 known_hosts。

    返回 True 表示 host key 已登记。等不到也照常起服务：演示主机那几个工具会提示「host key 还没登记」。
    """
    exchange, state = Path(exchange or EXCHANGE_DIR), Path(state or STATE_DIR)
    key = state / "demo_host_key"
    if not key.is_file():
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "doc2sop-demo", "-f", str(key)],
                       stdin=subprocess.DEVNULL, check=True, timeout=30)
    os.chmod(key, 0o600)
    environ["OPS_SECRET_" + HOST_KEY.upper()] = str(key)
    exchange.mkdir(parents=True, exist_ok=True)
    _atomic(exchange / "client.pub", (state / "demo_host_key.pub").read_text(encoding="utf-8"), 0o644)
    deadline = time.monotonic() + wait
    published = exchange / "host_ed25519.pub"
    while not published.is_file() and time.monotonic() < deadline:
        time.sleep(1)
    parts = published.read_text(encoding="utf-8").split() if published.is_file() else []
    if len(parts) < 2 or parts[0] != "ssh-ed25519":
        print(f"[demo] 等不到演示主机 {address} 的 host 公钥（{published}），它的工具暂时用不了", flush=True)
        return False
    _atomic(state / "ops_tools.known_hosts", f"{HOST_NAME} {parts[0]} {parts[1]}\n", 0o644)
    print(f"[demo] 已登记演示主机 {HOST_NAME}（{address}）的 host key", flush=True)
    return True


def prepare(environ=os.environ):
    """整理环境变量、生成配置，返回要传给 ops_readonly.py 的 --config 路径。"""
    base = gateway_root(environ.get("OPS_SECRET_GATEWAY_URL", ""))
    key = (environ.get("OPS_SECRET_GATEWAY_KEY") or "").strip()
    for name, value in (("OPS_SECRET_GATEWAY_URL", base), ("OPS_SECRET_GATEWAY_KEY", key)):
        if value:
            environ[name] = value
        else:
            environ.pop(name, None)
    if not (base and key):
        print("[demo] .env 里没有 LLM_BASE_URL / LLM_API_KEY：「模型网关」组工具会提示「未配置」。"
              "页面上填的模型不会传到这里；写进 .env 再 docker compose up -d 即可。", flush=True)

    ids = pack_ids(environ.get("DEMO_PACKS", ""))
    files, missing = include_list(ids)
    for pack_id in missing:
        print(f"[demo] DEMO_PACKS 里的 {pack_id} 在 {PACKS_DIR} 下没有 tools.yaml，已跳过", flush=True)
    if not ids:
        print("[demo] DEMO_PACKS 为空：sidecar 不提供任何工具", flush=True)
    hosts = None
    address = (environ.get("DEMO_HOST") or "").strip()
    if address:
        prepare_host(environ, address)
        wanted = pack_ids(environ.get("DEMO_HOST_PACKS", ""))
        extra, missing = include_list([pack_id for pack_id in wanted if pack_id not in ids])
        for pack_id in missing:
            print(f"[demo] DEMO_HOST_PACKS 里的 {pack_id} 在 {PACKS_DIR} 下没有 tools.yaml，已跳过", flush=True)
        if wanted:
            files += extra
            hosts = host_section(address)
        else:
            print("[demo] DEMO_HOST_PACKS 为空：不演示多机巡检（演示主机照常运行，只是没有工具用它）", flush=True)
    connections = demo_databases(ids)
    write_config(CONFIG, files, hosts, connections)
    print(f"[demo] 工具定义 {CONFIG}：include 了 {len(files)} 个场景包"
          + (f"；主机：本机 + {HOST_NAME}（{address}），分组 demo" if hosts else "")
          + (f"；演示库连接：{', '.join(c['name'] for c in connections)}" if connections else ""), flush=True)
    return CONFIG


def main():
    config = prepare()
    argv = [sys.executable, str(SERVER), "serve",
            "--host", os.environ.get("OPS_HOST", "0.0.0.0"),
            "--port", os.environ.get("OPS_PORT", "8799"),
            "--config", str(config)]
    os.execv(sys.executable, argv)


if __name__ == "__main__":
    main()
