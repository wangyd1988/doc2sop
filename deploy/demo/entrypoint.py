#!/usr/bin/env python3
"""演示 sidecar（kb-ops）的入口：把 compose 传进来的变量整理成 ops_readonly.py 要的样子，再起服务。

做三件事，目的都是让用户不用手工对齐任何值：

  1. 网关组工具的地址。.env 里的 LLM_BASE_URL 约定以 /v1 结尾，而工具模板写的是
     ${OPS_SECRET_GATEWAY_URL}/v1/...（根地址约定，和宿主机的 ops_tools.yaml 一致），
     所以这里把结尾的 /v1 去掉。
  2. 工具定义。生成 /ops/ops_tools.yaml，它的 include 恰好是 DEMO_PACKS 列出的那些包的
     tools.yaml——导入哪些包，就只提供哪些包的工具（运维包的 df/free 在容器里查到的只是
     容器自己，不该出现在演示里）。文件已存在时只改 include，保留 tools:，那里面是通过页面
     申请、在容器里批准过的工具。
  3. exec ops_readonly.py serve --host 0.0.0.0。容器内必须监听所有地址 kb-app 才连得上；
     端口不对外发布，只有同一 compose 网络里的容器能访问，令牌是第二道保险。
"""
import os
import sys
from pathlib import Path

PACKS_DIR = Path(os.environ.get("PACKS_DIR", "/packs"))
STATE_DIR = Path(os.environ.get("OPS_STATE_DIR", "/ops"))
CONFIG = STATE_DIR / "ops_tools.yaml"
HERE = Path(__file__).resolve().parent
# 镜像里两个文件并排在 /srv；源码检出里它在上一级 deploy/。两处都找，这样不装 Docker 也能直接跑这个入口。
SERVER = next((p for p in (HERE / "ops_readonly.py", HERE.parent / "ops_readonly.py") if p.is_file()),
              HERE / "ops_readonly.py")
HEADER = ("# 由 entrypoint.py 按 DEMO_PACKS 生成，每次启动重写 include；\n"
          "# tools: 里是通过页面申请、在本容器里批准过的工具，会保留。\n")


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


def write_config(path, includes):
    """写主定义文件：include 按本次启动重算，tools 保留上次批准过的。原子替换。"""
    import yaml
    path = Path(path)
    document = {}
    if path.is_file():
        try:
            document = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except Exception:
            document = {}
    tools = document.get("tools") if isinstance(document, dict) and isinstance(document.get("tools"), list) else []
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(HEADER + yaml.safe_dump({"include": list(includes), "tools": tools},
                                           allow_unicode=True, sort_keys=False), encoding="utf-8")
    os.replace(tmp, path)
    return path


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
    write_config(CONFIG, files)
    print(f"[demo] 工具定义 {CONFIG}：include 了 {len(files)} 个场景包", flush=True)
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
