#!/bin/bash
# 把整套系统打包成离线包，供内网等无外网环境部署。
#
# 在能访问外网的机器上执行：
#   bash deploy/make-offline-bundle.sh /tmp/bundle
#
# 产出目录可直接拷贝进内网，再按包内 README 部署。
set -euo pipefail

OUT="${1:-/tmp/kb-offline-bundle}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

echo "打包目录：$OUT"
mkdir -p "$OUT/images" "$OUT/src"

# --- 1. 应用镜像 ---------------------------------------------------------
echo
echo "[1/5] 构建应用镜像…"
docker build -q -t kb-app:offline "$ROOT" >/dev/null
echo "      导出 kb-app:offline"
docker save kb-app:offline | gzip -1 > "$OUT/images/kb-app.tar.gz"

# --- 2. 向量模型镜像（模型已烘焙，内网无需访问 HuggingFace）-------------
echo "[2/5] 构建向量模型镜像（含模型，约 744MB）…"
docker build -q -f "$ROOT/deploy/embedding/Dockerfile.offline" \
    -t kb-embedding:offline "$ROOT/deploy/embedding" >/dev/null
echo "      导出 kb-embedding:offline"
docker save kb-embedding:offline | gzip -1 > "$OUT/images/kb-embedding.tar.gz"

# --- 3. 只读运维接口（纯标准库，拷文件即可）-----------------------------
echo "[3/5] 拷贝只读运维接口…"
cp "$ROOT/deploy/ops_readonly.py" "$ROOT/deploy/ops_exec.py" "$OUT/src/"
cp "$ROOT/deploy/ops-readonly.service.example" "$OUT/src/"

# --- 4. 示例语料与评测 ---------------------------------------------------
echo "[4/5] 拷贝示例文档与评测集…"
cp -r "$ROOT/sample_kb" "$OUT/"
mkdir -p "$OUT/eval"
cp "$ROOT/eval/dataset.jsonl" "$ROOT/eval/run_eval.py" "$OUT/eval/"

# --- 5. 部署说明与启动脚本 -----------------------------------------------
echo "[5/5] 生成部署说明…"
cp "$ROOT/.env.example" "$OUT/env.example"

cat > "$OUT/deploy.sh" <<'DEPLOY'
#!/bin/bash
# 在内网机器上执行：bash deploy.sh
set -euo pipefail
cd "$(dirname "$0")"

[ -f .env ] || { echo "请先把 env.example 复制为 .env 并填写后再运行"; exit 1; }

echo "导入镜像…"
gunzip -c images/kb-app.tar.gz | docker load
gunzip -c images/kb-embedding.tar.gz | docker load

echo "启动向量模型…"
docker rm -f kb-embedding 2>/dev/null || true
docker run -d --name kb-embedding --restart unless-stopped \
  --memory 1400m -p 127.0.0.1:8080:8080 kb-embedding:offline

echo "启动只读运维接口…"
OPS_TOKEN=$(grep '^OPS_TOKEN=' .env | cut -d= -f2-)
if [ -n "$OPS_TOKEN" ]; then
  pkill -f ops_readonly.py 2>/dev/null || true
  nohup env OPS_TOKEN="$OPS_TOKEN" python3 src/ops_readonly.py --port 8799 \
    > ops.log 2>&1 &
  sleep 2
  curl -s http://127.0.0.1:8799/health && echo
fi

echo "启动知识库应用…"
mkdir -p data/files
docker rm -f kb-app 2>/dev/null || true
docker run -d --name kb-app --restart unless-stopped --network host \
  --env-file .env -v "$PWD/data:/data" --memory 900m --cpus 1.5 kb-app:offline

echo
echo "等待就绪…"
for i in $(seq 1 30); do
  curl -sf -o /dev/null "http://127.0.0.1:$(grep '^PORT=' .env | cut -d= -f2)/" && break
  sleep 2
done
docker ps --filter name=kb- --format '  {{.Names}}  {{.Status}}'
echo
echo "完成。浏览器打开 http://<本机IP>:$(grep '^PORT=' .env | cut -d= -f2)"
DEPLOY
chmod +x "$OUT/deploy.sh"

cat > "$OUT/README.md" <<'DOC'
# 离线部署包

无需访问外网即可部署（向量模型已烘焙进镜像）。唯一的外部依赖是大模型接口。

## 前置要求

- Docker
- Python 3.9+（只读运维接口用，纯标准库）
- 一个 OpenAI 兼容的大模型接口（内网 AI 网关或可达的外网网关）

## 部署步骤

```bash
cp env.example .env
vi .env          # 至少填 LLM_BASE_URL、LLM_API_KEY、WEB_PASSWORD、OPS_TOKEN
bash deploy.sh
```

## .env 关键项

| 变量 | 说明 |
|---|---|
| `LLM_BASE_URL` | 大模型接口地址，例如 `http://ai-gateway.内网域名/v1` |
| `LLM_API_KEY` | 接口密钥 |
| `CHAT_MODEL` | 对话模型名 |
| `EMBED_MODEL` | **填 `BAAI/bge-base-zh-v1.5`**，并把 `LLM_BASE_URL` 之外的向量请求指向本地 8080 |
| `WEB_PASSWORD` | 网页登录口令，用长随机串 |
| `OPS_TOKEN` | 只读运维接口令牌，用 `openssl rand -hex 16` 生成 |
| `OPS_URL` | 填 `http://127.0.0.1:8799` |

> 向量模型跑在本地 8080。如果内网 AI 网关自身提供 embedding 接口，
> 可以直接用网关的，不启本地向量容器。

## 验证

```bash
# 向量模型
curl -s http://127.0.0.1:8080/health

# 只读运维接口（应列出可用工具）
curl -s http://127.0.0.1:8799/health

# 注入防护（应被拒绝）
curl -s -X POST -H "X-Ops-Token: $OPS_TOKEN" -H 'Content-Type: application/json' \
  -d '{"tool":"container_logs","args":{"name":"a; rm -rf /"}}' \
  http://127.0.0.1:8799/exec
```

## 让 Agent 能看 Kubernetes

只读运维接口所在机器装好 `kubectl` 并配置**只读权限**的 kubeconfig 即可，
`kube_get` / `kube_describe` / `kube_logs` / `kube_events` 会自动出现在工具列表里。

建议用只读 ServiceAccount：

```bash
kubectl create serviceaccount kb-readonly -n default
kubectl create clusterrolebinding kb-readonly \
  --clusterrole=view --serviceaccount=default:kb-readonly
```

## 导入示例文档

`sample_kb/` 下有 6 篇通用技术文档，可直接上传试用。
`eval/` 下有 20 题评测集与脚本：

```bash
python3 eval/run_eval.py --url http://127.0.0.1:8765 --user admin --password '...'
```
DOC

echo
echo "打包完成：$OUT"
du -sh "$OUT" | sed 's/^/  总体积: /'
ls -lh "$OUT/images" | tail -2 | sed 's/^/  /'
