#!/bin/bash
# 正式发版：构建 → 切换 → 校验 → 不一致自动回滚。宿主机 host 网络形态，不走 compose（见 docs/正式部署.md）。
#
# 用法  bash deploy/release.sh                                   # 在仓库目录里：./.env、./data，容器 kb-app
#       ENV_FILE=/opt/kb-app/.env DATA_DIR=/opt/kb-app/data bash deploy/release.sh
#       bash deploy/release.sh --image kb-app:20261024195031     # 不构建，切到一个已有镜像（这就是回滚）
#       bash deploy/release.sh --rebuild-base                    # 强制重建依赖镜像
#       bash deploy/release.sh --backup                          # 切换前先跑 deploy/backup.sh
#       bash deploy/release.sh --print-config                    # 只打印解析后的配置，不碰 docker
#
# 两段式构建：依赖预烘焙成 <镜像名>:base-<哈希>（根 Dockerfile 的 base 阶段，哈希来自 requirements.txt、
# base 阶段文本和构建参数，变了才重建），应用镜像 FROM 它只 COPY 代码（deploy/Dockerfile.release），
# 打时间戳 tag。2 核小机器上每次 pip 要 10 分钟，而且清理旧镜像后构建缓存靠不住，所以不依赖缓存。
#
# 切换：stop 旧 → rename 成 <容器名>-prev → run 新 → 等 /api/documents 就绪 → 比对切换前后片段总数
# → 不一致或起不来就把 -prev 改回来并启动 → 成功才删 -prev，只保留最近 KEEP_IMAGES 个时间戳镜像和当前 base。
#
# 配置来源优先级：环境变量 > 环境文件里的同名键 > 默认值。密钥只从环境文件读进内存，不进命令行、不打印。
#   ENV_FILE        容器的 --env-file；也从这里读 PORT、WEB_USER、WEB_PASSWORD、APP_*    默认 <仓库>/.env
#   DATA_DIR        挂到容器 /data                                                     默认 <仓库>/data
#   APP_CONTAINER   容器名（container-guard、cron 等引用的就是它）                       默认 kb-app
#   APP_IMAGE       镜像名，冒号前的部分作为仓库名，时间戳和 base-<哈希> 都打在它上        默认 kb-app:latest
#   APP_MEM_LIMIT / APP_CPUS   --memory / --cpus                                       默认 900m / 1.5
#   APP_PORT        探活端口；host 网络下就是容器内的 PORT                                默认 环境文件的 PORT，再默认 8765
#   BASE_IMAGE / PIP_INDEX_URL   构建 base 用的基础镜像 / pip 源（国内镜像站）              默认 python:3.12-slim / 空
#   BACKUP_DIR      --backup 时的备份目录                                                默认 <DATA_DIR 的上级>/backups
#   KEEP_IMAGES     保留最近几个时间戳镜像                                                默认 2
#   START_TIMEOUT   等新容器就绪的秒数                                                    默认 120
set -euo pipefail

REPO=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

usage() { sed -n '2,/^set -euo/p' "${BASH_SOURCE[0]}" | sed '$d' | sed 's/^# \{0,1\}//'; }
log() { printf '%s %s\n' "$(date '+%F %T')" "$*"; }
die() { echo "!! $*" >&2; exit 2; }
# 只用来解析 JSON；没有 python3 的机器（或 Windows 上 Git Bash 里那个空壳 python3）退回 python
PYTHON=python3
"$PYTHON" -c pass >/dev/null 2>&1 || PYTHON=python
parse_chunks() {
  # stdin 是 /api/documents 的 JSON，输出片段总数；也暴露为 --parse-chunks 方便单测
  "$PYTHON" -c 'import json, sys
data = json.load(sys.stdin)
print(sum(int(d.get("chunks", 0)) for d in data["documents"]))'
}

IMAGE_ARG="" REBUILD_BASE=0 BACKUP=0 PRINT_ONLY=0
while [ $# -gt 0 ]; do
  case "$1" in
    --image) [ $# -ge 2 ] || die "--image 后面要跟镜像名"; IMAGE_ARG=$2; shift 2 ;;
    --image=*) IMAGE_ARG=${1#--image=}; shift ;;
    --rebuild-base) REBUILD_BASE=1; shift ;;
    --backup) BACKUP=1; shift ;;
    --print-config) PRINT_ONLY=1; shift ;;
    --parse-chunks) parse_chunks; exit 0 ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; die "未知参数：$1" ;;
  esac
done

ENV_FILE=${ENV_FILE:-$REPO/.env}
DATA_DIR=${DATA_DIR:-$REPO/data}

envfile_get() {
  # 只取一个键的值，不 source 整个文件：值里可能有空格、$ 或引号，而且 docker --env-file 读的也是原样的值
  [ -f "$ENV_FILE" ] || return 0
  sed -n "s/^[[:space:]]*$1=//p" "$ENV_FILE" | tail -n 1 | tr -d '\r'
}
setting() {
  # setting 名字 默认值：环境变量 > 环境文件 > 默认
  local name=$1 fallback=$2 value
  value=${!name:-}
  [ -n "$value" ] || value=$(envfile_get "$name")
  printf '%s' "${value:-$fallback}"
}

APP_CONTAINER=$(setting APP_CONTAINER kb-app)
APP_IMAGE=$(setting APP_IMAGE kb-app:latest)
APP_MEM_LIMIT=$(setting APP_MEM_LIMIT 900m)
APP_CPUS=$(setting APP_CPUS 1.5)
APP_PORT=$(setting APP_PORT "$(envfile_get PORT)")
APP_PORT=${APP_PORT:-8765}
BASE_IMAGE=$(setting BASE_IMAGE python:3.12-slim)
PIP_INDEX_URL=$(setting PIP_INDEX_URL "")
BACKUP_DIR=${BACKUP_DIR:-$(dirname "$DATA_DIR")/backups}
KEEP_IMAGES=${KEEP_IMAGES:-2}
START_TIMEOUT=${START_TIMEOUT:-120}
REPO_NAME=${APP_IMAGE%%:*}
PREV_CONTAINER="$APP_CONTAINER-prev"

base_stage() {
  # 根 Dockerfile 里 app 阶段之前的全部指令（注释和空行不算）；改了 pip 源、ENV 也该重建 base
  awk '/^FROM[[:space:]].*[[:space:]][Aa][Ss][[:space:]]+app[[:space:]]*$/ {exit}
       /^[[:space:]]*(#|$)/ {next} {print}' "$REPO/Dockerfile"
}
BASE_HASH=$({ cat "$REPO/requirements.txt"; base_stage; printf '%s\n%s\n' "$BASE_IMAGE" "$PIP_INDEX_URL"; } \
  | sha256sum | cut -c1-12)
BASE_TAG="$REPO_NAME:base-$BASE_HASH"

if [ "$PRINT_ONLY" = 1 ]; then
  cat <<EOF
REPO=$REPO
ENV_FILE=$ENV_FILE
DATA_DIR=$DATA_DIR
APP_CONTAINER=$APP_CONTAINER
APP_IMAGE=$APP_IMAGE
REPO_NAME=$REPO_NAME
APP_MEM_LIMIT=$APP_MEM_LIMIT
APP_CPUS=$APP_CPUS
APP_PORT=$APP_PORT
BASE_IMAGE=$BASE_IMAGE
PIP_INDEX_URL=$PIP_INDEX_URL
BASE_TAG=$BASE_TAG
BACKUP_DIR=$BACKUP_DIR
KEEP_IMAGES=$KEEP_IMAGES
START_TIMEOUT=$START_TIMEOUT
IMAGE=${IMAGE_ARG:-（构建新镜像）}
EOF
  exit 0
fi

# ---- 前置检查 ----------------------------------------------------------------
for cmd in docker curl sha256sum base64 "$PYTHON"; do
  command -v "$cmd" >/dev/null 2>&1 || die "缺少命令：$cmd"
done
[ -f "$ENV_FILE" ] || die "环境文件不存在：$ENV_FILE（复制 .env.example 改好，或用 ENV_FILE= 指定）"
ENV_FILE=$(cd "$(dirname "$ENV_FILE")" && pwd)/$(basename "$ENV_FILE")
mkdir -p "$DATA_DIR"
DATA_DIR=$(cd "$DATA_DIR" && pwd)
WEB_USER=$(envfile_get WEB_USER)
WEB_PASSWORD=$(envfile_get WEB_PASSWORD)
[ -n "$WEB_USER" ] && [ -n "$WEB_PASSWORD" ] || die "环境文件里缺 WEB_USER / WEB_PASSWORD，没法探活和比对片段数"
if docker container inspect "$PREV_CONTAINER" >/dev/null 2>&1; then
  die "已存在 $PREV_CONTAINER：上次发版没有收尾。当前 $APP_CONTAINER 正常就 docker rm -f $PREV_CONTAINER；" \
      "要回到它就 docker rm -f $APP_CONTAINER && docker rename $PREV_CONTAINER $APP_CONTAINER && docker start $APP_CONTAINER"
fi

# ---- 探活与片段计数 ----------------------------------------------------------
curl_auth() {
  # Basic 凭据先 base64（只剩字母数字 +/=，不用考虑转义），再经 stdin 的 curl 配置传入，不出现在命令行（ps 看不到）
  local token
  token=$(printf '%s:%s' "$WEB_USER" "$WEB_PASSWORD" | base64 | tr -d '\n')
  printf 'header = "Authorization: Basic %s"\n' "$token" | curl -s -K - "$@"
}
chunk_count() {
  # 片段总数；拿不到就输出空串
  curl_auth -m 10 "http://127.0.0.1:$APP_PORT/api/documents" 2>/dev/null | parse_chunks 2>/dev/null || true
}
running() { docker ps -q --filter "name=^${1}$" | grep -q .; }
wait_ready() {
  local deadline=$(( $(date +%s) + START_TIMEOUT )) code
  while [ "$(date +%s)" -lt "$deadline" ]; do
    code=$(curl_auth -o /dev/null -w '%{http_code}' -m 5 "http://127.0.0.1:$APP_PORT/api/documents" 2>/dev/null || true)
    [ "$code" = "200" ] && return 0
    running "$APP_CONTAINER" || return 1    # 容器已经退出，不用再等
    sleep 2
  done
  return 1
}

# ---- 现状 -------------------------------------------------------------------
HAVE_OLD=0 OLD_IMAGE="" BEFORE=""
if docker container inspect "$APP_CONTAINER" >/dev/null 2>&1; then
  HAVE_OLD=1
  OLD_IMAGE=$(docker inspect "$APP_CONTAINER" --format '{{.Config.Image}}')
  if running "$APP_CONTAINER"; then
    BEFORE=$(chunk_count)
    log "当前 $APP_CONTAINER 运行 $OLD_IMAGE，片段 ${BEFORE:-读不到（切换后不比对）}"
  else
    log "当前 $APP_CONTAINER 已停止（$OLD_IMAGE），切换后不比对片段数"
  fi
else
  log "没有名为 $APP_CONTAINER 的容器：按首次安装处理"
fi

# ---- 构建 -------------------------------------------------------------------
COMMIT=$(git -C "$REPO" rev-parse --short HEAD 2>/dev/null || echo unknown)
if [ -n "$IMAGE_ARG" ]; then
  docker image inspect "$IMAGE_ARG" >/dev/null 2>&1 || die "镜像不存在：$IMAGE_ARG（docker images $REPO_NAME 看看有哪些）"
  NEW_IMAGE=$IMAGE_ARG
  log "不构建，切到已有镜像 $NEW_IMAGE"
else
  if [ "$REBUILD_BASE" = 1 ] || ! docker image inspect "$BASE_TAG" >/dev/null 2>&1; then
    log "构建依赖镜像 $BASE_TAG（首次或 requirements.txt / base 阶段变了；2 核机器上约 10 分钟）"
    docker build --target base --build-arg "BASE_IMAGE=$BASE_IMAGE" --build-arg "PIP_INDEX_URL=$PIP_INDEX_URL" \
      -t "$BASE_TAG" -f "$REPO/Dockerfile" "$REPO"
  else
    log "依赖镜像 $BASE_TAG 已有，跳过 pip"
  fi
  NEW_IMAGE="$REPO_NAME:$(date +%Y%m%d%H%M%S)"
  log "构建应用镜像 $NEW_IMAGE（代码 $COMMIT）"
  docker build --build-arg "RUNTIME_IMAGE=$BASE_TAG" --label "doc2sop.commit=$COMMIT" --label "doc2sop.base=$BASE_TAG" \
    -t "$NEW_IMAGE" -f "$REPO/deploy/Dockerfile.release" "$REPO"
fi

if [ "$BACKUP" = 1 ]; then
  log "切换前备份到 $BACKUP_DIR"
  KB_DATA="$DATA_DIR" bash "$REPO/deploy/backup.sh" "$BACKUP_DIR"
fi

# ---- 切换 -------------------------------------------------------------------
rollback() {
  echo "!! $1" >&2
  if docker container inspect "$APP_CONTAINER" >/dev/null 2>&1; then
    echo "---- 新容器最后 40 行日志 ----" >&2
    docker logs --tail 40 "$APP_CONTAINER" >&2 2>&1 || true
    docker rm -f "$APP_CONTAINER" >/dev/null 2>&1 || true
  fi
  if [ "$HAVE_OLD" = 1 ]; then
    docker rename "$PREV_CONTAINER" "$APP_CONTAINER"
    docker start "$APP_CONTAINER" >/dev/null
    if wait_ready; then
      echo "已回滚到 $OLD_IMAGE，服务已恢复" >&2
    else
      echo "已回滚到 $OLD_IMAGE，但 $START_TIMEOUT s 内没探活成功，请看 docker logs $APP_CONTAINER" >&2
    fi
  fi
  exit 1
}

if [ "$HAVE_OLD" = 1 ]; then
  log "停止 $APP_CONTAINER（最多等 60 s）并改名为 $PREV_CONTAINER"
  docker stop -t 60 "$APP_CONTAINER" >/dev/null
  docker rename "$APP_CONTAINER" "$PREV_CONTAINER"
fi
log "启动 $APP_CONTAINER ← $NEW_IMAGE（host 网络，--memory $APP_MEM_LIMIT --cpus $APP_CPUS，$DATA_DIR → /data）"
docker run -d --name "$APP_CONTAINER" --restart unless-stopped --network host \
  --env-file "$ENV_FILE" -v "$DATA_DIR:/data" \
  --memory "$APP_MEM_LIMIT" --cpus "$APP_CPUS" "$NEW_IMAGE" >/dev/null || rollback "新容器启动失败"
wait_ready || rollback "新容器 $START_TIMEOUT s 内没有就绪（http://127.0.0.1:$APP_PORT/api/documents 不返回 200）"
AFTER=$(chunk_count)
if [ -n "$BEFORE" ]; then
  [ "$AFTER" = "$BEFORE" ] || rollback "片段总数不一致：切换前 $BEFORE，切换后 ${AFTER:-读不到}"
else
  [ -n "$AFTER" ] || rollback "切换后读不到 /api/documents 的片段数"
fi

# ---- 收尾 -------------------------------------------------------------------
[ "$HAVE_OLD" = 1 ] && docker rm -f "$PREV_CONTAINER" >/dev/null
# 只保留最近 KEEP_IMAGES 个时间戳镜像（正在跑的永远不删）和当前 base；grep 没匹配到也不算错
docker images "$REPO_NAME" --format '{{.Tag}}' | { grep -E '^[0-9]{14}$' || true; } | sort -r \
  | tail -n +$((KEEP_IMAGES + 1)) | { grep -vx "${NEW_IMAGE#*:}" || true; } \
  | while read -r tag; do docker rmi "$REPO_NAME:$tag" >/dev/null 2>&1 || true; done
docker images "$REPO_NAME" --format '{{.Tag}}' | { grep -E '^base-[0-9a-f]{12}$' || true; } \
  | { grep -vx "base-$BASE_HASH" || true; } \
  | while read -r tag; do docker rmi "$REPO_NAME:$tag" >/dev/null 2>&1 || true; done

log "发布完成：$APP_CONTAINER 运行 $NEW_IMAGE（代码 $COMMIT），片段 ${BEFORE:-?} → $AFTER"
[ -n "$OLD_IMAGE" ] && [ "$OLD_IMAGE" != "$NEW_IMAGE" ] && log "回滚：bash ${BASH_SOURCE[0]} --image $OLD_IMAGE"
exit 0
