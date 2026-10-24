# 两个阶段：base 只装依赖，app 再把代码拷进去。
#   · compose 不指定 target，构建的是末尾的 app 阶段，和单阶段时完全一样；
#   · deploy/release.sh 用 --target base 单独打出 kb-app:base-<哈希>，之后每次发版只 COPY 代码
#     （deploy/Dockerfile.release），2 核小机器上不用再等 10 分钟 pip，清掉旧镜像也不怕构建缓存失效。
# Docker Hub 拉不动时，.env 里把 BASE_IMAGE 指到国内镜像站（compose 透传进来），不用改这个文件
ARG BASE_IMAGE=python:3.12-slim
FROM ${BASE_IMAGE} AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    ANONYMIZED_TELEMETRY=False \
    DATA_DIR=/data

WORKDIR /srv
# PyPI 慢或不通时传 PIP_INDEX_URL（compose 的 .env 或 release.sh 的环境变量），留空用官方源
ARG PIP_INDEX_URL=
COPY requirements.txt /srv/requirements.txt
RUN pip install --no-cache-dir ${PIP_INDEX_URL:+-i "$PIP_INDEX_URL"} -r requirements.txt

EXPOSE 8765
CMD ["sh", "-c", "exec uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8765} --workers 1"]

FROM base AS app
COPY app /srv/app
# 场景包随镜像发布（文档 + 工具定义 + SOP，见 docs/场景包.md）；compose 里再把 ./packs 挂上来盖住它，改包不用重建
COPY packs /srv/packs
