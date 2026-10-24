# Docker Hub 拉不动时，.env 里把 BASE_IMAGE 指到国内镜像站（compose 透传进来），不用改这个文件
ARG BASE_IMAGE=python:3.12-slim
FROM ${BASE_IMAGE}

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    ANONYMIZED_TELEMETRY=False \
    DATA_DIR=/data

WORKDIR /srv
COPY requirements.txt /srv/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY app /srv/app
# 场景包随镜像发布（文档 + 工具定义 + SOP，见 docs/场景包.md）；compose 里再把 ./packs 挂上来盖住它，改包不用重建
COPY packs /srv/packs

EXPOSE 8765
CMD ["sh", "-c", "exec uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8765} --workers 1"]
