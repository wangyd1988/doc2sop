# 计算沙箱（python_exec）的镜像：Python 标准库，加一个锁定版本和哈希的 PyYAML（kubectl -o yaml 这类返回要解析）。
# 容器怎么跑——runsc、无网络、只读、nobody、各项上限——全由沙箱服务（sandbox_service.py）在 docker run 时定，
# 不靠这个镜像；这里的 USER 只是兜底。
#
# 和应用用同一个基础镜像，宿主机上已经有，不用再拉。在仓库根目录：
#   docker build --build-arg PIP_INDEX_URL=https://pypi.tuna.tsinghua.edu.cn/simple \
#     -t doc2sop-sandbox:$(git rev-parse --short HEAD) -t doc2sop-sandbox:latest deploy/sandbox
# Docker Hub 拉不动时加 --build-arg BASE_IMAGE=<国内镜像站>/library/python:3.12-slim。
ARG BASE_IMAGE=python:3.12-slim
FROM ${BASE_IMAGE}

ARG PIP_INDEX_URL=
COPY requirements.txt /tmp/sandbox-requirements.txt
# 只装 wheel、逐个核对哈希：镜像站给的文件和 PyPI 上的不一样就装不上
RUN pip install --no-cache-dir --require-hashes --only-binary=:all: ${PIP_INDEX_URL:+-i "$PIP_INDEX_URL"} \
        -r /tmp/sandbox-requirements.txt \
 && rm -f /tmp/sandbox-requirements.txt \
 && python -c "import yaml; print('PyYAML', yaml.__version__)"

USER 65534:65534
WORKDIR /tmp
