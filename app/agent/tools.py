"""Tool schemas exposed to the model.

Only tools whose backing command exists on the ops host are advertised, so the
model never tries to call something that cannot run.
"""
from langchain_core.tools import StructuredTool
from pydantic import BaseModel, Field

from app.agent import ops_client
from app.config import log


class Empty(BaseModel):
    pass


class ContainerName(BaseModel):
    name: str = Field(description="容器名，例如 kb-app")


class ContainerLogs(BaseModel):
    name: str = Field(description="容器名")
    lines: int = Field(default=100, description="查看最近多少行，默认 100，最多 500")


class KubeGet(BaseModel):
    resource: str = Field(description="资源类型，例如 pod、svc、subnet、ingress")
    name: str = Field(default="", description="资源名；留空则列出该类型全部资源")
    namespace: str = Field(default="default", description="命名空间")


class KubeNamed(BaseModel):
    resource: str = Field(description="资源类型，例如 pod、subnet")
    name: str = Field(description="资源名")
    namespace: str = Field(default="default", description="命名空间")


class KubeLogs(BaseModel):
    name: str = Field(description="Pod 名")
    namespace: str = Field(default="default", description="命名空间")
    lines: int = Field(default=100, description="查看最近多少行")


class KubeEvents(BaseModel):
    namespace: str = Field(default="default", description="命名空间")


# tool name -> (给模型看的说明, 参数模型)
SCHEMAS = {
    "list_containers": ("列出宿主机上所有容器及其运行状态。想知道某个服务是否在跑、"
                        "是否反复重启时先用它。", Empty),
    "container_logs": ("查看指定容器最近的日志，用于定位报错原因。", ContainerLogs),
    "container_stats": ("查看所有容器当前的 CPU 与内存占用，用于判断是否资源不足。", Empty),
    "container_inspect": ("查看容器的配置：镜像、内存上限、网络模式、挂载、重启次数。"
                          "怀疑配置问题时用它。", ContainerName),
    "host_resources": ("查看宿主机剩余内存与 swap 使用情况。", Empty),
    "kube_get": ("查询 Kubernetes 资源。不传 name 时列出该类型全部资源；"
                 "传 name 时返回该资源完整 YAML，用于核对具体字段配置。", KubeGet),
    "kube_describe": ("查看某个 Kubernetes 资源的详情与相关事件。", KubeNamed),
    "kube_logs": ("查看 Pod 日志。", KubeLogs),
    "kube_events": ("按时间顺序查看命名空间下的最近事件，用于发现调度或探针失败。",
                    KubeEvents),
}


def _make(name: str, description: str, schema):
    def call(**kwargs):
        result = ops_client.execute(name, kwargs)
        output = result.get("output", "")
        if not result.get("ok"):
            return f"[执行失败] {result.get('error') or output or '未知错误'}"
        return output or "（命令执行成功，但没有输出）"

    return StructuredTool.from_function(
        func=call, name=name, description=description, args_schema=schema)


def build_tools():
    """Build the tool list from whatever the ops host currently supports."""
    available = ops_client.available_tools()
    if not available:
        return []
    tools = [_make(name, meta[0], meta[1])
             for name, meta in SCHEMAS.items() if name in available]
    log.info("ops tools enabled: %s", ", ".join(t.name for t in tools) or "none")
    return tools
