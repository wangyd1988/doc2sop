# 演示集群

一台 2C2G 机器上的单节点 k3s，用来验证「真实文档 → 抽成 SOP → 对着真集群跑」这条链路。
组件名、命名空间完全按知识库里的两份真实文档布置，Agent 跑出来的结果能和文档一句句对上。

| 清单 | 对应文档 | 埋好的故障 |
|---|---|---|
| `gateway.yaml` | 《阿里云专有云 API 网关运维指南》：`csb-cop` / `higress-system` / `apigateway-system` 三个命名空间，cop-console、higress-gateway、WasmPlugin CRD 等 | `higress-plugin-server` 启动 45s 后退出（CrashLoopBackOff）；`rrsa-info-server` 镜像仓库域名不存在（ImagePullBackOff） |
| `ingress-nginx.yaml` | 《Kube-OVN + ingress-nginx 访问超时排查总结》：ingress-nginx + 业务命名空间 `biz` | `order-web` 的 Service selector 写成 `app=order-web-v2`，Endpoints 为空 → 503；`user-api` 是正常对照 |

所有工作负载都是 `busybox` 打日志，加起来不到 100MB 内存。

## 搭建

```bash
# 国内网络下 get.k3s.io 和 rancher 镜像站都可能超时；可在能出网的机器下好 k3s 二进制、
# install.sh、k3s-airgap-images-amd64.tar.zst 再拷过来，用 INSTALL_K3S_SKIP_DOWNLOAD=true 离线装。
install -m 755 k3s /usr/local/bin/k3s
mkdir -p /var/lib/rancher/k3s/agent/images/ && mv k3s-airgap-images-amd64.tar.zst "$_"
INSTALL_K3S_SKIP_DOWNLOAD=true INSTALL_K3S_EXEC="server --disable traefik --disable servicelb \
  --disable metrics-server --disable local-storage --disable-cloud-controller \
  --disable-network-policy --write-kubeconfig-mode 644" sh install.sh

kubectl apply -f gateway.yaml      # 首次会提示 WasmPlugin 找不到：CRD 刚建，再 apply 一次即可
kubectl apply -f gateway.yaml
kubectl apply -f ingress-nginx.yaml
```

精简后 k3s 本体约 500MB，加上演示负载整机占用约 1.4GB。

## 接到工具服务

工具服务所在机器装 `kubectl`，拿到 `/etc/rancher/k3s/k3s.yaml`，把 `server:` 改成可达地址
（安全组不放 6443 时可以走 SSH 隧道：`-L 127.0.0.1:16443:127.0.0.1:6443`，对端用
`restrict,port-forwarding,permitopen="127.0.0.1:6443"` 限制那把密钥只能转发这一个端口）。
然后在 `/etc/ops-readonly.env` 加 `KUBECONFIG=/etc/ops-readonly/kubeconfig`，重启服务，
K8s 分组的 5 个工具就从「不可用」变为可用。

## 演示问法

- 「按运维指南巡检一下 API 网关的各组件 Pod」→ 按 SOP 查三个命名空间，发现两个非终态 Pod，追 describe 给出原因
- 「biz 命名空间的 order.biz.example.com 通过 Ingress 访问超时，帮我查一下」→ Ingress → EndpointSlice → 日志 → Service，定位到 selector 不匹配
