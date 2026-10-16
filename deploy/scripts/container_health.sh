#!/usr/bin/env bash
# 示例只读脚本：一眼看懂容器健康状况。
# 脚本型工具的意义——把"多条只读命令 + 一点判断"固化成一个工具，
# 而不是让模型自己拼命令。脚本内容只能由宿主机管理员放入，页面只能引用它。
#
# 放置位置：与 ops_tools.yaml 同级的 scripts/ 目录；需要 chmod +x。
# 这里只用只读命令，不接收任何参数。
set -euo pipefail

echo "== 容器健康概览 =="
printf '%-22s %-10s %-8s %s\n' 名称 状态 重启次数 镜像
docker ps -a --format '{{.Names}}' | while read -r name; do
  status=$(docker inspect -f '{{.State.Status}}' "$name" 2>/dev/null || echo '?')
  restarts=$(docker inspect -f '{{.RestartCount}}' "$name" 2>/dev/null || echo '?')
  image=$(docker inspect -f '{{.Config.Image}}' "$name" 2>/dev/null || echo '?')
  printf '%-22s %-10s %-8s %s\n' "$name" "$status" "$restarts" "$image"
done

echo
echo "== 重启次数偏高的（>3）=="
hit=0
docker ps -a --format '{{.Names}}' | while read -r name; do
  restarts=$(docker inspect -f '{{.RestartCount}}' "$name" 2>/dev/null || echo 0)
  if [ "${restarts:-0}" -gt 3 ] 2>/dev/null; then
    echo "  $name 重启了 $restarts 次，建议查看日志"
    hit=1
  fi
done
echo "  （以上为空则说明没有偏高的）"
