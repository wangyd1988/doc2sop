#!/bin/bash
# Restart a container only when its memory has crept past a threshold.
# Usage: container-guard.sh <container-name> <threshold-mb>
set -uo pipefail

NAME="${1:?需要容器名}"
LIMIT_MB="${2:?需要阈值(MB)}"

to_mb() {
    local value="$1" number unit
    number="${value%%[A-Za-z]*}"
    unit="${value##*[0-9.]}"
    case "$unit" in
        GiB|GB) awk -v n="$number" 'BEGIN{printf "%.0f", n*1024}' ;;
        MiB|MB) awk -v n="$number" 'BEGIN{printf "%.0f", n}' ;;
        KiB|kB) awk -v n="$number" 'BEGIN{printf "%.0f", n/1024}' ;;
        B)      awk -v n="$number" 'BEGIN{printf "%.0f", n/1048576}' ;;
        *)      echo "" ;;
    esac
}

used_mb() {
    local raw
    raw=$(docker stats --no-stream --format '{{.MemUsage}}' "$NAME" 2>/dev/null | awk '{print $1}')
    [ -n "$raw" ] && to_mb "$raw"
}

if ! docker ps --format '{{.Names}}' | grep -qx "$NAME"; then
    echo "$NAME 未在运行，跳过"
    exit 0
fi

before=$(used_mb)
if [ -z "$before" ]; then
    echo "$NAME 读取内存用量失败，跳过"
    exit 0
fi

if [ "$before" -lt "$LIMIT_MB" ]; then
    echo "$NAME 当前 ${before}MB，低于阈值 ${LIMIT_MB}MB，无需处理"
    exit 0
fi

echo "$NAME 当前 ${before}MB，已达阈值 ${LIMIT_MB}MB，开始重启"
if ! docker restart "$NAME" >/dev/null; then
    echo "$NAME 重启失败"
    exit 1
fi

for _ in $(seq 1 30); do
    docker ps --format '{{.Names}}' | grep -qx "$NAME" && break
    sleep 2
done
if ! docker ps --format '{{.Names}}' | grep -qx "$NAME"; then
    echo "$NAME 重启后未能恢复运行，请检查"
    exit 1
fi

sleep 25
after=$(used_mb)
echo "$NAME 重启完成：${before}MB -> ${after:-未知}MB"
