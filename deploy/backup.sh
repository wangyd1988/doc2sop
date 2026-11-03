#!/bin/bash
# 每日备份：把向量库、会话、SOP、组织运行图谱、Agent 记忆、对外接入的令牌与审计和上传原件打成一个包，保留最近 N 天。
#
# 用法：  bash backup.sh                 # 备份到 /opt/kb-app/backups
#        bash backup.sh /mnt/nas/kb     # 指定目录
#        KB_DATA=/srv/kb/data bash backup.sh /srv/kb/backups   # 数据目录不在默认位置
#        BACKUP_KEEP=14 bash backup.sh  # 保留天数（默认 7）
#
# 安装为每日 03:30 的 cron（代码 clone 在 /opt/doc2sop 时；见 docs/正式部署.md）：
#   echo '30 3 * * * root KB_DATA=/opt/kb-app/data bash /opt/doc2sop/deploy/backup.sh /opt/kb-app/backups >> /var/log/kb-backup.log 2>&1' > /etc/cron.d/kb-backup
#
# 恢复：停容器 -> 把包解到 /opt/kb-app/data -> 起容器。SQLite 用 .backup 在线复制，
# 不会拷到写了一半的页；Chroma 目录直接复制，备份期间若恰好在入库可能不一致，所以 cron 放在凌晨。
set -euo pipefail

DATA=${KB_DATA:-/opt/kb-app/data}
DEST=${1:-/opt/kb-app/backups}
KEEP=${BACKUP_KEEP:-7}
STAMP=$(date +%Y%m%d-%H%M%S)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

mkdir -p "$DEST" "$WORK/data"

# SQLite：在线一致性复制（优先 sqlite3 命令，没有就用 python3 自带的 sqlite3 模块）
sqlite_copy() {
  if command -v sqlite3 >/dev/null; then
    sqlite3 "$1" ".backup '$2'"
  else
    python3 - "$1" "$2" <<'PY'
import sqlite3, sys
src, dst = sqlite3.connect(sys.argv[1]), sqlite3.connect(sys.argv[2])
src.backup(dst); dst.close(); src.close()
PY
  fi
}
for db in chat.db playbooks.db graph.db agent_memory.db access.db; do
  [ -f "$DATA/$db" ] && sqlite_copy "$DATA/$db" "$WORK/data/$db"
done
# 其余目录与文件直接复制。chat.yaml 是云上协同里谁能用、能查什么（没有密钥）；automation.page.json 是页面上填的自动执行设置
# （发件服务器、收件组、来源地址，不含密钥）。授权码、告警令牌在 automation.page-secrets.json 和手写的 automation.yaml 里，
# 这两个不进备份包：恢复以后在页面上重输授权码、重新生成告警令牌（automation.yaml 自己另存一份）
for item in chroma files vision_cache.json chat.yaml automation.page.json; do
  [ -e "$DATA/$item" ] && cp -a "$DATA/$item" "$WORK/data/"
done
# 工具配置也带上（宿主机侧，不在 data 里）：主文件、页面改的开关、脚本信任表、批准过的 MCP 工具、待审申请、
# 远程主机登记的 host key，页面上加的连接 / MCP server / 对外开放 / 主机和它们的 host key、配置变更记录。
# 私钥和页面上输入的凭据（/etc/ops-readonly 下的 page-secrets.json、page-hosts/）不在这里，也不该进备份包；
# 安装包（page-bundles/）随时能在页面上重新生成，也不带
for f in /opt/ops/ops_tools.yaml /opt/ops/ops_tools.overrides.yaml /opt/ops/ops_tools.trust.yaml \
         /opt/ops/ops_tools.mcp.yaml /opt/ops/ops_tools.pending.yaml /opt/ops/ops_tools.known_hosts \
         /opt/ops/ops_tools.page.yaml /opt/ops/ops_tools.page.known_hosts /opt/ops/ops_tools.page.log; do
  [ -f "$f" ] && { mkdir -p "$WORK/ops"; cp -a "$f" "$WORK/ops/"; }
done
# 群聊转接程序的推送目标（名字 → 群 ID / 用户 ID，没有密钥）；凭据在 /etc/doc2sop-ccwork.env、/etc/doc2sop-dingtalk.env，不带
f=/etc/doc2sop-ccwork/targets.yaml
[ -f "$f" ] && { mkdir -p "$WORK/ccwork"; cp -a "$f" "$WORK/ccwork/"; }
f=/etc/doc2sop-dingtalk/targets.yaml
[ -f "$f" ] && { mkdir -p "$WORK/dingtalk"; cp -a "$f" "$WORK/dingtalk/"; }

OUT="$DEST/kb-$STAMP.tgz"
tar -czf "$OUT" -C "$WORK" .
echo "$(date '+%F %T') 备份完成 $OUT ($(du -h "$OUT" | cut -f1))"

# 只保留最近 KEEP 份
ls -1t "$DEST"/kb-*.tgz 2>/dev/null | tail -n +$((KEEP + 1)) | xargs -r rm -f
