#!/bin/sh
# 演示主机（kb-host）的入口：
#   1. 生成（或沿用卷里的）自己的 host key，把 host 公钥放进交换目录，sidecar 拿它登记 known_hosts；
#   2. 等 sidecar 把它的客户端公钥放进交换目录，写成带 restrict + 强制命令的 authorized_keys（归 root）；
#   3. 前台起 sshd。
# 交换目录（compose 卷）里只有两份公钥，私钥都不出各自的容器。
set -eu
KEYS=/etc/ssh/keys
EXCHANGE=${OPS_EXCHANGE_DIR:-/exchange}
WAIT=${HOST_WAIT:-120}

install -d -o root -g root -m 0755 "$KEYS" /run/sshd
[ -s "$KEYS/ssh_host_ed25519_key" ] || ssh-keygen -q -t ed25519 -N '' -C demo-host -f "$KEYS/ssh_host_ed25519_key"
cp "$KEYS/ssh_host_ed25519_key.pub" "$EXCHANGE/host_ed25519.pub.tmp"
chmod 0644 "$EXCHANGE/host_ed25519.pub.tmp"
mv -f "$EXCHANGE/host_ed25519.pub.tmp" "$EXCHANGE/host_ed25519.pub"

waited=0
while [ ! -s "$EXCHANGE/client.pub" ]; do
  waited=$((waited + 1))
  if [ "$waited" -gt "$WAIT" ]; then
    echo "[demo-host] ${WAIT}s 内等不到 sidecar 的公钥 $EXCHANGE/client.pub" >&2
    exit 1
  fi
  sleep 1
done
set -- $(head -n 1 "$EXCHANGE/client.pub")
if [ "${1:-}" != "ssh-ed25519" ] || [ -z "${2:-}" ]; then
  echo "[demo-host] $EXCHANGE/client.pub 不是一行 ed25519 公钥" >&2
  exit 1
fi
printf 'restrict,command="/usr/local/bin/python3 /opt/ops-readonly/ops_exec.py --stdio" %s %s doc2sop-demo\n' "$1" "$2" \
  > /etc/ssh/authorized_keys/opsread
chmod 0644 /etc/ssh/authorized_keys/opsread
python3 /opt/ops-readonly/ops_exec.py --check /opt/ops-readonly/allowlist.json
echo "[demo-host] sshd 启动：只认 opsread 的这一把公钥，只能启动执行器"
exec /usr/sbin/sshd -D -e -f /etc/ssh/sshd_demo.conf
