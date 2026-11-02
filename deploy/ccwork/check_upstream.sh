#!/bin/bash
# 官方开发包（没有许可证）有新提交就提醒。转接程序没有拷它的代码，是按它的接口行为自己实现的：
# 上游一改，就要对照着看换令牌、机器人信息、MQTT 账号、消息字段、加解密规则有没有变，我们要不要跟着改。
# 加密程序换了新版时，按 crypto_vectors.py 的说明重新生成对照数据（要先问协调会话）。
#
# 用法：bash deploy/ccwork/check_upstream.sh      # 没变退出 0；有新提交退出 1；连不上退出 2
set -euo pipefail

URL=https://github.com/ccwork-sdk/ccwork-chat-sdk-go
PINNED=2cf4953c65513588c942d557070356d2834e4b31     # 2026-07-31「Initial commit」，即 v1.0.0

head=$(git ls-remote "$URL" refs/heads/master 2>/dev/null | cut -f1) || true
if [ -z "$head" ]; then
  echo "连不上 $URL" >&2
  exit 2
fi
if [ "$head" = "$PINNED" ]; then
  echo "官方开发包没有新提交（master 仍是 ${PINNED:0:7}）"
  exit 0
fi
echo "官方开发包有新提交：master 是 ${head:0:7}，我们核对到的是 ${PINNED:0:7}"
echo "看改了什么：$URL/compare/${PINNED:0:7}...${head:0:7}"
exit 1
