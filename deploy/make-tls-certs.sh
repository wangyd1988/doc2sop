#!/bin/bash
# 没有域名时给应用上 HTTPS：先生成一个私有 CA，再用它签一张带 IP 的服务器证书。客户端只导入 CA 证书（ca.crt），
# 不要让客户端「跳过证书校验」——那样谁都能冒充服务器，拿走网页密码和令牌。详见 docs/正式部署.md「HTTPS 与对外放开」。
#
# 用法  bash deploy/make-tls-certs.sh --ca-dir /root/doc2sop-ca --out /opt/kb-app/tls --ip 117.72.91.19
#       … --ip 10.0.0.5 --dns kb.internal      # 可以给多个 IP、多个名字
#       … --days 825                           # 服务器证书的有效天数（默认 825，苹果设备不认更长的）
#
# 第一次：在 --ca-dir 生成 ca.key（600）和 ca.crt（10 年），再签服务器证书，写到 --out 的 server.key（600）和 server.crt。
# 以后再跑（续期、换证书）：CA 已经有了就不动它，只重签服务器证书，客户端不用重新导入。换完要重启应用。
#
# CA 带名字约束（nameConstraints）：它只能给 --ip、--dns 给的地址和名字、再加 127.0.0.1、::1、localhost 签证书。
# 导入了这个 CA 的电脑，万一 CA 私钥泄露，也只会被拿来冒充这几个地址，冒充不了别的网站。要加新的 IP 或名字就得换一个 CA
# （把 --ca-dir 换成新目录，客户端重新导入）。
#
# 服务器证书的名字总是带上 127.0.0.1、::1、localhost：经 SSH 隧道打开 https://127.0.0.1:端口 也不报错。
# --out 就是 release.sh 的 TLS_DIR（只读挂进容器的 /tls）。CA 私钥不要放进 --out，也不要进备份：脚本拒绝两个目录相同或嵌套。
set -euo pipefail
export MSYS2_ARG_CONV_EXCL="/O=;/CN="   # Git Bash：别把 -subj 的 /O=…/CN=… 当成路径改写（文件路径照常改写）

usage() { sed -n '2,/^set -euo/p' "${BASH_SOURCE[0]}" | sed '$d' | sed 's/^# \{0,1\}//'; }
die() { echo "!! $*" >&2; exit 2; }

CA_DIR="" OUT="" DAYS=825 IPS=() NAMES=()
while [ $# -gt 0 ]; do
  case "$1" in
    --ca-dir) [ $# -ge 2 ] || die "--ca-dir 后面要跟目录"; CA_DIR=$2; shift 2 ;;
    --out) [ $# -ge 2 ] || die "--out 后面要跟目录"; OUT=$2; shift 2 ;;
    --ip) [ $# -ge 2 ] || die "--ip 后面要跟 IP 地址"; IPS+=("$2"); shift 2 ;;
    --dns) [ $# -ge 2 ] || die "--dns 后面要跟名字"; NAMES+=("$2"); shift 2 ;;
    --days) [ $# -ge 2 ] || die "--days 后面要跟天数"; DAYS=$2; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; die "未知参数：$1" ;;
  esac
done
[ -n "$CA_DIR" ] && [ -n "$OUT" ] || { usage >&2; die "要给 --ca-dir 和 --out"; }
[ ${#IPS[@]} -gt 0 ] || [ ${#NAMES[@]} -gt 0 ] || die "至少给一个 --ip（服务器对外的 IP）或 --dns"
[[ "$DAYS" =~ ^[0-9]+$ ]] && [ "$DAYS" -ge 1 ] && [ "$DAYS" -le 825 ] || die "--days 要在 1 到 825 之间"
command -v openssl >/dev/null 2>&1 || die "缺少 openssl"
PYTHON=python3
"$PYTHON" -c pass >/dev/null 2>&1 || PYTHON=python
"$PYTHON" -c pass >/dev/null 2>&1 || die "缺少 python3（用来核对 IP 写法）"

# IP 规范化（也挡住写错的）；名字只允许主机名的字符
canon_ip() { "$PYTHON" -c 'import ipaddress, sys
a = ipaddress.ip_address(sys.argv[1])
if a.is_unspecified or a.is_multicast: raise SystemExit(1)
sys.stdout.write(a.compressed)' "$1" 2>/dev/null; }
mask_of() { "$PYTHON" -c 'import ipaddress, sys
a = ipaddress.ip_address(sys.argv[1])
sys.stdout.write(a.compressed + "/" + ipaddress.ip_network(a).netmask.compressed)' "$1"; }
ALL_IPS=() ALL_NAMES=(localhost)
for raw in ${IPS[@]+"${IPS[@]}"} 127.0.0.1 ::1; do
  ip=$(canon_ip "$raw") || die "不是可用的 IP 地址：$raw"
  [[ " ${ALL_IPS[*]-} " == *" $ip "* ]] || ALL_IPS+=("$ip")
done
for name in ${NAMES[@]+"${NAMES[@]}"}; do
  name=$(printf '%s' "$name" | tr 'A-Z' 'a-z')
  [[ "$name" =~ ^[a-z0-9]([a-z0-9-]{0,62})(\.[a-z0-9]([a-z0-9-]{0,62}))*$ ]] || die "名字只能是主机名（字母、数字、- 和 .）：$name"
  [[ " ${ALL_NAMES[*]} " == *" $name "* ]] || ALL_NAMES+=("$name")
done

real() { mkdir -p "$1" && (cd "$1" && pwd -P); }
umask 077
CA_DIR=$(real "$CA_DIR") OUT=$(real "$OUT")
case "$CA_DIR/" in "$OUT/"*) die "--ca-dir 不能是 --out 或在它里面：--out 会挂进容器，CA 私钥不能跟着进去" ;; esac
case "$OUT/" in "$CA_DIR/"*) die "--out 不能在 --ca-dir 里面：两个目录分开放" ;; esac
chmod 700 "$CA_DIR"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

san="" constraints=""
for ip in "${ALL_IPS[@]}"; do
  san="$san,IP:$ip"
  constraints="$constraints,permitted;IP:$(mask_of "$ip")"
done
for name in "${ALL_NAMES[@]}"; do
  san="$san,DNS:$name"
  constraints="$constraints,permitted;DNS:$name"
done
san=${san#,} constraints=${constraints#,}

cat >"$WORK/openssl.cnf" <<EOF
[req]
distinguished_name = dn
prompt = no
[dn]
CN = unused
[ca]
basicConstraints = critical,CA:TRUE,pathlen:0
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
nameConstraints = critical,$constraints
[server]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = serverAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
subjectAltName = $san
EOF

if [ -f "$CA_DIR/ca.key" ] && [ -f "$CA_DIR/ca.crt" ]; then
  echo "== 用已有的 CA：$CA_DIR/ca.crt（不改它，客户端不用重新导入）"
else
  [ ! -e "$CA_DIR/ca.key" ] && [ ! -e "$CA_DIR/ca.crt" ] || die "$CA_DIR 里只有 ca.key、ca.crt 中的一个：核对后删掉残留的再跑"
  echo "== 生成私有 CA（10 年，只能给这些名字签：${ALL_IPS[*]} ${ALL_NAMES[*]}）"
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$WORK/ca.key" 2>/dev/null
  openssl req -x509 -new -key "$WORK/ca.key" -sha256 -days 3650 -config "$WORK/openssl.cnf" -extensions ca \
    -subj "/O=doc2sop/CN=doc2sop private CA $(date +%Y%m%d)" -out "$WORK/ca.crt"
  install -m 600 "$WORK/ca.key" "$CA_DIR/ca.key"
  install -m 644 "$WORK/ca.crt" "$CA_DIR/ca.crt"
fi

echo "== 签服务器证书（$DAYS 天）：${ALL_IPS[*]} ${ALL_NAMES[*]}"
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$WORK/server.key" 2>/dev/null
openssl req -new -key "$WORK/server.key" -config "$WORK/openssl.cnf" -subj "/O=doc2sop/CN=doc2sop server" \
  -out "$WORK/server.csr"
openssl x509 -req -in "$WORK/server.csr" -CA "$CA_DIR/ca.crt" -CAkey "$CA_DIR/ca.key" -sha256 -days "$DAYS" \
  -set_serial "0x$(openssl rand -hex 15)" -extfile "$WORK/openssl.cnf" -extensions server -out "$WORK/server.crt" 2>/dev/null
# 名字超出已有 CA 的约束时，这一步就过不了（OpenSSL 会检查 nameConstraints）
openssl verify -CAfile "$CA_DIR/ca.crt" -purpose sslserver "$WORK/server.crt" >/dev/null 2>"$WORK/verify.err" || {
  cat "$WORK/verify.err" >&2
  die "新证书过不了 CA 的校验：多半是这次给的 IP 或名字不在已有 CA 的名字约束里。要加名字就换一个 CA（--ca-dir 用新目录），客户端重新导入"
}
chmod 700 "$OUT"
install -m 600 "$WORK/server.key" "$OUT/server.key.new"
install -m 644 "$WORK/server.crt" "$OUT/server.crt.new"
mv -f "$OUT/server.key.new" "$OUT/server.key"
mv -f "$OUT/server.crt.new" "$OUT/server.crt"

FINGERPRINT=$(openssl x509 -in "$CA_DIR/ca.crt" -noout -fingerprint -sha256 | sed 's/^.*=//')
cat <<EOF

== 完成
  服务器证书  $OUT/server.crt（到 $(openssl x509 -in "$OUT/server.crt" -noout -enddate | sed 's/^notAfter=//')）
  服务器私钥  $OUT/server.key（600）
  CA 证书     $CA_DIR/ca.crt   ← 发给要连的人，只发这一个文件
  CA 私钥     $CA_DIR/ca.key   ← 留在这里：不要放进 TLS_DIR、不要进备份、不要发给任何人
  CA 指纹     SHA256 $FINGERPRINT（对方导入前核对这一串）

下一步（正式部署，见 docs/正式部署.md「HTTPS 与对外放开」）：
  1. 环境文件里加（先备份）：TLS_CERT_FILE=/tls/server.crt、TLS_KEY_FILE=/tls/server.key
  2. 发版时带上 TLS_DIR=$OUT，例如：
     TLS_DIR=$OUT KEEP_IMAGES=24 ENV_FILE=… DATA_DIR=… bash deploy/release.sh
  3. 客户端导入 ca.crt，打开 https://${ALL_IPS[0]}:端口；不要点「继续访问（不安全）」，也不要关掉证书校验。
  续期：再跑一次同样的命令（CA 不变），然后重启应用（docker restart kb-app）。
EOF
