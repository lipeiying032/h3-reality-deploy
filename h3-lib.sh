#!/usr/bin/env bash
# =============================================================================
# h3-lib.sh — H3 REALITY SNI 部署/管理公共函数库
#
# 被 deploy-h3-sni.sh 与 h3reality 共同 source：同一份逻辑、两个入口，
# 保证 SNI 校验、H3 探测、配置修改、VLESS 链接生成等核心行为完全一致。
#
# 依赖：bash 4+（mapfile）；curl 或 wget；openssl（自签证书/shortId/UUID 兜底）；
#      tar/sha256sum（H3 版 curl 校验安装）；root 或 sudo。
#      不依赖 python3/jq/dig（JSON 编辑优先 jq，无 jq 用 sed/awk 兜底）。
# 调用方必须启用 set -euo pipefail；本库函数均兼容 set -e。
#
# 函数分组：
#   A. 输出函数       red/green/yellow/banner/die
#   B. 配置常量       路径/服务名/SNI 库/内核 URL/默认端口
#   C. 工具函数       urlencode/valid_domain/resolve_ip/port_in_use/
#                     pick_random_port/get_server_ip/require_root
#   D. SNI 库与探测   fetch_sni_list/random_sni/probe_h3/validate_sni_h3/
#                     curl_supports_h3/curl_supports_http3_only/
#                     curl_bin_supports_http3_only/ensure_curl_h3/install_curl_h3
#   E. 探针获取       ensure_probe/build_probe_from_source/download_probe_release
#   F. 内核获取       detect_xray/download_xray/build_xray_from_source
#   G. 配置操作       detect_config_path/find_h3_inbound/backup_config/
#                     update_sni_routes（切换 SNI：dest+serverNames+fallbackDest，
#                     清除路由表）/add_sni_route/remove_sni_route（手动高级配置，
#                     fallbackDestRoutes 路由表，默认部署不再使用）/
#                     run_test/restart_service/start_service/stop_service/
#                     service_is_active/rollback/extract_client_params/gen_keys
#   H. VLESS 链接     gen_vless_link/get_current_sni/get_h3_port
# =============================================================================

# ---------------- A. 输出函数（红=错误/拒绝，绿=成功，黄=警告） ----------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

red()    { printf "${RED}%s${NC}\n" "$*"; }
green()  { printf "${GREEN}%s${NC}\n" "$*"; }
yellow() { printf "${YELLOW}%s${NC}\n" "$*"; }

# 彩色横幅：banner <颜色函数名> <标题>，如 banner green "部署完成"
banner() {
  local color="$1"
  shift
  "$color" "=========== $* ==========="
}

die() { red "错误: $*"; exit 1; }

# ---------------- B. 配置常量 ----------------
# 内核/配置路径支持环境变量覆盖（测试沙箱与特殊场景），默认与历史行为一致：
#   XRAY_CONFIG=/path/to/server.json  覆盖配置路径（默认 /opt/xray/server.json，
#                                      本项目只认该路径，绝不扫描官方 xray 配置）
#   XRAY_BIN=/path/to/xray            跳过内核检测，直接使用
#   UNIT_FILE=/path/to/xray-h3.service 覆盖 systemd 单元文件路径
SERVICE="${SERVICE:-xray-h3}"
UNIT_FILE="${UNIT_FILE:-/etc/systemd/system/xray-h3.service}"
SNI_LIST_URL="https://raw.githubusercontent.com/lipeiying032/h3-reality-sni/main/snis.json"
SNI_LIST_CACHE="/tmp/h3-sni-cache.json"
KERNEL_URL="https://github.com/lipeiying032/h3-reality-deploy/releases/latest/download/xray-h3-server-linux-amd64"
KERNEL_SRC_URL="https://github.com/lipeiying032/h3-reality-deploy.git"
PROBE_RELEASE_URL="https://github.com/lipeiying032/h3-reality-deploy/releases/latest/download/probe-h3-sni-linux-amd64"
PROBE_TIMEOUT=12s
MAX_ATTEMPTS=5

# 默认端口 443（TCP 与 UDP 可共存）；非标准端口可用环境变量覆盖，例如：
#   H2_PORT=8443 H3_PORT=8446 ./deploy-h3-sni.sh
H2_PORT="${H2_PORT:-443}"
H3_PORT="${H3_PORT:-443}"

# 本库所在目录：探针二进制/源码/管理命令均以它为基准
LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROBE="$LIB_DIR/probe-h3-sni"
PROBE_SRC="$LIB_DIR/probe-h3-sni.go"
PROBE_MOD_DIR="$LIB_DIR/probe-mod"

# 全局状态变量（两个入口共享）
XRAY_BIN="${XRAY_BIN:-}"
CONFIG_PATH="${XRAY_CONFIG:-/opt/xray/server.json}"
DEGRADED=0        # 1=官方内核 H2 降级模式
CONFIG_GENERATED=0 # 1=本次新生成的配置（回滚时整体移除）
sni=""
probe_out=""
# H3 版 curl：系统 curl 支持 H3 时=系统 curl 路径，否则=$CURL_H3_BIN；
# 两者皆不可用时为空（validate_sni_h3 回退内置探针），由 ensure_curl_h3 填充。
CURL_H3_BIN="${CURL_H3_BIN:-/usr/local/bin/curl-http3}"
CURL_H3=""
TS=""
BACKUP=""
UUID=""
PRIVATE_KEY=""
PUBLIC_KEY=""
SHORT_ID=""
SNI_LIST=()

# ---------------- C. 工具函数 ----------------

# URL 编码：仅编码非 unreserved 字符（RFC 3986），用于 vless:// 链接的参数值
urlencode() {
  local s="$1" c="" out=""
  while [ -n "$s" ]; do
    c="${s%"${s#?}"}"
    case "$c" in
      [a-zA-Z0-9._~-]) out+="$c" ;;
      *) printf -v c '%%%02X' "'$c"; out+="$c" ;;
    esac
    s="${s#?}"
  done
  printf '%s' "$out"
}

# 域名格式校验（简单正则：至少两段，字母/数字/连字符）
valid_domain() {
  echo "$1" | grep -qE '^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)+$'
}

# DNS 解析：getent → dig → host → nslookup，返回第一个 IPv4 或失败
resolve_ip() {
  local host="$1" ip=""
  if command -v getent >/dev/null 2>&1; then
    ip=$(getent ahostsv4 "$host" 2>/dev/null | awk 'NR==1{print $1}' || true)
    [ -z "$ip" ] && ip=$(getent ahosts "$host" 2>/dev/null | awk 'NR==1{print $1}' || true)
  fi
  if [ -z "$ip" ] && command -v dig >/dev/null 2>&1; then
    ip=$(dig +short A "$host" 2>/dev/null | grep -E '^[0-9.]+$' | head -n1 || true)
  fi
  if [ -z "$ip" ] && command -v host >/dev/null 2>&1; then
    ip=$(host -t A "$host" 2>/dev/null | awk '/has address/{print $NF; exit}' || true)
  fi
  if [ -z "$ip" ] && command -v nslookup >/dev/null 2>&1; then
    ip=$(nslookup "$host" 2>/dev/null | awk '/^Name:/{found=1; next} found && /^Address/{print $NF; exit}' \
           | grep -E '^[0-9.]+$' | head -n1 || true)
  fi
  [ -n "$ip" ] && { echo "$ip"; return 0; }
  return 1
}

# 判断指定协议的端口是否已被监听：0=未占用，1=占用
port_in_use() {
  local proto="$1" port="$2" out
  case "$proto" in
    udp) out=$(ss -ulnp 2>/dev/null | grep ":${port} " || true) ;;
    tcp) out=$(ss -tlnp 2>/dev/null | grep ":${port} " || true) ;;
  esac
  [ -n "$out" ]
}

# 判断 ss 输出行中占用端口的进程是否为本项目内核进程（$XRAY_BIN）：
# 只有本项目自己的内核占端口不算冲突（xray-h3 服务正在运行）；
# 官方 xray（/usr/local/bin/xray 等）或其他进程一律视为冲突
is_own_kernel_process() {
  local line="$1" pid exe
  [ -n "$XRAY_BIN" ] || return 1
  pid=$(printf '%s\n' "$line" | sed -n 's/.*pid=\([0-9][0-9]*\).*/\1/p' | head -n1)
  [ -n "$pid" ] || return 1
  exe=$(readlink "/proc/$pid/exe" 2>/dev/null | sed 's/ (deleted)$//')
  [ -n "$exe" ] && [ "$exe" = "$XRAY_BIN" ]
}

# 随机选一个未被占用的端口（udp/tcp，1024-65535），最多尝试 20 次；
# 成功输出端口并返回 0，失败返回 1
pick_random_port() {
  local proto="$1" port attempts=0
  while [ "$attempts" -lt 20 ]; do
    attempts=$((attempts + 1))
    port=$(( (RANDOM % 64512) + 1024 ))
    if ! port_in_use "$proto" "$port"; then
      echo "$port"
      return 0
    fi
  done
  return 1
}

# 公网 IP 检测（hostname -I → ip route → 手动输入）
get_server_ip() {
  local ip=""
  if command -v hostname >/dev/null 2>&1; then
    ip=$(hostname -I 2>/dev/null | awk '{print $1}' || true)
  fi
  if [ -z "$ip" ] && command -v ip >/dev/null 2>&1; then
    ip=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '/src/{print $7; exit}' || true)
  fi
  if [ -z "$ip" ]; then
    printf "无法自动检测公网 IP，请手动输入: "
    read -r ip || { echo; die "读取输入失败"; }
  fi
  echo "$ip"
}

# 非 root → sudo 重执行（两个入口一致）
require_root() {
  if [ "$(id -u)" -ne 0 ]; then
    if command -v sudo >/dev/null 2>&1; then
      yellow "当前用户非 root，使用 sudo 重新执行..."
      exec sudo bash "$0" "$@"
    else
      die "需要 root 权限（且未找到 sudo），请用 root 运行本脚本"
    fi
  fi
}

# ---------------- D. SNI 库与 H3 探测 ----------------

# 拉取 SNI 维护库（snis.json）并解析出 sni 数组；
# 失败（网络/解析）给黄色警告并返回空；本地缓存兜底
fetch_sni_list() {
  local data="" json=""
  SNI_LIST=()
  if command -v curl >/dev/null 2>&1; then
    data=$(curl -fsSL --connect-timeout 10 --max-time 20 "$SNI_LIST_URL" 2>/dev/null) || data=""
  elif command -v wget >/dev/null 2>&1; then
    data=$(wget -qO- --timeout=10 -T 20 "$SNI_LIST_URL" 2>/dev/null) || data=""
  fi
  if [ -n "$data" ]; then
    json="$data"
    printf '%s' "$json" > "$SNI_LIST_CACHE" 2>/dev/null
  elif [ -f "$SNI_LIST_CACHE" ]; then
    json=$(cat "$SNI_LIST_CACHE" 2>/dev/null || true)
    yellow "SNI 库拉取失败，使用本地缓存..."
  fi
  if [ -n "$json" ]; then
    if command -v jq >/dev/null 2>&1; then
      mapfile -t SNI_LIST < <(printf '%s' "$json" | jq -r '.snis[].sni' 2>/dev/null)
    else
      # sed/grep 兜底：snis.json 结构固定为 {"snis":[{"sni":"...",...},...]}，
      # 兼容换行展开与单行压缩两种格式
      mapfile -t SNI_LIST < <(printf '%s' "$json" \
        | sed 's/}, */}\n/g' \
        | sed -n 's/.*"sni"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
    fi
  fi
  if [ "${#SNI_LIST[@]}" -eq 0 ]; then
    yellow "警告: 无法获取 SNI 库（$SNI_LIST_URL），请手动输入 SNI"
    return 1
  fi
  green "SNI 维护库已加载（${#SNI_LIST[@]} 个候选）"
  return 0
}

# 从 SNI 维护库随机挑一个（库为空时返回 1）
random_sni() {
  [ "${#SNI_LIST[@]}" -eq 0 ] && return 1
  if command -v shuf >/dev/null 2>&1; then
    printf '%s\n' "${SNI_LIST[@]}" | shuf -n1
  else
    printf '%s\n' "${SNI_LIST[$((RANDOM % ${#SNI_LIST[@]}))]}"
  fi
}

# H3 探测统一入口（部署/管理共用同一函数）：
#   probe_h3 <sni> [addr] [timeout]
# 探测输出写入全局 probe_out，返回探针退出码（0=支持 H3）
probe_h3() {
  local sni="$1" addr="${2:-}" timeout="${3:-$PROBE_TIMEOUT}" rc=0
  probe_out=""
  if [ -n "$addr" ]; then
    probe_out=$("$PROBE" -sni "$sni" -addr "$addr" -timeout "$timeout" 2>&1) || rc=$?
  else
    probe_out=$("$PROBE" -sni "$sni" -timeout "$timeout" 2>&1) || rc=$?
  fi
  return "$rc"
}

# 检测 curl 是否带 HTTP/3 支持（Features 含 HTTP3，或 --help-all 有 --http3-only）
curl_supports_h3() {
  if command -v curl >/dev/null 2>&1; then
    curl --version 2>/dev/null | grep -qi 'HTTP3' && return 0
    curl --help-all 2>/dev/null | grep -q -- '--http3-only' && return 0
  fi
  return 1
}

# 检测 curl 是否支持 --http3-only（curl >= 8.2，严格只走 H3，禁止降级）
curl_supports_http3_only() {
  curl --help-all 2>/dev/null | grep -q -- '--http3-only'
}

# 判断指定 curl 二进制是否支持 --http3-only（curl >= 8.2，严格只走 H3，禁止降级）。
# 不依赖 --help 文本（curl 8.20+ 移除 --help-all，且无 H3 的构建也会列出该选项），
# 而是真实调用一次：选项被接受（出现网络层错误/成功）即支持；
# 选项不存在或构建不支持则报 "is unknown"/"doesn't support this"，判定不支持
curl_bin_supports_http3_only() {
  local bin="$1" out="" rc=0
  out=$("$bin" --http3-only -sS -o /dev/null --connect-timeout 1 --max-time 2 "https://127.0.0.1/" 2>&1) || rc=$?
  case "$out" in
    *"doesn't support this"*|*"is unknown"*)
      return 1
      ;;
  esac
  return 0
}

# 从 stunnel/static-curl 官方 GitHub Releases 下载静态编译、带 HTTP/3（ngtcp2）
# 的 Linux curl，校验通过后安装为系统级独立二进制 $CURL_H3_BIN（默认
# /usr/local/bin/curl-http3，chmod 755，绝不覆盖 apt 管理的 /usr/bin/curl）：
#   ① 查询官方 API（/releases/latest）拿最新 tag 与资产名
#      curl-linux-<arch>-glibc-<tag>.tar.xz（x86_64/aarch64，glibc 静态构建）
#   ② 官方 sha256 取该资产在 API 中的 digest 字段（GitHub 对每个资产维护的
#      官方校验值），下载后先比对压缩包 sha256
#   ③ 解压后再校验包内官方 SHA256SUMS（curl 二进制），双重校验
#   ④ 全部通过且二进制支持 --http3-only 才安装并设置 CURL_H3
# 成功返回 0；任一环节失败 yellow/red 提示并返回 1（不静默使用损坏文件，
# 由调用方回退内置探针）
install_curl_h3() {
  local arch="" libc="glibc" api_url="https://api.github.com/repos/stunnel/static-curl/releases/latest"
  local api_json="" tag="" asset="" expected="" actual="" url="" tmpdir=""
  case "$(uname -m)" in
    x86_64|amd64) arch="x86_64" ;;
    aarch64|arm64) arch="aarch64" ;;
    *)
      yellow "警告: 不支持的 CPU 架构 $(uname -m)，无法自动获取 H3 版 curl（仅支持 x86_64/aarch64）"
      return 1
      ;;
  esac
  if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then
    yellow "警告: 未找到 curl/wget，无法下载 H3 版 curl（SNI 校验将回退内置探针）"
    return 1
  fi
  if ! command -v sha256sum >/dev/null 2>&1; then
    yellow "警告: 未找到 sha256sum，无法校验 H3 版 curl（SNI 校验将回退内置探针）"
    return 1
  fi
  yellow "系统 curl 无 HTTP/3 支持，尝试下载静态编译的 H3 版 curl（stunnel/static-curl）..."
  # ① 官方 API：最新版本号 + 目标资产名 + 官方 sha256（资产 digest）
  api_json=$(curl -fsSL --connect-timeout 10 --max-time 30 "$api_url" 2>/dev/null) || api_json=""
  tag=$(printf '%s' "$api_json" | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n1) || tag=""
  if [ -z "$tag" ]; then
    yellow "警告: 查询 static-curl 最新版本失败（网络或 GitHub API 限制），无法安全获取 H3 版 curl"
    return 1
  fi
  asset="curl-linux-${arch}-${libc}-${tag}.tar.xz"
  expected=$(printf '%s' "$api_json" | awk -v a="$asset" '
    $0 ~ "\"name\": \"" a "\"" { found=1 }
    found && /"digest": "sha256:[0-9a-f]+"/ { sub(/.*"digest": "sha256:/, ""); sub(/".*/, ""); print; exit }
  ') || expected=""
  if [ -z "$expected" ]; then
    yellow "警告: 官方 Release 中未找到资产 $asset 的 sha256，无法安全下载 H3 版 curl"
    return 1
  fi
  url="https://github.com/stunnel/static-curl/releases/download/${tag}/${asset}"
  yellow "  下载 $url"
  tmpdir=$(mktemp -d) || return 1
  if command -v curl >/dev/null 2>&1; then
    if ! curl -fL --connect-timeout 15 --max-time 300 -o "$tmpdir/curl.tar.xz" "$url"; then
      yellow "警告: 下载 H3 版 curl 失败（网络错误或超时），SNI 校验将回退内置探针"
      rm -rf "$tmpdir"
      return 1
    fi
  elif command -v wget >/dev/null 2>&1; then
    if ! wget -q --timeout=15 -T 300 -O "$tmpdir/curl.tar.xz" "$url"; then
      yellow "警告: 下载 H3 版 curl 失败（网络错误或超时），SNI 校验将回退内置探针"
      rm -rf "$tmpdir"
      return 1
    fi
  else
    yellow "警告: 未找到 curl/wget，无法下载 H3 版 curl"
    rm -rf "$tmpdir"
    return 1
  fi
  # ② 官方 sha256 比对（GitHub API digest）
  actual=$(sha256sum "$tmpdir/curl.tar.xz" | awk '{print $1}')
  if [ "$actual" != "$expected" ]; then
    red "错误: H3 版 curl sha256 校验失败（预期 $expected，实际 $actual），中止安装"
    rm -rf "$tmpdir"
    return 1
  fi
  green "sha256 校验通过: $asset"
  # ③ 解压 + 包内官方 SHA256SUMS 二次校验 curl 二进制
  if ! tar -xJf "$tmpdir/curl.tar.xz" -C "$tmpdir"; then
    yellow "警告: 解压 H3 版 curl 失败"
    rm -rf "$tmpdir"
    return 1
  fi
  if ! ( cd "$tmpdir" && sha256sum -c SHA256SUMS >/dev/null 2>&1 ); then
    red "错误: H3 版 curl 压缩包内 SHA256SUMS 校验失败，中止安装"
    rm -rf "$tmpdir"
    return 1
  fi
  if [ ! -x "$tmpdir/curl" ] || ! curl_bin_supports_http3_only "$tmpdir/curl"; then
    yellow "警告: 下载的 curl 二进制不可用或不支持 --http3-only，放弃安装"
    rm -rf "$tmpdir"
    return 1
  fi
  # ④ 安装为系统级独立二进制（不覆盖系统 curl）
  if ! cp -f "$tmpdir/curl" "$CURL_H3_BIN" || ! chmod 755 "$CURL_H3_BIN"; then
    yellow "警告: 安装 $CURL_H3_BIN 失败（需要 root 权限），SNI 校验将回退内置探针"
    rm -rf "$tmpdir"
    return 1
  fi
  rm -rf "$tmpdir"
  CURL_H3="$CURL_H3_BIN"
  green "已安装 H3 版 curl（静态编译，HTTP/3 支持）: $CURL_H3_BIN"
  yellow "  版本: $("$CURL_H3_BIN" --version 2>/dev/null | head -n1 || true)"
  return 0
}

# 确保 H3 版 curl 可用并填充全局 CURL_H3（幂等，重复调用不重复下载）：
#   ① 系统 curl 支持 H3 → CURL_H3=系统 curl 路径
#   ② $CURL_H3_BIN 已存在且支持 --http3-only → 直接复用，跳过下载
#   ③ 都没有 → install_curl_h3 下载安装
# 成功返回 0；最终失败 yellow 提示并返回 1（调用方回退内置探针，不阻断部署）
ensure_curl_h3() {
  local sys_curl_ver=""
  if [ -n "$CURL_H3" ]; then
    return 0
  fi
  if curl_supports_h3; then
    CURL_H3="$(command -v curl)"
    green "检测到系统 curl 支持 HTTP/3: $CURL_H3"
    return 0
  fi
  if [ -x "$CURL_H3_BIN" ] && curl_bin_supports_http3_only "$CURL_H3_BIN"; then
    CURL_H3="$CURL_H3_BIN"
    green "检测到已安装的 H3 版 curl（跳过下载）: $CURL_H3"
    return 0
  fi
  if command -v curl >/dev/null 2>&1; then
    sys_curl_ver=$(curl --version 2>/dev/null | head -n1 || true)
    yellow "系统 curl 无 HTTP/3 支持（${sys_curl_ver:-未知版本}），尝试获取 H3 版 curl..."
  else
    yellow "未找到系统 curl，尝试下载 H3 版 curl（用于 SNI 校验）..."
  fi
  if install_curl_h3; then
    return 0
  fi
  yellow "警告: H3 版 curl 获取失败，SNI 校验将回退内置探针（不影响部署流程）"
  CURL_H3=""
  return 1
}

# SNI 三段校验（与部署脚本完全一致）：域名格式 → DNS 解析 → H3 探测；
# H3 探测优先用 curl 发真实 HTTP/3 请求（--http3-only，旧版 --http3 + 校验
# http_version=3 防降级假阳性）；curl 来源链为「系统 curl（有 H3）→
# /usr/local/bin/curl-http3（无 H3 时自动下载安装，幂等）→ 内置探针 probe_h3 兜底」；
# 成功返回 0，失败返回 1（内部已输出红色原因）
validate_sni_h3() {
  local sni="$1" curl_out="" curl_ver="" curl_code="" curl_timeout="" rc=0
  if ! valid_domain "$sni"; then
    red "SNI 格式不合法（示例: example.com / www.example.com）"
    return 1
  fi
  if ! resolve_ip "$sni" >/dev/null; then
    red "DNS 解析失败: $sni（请检查域名是否真实存在）"
    return 1
  fi
  # curl 来源：系统 curl（支持 H3）→ /usr/local/bin/curl-http3（自动下载安装）→ 内置探针
  if [ -z "$CURL_H3" ]; then
    ensure_curl_h3 || true
  fi
  if [ -n "$CURL_H3" ]; then
    yellow "正在测试 $sni 的 HTTP/3 支持（$CURL_H3 实测，最长 ${PROBE_TIMEOUT}）..."
    # PROBE_TIMEOUT 形如 12s（带单位），curl 的 --max-time 只接受纯数字秒
    curl_timeout="${PROBE_TIMEOUT%s}"
    if curl_bin_supports_http3_only "$CURL_H3"; then
      curl_out=$("$CURL_H3" -sI --http3-only --connect-timeout 5 --max-time "${curl_timeout:-10}" \
        -o /dev/null -w '%{http_version} %{http_code}' "https://$sni/" 2>&1) || rc=$?
    else
      # 旧版 curl 的 --http3 可能静默降级到 H2/H1，必须校验 http_version=3 防假阳性
      curl_out=$("$CURL_H3" -sI --http3 --connect-timeout 5 --max-time "${curl_timeout:-10}" \
        -o /dev/null -w '%{http_version} %{http_code}' "https://$sni/" 2>&1) || rc=$?
    fi
    curl_ver="${curl_out%% *}"
    curl_code="${curl_out##* }"
    if [ "$curl_ver" = "3" ] && [ "${curl_code:-0}" -ne 0 ] 2>/dev/null; then
      green "SNI 支持 H3: $sni"
      green "探测结果（HTTP/3 真实响应）: $curl_out"
      return 0
    fi
    red "该 SNI 不支持 H3: $sni"
    if [ -n "${curl_out# }" ]; then
      red "探测结果: ${curl_out# }"
    else
      red "探测结果: curl 请求失败（未收到 HTTP/3 响应）"
    fi
    return 1
  fi
  yellow "curl 无 HTTP/3 支持，改用内置探针"
  yellow "正在测试 $sni 的 HTTP/3 支持（最长 ${PROBE_TIMEOUT}）..."
  if probe_h3 "$sni"; then
    green "SNI 支持 H3: $sni"
    green "探测结果（握手状态码）: $probe_out"
    return 0
  fi
  red "该 SNI 不支持 H3: $sni"
  red "探测结果: $probe_out"
  return 1
}

# ---------------- E. 探针获取（自给自足，无需预装 Go） ----------------

# 内嵌探针源码（与仓库根目录 probe-h3-sni.go 保持同步）
EMBEDDED_PROBE_SRC='// probe-h3-sni 是一个极简 HTTP/3 (QUIC) 支持探测工具，用于在部署 H3 REALITY
// 节点前确认某个 SNI 是否真的有 H3 端点，以及部署后用 -addr 指向本机 443
// 验证 relay 闭环（预检把未认证的 QUIC 流原样转发到真实 dest，由 dest 完成握手）。
//
// 用法:
//
//	probe-h3-sni -sni <域名>                  # 直连 https://<域名>/ 探测该 SNI 的 H3 支持
//	probe-h3-sni -sni <域名> -addr <ip:port>  # 连 https://<addr>/，但 TLS SNI 仍用 -sni
//	probe-h3-sni -sni <域名> -timeout 15s     # 自定义握手超时（默认 12s）
//
// 判定规则:
//
//	任何 HTTP 响应（200/301/307/400/403 等）=> 完整握手，STATUS: <code>，退出码 0
//	握手/请求错误（超时、CRYPTO_ERROR 0x128/0x150 等）=> ERR: <错误>，退出码 1
//	参数错误 => 退出码 2
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

func main() {
	sni := flag.String("sni", "", "要探测/发送的 SNI 域名（必填）")
	timeout := flag.Duration("timeout", 12*time.Second, "握手与请求总超时")
	addr := flag.String("addr", "", "可选：要连接的 host:port（例如 127.0.0.1:443 用于 relay 闭环验证）；为空则直连 https://<sni>/")
	flag.Parse()

	if *sni == "" {
		fmt.Fprintln(os.Stderr, "参数错误: -sni 必填")
		fmt.Fprintln(os.Stderr, "用法: probe-h3-sni -sni <域名> [-timeout 12s] [-addr host:port]")
		os.Exit(2)
	}
	if *timeout <= 0 {
		fmt.Fprintln(os.Stderr, "参数错误: -timeout 必须为正数")
		os.Exit(2)
	}

	// 目标 URL：默认 https://<sni>/；-addr 模式连 https://<addr>/（TLS SNI 仍是 -sni）。
	host := *sni
	if *addr != "" {
		host = normalizeHostPort(*addr)
	}
	u := &url.URL{Scheme: "https", Host: host, Path: "/"}

	tlsCfg := &tls.Config{
		ServerName:         *sni,
		InsecureSkipVerify: true, // 只关心握手是否完成，不校验证书链
		NextProtos:         []string{"h3"},
	}
	quicCfg := &quic.Config{
		HandshakeIdleTimeout: *timeout,
		MaxIdleTimeout:       30 * time.Second,
	}

	transport := &http3.Transport{
		QUICConfig:      quicCfg,
		TLSClientConfig: tlsCfg,
	}
	defer transport.Close()

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		fmt.Printf("ERR: %v\n", err)
		os.Exit(1)
	}
	// :authority 固定为目标 host（-addr 模式为 addr，否则为 SNI）。
	req.Host = u.Host

	resp, err := transport.RoundTrip(req)
	if err != nil {
		fmt.Printf("ERR: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	fmt.Printf("STATUS: %d\n", resp.StatusCode)
	os.Exit(0)
}

// normalizeHostPort 保证 host:port 完整：无端口补 443，IPv6 加方括号。
func normalizeHostPort(hostport string) string {
	hostport = strings.TrimSpace(hostport)
	if _, _, err := net.SplitHostPort(hostport); err == nil {
		return hostport
	}
	// 纯 IP（含 IPv6）或裸域名：按 host 处理
	if ip := net.ParseIP(hostport); ip != nil {
		if strings.Contains(hostport, ":") {
			return "[" + hostport + "]:443"
		}
		return hostport + ":443"
	}
	return hostport + ":443"
}
'

# 用源码编译探针（优先仓库自带 probe-mod，其次内嵌源码临时编译）
# 需要 go 环境 + 可访问 proxy.golang.org 拉取 quic-go 依赖
build_probe_from_source() {
  local tmpdir rc=0
  if [ -f "$PROBE_MOD_DIR/go.mod" ] && [ -f "$PROBE_MOD_DIR/main.go" ]; then
    if ( cd "$PROBE_MOD_DIR" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags '-s -w' -o "$PROBE" . ); then
      if [ -x "$PROBE" ]; then
        green "探针编译成功（probe-mod）: $PROBE"
        return 0
      fi
    fi
  fi
  tmpdir=$(mktemp -d)
  if [ -f "$PROBE_SRC" ]; then
    cp "$PROBE_SRC" "$tmpdir/main.go"
  else
    printf '%s\n' "$EMBEDDED_PROBE_SRC" > "$tmpdir/main.go"
  fi
  if ! ( cd "$tmpdir" && go mod init probe-h3-sni >/dev/null 2>&1 && go mod tidy >/dev/null 2>&1 && \
         CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags '-s -w' -o "$PROBE" . ); then
    rc=1
  fi
  rm -rf "$tmpdir"
  return $rc
}

# 从 GitHub Release 下载预编译探针（curl 优先，其次 wget）
download_probe_release() {
  yellow "尝试从 GitHub Release 下载预编译探针..."
  yellow "  $PROBE_RELEASE_URL"
  if command -v curl >/dev/null 2>&1; then
    curl -fL --connect-timeout 15 --max-time 120 -o "$PROBE" "$PROBE_RELEASE_URL" || return 1
  elif command -v wget >/dev/null 2>&1; then
    wget -q --timeout=15 -T 120 -O "$PROBE" "$PROBE_RELEASE_URL" || return 1
  else
    return 1
  fi
  chmod +x "$PROBE"
  [ -x "$PROBE" ] || return 1
  return 0
}

# 确保探针可用：① 同目录二进制 → ② 同目录源码 + go 编译 → ③ Release 下载 → ④ 内嵌源码提示
ensure_probe() {
  if [ -x "$PROBE" ]; then
    green "使用探针: $PROBE"
    return 0
  fi
  if [ -f "$PROBE_SRC" ] && command -v go >/dev/null 2>&1; then
    yellow "未找到探针二进制，检测到 Go 环境，尝试编译 probe-h3-sni.go..."
    if build_probe_from_source; then
      green "探针编译成功: $PROBE"
      return 0
    fi
    yellow "源码编译失败（可能无法访问 proxy.golang.org），尝试下载预编译二进制..."
  elif [ -f "$PROBE_SRC" ]; then
    yellow "未找到探针二进制，且本机没有 Go 环境，尝试下载预编译二进制..."
  else
    yellow "未找到探针二进制与源码，尝试下载预编译二进制..."
  fi
  if download_probe_release; then
    green "探针下载成功: $PROBE"
    return 0
  fi
  # 最后手段：黄色警告 + 手动获取方式
  yellow "警告: 探针获取失败，请手动获取后重试："
  yellow "  方式1: 在 GitHub Releases 页面下载 probe-h3-sni-linux-amd64，放到本脚本同目录"
  yellow "  方式2: 脚本已内嵌探针源码（EMBEDDED_PROBE_SRC），需 Go 1.22+ 编译："
  yellow "         提取内嵌源码为 main.go，执行 go mod init probe-h3-sni && go mod tidy &&"
  yellow "         CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o probe-h3-sni ."
  yellow "  方式3: curl -fL -o probe-h3-sni $PROBE_RELEASE_URL && chmod +x probe-h3-sni"
  die "探针不可用，无法进行 H3 探测。"
}

# ---------------- F. xray 内核获取 ----------------

# 从 GitHub Release 下载预编译 fork 内核到 /opt/xray/xray-linux-amd64
# （curl 优先，其次 wget）；成功返回 0 并设置 XRAY_BIN
download_xray() {
  yellow "尝试从 GitHub Release 下载预编译内核..."
  yellow "  $KERNEL_URL"
  mkdir -p /opt/xray || return 1
  if command -v curl >/dev/null 2>&1; then
    curl -fL --connect-timeout 15 --max-time 300 -o /opt/xray/xray-linux-amd64 "$KERNEL_URL" || return 1
  elif command -v wget >/dev/null 2>&1; then
    wget -q --timeout=15 -T 300 -O /opt/xray/xray-linux-amd64 "$KERNEL_URL" || return 1
  else
    return 1
  fi
  chmod +x /opt/xray/xray-linux-amd64
  XRAY_BIN=/opt/xray/xray-linux-amd64
  if [ -x "$XRAY_BIN" ] && "$XRAY_BIN" version >/dev/null 2>&1; then
    return 0
  fi
  rm -f "$XRAY_BIN"
  XRAY_BIN=""
  return 1
}

# 从仓库 core/ 源码编译 fork 内核（git clone + go build -mod=vendor ./main，
# 无需联网拉依赖）；成功返回 0 并设置 XRAY_BIN，失败清理临时目录
build_xray_from_source() {
  local rc=0
  rm -rf /tmp/h3-core
  git clone --depth 1 "$KERNEL_SRC_URL" /tmp/h3-core || return 1
  if ! ( cd /tmp/h3-core/core && go build -mod=vendor -o /opt/xray/xray-linux-amd64 ./main ); then
    rc=1
  fi
  rm -rf /tmp/h3-core
  [ "$rc" -ne 0 ] && return 1
  chmod +x /opt/xray/xray-linux-amd64
  XRAY_BIN=/opt/xray/xray-linux-amd64
  if [ -x "$XRAY_BIN" ] && "$XRAY_BIN" version >/dev/null 2>&1; then
    return 0
  fi
  rm -f "$XRAY_BIN"
  XRAY_BIN=""
  return 1
}

# 检测本项目 fork 内核（固定路径 /opt/xray/xray-linux-amd64）：
#   - 环境变量 XRAY_BIN 显式指定时直接使用（测试/特殊场景）
#   - 机器上已存在的官方 xray（/usr/local/bin/xray 或 PATH 中的 xray）只是
#     "干扰项"：黄色提示后忽略，不询问、不降级，仍自动获取 fork 内核
#   - 自动获取链路：Release 预编译下载 → 仓库 core/ 源码编译兜底；
#     只有自动获取也全部失败才返回 1（由调用方进入降级模式菜单）
detect_xray() {
  local v official=""
  if [ -n "$XRAY_BIN" ]; then
    v=$("$XRAY_BIN" version 2>/dev/null | head -n1 || true)
    if [ -n "$v" ]; then
      green "检测到 xray 内核: $XRAY_BIN"
      yellow "  版本: $v"
      return 0
    fi
    yellow "警告: $XRAY_BIN 存在但无法执行（架构不匹配或文件损坏），按未检测到处理"
    XRAY_BIN=""
  fi

  # 本项目 fork 内核固定安装路径
  if [ -x /opt/xray/xray-linux-amd64 ]; then
    XRAY_BIN=/opt/xray/xray-linux-amd64
    v=$("$XRAY_BIN" version 2>/dev/null | head -n1 || true)
    if [ -n "$v" ]; then
      green "检测到本项目 fork 内核: $XRAY_BIN"
      yellow "  版本: $v"
      return 0
    fi
    yellow "警告: /opt/xray/xray-linux-amd64 存在但无法执行（架构不匹配或文件损坏），将重新获取"
    XRAY_BIN=""
  fi

  # 官方 xray 只是干扰项：提示但忽略，继续自动获取 fork 内核
  if [ -x /usr/local/bin/xray ]; then
    official=/usr/local/bin/xray
  elif command -v xray >/dev/null 2>&1; then
    official="$(command -v xray)"
  fi
  if [ -n "$official" ]; then
    yellow "检测到官方 xray（$official），将忽略并自动获取 fork 内核"
    v=$("$official" version 2>/dev/null | head -n1 || true)
    [ -n "$v" ] && yellow "  版本: $v"
  fi

  # 自动获取（Release 预编译下载 → 源码编译兜底）
  yellow "未检测到本项目 fork 内核（/opt/xray/xray-linux-amd64），尝试自动获取..."
  if download_xray; then
    green "fork 内核下载成功: $XRAY_BIN（Release 预编译）"
    return 0
  fi
  if command -v go >/dev/null 2>&1; then
    yellow "Release 下载失败，检测到 Go 环境，尝试从仓库 core/ 源码编译..."
    if build_xray_from_source; then
      green "fork 内核编译成功: $XRAY_BIN（源码编译）"
      return 0
    fi
    yellow "源码编译失败，已清理临时目录"
  else
    yellow "Release 下载失败，且本机没有 Go 环境，无法源码编译"
  fi
  yellow "警告: fork 内核自动获取失败（Release 下载与源码编译均未成功），请检查网络后重试或手动准备"
  return 1
}

# ---------------- G. 配置操作 ----------------

# 本项目配置路径固定为 XRAY_CONFIG（默认 /opt/xray/server.json）；
# 绝不把 /usr/local/etc/xray/config.json 等官方 xray 配置当作本项目已有配置
detect_config_path() {
  CONFIG_PATH="${XRAY_CONFIG:-/opt/xray/server.json}"
}

# --- sed/awk 兜底工具（无 jq 时使用；仅适配本项目生成式配置的固定格式） ---

# 单行压缩 JSON → 多行展开（打印到 stdout）。
# 字符串感知（值内逗号/转义不拆分），展开后每个结构单元占一行，
# 行级 awk/sed 即可精确限定编辑范围。
json_explode() {
  # 字符串感知：只在字符串外把 { } [ ] , 当作结构字符分行，
  # 值内的逗号（如 "gzip, deflate, br, zstd"）与转义字符保持原样
  awk '
    function indent(d, s, i) { s = ""; for (i = 0; i < d; i++) s = s "  "; return s }
    {
      line = ""; depth = 0; in_str = 0
      n = split($0, ch, "")
      for (i = 1; i <= n; i++) {
        c = ch[i]
        if (in_str) {
          line = line c
          if (c == "\\") { i++; if (i <= n) line = line ch[i] }
          else if (c == "\"") in_str = 0
          continue
        }
        if (c == "\"") { in_str = 1; line = line c; continue }
        if (c == "{") {
          printf "%s%s{\n", indent(depth), line
          line = ""; depth++
        } else if (c == "}") {
          if (line != "") printf "%s%s\n", indent(depth), line
          depth--
          printf "%s}\n", indent(depth)
          line = ""
        } else if (c == "[") {
          printf "%s%s[\n", indent(depth), line
          line = ""; depth++
        } else if (c == "]") {
          if (line != "") printf "%s%s\n", indent(depth), line
          depth--
          printf "%s]\n", indent(depth)
          line = ""
        } else if (c == ",") {
          printf "%s%s,\n", indent(depth), line
          line = ""
        } else {
          line = line c
        }
      }
      if (line != "") printf "%s%s\n", indent(depth), line
    }
  ' "$1"
}

# 判断配置是否为单行压缩 JSON（整个文件仅 1 行）
json_is_compressed() {
  [ "$(sed -n '$=' "$CONFIG_PATH" 2>/dev/null)" -le 1 ]
}

# 若配置为单行压缩 JSON，原地展开为多行（与 jq 分支一样会重排为多行格式）
json_explode_if_compressed() {
  if json_is_compressed; then
    json_explode "$CONFIG_PATH" > "$CONFIG_PATH.tmp" && mv "$CONFIG_PATH.tmp" "$CONFIG_PATH"
  fi
}

# 逐 inbound 输出一行（以 | 分隔）：port|xhttp|h3mark|id|privateKey|shortId|serverName|dest
#   xhttp=1  streamSettings.network == "xhttp"
#   h3mark=1 realitySettings 含 alpn "h3" / fallbackDest / fallbackDestRoutes
# 无 inbounds 或解析失败时输出为空
scan_inbounds() {
  local src="$CONFIG_PATH" tmp=""
  if json_is_compressed; then
    tmp="$CONFIG_PATH.scan.$$"
    json_explode "$CONFIG_PATH" > "$tmp"
    src="$tmp"
  fi
  awk '
    function clean(v, x) {
      x = v
      sub(/^[[:space:]]*"/, "", x)
      sub(/"[[:space:]]*,?[[:space:]]*$/, "", x)
      return x
    }
    # 提取 key: "value" 行中的 value（值内允许含冒号，如 dest 的 host:443）
    function val(v, x) {
      x = v
      sub(/^[^:]*:[[:space:]]*"/, "", x)
      sub(/"[[:space:]]*,?[[:space:]]*$/, "", x)
      return x
    }
    /"inbounds"[[:space:]]*:[[:space:]]*\[/ { in_list = 1 }
    in_list && !in_obj && /^[[:space:]]*\{/ {
      in_obj = 1; depth = 0; p = ""; xhttp = 0; h3mark = 0
      id = ""; priv = ""; sid = ""; sn = ""; dest = ""; in_sid = 0; in_sn = 0
    }
    in_obj {
      n_open = gsub(/\{/, "{")
      n_close = gsub(/\}/, "}")
      if (p == "" && $0 ~ /^[[:space:]]*"port"[[:space:]]*:[[:space:]]*[0-9]+/) {
        p = $0
        sub(/^[[:space:]]*"port"[[:space:]]*:[[:space:]]*/, "", p)
        sub(/,?[[:space:]]*$/, "", p)
      }
      if ($0 ~ /"network"[[:space:]]*:[[:space:]]*"xhttp"/) xhttp = 1
      if (h3mark == 0 && ($0 ~ /"fallbackDest"/ || $0 ~ /^[[:space:]]*"h3"[[:space:]]*,?/)) h3mark = 1
      if (id == "" && $0 ~ /^[[:space:]]*"id"[[:space:]]*:[[:space:]]*/) id = val($0)
      if (priv == "" && $0 ~ /^[[:space:]]*"privateKey"[[:space:]]*:[[:space:]]*/) priv = val($0)
      if ($0 ~ /^[[:space:]]*"shortIds"[[:space:]]*:[[:space:]]*\[/) in_sid = 1
      else if (in_sid == 1 && sid == "" && $0 ~ /^[[:space:]]*"/) { sid = clean($0); in_sid = 0 }
      if ($0 ~ /^[[:space:]]*"serverNames"[[:space:]]*:[[:space:]]*\[/) in_sn = 1
      else if (in_sn == 1 && sn == "" && $0 ~ /^[[:space:]]*"/) { sn = clean($0); in_sn = 0 }
      if (dest == "" && $0 ~ /^[[:space:]]*"dest"[[:space:]]*:[[:space:]]*/) dest = val($0)
      depth += n_open - n_close
      if (depth <= 0) {
        printf "%s|%s|%s|%s|%s|%s|%s|%s\n", p, xhttp, h3mark, id, priv, sid, sn, dest
        in_obj = 0
      }
    }
    in_list && !in_obj && /^[[:space:]]*\]/ { in_list = 0 }
  ' "$src"
  if [ -n "$tmp" ]; then rm -f "$tmp"; fi
  return 0
}

# 输出第一个 H3 inbound（xhttp=1 且 h3mark=1）对象在配置中的起止行号（start|end）；
# 未找到时输出为空。编辑函数据此把 sed/awk 修改限定在 H3 inbound 范围内，
# 与 jq 分支（只改 h3mark=1 的 inbound）行为一致。
scan_h3_range() {
  json_explode_if_compressed
  awk '
    /"inbounds"[[:space:]]*:[[:space:]]*\[/ { in_list = 1 }
    in_list && !in_obj && /^[[:space:]]*\{/ {
      in_obj = 1; depth = 0; start = NR; xhttp = 0; h3mark = 0
    }
    in_obj {
      n_open = gsub(/\{/, "{")
      n_close = gsub(/\}/, "}")
      if ($0 ~ /"network"[[:space:]]*:[[:space:]]*"xhttp"/) xhttp = 1
      if (h3mark == 0 && ($0 ~ /"fallbackDest"/ || $0 ~ /^[[:space:]]*"h3"[[:space:]]*,?/)) h3mark = 1
      depth += n_open - n_close
      if (depth <= 0) {
        if (xhttp == 1 && h3mark == 1) { print start "|" NR; exit }
        in_obj = 0
      }
    }
    in_list && !in_obj && /^[[:space:]]*\]/ { in_list = 0 }
  ' "$CONFIG_PATH"
}

# 仅替换 H3 inbound 范围内 serverNames 数组的首个元素（保留行尾逗号与缩进）；
# 数组为空时补入首元素
sed_set_server_names() {
  local sni="$1" range start end
  range=$(scan_h3_range) || true
  [ -n "$range" ] || { red "ERROR: 未找到 H3 inbound"; return 1; }
  start=${range%%|*}; end=${range##*|}
  awk -v sni="$sni" -v s="$start" -v e="$end" '
    NR < s || NR > e { print; next }
    /"serverNames"[[:space:]]*:[[:space:]]*\[/ {
      in_sn = 1; replaced = 0
      print
      next
    }
    in_sn && /^[[:space:]]*"/ {
      ind = $0; sub(/[^[:space:]].*$/, "", ind)
      comma = ($0 ~ /,[[:space:]]*$/) ? "," : ""
      printf "%s\"%s\"%s\n", ind, sni, comma
      in_sn = 0; replaced = 1
      next
    }
    in_sn && /]/ {
      if (!replaced) {
        ind = $0; sub(/[^[:space:]].*$/, "", ind)
        printf "%s\"%s\"\n", ind, sni
      }
      in_sn = 0
      print
      next
    }
    { print }
  ' "$CONFIG_PATH" > "$CONFIG_PATH.tmp" && mv "$CONFIG_PATH.tmp" "$CONFIG_PATH"
}

# ===== 手动高级配置：fallbackDestRoutes 路由表（默认部署不再生成/维护） =====
# 经典 REALITY 不按 SNI 分流 fallback：路由表是额外特征（表外 SNI 统一落
# fallbackDest、换 SNI 主动探测多测必露馅）。以下函数仅供确实需要该行为的
# 高级用户手动使用，普通 switch/add/remove 流程不再触碰路由表。

# 在 H3 inbound 的 fallbackDestRoutes 块末尾插入 <sni>: <sni>:443
# （自动给原最后一条补逗号，缩进沿用块收尾行）
sed_insert_route() {
  local sni="$1" range start end
  range=$(scan_h3_range) || true
  [ -n "$range" ] || { red "ERROR: 未找到 H3 inbound"; return 1; }
  start=${range%%|*}; end=${range##*|}
  awk -v sni="$sni" -v s="$start" -v e="$end" '
    NR < s || NR > e {
      if (buf != "") { print buf; buf = "" }
      print
      next
    }
    /"fallbackDestRoutes"[[:space:]]*:[[:space:]]*\{/ {
      if (buf != "") print buf
      buf = ""
      in_routes = 1
      print
      next
    }
    in_routes && /^[[:space:]]*\}/ {
      ind = $0; sub(/[^[:space:]].*$/, "", ind)
      if (buf != "") {
        if (buf ~ /,[[:space:]]*$/) { print buf }
        else { sub(/[[:space:]]*$/, ",", buf); print buf }
      }
      printf "%s\"%s\": \"%s:443\"\n", ind, sni, sni
      print
      in_routes = 0
      buf = ""
      next
    }
    { if (buf != "") print buf; buf = $0 }
    END { if (buf != "") print buf }
  ' "$CONFIG_PATH" > "$CONFIG_PATH.tmp" && mv "$CONFIG_PATH.tmp" "$CONFIG_PATH"
}

# 无 jq 时切换 SNI：改 H3 inbound 的 dest、fallbackDest、serverNames[0]，
# 并删除 fallbackDestRoutes 路由表（经典 REALITY 语义：fallback 一律转发
# 单一 dest，不按 SNI 分流；旧配置残留的路由表在此一并清除）
sed_update_sni_routes() {
  local sni="$1" range start end
  range=$(scan_h3_range) || true
  [ -n "$range" ] || { red "ERROR: 未找到 H3 inbound"; return 1; }
  start=${range%%|*}; end=${range##*|}
  # 替换 H3 inbound 范围内的 dest 与 fallbackDest（"fallbackDestRoutes" 不会被
  # 误匹配：其 "fallbackDest" 后跟的是 Routes" 而非冒号）
  sed "${start},${end}s/\"dest\"[[:space:]]*:[[:space:]]*\"[^\"]*\"/\"dest\": \"${sni}:443\"/" "$CONFIG_PATH" \
    > "$CONFIG_PATH.tmp" && mv "$CONFIG_PATH.tmp" "$CONFIG_PATH"
  sed "${start},${end}s/\"fallbackDest\"[[:space:]]*:[[:space:]]*\"[^\"]*\"/\"fallbackDest\": \"${sni}:443\"/" "$CONFIG_PATH" \
    > "$CONFIG_PATH.tmp" && mv "$CONFIG_PATH.tmp" "$CONFIG_PATH"
  sed_set_server_names "$sni"
  # 删除 fallbackDestRoutes 块（本项目模板中它是 realitySettings 的末键，
  # 删除时给前一行补掉尾逗号；无该键时原样输出）
  awk -v s="$start" -v e="$end" '
    NR < s || NR > e {
      if (buf != "") { print buf; buf = "" }
      print
      next
    }
    /"fallbackDestRoutes"[[:space:]]*:[[:space:]]*\{/ {
      if (buf != "") {
        if (buf ~ /,[[:space:]]*$/) sub(/,[[:space:]]*$/, "", buf)
        print buf
        buf = ""
      }
      in_routes = 1
      next
    }
    in_routes && /^[[:space:]]*\}/ { in_routes = 0; next }
    in_routes { next }
    { if (buf != "") print buf; buf = $0 }
    END { if (buf != "") print buf }
  ' "$CONFIG_PATH" > "$CONFIG_PATH.tmp" && mv "$CONFIG_PATH.tmp" "$CONFIG_PATH"
  return 0
}

# 无 jq 时添加路由条目（手动高级配置；仅 H3 inbound；已存在则幂等成功）
sed_add_sni_route() {
  local sni="$1" range start end
  range=$(scan_h3_range) || true
  [ -n "$range" ] || { red "ERROR: 未找到 H3 inbound"; return 1; }
  start=${range%%|*}; end=${range##*|}
  sed -n "${start},${end}p" "$CONFIG_PATH" | grep -q '"fallbackDestRoutes"[[:space:]]*:[[:space:]]*{' \
    || { red "ERROR: 未找到 H3 inbound"; return 1; }
  sed -n "${start},${end}p" "$CONFIG_PATH" | grep -q '^[[:space:]]*"'"$sni"'"[[:space:]]*:[[:space:]]*"' && return 0
  sed_insert_route "$sni"
}

# 无 jq 时删除路由条目（手动高级配置；仅 H3 inbound；含存在性与至少保留 1 条的校验）
sed_remove_sni_route() {
  local sni="$1" count range start end
  range=$(scan_h3_range) || true
  [ -n "$range" ] || { red "ERROR: 未找到 H3 inbound"; return 1; }
  start=${range%%|*}; end=${range##*|}
  sed -n "${start},${end}p" "$CONFIG_PATH" | grep -q '"fallbackDestRoutes"[[:space:]]*:[[:space:]]*{' \
    || { red "ERROR: 未找到 H3 inbound"; return 1; }
  if ! sed -n "${start},${end}p" "$CONFIG_PATH" | grep -q '^[[:space:]]*"'"$sni"'"[[:space:]]*:'; then
    red "ERROR: 路由不存在: $sni"
    return 1
  fi
  count=$(sed -n "${start},${end}p" "$CONFIG_PATH" | awk '
    /"fallbackDestRoutes"[[:space:]]*:[[:space:]]*\{/ { in_routes = 1; next }
    in_routes && /^[[:space:]]*\}/ { exit }
    in_routes && /^[[:space:]]*"/ { n++ }
    END { print n + 0 }
  ')
  if [ "$count" -le 1 ]; then
    red "ERROR: 至少需要保留 1 条路由，拒绝删除最后一个条目: $sni"
    return 1
  fi
  awk -v sni="$sni" -v s="$start" -v e="$end" '
    NR < s || NR > e {
      if (buf != "") { print buf; buf = "" }
      print
      next
    }
    /"fallbackDestRoutes"[[:space:]]*:[[:space:]]*\{/ {
      if (buf != "") print buf
      buf = ""
      in_routes = 1
      print
      next
    }
    in_routes && /^[[:space:]]*\}/ {
      if (removed && buf ~ /,[[:space:]]*$/) sub(/,[[:space:]]*$/, "", buf)
      if (buf != "") print buf
      print
      in_routes = 0; buf = ""; removed = 0
      next
    }
    in_routes && index($0, "\"" sni "\":") { removed = 1; next }
    { if (buf != "") print buf; buf = $0 }
    END { if (buf != "") print buf }
  ' "$CONFIG_PATH" > "$CONFIG_PATH.tmp" && mv "$CONFIG_PATH.tmp" "$CONFIG_PATH"
}


# 校验配置中存在结构正常的 H3 inbound（network=xhttp 且 alpn 含 h3，
# 或存在 fallbackDest/fallbackDestRoutes）；0=存在，1=不存在
find_h3_inbound() {
  if command -v jq >/dev/null 2>&1; then
    if jq -e '[.inbounds[] | select(.streamSettings.network == "xhttp" and (
          ((.streamSettings.realitySettings.alpn // []) | index("h3")) or
          (.streamSettings.realitySettings | has("fallbackDest")) or
          (.streamSettings.realitySettings.fallbackDestRoutes != null)))] | length > 0' "$CONFIG_PATH" >/dev/null 2>&1; then
      return 0
    fi
    return 1
  fi
  # sed/awk 兜底
  if scan_inbounds | awk -F'|' '$2==1 && $3==1 {found=1; exit} END {exit !found}'; then
    return 0
  fi
  return 1
}

# 修改配置前自动备份：backup_config <标签> → 生成 <CONFIG_PATH>.bak-<标签>-<时间戳>
backup_config() {
  local label="${1:-h3reality}"
  TS=$(date +%Y%m%d-%H%M%S)
  BACKUP="$CONFIG_PATH.bak-$label-$TS"
  cp -a "$CONFIG_PATH" "$BACKUP" || die "备份失败: $CONFIG_PATH -> $BACKUP"
  green "已备份: $BACKUP"
}

# 切换/更新当前 SNI：改 H3 inbound 的 dest、fallbackDest、serverNames[0]，
# 并删除 fallbackDestRoutes 路由表（经典 REALITY 语义：fallback 一律转发
# 单一 dest，不按 SNI 分流，路由表是额外特征；部署流程不生成/不维护路由表）；
# 成功返回 0
update_sni_routes() {
  local sni="$1" edit_ok=0
  yellow "更新 H3 inbound: dest=$sni:443 serverNames[0]=$sni fallbackDest=$sni:443（清除 fallbackDestRoutes 路由表）"
  if command -v jq >/dev/null 2>&1; then
    if jq --arg sni "$sni" '
      .inbounds = [ .inbounds[] | if (.streamSettings.network == "xhttp" and
          (((.streamSettings.realitySettings.alpn // []) | index("h3")) or
           (.streamSettings.realitySettings | has("fallbackDest")) or
           (.streamSettings.realitySettings.fallbackDestRoutes != null))) then
        .streamSettings.realitySettings.dest = ($sni + ":443")
        | .streamSettings.realitySettings.fallbackDest = ($sni + ":443")
        | .streamSettings.realitySettings.serverNames[0] = $sni
        | del(.streamSettings.realitySettings.fallbackDestRoutes)
      else . end ]' "$CONFIG_PATH" > "$CONFIG_PATH.tmp" && mv "$CONFIG_PATH.tmp" "$CONFIG_PATH"
    then
      edit_ok=1
    fi
  elif sed_update_sni_routes "$sni"; then
    edit_ok=1
  fi
  [ "$edit_ok" -eq 1 ]
}

# 添加 SNI 到 fallbackDestRoutes（手动高级配置；不动当前 dest/serverNames）；
# 成功返回 0
add_sni_route() {
  local sni="$1" edit_ok=0
  yellow "添加 fallbackDestRoutes[$sni]=$sni:443（不改动当前 dest/serverNames）"
  if command -v jq >/dev/null 2>&1; then
    if jq --arg sni "$sni" '
      .inbounds = [ .inbounds[] | if (.streamSettings.network == "xhttp" and
          (((.streamSettings.realitySettings.alpn // []) | index("h3")) or
           (.streamSettings.realitySettings | has("fallbackDest")) or
           (.streamSettings.realitySettings.fallbackDestRoutes != null))) then
        .streamSettings.realitySettings.fallbackDestRoutes[$sni] = ($sni + ":443")
      else . end ]' "$CONFIG_PATH" > "$CONFIG_PATH.tmp" && mv "$CONFIG_PATH.tmp" "$CONFIG_PATH"
    then
      edit_ok=1
    fi
  elif sed_add_sni_route "$sni"; then
    edit_ok=1
  fi
  [ "$edit_ok" -eq 1 ]
}

# 从 fallbackDestRoutes 移除 SNI（手动高级配置；至少保留 1 条，防误删清空
# 路由表）；目标不存在（4）或仅剩 1 条（5）时输出红色原因并返回 1
remove_sni_route() {
  local sni="$1" edit_ok=0
  yellow "删除 fallbackDestRoutes[$sni]（至少保留 1 条路由）"
  if command -v jq >/dev/null 2>&1; then
    if jq -e --arg sni "$sni" '[.inbounds[] | select(.streamSettings.network == "xhttp" and (
          ((.streamSettings.realitySettings.alpn // []) | index("h3")) or
          (.streamSettings.realitySettings | has("fallbackDest")) or
          (.streamSettings.realitySettings.fallbackDestRoutes != null))) | .streamSettings.realitySettings.fallbackDestRoutes][0] | has($sni)' "$CONFIG_PATH" >/dev/null 2>&1 && \
       jq -e --arg sni "$sni" '[.inbounds[] | select(.streamSettings.network == "xhttp" and (
          ((.streamSettings.realitySettings.alpn // []) | index("h3")) or
          (.streamSettings.realitySettings | has("fallbackDest")) or
          (.streamSettings.realitySettings.fallbackDestRoutes != null))) | .streamSettings.realitySettings.fallbackDestRoutes][0] | length > 1' "$CONFIG_PATH" >/dev/null 2>&1
    then
      if jq --arg sni "$sni" '
        .inbounds = [ .inbounds[] | if (.streamSettings.network == "xhttp" and
            (((.streamSettings.realitySettings.alpn // []) | index("h3")) or
             (.streamSettings.realitySettings | has("fallbackDest")) or
             (.streamSettings.realitySettings.fallbackDestRoutes != null))) then
          del(.streamSettings.realitySettings.fallbackDestRoutes[$sni])
        else . end ]' "$CONFIG_PATH" > "$CONFIG_PATH.tmp" && mv "$CONFIG_PATH.tmp" "$CONFIG_PATH"
      then
        edit_ok=1
      fi
    fi
  elif sed_remove_sni_route "$sni"; then
    edit_ok=1
  fi
  [ "$edit_ok" -eq 1 ]
}

# 配置校验：<XRAY_BIN> run -test -c <CONFIG_PATH>；通过返回 0
run_test() {
  yellow "校验配置: $XRAY_BIN run -test -c $CONFIG_PATH"
  "$XRAY_BIN" run -test -c "$CONFIG_PATH" >/dev/null 2>&1
}

# 重启服务并确认 active：restart + sleep 2 + is-active 检查；通过返回 0
restart_service() {
  yellow "重启服务: systemctl restart $SERVICE"
  systemctl restart "$SERVICE" >/dev/null 2>&1 || return 1
  sleep 2
  [ "$(systemctl is-active "$SERVICE" 2>/dev/null)" = "active" ]
}

start_service() { systemctl start "$SERVICE" >/dev/null 2>&1; }
stop_service()  { systemctl stop "$SERVICE" >/dev/null 2>&1; }

service_is_active() {
  [ "$(systemctl is-active "$SERVICE" 2>/dev/null)" = "active" ]
}

# 回滚：新生成的配置 → 移除配置与服务单元；编辑的配置 → 恢复备份
rollback() {
  if [ "$CONFIG_GENERATED" -eq 1 ]; then
    yellow "回滚中：移除新生成的配置与服务单元"
    rm -f "$CONFIG_PATH" "$UNIT_FILE"
    systemctl daemon-reload >/dev/null 2>&1 || true
    return 0
  fi
  if [ -n "$BACKUP" ] && [ -f "$BACKUP" ]; then
    yellow "回滚中：恢复 $BACKUP -> $CONFIG_PATH"
    cp -a "$BACKUP" "$CONFIG_PATH" || red "回滚失败：无法恢复备份"
    "$XRAY_BIN" run -test -c "$CONFIG_PATH" >/dev/null 2>&1 || true
    systemctl restart "$SERVICE" >/dev/null 2>&1 || true
  fi
}

# 从已有配置提取客户端参数（UUID/privateKey/shortId → publicKey）。
# 用法: extract_client_params [port]；指定端口按 inbound 端口匹配，
# 留空则按 H3 inbound 特征匹配（h3reality link 使用）
extract_client_params() {
  local port="${1:-}" out uuid priv sid pk
  if command -v jq >/dev/null 2>&1; then
    if [ -n "$port" ]; then
      out=$(jq -r --arg port "$port" '[.inbounds[] | select(.port == ($port | tonumber)) |
            [.settings.clients[0].id // "", .streamSettings.realitySettings.privateKey // "",
             (.streamSettings.realitySettings.shortIds[0] // "")]] | .[0] | .[]' "$CONFIG_PATH" 2>/dev/null || true)
    else
      out=$(jq -r '[.inbounds[] | select(.streamSettings.network == "xhttp" and (
            ((.streamSettings.realitySettings.alpn // []) | index("h3")) or
            (.streamSettings.realitySettings | has("fallbackDest")) or
            (.streamSettings.realitySettings.fallbackDestRoutes != null))) |
            [.settings.clients[0].id // "", .streamSettings.realitySettings.privateKey // "",
             (.streamSettings.realitySettings.shortIds[0] // "")]] | .[0] | .[]' "$CONFIG_PATH" 2>/dev/null || true)
    fi
  else
    # sed/awk 兜底
    if [ -n "$port" ]; then
      out=$(scan_inbounds | awk -F'|' -v p="$port" '$1==p {print $4; print $5; print $6; exit}')
    else
      out=$(scan_inbounds | awk -F'|' '$3==1 {print $4; print $5; print $6; exit}')
    fi
  fi
  uuid=$(echo "$out" | sed -n '1p')
  priv=$(echo "$out" | sed -n '2p')
  sid=$(echo "$out" | sed -n '3p')
  [ -n "$uuid" ] && UUID="$uuid"
  [ -n "$priv" ] && PRIVATE_KEY="$priv"
  [ -n "$sid" ] && SHORT_ID="$sid"
  if [ -n "$PRIVATE_KEY" ]; then
    pk=$("$XRAY_BIN" x25519 -i "$PRIVATE_KEY" 2>/dev/null | awk '/^Password/{print $NF}' || true)
    [ -n "$pk" ] && PUBLIC_KEY="$pk"
  fi
  return 0
}

# 生成新密钥（UUID/x25519 keypair/shortId，用检测到的内核二进制）
gen_keys() {
  local out
  out=$("$XRAY_BIN" x25519 2>/dev/null || true)
  PRIVATE_KEY=$(echo "$out" | awk '/^PrivateKey:/{print $2}')
  PUBLIC_KEY=$(echo "$out" | awk '/^Password/{print $NF}')
  UUID=$("$XRAY_BIN" uuid 2>/dev/null | head -n1 || true)
  if [ -z "$UUID" ] && [ -r /proc/sys/kernel/random/uuid ]; then
    UUID=$(cat /proc/sys/kernel/random/uuid)
  fi
  if [ -z "$UUID" ] && command -v openssl >/dev/null 2>&1; then
    UUID=$(openssl rand -hex 16 2>/dev/null | sed -E 's/^([0-9a-f]{8})([0-9a-f]{4})([0-9a-f]{4})([0-9a-f]{4})([0-9a-f]{12})$/\1-\2-\3-\4-\5/')
  fi
  if command -v openssl >/dev/null 2>&1; then
    SHORT_ID=$(openssl rand -hex 4 2>/dev/null)
  fi
  [ -z "$SHORT_ID" ] && SHORT_ID=$(head -c4 /dev/urandom | od -An -tx1 | tr -d ' \n')
  [ -z "$PRIVATE_KEY" ] && die "无法从内核生成 x25519 密钥（$XRAY_BIN x25519 失败）"
  [ -z "$UUID" ] && die "无法生成 UUID"
  [ -z "$SHORT_ID" ] && die "无法生成 shortId"
  green "已生成 UUID / x25519 keypair / shortId"
}

# ---------------- H. VLESS 链接生成与当前状态提取 ----------------

# 生成 VLESS 分享链接（部署脚本与 h3reality link 共用同一函数）：
#   gen_vless_link <fork|degraded> <ip> <port> <uuid> <pbk> <sid> <sni> [h2]
# fork:  H3 全参数链接（security=reality, enableH3=1, fp=chrome, host, alpn=h3）
#        第 8 参为 h2 时输出同节点 H2 端口链接（无 enableH3/alpn）
# degraded: 官方内核 H2 降级链接（security=tls, allowInsecure=1）
gen_vless_link() {
  local mode="$1" ip="$2" port="$3" uuid="$4" pub="$5" sid="$6" sni="$7" variant="${8:-h3}"
  local enc_sni enc_pub enc_sid
  enc_sni=$(urlencode "$sni")
  enc_pub=$(urlencode "$pub")
  enc_sid=$(urlencode "$sid")
  case "$mode" in
    degraded)
      printf 'vless://%s@%s:%s?encryption=none&security=tls&type=xhttp&mode=stream-one&path=%%2Fv1%%2Fcollect&sni=%s&allowInsecure=1#H2-DEGRADED-%s\n' \
        "$uuid" "$ip" "$port" "$enc_sni" "$port"
      ;;
    fork)
      if [ "$variant" = "h2" ]; then
        printf 'vless://%s@%s:%s?encryption=none&security=reality&type=xhttp&mode=stream-one&path=%%2Fv1%%2Fcollect&sni=%s&fp=chrome&pbk=%s&sid=%s&host=%s#H3-REALITY-H2-%s\n' \
          "$uuid" "$ip" "$port" "$enc_sni" "$enc_pub" "$enc_sid" "$enc_sni" "$port"
      else
        printf 'vless://%s@%s:%s?encryption=none&security=reality&type=xhttp&mode=stream-one&enableH3=1&path=%%2Fv1%%2Fcollect&sni=%s&fp=chrome&pbk=%s&sid=%s&host=%s&alpn=h3#H3-REALITY-%s\n' \
          "$uuid" "$ip" "$port" "$enc_sni" "$enc_pub" "$enc_sid" "$enc_sni" "$port"
      fi
      ;;
  esac
}

# 输出当前 SNI（H3 inbound 的 serverNames[0]，为空则取 dest 主机名）；失败返回 1
get_current_sni() {
  if command -v jq >/dev/null 2>&1; then
    local sni
    sni=$(jq -r '[.inbounds[] | select(.streamSettings.network == "xhttp" and (
          ((.streamSettings.realitySettings.alpn // []) | index("h3")) or
          (.streamSettings.realitySettings | has("fallbackDest")) or
          (.streamSettings.realitySettings.fallbackDestRoutes != null))) | .streamSettings.realitySettings.serverNames[0]][0] // empty' "$CONFIG_PATH" 2>/dev/null) || return 1
    [ -n "$sni" ] || return 1
    echo "$sni"
    return 0
  fi
  # sed/awk 兜底：取 H3 inbound 的 serverNames[0]，为空则取 dest 主机名
  local line sni
  line=$(scan_inbounds | awk -F'|' '$3==1 {print; exit}') || true
  [ -n "$line" ] || return 1
  sni=$(printf '%s\n' "$line" | cut -d'|' -f7)
  if [ -z "$sni" ]; then
    sni=$(printf '%s\n' "$line" | cut -d'|' -f8)
    sni=${sni%:*}
  fi
  [ -n "$sni" ] || return 1
  echo "$sni"
  return 0
}

# 输出 H3 inbound 的监听端口；失败返回 1
get_h3_port() {
  if command -v jq >/dev/null 2>&1; then
    local port
    port=$(jq -r '[.inbounds[] | select(.streamSettings.network == "xhttp" and (
          ((.streamSettings.realitySettings.alpn // []) | index("h3")) or
          (.streamSettings.realitySettings | has("fallbackDest")) or
          (.streamSettings.realitySettings.fallbackDestRoutes != null))) | .port][0] // empty' "$CONFIG_PATH" 2>/dev/null) || return 1
    [ -n "$port" ] || return 1
    echo "$port"
    return 0
  fi
  # sed/awk 兜底
  local line port
  line=$(scan_inbounds | awk -F'|' '$3==1 {print; exit}') || true
  [ -n "$line" ] || return 1
  port=$(printf '%s\n' "$line" | cut -d'|' -f1)
  port=${port:-443}
  echo "$port"
  return 0
}

# 输出 H2 inbound 的监听端口（fork 配置：xhttp 且非 H3 的 inbound；
# 降级配置：唯一的 xhttp inbound）；失败返回 1
get_h2_port() {
  if command -v jq >/dev/null 2>&1; then
    local port
    port=$(jq -r '[.inbounds[] |
          select(.streamSettings.network == "xhttp") |
          select(((.streamSettings.realitySettings.alpn // []) | index("h3")) == null
             and (.streamSettings.realitySettings | has("fallbackDest") | not)
             and (.streamSettings.realitySettings.fallbackDestRoutes == null)) |
          .port][0] // empty' "$CONFIG_PATH" 2>/dev/null) || return 1
    [ -n "$port" ] || return 1
    echo "$port"
    return 0
  fi
  # sed/awk 兜底
  local line port
  line=$(scan_inbounds | awk -F'|' '$2==1 && $3==0 {print; exit}') || true
  [ -n "$line" ] || return 1
  port=$(printf '%s\n' "$line" | cut -d'|' -f1)
  port=${port:-443}
  echo "$port"
  return 0
}


# 输出 H3 inbound 的 dest（形如 host:443）；失败返回 1
get_h3_dest() {
  if command -v jq >/dev/null 2>&1; then
    local dest
    dest=$(jq -r '[.inbounds[] | select(.streamSettings.network == "xhttp" and (
          ((.streamSettings.realitySettings.alpn // []) | index("h3")) or
          (.streamSettings.realitySettings | has("fallbackDest")) or
          (.streamSettings.realitySettings.fallbackDestRoutes != null))) | .streamSettings.realitySettings.dest][0] // empty' "$CONFIG_PATH" 2>/dev/null) || true
    [ -n "$dest" ] || return 1
    echo "$dest"
    return 0
  fi
  # sed/awk 兜底
  local line dest
  line=$(scan_inbounds | awk -F'|' '$3==1 {print; exit}') || true
  [ -n "$line" ] || return 1
  dest=$(printf '%s\n' "$line" | cut -d'|' -f8)
  [ -n "$dest" ] || return 1
  echo "$dest"
  return 0
}

# 输出 H3 inbound 的 serverNames 全部元素（空格分隔，顺序同配置）
get_h3_server_names() {
  if command -v jq >/dev/null 2>&1; then
    jq -r '[.inbounds[] | select(.streamSettings.network == "xhttp" and (
          ((.streamSettings.realitySettings.alpn // []) | index("h3")) or
          (.streamSettings.realitySettings | has("fallbackDest")) or
          (.streamSettings.realitySettings.fallbackDestRoutes != null))) | .streamSettings.realitySettings.serverNames][0] // [] | join(" ")' "$CONFIG_PATH" 2>/dev/null || true
    return 0
  fi
  # sed/awk 兜底：解析 H3 inbound 范围内 serverNames 数组的全部元素
  local range start end names
  range=$(scan_h3_range) || true
  [ -n "$range" ] || return 1
  start=${range%%|*}; end=${range##*|}
  names=$(sed -n "${start},${end}p" "$CONFIG_PATH" | awk '
    /"serverNames"[[:space:]]*:[[:space:]]*\[/ { in_sn = 1; next }
    in_sn && /^[[:space:]]*"/ {
      v = $0
      sub(/^[[:space:]]*"/, "", v)
      sub(/"[[:space:]]*,?[[:space:]]*$/, "", v)
      printf "%s%s", (n ? " " : ""), v
      n++
      next
    }
    in_sn && /]/ { in_sn = 0 }
  ')
  echo "$names"
  return 0
}

# 输出 H3 inbound 的 fallbackDestRoutes 条目数（手动高级配置；无路由表时输出 0）
get_h3_route_count() {
  if command -v jq >/dev/null 2>&1; then
    local n
    n=$(jq -r '[.inbounds[] | select(.streamSettings.network == "xhttp" and (
          ((.streamSettings.realitySettings.alpn // []) | index("h3")) or
          (.streamSettings.realitySettings | has("fallbackDest")) or
          (.streamSettings.realitySettings.fallbackDestRoutes != null))) | .streamSettings.realitySettings.fallbackDestRoutes][0] | length' "$CONFIG_PATH" 2>/dev/null) || true
    echo "${n:-0}"
    return 0
  fi
  # sed/awk 兜底：统计 H3 inbound 范围内路由条目数
  local range start end n
  range=$(scan_h3_range) || true
  [ -n "$range" ] || return 1
  start=${range%%|*}; end=${range##*|}
  n=$(sed -n "${start},${end}p" "$CONFIG_PATH" | awk '
    /"fallbackDestRoutes"[[:space:]]*:[[:space:]]*\{/ { in_routes = 1; next }
    in_routes && /^[[:space:]]*\}/ { exit }
    in_routes && /^[[:space:]]*"/ { n++ }
    END { print n + 0 }
  ')
  echo "${n:-0}"
  return 0
}

# 输出 H3 inbound 的 fallbackDestRoutes 全部条目（手动高级配置；
# 每行 key<TAB>value，按 key 排序；无路由表时输出为空）
get_h3_routes() {
  if command -v jq >/dev/null 2>&1; then
    jq -r '[.inbounds[] | select(.streamSettings.network == "xhttp" and (
          ((.streamSettings.realitySettings.alpn // []) | index("h3")) or
          (.streamSettings.realitySettings | has("fallbackDest")) or
          (.streamSettings.realitySettings.fallbackDestRoutes != null))) | .streamSettings.realitySettings.fallbackDestRoutes][0] | to_entries[] | (.key + "\t" + .value)' "$CONFIG_PATH" 2>/dev/null || true
    return 0
  fi
  # sed/awk 兜底：解析 H3 inbound 范围内路由条目并按 key 排序（与旧 python 行为一致）
  local range start end
  range=$(scan_h3_range) || true
  [ -n "$range" ] || return 1
  start=${range%%|*}; end=${range##*|}
  sed -n "${start},${end}p" "$CONFIG_PATH" | awk '
    /"fallbackDestRoutes"[[:space:]]*:[[:space:]]*\{/ { in_routes = 1; next }
    in_routes && /^[[:space:]]*\}/ { exit }
    in_routes && /^[[:space:]]*"/ {
      line = $0
      k = line; sub(/^[[:space:]]*"/, "", k); sub(/"[[:space:]]*:.*$/, "", k)
      v = line; sub(/^[^:]*:[[:space:]]*"/, "", v); sub(/"[[:space:]]*,?[[:space:]]*$/, "", v)
      print k "\t" v
    }
  ' | LC_ALL=C sort
}
