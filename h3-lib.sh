#!/usr/bin/env bash
# =============================================================================
# h3-lib.sh — H3 REALITY SNI 部署/管理公共函数库
#
# 被 deploy-h3-sni.sh 与 h3reality 共同 source：同一份逻辑、两个入口，
# 保证 SNI 校验、H3 探测、配置修改、VLESS 链接生成等核心行为完全一致。
#
# 依赖：bash 4+（mapfile）；python3 或 jq（JSON 编辑）；root 或 sudo。
# 调用方必须启用 set -euo pipefail；本库函数均兼容 set -e。
#
# 函数分组：
#   A. 输出函数       red/green/yellow/banner/die
#   B. 配置常量       路径/服务名/SNI 库/内核 URL/默认端口
#   C. 工具函数       urlencode/valid_domain/resolve_ip/port_in_use/
#                     pick_random_port/get_server_ip/require_root
#   D. SNI 库与探测   fetch_sni_list/random_sni/probe_h3/validate_sni_h3
#   E. 探针获取       ensure_probe/build_probe_from_source/download_probe_release
#   F. 内核获取       detect_xray/download_xray/build_xray_from_source
#   G. 配置操作       detect_config_path/find_h3_inbound/backup_config/
#                     update_sni_routes/add_sni_route/remove_sni_route/
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
#   XRAY_CONFIG=/path/to/server.json  覆盖配置路径
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
CONFIG_PATH="${XRAY_CONFIG:-}"
DEGRADED=0        # 1=官方内核 H2 降级模式
CONFIG_GENERATED=0 # 1=本次新生成的配置（回滚时整体移除）
sni=""
probe_out=""
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

# DNS 解析：getent → dig → host，返回第一个 IPv4 或失败
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
    if command -v python3 >/dev/null 2>&1; then
      mapfile -t SNI_LIST < <(printf '%s' "$json" | python3 -c 'import json,sys; [print(e["sni"]) for e in json.load(sys.stdin).get("snis",[])]' 2>/dev/null)
    elif command -v jq >/dev/null 2>&1; then
      mapfile -t SNI_LIST < <(printf '%s' "$json" | jq -r '.snis[].sni' 2>/dev/null)
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

# SNI 三段校验（与部署脚本完全一致）：域名格式 → DNS 解析 → H3 探测；
# 成功返回 0，失败返回 1（内部已输出红色原因）
validate_sni_h3() {
  local sni="$1"
  if ! valid_domain "$sni"; then
    red "SNI 格式不合法（示例: example.com / www.example.com）"
    return 1
  fi
  if ! resolve_ip "$sni" >/dev/null; then
    red "DNS 解析失败: $sni（请检查域名是否真实存在）"
    return 1
  fi
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

# 检测顺序：/opt/xray/xray-linux-amd64 → /usr/local/bin/xray → PATH 中 xray；
# 已通过环境变量 XRAY_BIN 指定则直接使用；找不到 → 自动获取
# （Release 预编译下载 → 仓库 core/ 源码编译兜底）；全部失败返回 1
detect_xray() {
  local cand v
  if [ -z "$XRAY_BIN" ]; then
    for cand in /opt/xray/xray-linux-amd64 /usr/local/bin/xray; do
      if [ -x "$cand" ]; then
        XRAY_BIN="$cand"
        break
      fi
    done
    if [ -z "$XRAY_BIN" ] && command -v xray >/dev/null 2>&1; then
      XRAY_BIN="$(command -v xray)"
    fi
  fi
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
  # 未检测到：自动获取（Release 预编译下载 → 源码编译兜底）
  yellow "未检测到 xray-h3 fork 内核，尝试自动获取..."
  if download_xray; then
    green "内核下载成功: $XRAY_BIN (Release 预编译)"
    return 0
  fi
  if command -v go >/dev/null 2>&1; then
    yellow "Release 下载失败，检测到 Go 环境，尝试从仓库 core/ 源码编译..."
    if build_xray_from_source; then
      green "内核编译成功: $XRAY_BIN (源码编译)"
      return 0
    fi
    yellow "源码编译失败，已清理临时目录"
  else
    yellow "Release 下载失败，且本机没有 Go 环境，无法源码编译"
  fi
  yellow "警告: 内核自动获取失败（Release 下载与源码编译均未成功），请检查网络后重试或手动准备"
  return 1
}

# ---------------- G. 配置操作 ----------------

# 配置路径检测：默认保留 /opt/xray/server.json 为首选；
# 找不到已有配置时用它作为待生成路径；XRAY_CONFIG 已指定则直接采用
detect_config_path() {
  if [ -n "$CONFIG_PATH" ]; then
    return 0
  fi
  CONFIG_PATH=""
  if [ -f /opt/xray/server.json ]; then
    CONFIG_PATH=/opt/xray/server.json
  elif [ -f /usr/local/etc/xray/config.json ]; then
    CONFIG_PATH=/usr/local/etc/xray/config.json
  else
    CONFIG_PATH=/opt/xray/server.json
  fi
}

# 校验配置中存在结构正常的 H3 inbound（network=xhttp 且 alpn 含 h3，
# 或存在 fallbackDest/fallbackDestRoutes）；0=存在，1=不存在
find_h3_inbound() {
  if command -v python3 >/dev/null 2>&1; then
    if python3 - "$CONFIG_PATH" <<'PYEOF'
import json, sys
cfg = json.load(open(sys.argv[1], encoding="utf-8"))
def is_h3_inbound(x):
    ss = x.get("streamSettings") or {}
    if ss.get("network") != "xhttp":
        return False
    rs = ss.get("realitySettings") or {}
    return "h3" in (rs.get("alpn") or []) or "fallbackDest" in rs or bool(rs.get("fallbackDestRoutes"))
for ib in cfg.get("inbounds", []):
    if is_h3_inbound(ib):
        print("OK: H3 inbound 存在，realitySettings 正常")
        sys.exit(0)
print("ERROR: 未找到 H3 inbound（network=xhttp 且 alpn 含 h3，或存在 fallbackDest/fallbackDestRoutes）", file=sys.stderr)
sys.exit(1)
PYEOF
    then
      return 0
    fi
    return 1
  fi
  if command -v jq >/dev/null 2>&1; then
    if jq -e '[.inbounds[] | select(.streamSettings.network == "xhttp" and (
          ((.streamSettings.realitySettings.alpn // []) | index("h3")) or
          (.streamSettings.realitySettings | has("fallbackDest")) or
          (.streamSettings.realitySettings.fallbackDestRoutes != null)))] | length > 0' "$CONFIG_PATH" >/dev/null 2>&1; then
      return 0
    fi
    return 1
  fi
  red "需要 python3 或 jq 来解析配置"
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

# 切换/更新当前 SNI：改 H3 inbound 的 dest、serverNames[0] 与
# fallbackDestRoutes[<sni>]（其余 inbound 与路由条目不动）；成功返回 0
update_sni_routes() {
  local sni="$1" edit_ok=0
  yellow "更新 H3 inbound: dest=$sni:443 serverNames[0]=$sni fallbackDestRoutes[$sni]=$sni:443"
  if command -v python3 >/dev/null 2>&1; then
    if python3 - "$CONFIG_PATH" "$sni" <<'PYEOF'
import json, os, sys
conf, sni = sys.argv[1], sys.argv[2]
with open(conf, encoding="utf-8") as f:
    cfg = json.load(f)
def is_h3_inbound(x):
    ss = x.get("streamSettings") or {}
    if ss.get("network") != "xhttp":
        return False
    rs = ss.get("realitySettings") or {}
    return "h3" in (rs.get("alpn") or []) or "fallbackDest" in rs or bool(rs.get("fallbackDestRoutes"))
ib = None
for x in cfg.get("inbounds", []):
    if is_h3_inbound(x):
        ib = x
        break
if ib is None:
    print("ERROR: 未找到 H3 inbound", file=sys.stderr)
    sys.exit(3)
ss = ib.setdefault("streamSettings", {})
rs = ss.setdefault("realitySettings", {})
rs["dest"] = sni + ":443"
sn = rs.get("serverNames") or []
if sn:
    sn[0] = sni
else:
    rs["serverNames"] = [sni]
routes = rs.setdefault("fallbackDestRoutes", {})
routes[sni] = sni + ":443"
tmp = conf + ".tmp"
with open(tmp, "w", encoding="utf-8") as f:
    json.dump(cfg, f, ensure_ascii=False, indent=2)
    f.write("\n")
os.replace(tmp, conf)
print("OK: 已更新 H3 inbound（其余 inbound 与路由条目未动）")
PYEOF
    then
      edit_ok=1
    fi
  elif command -v jq >/dev/null 2>&1; then
    if jq --arg sni "$sni" '
      .inbounds = [ .inbounds[] | if (.streamSettings.network == "xhttp" and
          (((.streamSettings.realitySettings.alpn // []) | index("h3")) or
           (.streamSettings.realitySettings | has("fallbackDest")) or
           (.streamSettings.realitySettings.fallbackDestRoutes != null))) then
        .streamSettings.realitySettings.dest = ($sni + ":443")
        | .streamSettings.realitySettings.serverNames[0] = $sni
        | .streamSettings.realitySettings.fallbackDestRoutes[$sni] = ($sni + ":443")
      else . end ]' "$CONFIG_PATH" > "$CONFIG_PATH.tmp" && mv "$CONFIG_PATH.tmp" "$CONFIG_PATH"
    then
      edit_ok=1
    fi
  fi
  [ "$edit_ok" -eq 1 ]
}

# 添加 SNI 到 fallbackDestRoutes（不动当前 dest/serverNames）；成功返回 0
add_sni_route() {
  local sni="$1" edit_ok=0
  yellow "添加 fallbackDestRoutes[$sni]=$sni:443（不改动当前 dest/serverNames）"
  if command -v python3 >/dev/null 2>&1; then
    if python3 - "$CONFIG_PATH" "$sni" <<'PYEOF'
import json, os, sys
conf, sni = sys.argv[1], sys.argv[2]
with open(conf, encoding="utf-8") as f:
    cfg = json.load(f)
def is_h3_inbound(x):
    ss = x.get("streamSettings") or {}
    if ss.get("network") != "xhttp":
        return False
    rs = ss.get("realitySettings") or {}
    return "h3" in (rs.get("alpn") or []) or "fallbackDest" in rs or bool(rs.get("fallbackDestRoutes"))
ib = None
for x in cfg.get("inbounds", []):
    if is_h3_inbound(x):
        ib = x
        break
if ib is None:
    print("ERROR: 未找到 H3 inbound", file=sys.stderr)
    sys.exit(3)
rs = ib.setdefault("streamSettings", {}).setdefault("realitySettings", {})
routes = rs.setdefault("fallbackDestRoutes", {})
routes[sni] = sni + ":443"
tmp = conf + ".tmp"
with open(tmp, "w", encoding="utf-8") as f:
    json.dump(cfg, f, ensure_ascii=False, indent=2)
    f.write("\n")
os.replace(tmp, conf)
print("OK: 已添加路由 " + sni + "（其余条目未动）")
PYEOF
    then
      edit_ok=1
    fi
  elif command -v jq >/dev/null 2>&1; then
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
  fi
  [ "$edit_ok" -eq 1 ]
}

# 从 fallbackDestRoutes 移除 SNI（至少保留 1 条，防误删清空路由表）；
# 目标不存在（4）或仅剩 1 条（5）时输出红色原因并返回 1
remove_sni_route() {
  local sni="$1" edit_ok=0
  yellow "删除 fallbackDestRoutes[$sni]（至少保留 1 条路由）"
  if command -v python3 >/dev/null 2>&1; then
    if python3 - "$CONFIG_PATH" "$sni" <<'PYEOF'
import json, os, sys
conf, sni = sys.argv[1], sys.argv[2]
with open(conf, encoding="utf-8") as f:
    cfg = json.load(f)
def is_h3_inbound(x):
    ss = x.get("streamSettings") or {}
    if ss.get("network") != "xhttp":
        return False
    rs = ss.get("realitySettings") or {}
    return "h3" in (rs.get("alpn") or []) or "fallbackDest" in rs or bool(rs.get("fallbackDestRoutes"))
ib = None
for x in cfg.get("inbounds", []):
    if is_h3_inbound(x):
        ib = x
        break
if ib is None:
    print("ERROR: 未找到 H3 inbound", file=sys.stderr)
    sys.exit(3)
rs = ib.setdefault("streamSettings", {}).setdefault("realitySettings", {})
routes = rs.setdefault("fallbackDestRoutes", {})
if sni not in routes:
    print("ERROR: 路由不存在: " + sni, file=sys.stderr)
    sys.exit(4)
if len(routes) <= 1:
    print("ERROR: 至少需要保留 1 条路由，拒绝删除最后一个条目: " + sni, file=sys.stderr)
    sys.exit(5)
del routes[sni]
tmp = conf + ".tmp"
with open(tmp, "w", encoding="utf-8") as f:
    json.dump(cfg, f, ensure_ascii=False, indent=2)
    f.write("\n")
os.replace(tmp, conf)
print("OK: 已移除路由 " + sni + "（其余条目未动）")
PYEOF
    then
      edit_ok=1
    fi
  elif command -v jq >/dev/null 2>&1; then
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
  out=$(python3 - "$CONFIG_PATH" "$port" <<'PYEOF' || true
import json, sys
conf, port = sys.argv[1], sys.argv[2]
cfg = json.load(open(conf, encoding="utf-8"))
def is_h3_inbound(x):
    ss = x.get("streamSettings") or {}
    if ss.get("network") != "xhttp":
        return False
    rs = ss.get("realitySettings") or {}
    return "h3" in (rs.get("alpn") or []) or "fallbackDest" in rs or bool(rs.get("fallbackDestRoutes"))
for ib in cfg.get("inbounds", []):
    if port:
        if ib.get("port") != int(port):
            continue
    else:
        if not is_h3_inbound(ib):
            continue
    rs = ib.get("streamSettings", {}).get("realitySettings", {})
    clients = ib.get("settings", {}).get("clients", [])
    uuid = clients[0]["id"] if clients else ""
    priv = rs.get("privateKey", "")
    sid = (rs.get("shortIds") or [""])[0]
    print(uuid)
    print(priv)
    print(sid)
    sys.exit(0)
sys.exit(1)
PYEOF
)
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
  if [ -z "$UUID" ] && command -v python3 >/dev/null 2>&1; then
    UUID=$(python3 -c 'import uuid;print(uuid.uuid4())')
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
  if command -v python3 >/dev/null 2>&1; then
    if python3 - "$CONFIG_PATH" <<'PYEOF'
import json, sys
cfg = json.load(open(sys.argv[1], encoding="utf-8"))
def is_h3_inbound(x):
    ss = x.get("streamSettings") or {}
    if ss.get("network") != "xhttp":
        return False
    rs = ss.get("realitySettings") or {}
    return "h3" in (rs.get("alpn") or []) or "fallbackDest" in rs or bool(rs.get("fallbackDestRoutes"))
for ib in cfg.get("inbounds", []):
    if not is_h3_inbound(ib):
        continue
    rs = ib.get("streamSettings", {}).get("realitySettings", {})
    sn = rs.get("serverNames") or []
    if sn:
        print(sn[0])
    else:
        print((rs.get("dest") or "").split(":")[0])
    sys.exit(0)
sys.exit(1)
PYEOF
    then
      return 0
    fi
    return 1
  fi
  local sni
  sni=$(jq -r '[.inbounds[] | select(.streamSettings.network == "xhttp" and (
        ((.streamSettings.realitySettings.alpn // []) | index("h3")) or
        (.streamSettings.realitySettings | has("fallbackDest")) or
        (.streamSettings.realitySettings.fallbackDestRoutes != null))) | .streamSettings.realitySettings.serverNames[0]][0] // empty' "$CONFIG_PATH" 2>/dev/null) || return 1
  [ -n "$sni" ] || return 1
  echo "$sni"
  return 0
}

# 输出 H3 inbound 的监听端口；失败返回 1
get_h3_port() {
  if command -v python3 >/dev/null 2>&1; then
    if python3 - "$CONFIG_PATH" <<'PYEOF'
import json, sys
cfg = json.load(open(sys.argv[1], encoding="utf-8"))
def is_h3_inbound(x):
    ss = x.get("streamSettings") or {}
    if ss.get("network") != "xhttp":
        return False
    rs = ss.get("realitySettings") or {}
    return "h3" in (rs.get("alpn") or []) or "fallbackDest" in rs or bool(rs.get("fallbackDestRoutes"))
for ib in cfg.get("inbounds", []):
    if is_h3_inbound(ib):
        print(ib.get("port", 443))
        sys.exit(0)
sys.exit(1)
PYEOF
    then
      return 0
    fi
    return 1
  fi
  local port
  port=$(jq -r '[.inbounds[] | select(.streamSettings.network == "xhttp" and (
        ((.streamSettings.realitySettings.alpn // []) | index("h3")) or
        (.streamSettings.realitySettings | has("fallbackDest")) or
        (.streamSettings.realitySettings.fallbackDestRoutes != null))) | .port][0] // empty' "$CONFIG_PATH" 2>/dev/null) || return 1
  [ -n "$port" ] || return 1
  echo "$port"
  return 0
}
