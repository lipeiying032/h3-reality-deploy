#!/usr/bin/env bash
# =============================================================================
# deploy-h3-sni.sh — H3 REALITY SNI 一键部署脚本（服务端，自包含引导版）
#
# 功能：
#   1. 交互输入 SNI（默认 ea.com，q/quit 退出）
#   2. 校验域名格式 + DNS 解析
#   3. 探针测试该 SNI 的 HTTP/3 支持：任何 HTTP 响应 = 支持；
#      超时 / CRYPTO_ERROR = 不支持 → 红色拒绝并建议换 SNI（最多 5 次）
#   4. 探针自给自足（使用者无需预装 Go）：
#      ① 同目录 probe-h3-sni 二进制
#      ② 同目录 probe-h3-sni.go + 系统有 go → 自动 go build
#      ③ 都没有 → 从 GitHub Release 下载预编译二进制
#      ④ 下载失败 → 黄色警告 + 手动获取方式（脚本已内嵌源码，需 Go 1.22+ 编译）
#   5. xray-h3 fork 内核自动检测：
#      /opt/xray/xray-linux-amd64 → /usr/local/bin/xray → PATH 中的 xray；
#      找不到 → 黄色警告 + 两种引导（①联系作者 ②官方内核 H2 降级模式）
#   6. server.json 自动生成（不存在时）：8443 H2 + 8446 H3 双 inbound，
#      UUID/privateKey/publicKey/shortId 自动生成；已存在 → 只改 8446 的
#      dest/serverNames/fallbackDestRoutes[SNI]（其余条目不动）
#   7. systemd 服务自动创建（xray-h3.service 不存在时），已存在只 restart
#   8. 端口冲突检测（8446 UDP / 8443 TCP，被非 xray 进程占用时黄色警告 + 确认）
#   9. 部署后输出完整 VLESS 分享链接（vless://...，含 sni/host/pbk/sid/fp/type）
#
# 说明：
#   - 已有配置时只改 8446 inbound，绝不触碰 8443 / 8445
#   - 内核路径/配置路径自动检测（默认保留 /opt/xray 为首选），均通过变量传递
#   - 非 root 自动用 sudo 重执行（已 root 则跳过）
#   - JSON 编辑优先 python3，其次 jq
#   - 中文输出，红=错误/拒绝，绿=成功，黄=警告
# =============================================================================

set -u
set -o pipefail

# ---------------- 颜色 ----------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

red()    { printf "${RED}%s${NC}\n" "$*"; }
green()  { printf "${GREEN}%s${NC}\n" "$*"; }
yellow() { printf "${YELLOW}%s${NC}\n" "$*"; }

# ---------------- 路径与常量 ----------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROBE="$SCRIPT_DIR/probe-h3-sni"
PROBE_SRC="$SCRIPT_DIR/probe-h3-sni.go"
PROBE_MOD_DIR="$SCRIPT_DIR/probe-mod"
PROBE_RELEASE_URL="https://github.com/lipeiying032/h3-reality-deploy/releases/latest/download/probe-h3-sni-linux-amd64"
XRAY_BIN=""
CONFIG_PATH=""
SERVICE=xray-h3
UNIT_FILE=/etc/systemd/system/xray-h3.service
H2_PORT=8443
H3_PORT=8446
PROBE_TIMEOUT=12s
MAX_ATTEMPTS=5
DEGRADED=0
CONFIG_GENERATED=0
sni=""
probe_out=""
TS=""
BACKUP=""
UUID=""
PRIVATE_KEY=""
PUBLIC_KEY=""
SHORT_ID=""

# 已知支持 H3 的建议 SNI 列表（2026-08 实测）
SUGGEST_SNIS="ea.com google.com www.google.com youtube.com www.youtube.com
facebook.com www.facebook.com cloudflare-quic.com cdn.cloudflare.steamstatic.com
steampipe.akamaized.net eaassets-a.akamaihd.net ubisoft.com www.epicgames.com
www.nintendo.com www.xbox.com"

# ---------------- 工具函数 ----------------
die() { red "错误: $*"; exit 1; }

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

# 非 root → sudo 重执行
if [ "$(id -u)" -ne 0 ]; then
  if command -v sudo >/dev/null 2>&1; then
    yellow "当前用户非 root，使用 sudo 重新执行..."
    exec sudo bash "$0" "$@"
  else
    die "需要 root 权限（且未找到 sudo），请用 root 运行本脚本"
  fi
fi

# DNS 解析：getent → dig → host，返回第一个 IPv4 或失败
resolve_ip() {
  local host="$1" ip=""
  if command -v getent >/dev/null 2>&1; then
    ip=$(getent ahostsv4 "$host" 2>/dev/null | awk 'NR==1{print $1}')
    [ -z "$ip" ] && ip=$(getent ahosts "$host" 2>/dev/null | awk 'NR==1{print $1}')
  fi
  if [ -z "$ip" ] && command -v dig >/dev/null 2>&1; then
    ip=$(dig +short A "$host" 2>/dev/null | grep -E '^[0-9.]+$' | head -n1)
  fi
  if [ -z "$ip" ] && command -v host >/dev/null 2>&1; then
    ip=$(host -t A "$host" 2>/dev/null | awk '/has address/{print $NF; exit}')
  fi
  [ -n "$ip" ] && { echo "$ip"; return 0; }
  return 1
}

# 域名格式校验（简单正则：至少两段，字母/数字/连字符）
valid_domain() {
  echo "$1" | grep -qE '^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)+$'
}

# 内嵌探针源码（与仓库根目录 probe-h3-sni.go 保持同步）
EMBEDDED_PROBE_SRC='// probe-h3-sni 是一个极简 HTTP/3 (QUIC) 支持探测工具，用于在部署 H3 REALITY
// 节点前确认某个 SNI 是否真的有 H3 端点，以及部署后用 -addr 指向本机 8446
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
	addr := flag.String("addr", "", "可选：要连接的 host:port（例如 127.0.0.1:8446 用于 relay 闭环验证）；为空则直连 https://<sni>/")
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
  local tmpdir rc
  if [ -f "$PROBE_MOD_DIR/go.mod" ] && [ -f "$PROBE_MOD_DIR/main.go" ]; then
    (
      cd "$PROBE_MOD_DIR" || exit 1
      CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags '-s -w' -o "$PROBE" . || exit 1
    )
    [ -x "$PROBE" ] && { green "探针编译成功（probe-mod）: $PROBE"; return 0; }
  fi
  tmpdir=$(mktemp -d)
  if [ -f "$PROBE_SRC" ]; then
    cp "$PROBE_SRC" "$tmpdir/main.go"
  else
    printf '%s\n' "$EMBEDDED_PROBE_SRC" > "$tmpdir/main.go"
  fi
  (
    cd "$tmpdir" || exit 1
    go mod init probe-h3-sni >/dev/null 2>&1 || exit 1
    go mod tidy >/dev/null 2>&1 || exit 1
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags '-s -w' -o "$PROBE" . || exit 1
  )
  rc=$?
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

# 确保探针可用：
#   ① 同目录二进制 → ② 同目录源码 + go 编译 → ③ Release 下载 → ④ 内嵌源码提示
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

# ---------------- xray 内核检测 ----------------
# 检测顺序：/opt/xray/xray-linux-amd64 → /usr/local/bin/xray → PATH 中 xray
detect_xray() {
  local cand v
  XRAY_BIN=""
  for cand in /opt/xray/xray-linux-amd64 /usr/local/bin/xray; do
    if [ -x "$cand" ]; then
      XRAY_BIN="$cand"
      break
    fi
  done
  if [ -z "$XRAY_BIN" ] && command -v xray >/dev/null 2>&1; then
    XRAY_BIN="$(command -v xray)"
  fi
  if [ -n "$XRAY_BIN" ]; then
    v=$("$XRAY_BIN" version 2>/dev/null | head -n1)
    if [ -n "$v" ]; then
      green "检测到 xray 内核: $XRAY_BIN"
      yellow "  版本: $v"
      return 0
    fi
    yellow "警告: $XRAY_BIN 存在但无法执行（架构不匹配或文件损坏），按未检测到处理"
    XRAY_BIN=""
  fi
  return 1
}

# 确认内核是 fork（支持 H3）还是官方（降级 H2）
confirm_kernel_mode() {
  local ans
  # /opt/xray/xray-linux-amd64 是本项目 fork 内核的默认安装路径
  if [ "$XRAY_BIN" = "/opt/xray/xray-linux-amd64" ]; then
    green "该内核位于本项目 fork 内核默认路径，按 H3 fork 内核处理"
    return 0
  fi
  yellow "注意: 未在 /opt/xray 找到本项目 fork 内核，检测到的是: $XRAY_BIN"
  printf "该二进制是否为 xray-h3 fork 内核（支持 H3/QUIC REALITY）？[y/N]: "
  read -r ans || { echo; die "读取输入失败"; }
  case "$ans" in
    y|Y)
      green "按 H3 fork 内核处理: $XRAY_BIN"
      ;;
    *)
      DEGRADED=1
      yellow "已选择官方内核降级模式：只部署 H2（8443）节点，跳过 H3 部分"
      ;;
  esac
}

# 未检测到内核时的引导（①联系作者 ②官方内核 H2 降级）
no_kernel_guide() {
  local ans cand
  echo
  yellow "=========== 检测不到 xray-h3 fork 内核 ==========="
  yellow "本项目不打包内核（避免暴露防探测细节），需要你自行准备："
  yellow "  ① 联系作者获取 xray-h3 fork 内核（或自行构建），放到 /opt/xray/xray-linux-amd64"
  yellow "  ② 若你已安装官方 xray 内核，可先用降级模式部署 H2 节点（只输出 H2 配置+客户端链接）"
  echo
  printf "你已安装官方 xray 内核（如 /usr/local/bin/xray 或 PATH 中的 xray）吗？[y/N]: "
  read -r ans || { echo; die "读取输入失败"; }
  case "$ans" in
    y|Y)
      for cand in /usr/local/bin/xray /usr/bin/xray /usr/local/x-ui/bin/xray-linux-amd64; do
        if [ -x "$cand" ]; then
          XRAY_BIN="$cand"
          break
        fi
      done
      if [ -z "$XRAY_BIN" ] && command -v xray >/dev/null 2>&1; then
        XRAY_BIN="$(command -v xray)"
      fi
      if [ -z "$XRAY_BIN" ]; then
        red "仍未找到官方 xray 内核。请先安装官方 xray 或获取 fork 内核后再运行本脚本。"
        red "H3（8446）节点必须使用 xray-h3 fork 内核，官方内核不支持 H3/QUIC REALITY。"
        exit 1
      fi
      DEGRADED=1
      green "使用官方内核降级模式: $XRAY_BIN（仅 H2 8443，跳过 H3 部分）"
      ;;
    *)
      red "未部署任何内核。H3（8446）节点必须使用 xray-h3 fork 内核，请联系作者获取。"
      exit 1
      ;;
  esac
}

# ---------------- 配置路径检测 ----------------
# 默认保留 /opt/xray/server.json 为首选；找不到已有配置时用它作为待生成路径
detect_config_path() {
  CONFIG_PATH=""
  if [ -f /opt/xray/server.json ]; then
    CONFIG_PATH=/opt/xray/server.json
  elif [ -f /usr/local/etc/xray/config.json ]; then
    CONFIG_PATH=/usr/local/etc/xray/config.json
  else
    CONFIG_PATH=/opt/xray/server.json
  fi
}

# ---------------- 端口冲突检测 ----------------
# 检查 8446 UDP 与 8443 TCP；被非 xray 进程占用 → 黄色警告 + 询问（默认继续）
check_port_conflicts() {
  local warn=0 line ans
  if ! command -v ss >/dev/null 2>&1; then
    yellow "警告: 未找到 ss，跳过端口冲突检测"
    return 0
  fi
  line=$(ss -ulnp 2>/dev/null | grep ":${H3_PORT} " || true)
  if [ -n "$line" ]; then
    echo "$line" | grep -q "xray" || warn=1
  fi
  line=$(ss -tlnp 2>/dev/null | grep ":${H2_PORT} " || true)
  if [ -n "$line" ]; then
    echo "$line" | grep -q "xray" || warn=1
  fi
  if [ "$warn" -eq 1 ]; then
    yellow "警告: 检测到以下端口被非 xray 进程占用："
    ss -ulnp 2>/dev/null | grep ":${H3_PORT} " | sed 's/^/  UDP /' || true
    ss -tlnp 2>/dev/null | grep ":${H2_PORT} " | sed 's/^/  TCP /' || true
    yellow "脚本继续后 xray 将绑定 8446/8443（覆盖端口说明：若占用进程不释放，绑定会失败）"
    printf "是否继续？[Y/n] "
    read -r ans || { echo; die "读取输入失败"; }
    case "$ans" in
      n|N) die "用户取消，未做任何修改" ;;
    esac
  fi
}

# ---------------- 交互输入 SNI（fork 完整模式：格式 + DNS + H3 探测 + 拒绝循环） ----------------
input_sni_fork() {
  local attempt=0 input
  sni=""
  while [ "$attempt" -lt "$MAX_ATTEMPTS" ]; do
    attempt=$((attempt + 1))
    printf "请输入 SNI（直接回车默认 ea.com，q/quit 退出）[%d/%d]: " "$attempt" "$MAX_ATTEMPTS"
    read -r input || { echo; die "读取输入失败"; }
    input=$(echo "${input:-ea.com}" | tr 'A-Z' 'a-z' | xargs)
    case "$input" in
      q|quit) echo "已退出，未做任何修改。"; exit 1 ;;
    esac
    sni="$input"

    # 1. 域名格式
    if ! valid_domain "$sni"; then
      red "SNI 格式不合法（示例: ea.com / www.google.com）"
      continue
    fi
    # 2. DNS 解析
    if ! resolve_ip "$sni" >/dev/null; then
      red "DNS 解析失败: $sni（请检查域名是否真实存在）"
      continue
    fi
    # 3. H3 支持测试（直连 https://<SNI>/）
    yellow "正在测试 $sni 的 HTTP/3 支持（最长 ${PROBE_TIMEOUT}）..."
    probe_out=$("$PROBE" -sni "$sni" -timeout "$PROBE_TIMEOUT" 2>&1)
    probe_rc=$?
    if [ "$probe_rc" -eq 0 ]; then
      green "SNI 支持 H3: $sni"
      green "探测结果（握手状态码）: $probe_out"
      return 0
    fi
    red "该 SNI 不支持 H3，已拒绝部署: $sni"
    red "探测结果: $probe_out"
    yellow "建议换用以下实测支持 H3 的 SNI："
    printf "${YELLOW}  %s${NC}\n" $SUGGEST_SNIS
    sni=""
    if [ "$attempt" -ge "$MAX_ATTEMPTS" ]; then
      red "连续 $MAX_ATTEMPTS 次未通过，退出。"
      exit 1
    fi
  done
}

# 降级模式 SNI 输入（只校验格式 + DNS，跳过 H3 探测）
input_sni_degraded() {
  local attempt=0 input
  sni=""
  while [ "$attempt" -lt 3 ]; do
    attempt=$((attempt + 1))
    printf "请输入 H2 节点的 serverName（直接回车默认 ea.com，q/quit 退出）[%d/3]: " "$attempt"
    read -r input || { echo; die "读取输入失败"; }
    input=$(echo "${input:-ea.com}" | tr 'A-Z' 'a-z' | xargs)
    case "$input" in
      q|quit) echo "已退出，未做任何修改。"; exit 1 ;;
    esac
    sni="$input"
    if ! valid_domain "$sni"; then
      red "SNI 格式不合法（示例: ea.com / www.google.com）"
      continue
    fi
    if ! resolve_ip "$sni" >/dev/null; then
      red "DNS 解析失败: $sni（请检查域名是否真实存在）"
      continue
    fi
    green "serverName 使用: $sni（降级模式跳过 H3 探测）"
    return 0
  done
}

# ---------------- 密钥生成（用检测到的内核二进制） ----------------
gen_keys() {
  local out
  out=$("$XRAY_BIN" x25519 2>/dev/null)
  PRIVATE_KEY=$(echo "$out" | awk '/^PrivateKey:/{print $2}')
  PUBLIC_KEY=$(echo "$out" | awk '/^Password/{print $NF}')
  UUID=$("$XRAY_BIN" uuid 2>/dev/null | head -n1)
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

# ---------------- 配置生成（fork 模式：8443 H2 + 8446 H3 最小可运行模板） ----------------
generate_fork_config() {
  local conf_dir
  conf_dir=$(dirname "$CONFIG_PATH")
  mkdir -p "$conf_dir" || die "无法创建配置目录 $conf_dir"
  python3 - "$CONFIG_PATH" "$UUID" "$PRIVATE_KEY" "$SHORT_ID" "$sni" <<'PYEOF' || die "配置模板生成失败"
import json, sys
conf, uuid, priv, sid, sni = sys.argv[1:6]
routes = {
    "www.apple.com": "www.apple.com:443",
    "apple.com": "apple.com:443",
    "google.com": "google.com:443",
    "www.google.com": "www.google.com:443",
    "youtube.com": "youtube.com:443",
    "www.youtube.com": "www.youtube.com:443",
    "facebook.com": "facebook.com:443",
    "www.facebook.com": "www.facebook.com:443",
    "cloudflare-quic.com": "cloudflare-quic.com:443",
    "cdn.cloudflare.steamstatic.com": "cdn.cloudflare.steamstatic.com:443",
    "steampipe.akamaized.net": "steampipe.akamaized.net:443",
    "ea.com": "ea.com:443",
    "eaassets-a.akamaihd.net": "eaassets-a.akamaihd.net:443",
    "ubisoft.com": "ubisoft.com:443",
    "www.epicgames.com": "www.epicgames.com:443",
    "www.nintendo.com": "www.nintendo.com:443",
    "www.xbox.com": "www.xbox.com:443",
}
routes.pop(sni, None)   # 避免与占位 SNI 重复
routes[sni] = sni + ":443"
cfg = {
    "log": {"loglevel": "warning"},
    "inbounds": [
        {
            "listen": "0.0.0.0",
            "port": 8443,
            "protocol": "vless",
            "settings": {
                "clients": [{"id": uuid, "flow": ""}],
                "decryption": "none",
            },
            "streamSettings": {
                "network": "xhttp",
                "security": "reality",
                "xhttpSettings": {
                    "mode": "stream-one",
                    "path": "/v1/collect",
                    "noGRPCHeader": True,
                },
                "realitySettings": {
                    "show": False,
                    "dest": sni + ":443",
                    "serverNames": [sni],
                    "privateKey": priv,
                    "shortIds": [sid],
                    "fingerprint": "chrome",
                },
            },
        },
        {
            "listen": "0.0.0.0",
            "port": 8446,
            "protocol": "vless",
            "settings": {
                "clients": [{"id": uuid, "flow": ""}],
                "decryption": "none",
            },
            "streamSettings": {
                "network": "xhttp",
                "security": "reality",
                "sockopt": {
                    "customSockopt": [
                        {"system": "linux", "network": "udp", "level": "1", "opt": "8", "value": "8388608", "type": "int"},
                        {"system": "linux", "network": "udp", "level": "1", "opt": "7", "value": "8388608", "type": "int"},
                    ]
                },
                "xhttpSettings": {
                    "mode": "stream-one",
                    "enableH3": True,
                    "path": "/v1/collect",
                    "noGRPCHeader": True,
                    "headers": {
                        "accept-encoding": "gzip, deflate, br, zstd",
                        "content-type": "application/octet-stream",
                        "dnt": "",
                    },
                    "xPaddingBytes": "32-96",
                    "xPaddingObfsMode": True,
                    "xPaddingPlacement": "query",
                    "xPaddingKey": "cb",
                    "xPaddingMethod": "tokenish",
                },
                "realitySettings": {
                    "show": False,
                    "dest": sni + ":443",
                    "serverNames": [sni],
                    "privateKey": priv,
                    "shortIds": [sid],
                    "fingerprint": "chrome",
                    "alpn": ["h3"],
                    "fallbackDest": "cloudflare-quic.com:443",
                    "fallbackDestRoutes": routes,
                },
                "finalmask": {
                    "quicParams": {
                        "congestion": "bbr",
                        "bbrProfile": "aggressive",
                        "initStreamReceiveWindow": 4194304,
                        "maxStreamReceiveWindow": 16777216,
                        "initConnectionReceiveWindow": 8388608,
                        "maxConnectionReceiveWindow": 67108864,
                        "maxIdleTimeout": 60,
                        "keepAlivePeriod": 30,
                        "maxIncomingStreams": 1000,
                    }
                },
            },
        },
    ],
    "outbounds": [
        {"protocol": "freedom", "tag": "direct"},
        {"protocol": "blackhole", "tag": "blocked"},
    ],
}
with open(conf, "w", encoding="utf-8") as f:
    json.dump(cfg, f, ensure_ascii=False, indent=2)
    f.write("\n")
print("OK: 已生成最小可运行配置（8443 H2 + 8446 H3）")
PYEOF
  green "配置已生成: $CONFIG_PATH"
}

# ---------------- 配置生成（降级模式：仅 8443 H2 + 自签证书） ----------------
generate_degraded_config() {
  local conf_dir cert key
  conf_dir=$(dirname "$CONFIG_PATH")
  mkdir -p "$conf_dir" || die "无法创建配置目录 $conf_dir"
  cert="$conf_dir/selfsigned.crt"
  key="$conf_dir/selfsigned.key"
  if [ ! -f "$cert" ] || [ ! -f "$key" ]; then
    if command -v openssl >/dev/null 2>&1; then
      yellow "降级模式使用自签证书（官方内核不支持本项目 fork 的 dest 真证书伪装）："
      openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
        -keyout "$key" -out "$cert" \
        -subj "/CN=localhost" \
        -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" >/dev/null 2>&1 \
        || die "自签证书生成失败"
      green "自签证书已生成: $cert"
    else
      die "降级模式需要 openssl 生成自签证书（或先自行提供证书），请安装 openssl 后重试"
    fi
  fi
  python3 - "$CONFIG_PATH" "$UUID" "$cert" "$key" <<'PYEOF' || die "降级配置生成失败"
import json, sys
conf, uuid, cert, key = sys.argv[1:5]
cfg = {
    "log": {"loglevel": "warning"},
    "inbounds": [
        {
            "listen": "0.0.0.0",
            "port": 8443,
            "protocol": "vless",
            "settings": {
                "clients": [{"id": uuid, "flow": ""}],
                "decryption": "none",
            },
            "streamSettings": {
                "network": "xhttp",
                "security": "tls",
                "tlsSettings": {
                    "certificates": [
                        {"certificateFile": cert, "keyFile": key}
                    ]
                },
                "xhttpSettings": {
                    "mode": "stream-one",
                    "path": "/v1/collect",
                    "noGRPCHeader": True,
                },
            },
        }
    ],
    "outbounds": [
        {"protocol": "freedom", "tag": "direct"},
        {"protocol": "blackhole", "tag": "blocked"},
    ],
}
with open(conf, "w", encoding="utf-8") as f:
    json.dump(cfg, f, ensure_ascii=False, indent=2)
    f.write("\n")
print("OK: 已生成 H2 降级配置（仅 8443）")
PYEOF
  green "配置已生成: $CONFIG_PATH"
  yellow "警告: 降级模式使用自签证书（非 REALITY 伪装），仅作为临时 H2 节点；"
  yellow "      正式 H3 部署仍需要 xray-h3 fork 内核。"
}

# ---------------- 已有配置：只改 8446 inbound 的 dest/serverNames/fallbackDestRoutes[SNI] ----------------
edit_existing_config() {
  TS=$(date +%Y%m%d-%H%M%S)
  BACKUP="$CONFIG_PATH.bak-sni-$sni-$TS"
  cp -a "$CONFIG_PATH" "$BACKUP" || die "备份失败"
  green "已备份: $BACKUP"

  yellow "修改 $CONFIG_PATH 的 8446 inbound: dest=$sni:443 serverNames=[$sni] fallbackDestRoutes[$sni]=$sni:443"

  local edit_ok=0
  if command -v python3 >/dev/null 2>&1; then
    python3 - "$CONFIG_PATH" "$sni" <<'PYEOF'
import json, os, sys
conf, sni = sys.argv[1], sys.argv[2]
with open(conf, encoding="utf-8") as f:
    cfg = json.load(f)
ib = None
for x in cfg.get("inbounds", []):
    if x.get("port") == 8446:
        ib = x
        break
if ib is None:
    print("ERROR: 未找到 port=8446 的 inbound", file=sys.stderr)
    sys.exit(3)
ss = ib.setdefault("streamSettings", {})
rs = ss.setdefault("realitySettings", {})
rs["dest"] = sni + ":443"
rs["serverNames"] = [sni]
routes = rs.setdefault("fallbackDestRoutes", {})
routes[sni] = sni + ":443"
tmp = conf + ".tmp"
with open(tmp, "w", encoding="utf-8") as f:
    json.dump(cfg, f, ensure_ascii=False, indent=2)
    f.write("\n")
os.replace(tmp, conf)
print("OK: 已更新 8446 inbound（其余 inbound 与路由条目未动）")
PYEOF
    [ $? -eq 0 ] && edit_ok=1
  elif command -v jq >/dev/null 2>&1; then
    jq --arg sni "$sni" '
      .inbounds = [ .inbounds[] | if .port == 8446 then
        .streamSettings.realitySettings.dest = ($sni + ":443")
        | .streamSettings.realitySettings.serverNames = [$sni]
        | .streamSettings.realitySettings.fallbackDestRoutes[$sni] = ($sni + ":443")
      else . end ]' "$CONFIG_PATH" > "$CONFIG_PATH.tmp" && mv "$CONFIG_PATH.tmp" "$CONFIG_PATH" && edit_ok=1
  fi
  if [ "$edit_ok" -ne 1 ]; then
    rollback
    die "修改配置失败，已回滚"
  fi
}

# ---------------- 从已有配置提取客户端参数（UUID/privateKey/shortId → publicKey） ----------------
extract_client_params() {
  local port="$1" out uuid priv sid pk
  out=$(python3 - "$CONFIG_PATH" "$port" <<'PYEOF' || true
import json, sys
conf, port = sys.argv[1], int(sys.argv[2])
cfg = json.load(open(conf, encoding="utf-8"))
for ib in cfg.get("inbounds", []):
    if ib.get("port") == port:
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
    pk=$("$XRAY_BIN" x25519 -i "$PRIVATE_KEY" 2>/dev/null | awk '/^Password/{print $NF}')
    [ -n "$pk" ] && PUBLIC_KEY="$pk"
  fi
}

# ---------------- systemd 服务（不存在则创建，ExecStart 不一致则更新） ----------------
ensure_service() {
  local need_create=0 need_update=0
  if [ ! -f "$UNIT_FILE" ]; then
    need_create=1
  else
    if ! grep -q "ExecStart=.*$(basename "$XRAY_BIN")" "$UNIT_FILE" 2>/dev/null || \
       ! grep -q -- "$CONFIG_PATH" "$UNIT_FILE" 2>/dev/null; then
      need_update=1
    fi
  fi
  if [ "$need_create" -eq 1 ] || [ "$need_update" -eq 1 ]; then
    if [ "$need_update" -eq 1 ]; then
      yellow "警告: 现有 $UNIT_FILE 的 ExecStart 与当前内核/配置不一致，将更新为:"
      yellow "  $XRAY_BIN run -c $CONFIG_PATH"
    fi
    cat > "$UNIT_FILE" <<EOF
[Unit]
Description=Xray Reality H3 Server
After=network.target

[Service]
Type=simple
ExecStart=$XRAY_BIN run -c $CONFIG_PATH
Restart=on-failure
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload >/dev/null 2>&1 || true
    systemctl enable "$SERVICE" >/dev/null 2>&1 || true
    green "systemd 服务已创建/更新: $UNIT_FILE"
  else
    green "systemd 服务已存在: $UNIT_FILE（只做 restart）"
  fi
}

# 回滚：新生成的配置 → 移除；编辑的配置 → 恢复备份
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

# 公网 IP 检测（hostname -I → ip route → 手动输入）
get_server_ip() {
  local ip=""
  if command -v hostname >/dev/null 2>&1; then
    ip=$(hostname -I 2>/dev/null | awk '{print $1}')
  fi
  if [ -z "$ip" ] && command -v ip >/dev/null 2>&1; then
    ip=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '/src/{print $7; exit}')
  fi
  if [ -z "$ip" ]; then
    printf "无法自动检测公网 IP，请手动输入: "
    read -r ip || { echo; die "读取输入失败"; }
  fi
  echo "$ip"
}

# ---------------- 主流程 ----------------
command -v systemctl >/dev/null 2>&1 || die "未找到 systemctl"
command -v python3 >/dev/null 2>&1 || command -v jq >/dev/null 2>&1 \
  || die "需要 python3 或 jq 来编辑 JSON"

# 1. 内核检测与模式确认
detect_xray
if [ -z "$XRAY_BIN" ]; then
  no_kernel_guide
else
  confirm_kernel_mode
fi

# 2. 配置路径 + 端口冲突
detect_config_path
check_port_conflicts

# 3. SNI 输入
if [ "$DEGRADED" -eq 1 ]; then
  gen_keys
  input_sni_degraded
else
  ensure_probe
  input_sni_fork
fi

# 4. 配置准备（已有配置 → 只改 8446；没有 → 自动生成）
if [ -f "$CONFIG_PATH" ]; then
  if [ "$DEGRADED" -eq 1 ]; then
    yellow "已存在 $CONFIG_PATH，降级模式跳过配置生成，直接使用现有配置"
  else
    # 确认现有 8446 inbound 结构正常
    python3 - "$CONFIG_PATH" <<'PYEOF' || die "8446 inbound 结构异常，拒绝继续"
import json, sys
cfg = json.load(open(sys.argv[1], encoding="utf-8"))
for ib in cfg.get("inbounds", []):
    if ib.get("port") == 8446:
        rs = ib.get("streamSettings", {}).get("realitySettings")
        if not rs:
            print("ERROR: 8446 inbound 未配置 realitySettings", file=sys.stderr)
            sys.exit(1)
        print("OK: 8446 inbound 存在，realitySettings 正常")
        sys.exit(0)
print("ERROR: 未找到 port=8446 的 inbound", file=sys.stderr)
sys.exit(1)
PYEOF
    edit_existing_config
  fi
else
  if [ "$DEGRADED" -eq 1 ]; then
    generate_degraded_config
  else
    gen_keys
    generate_fork_config
  fi
  CONFIG_GENERATED=1
fi

# 5. 配置校验（run -test）
yellow "校验配置: $XRAY_BIN run -test -c $CONFIG_PATH"
if ! "$XRAY_BIN" run -test -c "$CONFIG_PATH" >/dev/null 2>&1; then
  rollback
  die "配置校验失败，已回滚"
fi
green "配置校验通过"

# 6. systemd 服务 + 重启
ensure_service
yellow "重启服务: systemctl restart $SERVICE"
if ! systemctl restart "$SERVICE" >/dev/null 2>&1; then
  rollback
  die "服务重启失败，已回滚"
fi
sleep 2
if [ "$(systemctl is-active "$SERVICE" 2>/dev/null)" != "active" ]; then
  rollback
  die "服务未处于 active 状态，已回滚"
fi
green "服务已重启并运行"

# 7. 验证（fork：8446 UDP 监听 + relay 闭环；降级：8443 TCP 监听）
if [ "$DEGRADED" -eq 0 ]; then
  if command -v ss >/dev/null 2>&1; then
    LISTEN_INFO=$(ss -ulnp 2>/dev/null | grep ":${H3_PORT} " || true)
  else
    LISTEN_INFO=$(netstat -ulnp 2>/dev/null | grep ":${H3_PORT} " || true)
  fi
  if [ -n "$LISTEN_INFO" ]; then
    green "8446 UDP 监听确认:"
    echo "$LISTEN_INFO" | sed 's/^/  /'
  else
    yellow "警告: 未在 ss -ulnp 输出中找到 :${H3_PORT}，请手动确认监听状态"
  fi

  yellow "relay 闭环验证: probe-h3-sni -sni $sni -addr 127.0.0.1:${H3_PORT}"
  relay_out=$("$PROBE" -sni "$sni" -addr "127.0.0.1:${H3_PORT}" -timeout 15s 2>&1)
  relay_rc=$?
  if [ "$relay_rc" -eq 0 ]; then
    green "relay 闭环验证通过（路由命中，dest 完成握手）: $relay_out"
  else
    yellow "警告: relay 闭环未通过: $relay_out"
    yellow "配置已生效。请检查 dest/$sni 的 443 是否可达、fallbackDestRoutes 是否正确。"
  fi
else
  if command -v ss >/dev/null 2>&1; then
    LISTEN_INFO=$(ss -tlnp 2>/dev/null | grep ":${H2_PORT} " || true)
  else
    LISTEN_INFO=$(netstat -tlnp 2>/dev/null | grep ":${H2_PORT} " || true)
  fi
  if [ -n "$LISTEN_INFO" ]; then
    green "8443 TCP 监听确认:"
    echo "$LISTEN_INFO" | sed 's/^/  /'
  else
    yellow "警告: 未在 ss -tlnp 输出中找到 :${H2_PORT}，请手动确认监听状态"
  fi
fi

# 8. 提取客户端参数（生成的新配置已在 gen_keys 中得到）
if [ "$CONFIG_GENERATED" -eq 0 ]; then
  if [ "$DEGRADED" -eq 1 ]; then
    extract_client_params "$H2_PORT"
  else
    extract_client_params "$H3_PORT"
  fi
fi

# 9. 输出：客户端提醒 + VLESS 分享链接
echo
green "=========== 部署完成 ==========="
if [ "$DEGRADED" -eq 1 ]; then
  echo "  模式:          官方内核 H2 降级（仅 8443，无 H3）"
  echo "  配置:          $CONFIG_PATH"
  echo "  内核:          $XRAY_BIN"
  echo "  证书:          $(dirname "$CONFIG_PATH")/selfsigned.crt（自签，客户端需 allowInsecure）"
else
  green "8446 inbound 已切换 SNI -> $sni"
  echo "  当前 dest:        $sni:443"
  echo "  当前 serverNames: [$sni]"
  echo "  路由表条目:       fallbackDestRoutes[$sni] = $sni:443（其余条目未动）"
  if [ -n "$BACKUP" ]; then
    echo "  配置备份:         $BACKUP"
  fi
fi

SERVER_IP=$(get_server_ip)
echo
yellow "=========== VLESS 分享链接（可直接导入客户端） ==========="
if [ "$DEGRADED" -eq 1 ]; then
  if [ -n "$UUID" ]; then
    echo "vless://${UUID}@${SERVER_IP}:${H2_PORT}?encryption=none&security=tls&type=xhttp&mode=stream-one&path=%2Fv1%2Fcollect&sni=${sni}&allowInsecure=1#H2-DEGRADED-${H2_PORT}"
  else
    yellow "警告: 无法生成分享链接（缺少 UUID），请从 $CONFIG_PATH 中手动提取"
  fi
else
  if [ -n "$UUID" ] && [ -n "$PUBLIC_KEY" ] && [ -n "$SHORT_ID" ]; then
    echo "vless://${UUID}@${SERVER_IP}:${H3_PORT}?encryption=none&security=reality&type=xhttp&mode=stream-one&enableH3=1&path=%2Fv1%2Fcollect&sni=$(urlencode "$sni")&fp=chrome&pbk=$(urlencode "$PUBLIC_KEY")&sid=$(urlencode "$SHORT_ID")&host=$(urlencode "$sni")&alpn=h3#H3-REALITY-${H3_PORT}"
    echo "vless://${UUID}@${SERVER_IP}:${H2_PORT}?encryption=none&security=reality&type=xhttp&mode=stream-one&path=%2Fv1%2Fcollect&sni=$(urlencode "$sni")&fp=chrome&pbk=$(urlencode "$PUBLIC_KEY")&sid=$(urlencode "$SHORT_ID")&host=$(urlencode "$sni")#H3-REALITY-H2-${H2_PORT}"
  else
    yellow "警告: 无法生成分享链接（缺少 UUID/publicKey/shortId），请从 $CONFIG_PATH 中手动提取"
  fi
fi

echo
yellow "客户端需要同步修改的参数（务必修改）："
if [ "$DEGRADED" -eq 1 ]; then
  yellow "  VLESS outbound 的 address -> $SERVER_IP，port -> ${H2_PORT}"
  yellow "  security=tls + allowInsecure=1（自签证书），path=/v1/collect"
else
  yellow "  VLESS outbound 的 realitySettings.serverName（SNI）-> $sni"
  yellow "  （同一 outbound 的 xhttpSettings / alpn=[h3] / fingerprint=chrome 不变）"
  yellow "  UUID / publicKey / shortId / 端口 见上方分享链接（与配置一致）"
fi
echo
if [ -n "$BACKUP" ]; then
  yellow "回滚方式: cp $BACKUP $CONFIG_PATH && systemctl restart $SERVICE"
fi
green "部署完成，祝使用愉快！"
