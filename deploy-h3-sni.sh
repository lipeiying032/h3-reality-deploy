#!/usr/bin/env bash
# =============================================================================
# deploy-h3-sni.sh — H3 REALITY SNI 一键部署脚本（服务端）
#
# 功能：
#   1. 交互输入 SNI（直接回车：从 SNI 维护库随机挑选，q/quit 退出）
#   2. 校验域名格式 + DNS 解析 + H3 探测（validate_sni_h3，与 h3reality 共用）
#   3. 探针自给自足（二进制 → 源码编译 → Release 下载，ensure_probe）
#   4. xray-h3 fork 内核自动获取（Release 下载 → core/ 源码编译兜底，detect_xray）
#   5. server.json 自动生成（不存在时）或按特征修改 H3 inbound（已存在时）
#   6. systemd 服务自动创建（xray-h3.service 不存在时），已存在只 restart
#   7. 端口冲突处理（仅新配置生成模式）：自定义/随机端口（H2_PORT/H3_PORT 可覆盖）
#   8. 部署后输出完整 VLESS 分享链接（gen_vless_link，与 h3reality link 共用）
#   9. 部署成功后自动安装便携管理命令 h3reality（幂等，install_h3reality）
#
# 公共逻辑全部在 h3-lib.sh（本脚本与 h3reality 共同 source），本文件只保留
# 交互引导与步骤编排；SNI 校验、配置修改、链接生成等核心行为两入口完全一致。
#
# 架构总览（每步 → 对应函数，[lib] 表示在 h3-lib.sh 中）：
#
#   ┌─────────────┐   ┌─────────────┐   ┌─────────────┐   ┌─────────────┐
#   │ ① 交互输入 SNI │──►│ ② SNI 验证    │──►│ ③ 内核获取    │──►│ ④ 配置生成/修改 │
#   └─────────────┘   └─────────────┘   └─────────────┘   └─────────────┘
#    input_sni_fork     validate_sni_h3  detect_xray       generate_*_config
#    fetch/random_sni   [lib]            confirm_mode      update_sni_routes [lib]
#    [lib]              probe_h3 [lib]   download/build    backup_config [lib]
#                                        [lib]
#   ┌─────────────┐   ┌─────────────┐   ┌─────────────┐
#   │ ⑤ 服务部署    │──►│ ⑥ 部署验证    │──►│ ⑦ 链接输出    │
#   └─────────────┘   └─────────────┘   └─────────────┘
#    ensure_service     ss + relay       gen_vless_link [lib]
#    restart_service    probe_h3 [lib]   install_h3reality
#    [lib]
#
# 说明：
#   - 已有配置时按特征定位 H3 inbound（network=xhttp 且 alpn 含 h3，
#     或存在 fallbackDest/fallbackDestRoutes）修改，绝不触碰其他 inbound
#   - 端口冲突询问仅在新配置生成模式（server.json 不存在）触发；
#     已存在配置时 inbound 端口是既成事实，以现有配置为准
#   - 非 root 自动用 sudo 重执行（已 root 则跳过）
#   - JSON 编辑优先 python3，其次 jq
#   - 中文输出，红=错误/拒绝，绿=成功，黄=警告
# =============================================================================

set -Eeuo pipefail

# 任何未预期的失败都输出可见错误（行号 + 退出码），绝不静默退出
_deploy_err_trap() {
  local line="${1:-?}" rc=$?
  printf '\033[0;31m错误: 脚本异常退出（第 %s 行，退出码 %s）\033[0m\n' "$line" "$rc" >&2
  exit "$rc"
}
trap '_deploy_err_trap "$LINENO"' ERR

# ---------------- 引入公共函数库（与 h3reality 共用同一份逻辑） ----------------
LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=h3-lib.sh
if ! source "$LIB_DIR/h3-lib.sh"; then
  echo "错误: 无法加载公共函数库 $LIB_DIR/h3-lib.sh（缺失或语法错误），脚本终止。" >&2
  exit 1
fi

require_root
command -v systemctl >/dev/null 2>&1 || die "未找到 systemctl"
command -v python3 >/dev/null 2>&1 || command -v jq >/dev/null 2>&1 \
  || die "需要 python3 或 jq 来编辑 JSON"

# ===== 阶段 1: 端口冲突检测（仅新配置生成模式） =====

# 交互输入自定义端口：数字 + 1024-65535 + 未占用；非法输入红字重试；
# 成功输出端口并返回 0，直接回车取消返回 1（由调用方转随机端口）
input_custom_port() {
  local proto="$1" label="$2" input
  while :; do
    printf "请输入新的 %s 端口（1024-65535，需未被占用；直接回车改为随机）: " "$label" >&2
    read -r input || { echo; die "读取输入失败"; }
    if [ -z "$input" ]; then
      return 1
    fi
    case "$input" in
      ''|*[!0-9]*) red "端口必须是数字，请重新输入" >&2; continue ;;
    esac
    if [ "$input" -lt 1024 ] || [ "$input" -gt 65535 ]; then
      red "端口必须在 1024-65535 之间，请重新输入" >&2; continue
    fi
    if port_in_use "$proto" "$input"; then
      red "端口 $input 已被占用，请重新输入" >&2; continue
    fi
    echo "$input"
    return 0
  done
}

# 检测 ${H3_PORT} UDP / ${H2_PORT} TCP 被非 xray 进程占用时黄色警告 →
# 询问自定义端口 [y/N] → 自定义或自动随机；端口最终确定后打印绿色摘要
check_port_conflicts() {
  local ans new_port occupied
  if ! command -v ss >/dev/null 2>&1; then
    yellow "警告: 未找到 ss，跳过端口冲突检测"
    return 0
  fi
  # 已有配置模式：inbound 端口是既成事实，不触发端口询问
  if [ -f "$CONFIG_PATH" ]; then
    yellow "已存在 $CONFIG_PATH，端口以现有配置为准，跳过端口冲突询问"
    return 0
  fi

  # H3（UDP）冲突处理
  occupied=$(ss -ulnp 2>/dev/null | grep ":${H3_PORT} " || true)
  if [ -n "$occupied" ] && ! echo "$occupied" | grep -q "xray"; then
    yellow "警告: UDP ${H3_PORT} 被非 xray 进程占用："
    echo "$occupied" | sed 's/^/  UDP /' || true
    printf "UDP ${H3_PORT} 被占用，是否自定义端口？[y/N] "
    read -r ans || { echo; die "读取输入失败"; }
    case "$ans" in
      y|Y)
        if new_port=$(input_custom_port udp "H3(UDP)"); then
          H3_PORT="$new_port"
          yellow "H3 端口已设置为 $H3_PORT（客户端分享链接将带此端口）"
        else
          if new_port=$(pick_random_port udp); then
            H3_PORT="$new_port"
            yellow "未输入自定义端口，自动使用随机端口 ${H3_PORT}（UDP）"
          else
            die "无法找到空闲 UDP 端口"
          fi
        fi
        ;;
      *)
        if new_port=$(pick_random_port udp); then
          H3_PORT="$new_port"
          yellow "已使用随机端口 ${H3_PORT}（UDP）"
        else
          die "无法找到空闲 UDP 端口"
        fi
        ;;
    esac
  fi

  # H2（TCP）冲突处理
  occupied=$(ss -tlnp 2>/dev/null | grep ":${H2_PORT} " || true)
  if [ -n "$occupied" ] && ! echo "$occupied" | grep -q "xray"; then
    yellow "警告: TCP ${H2_PORT} 被非 xray 进程占用："
    echo "$occupied" | sed 's/^/  TCP /' || true
    printf "TCP ${H2_PORT} 被占用，是否自定义端口？[y/N] "
    read -r ans || { echo; die "读取输入失败"; }
    case "$ans" in
      y|Y)
        if new_port=$(input_custom_port tcp "H2(TCP)"); then
          H2_PORT="$new_port"
          yellow "H2 端口已设置为 $H2_PORT（客户端分享链接将带此端口）"
        else
          if new_port=$(pick_random_port tcp); then
            H2_PORT="$new_port"
            yellow "未输入自定义端口，自动使用随机端口 ${H2_PORT}（TCP）"
          else
            die "无法找到空闲 TCP 端口"
          fi
        fi
        ;;
      *)
        if new_port=$(pick_random_port tcp); then
          H2_PORT="$new_port"
          yellow "已使用随机端口 ${H2_PORT}（TCP）"
        else
          die "无法找到空闲 TCP 端口"
        fi
        ;;
    esac
  fi

  green "最终端口: H2=${H2_PORT} (TCP) / H3=${H3_PORT} (UDP)"
}

# ===== 阶段 2: 交互输入 SNI（fork 完整模式：格式 + DNS + H3 探测 + 拒绝循环） =====
input_sni_fork() {
  local attempt=0 input auto=0
  sni=""
  while [ "$attempt" -lt "$MAX_ATTEMPTS" ]; do
    attempt=$((attempt + 1))
    if [ "$auto" -eq 0 ]; then
      if [ "${#SNI_LIST[@]}" -gt 0 ]; then
        printf "请输入 SNI（直接回车：从维护库随机挑选 SNI，q/quit 退出）[%d/%d]: " "$attempt" "$MAX_ATTEMPTS"
      else
        printf "请输入 SNI（q/quit 退出）[%d/%d]: " "$attempt" "$MAX_ATTEMPTS"
      fi
      read -r input || { echo; die "读取输入失败"; }
      if [ -z "$input" ]; then
        if [ "${#SNI_LIST[@]}" -eq 0 ]; then
          red "SNI 不能为空（SNI 库不可用），请手动输入"
          continue
        fi
        auto=1
        input=$(random_sni)
        yellow "已从 SNI 维护库随机挑选: $input"
      else
        auto=0
      fi
      input=$(echo "$input" | tr 'A-Z' 'a-z' | xargs)
    else
      # 随机模式：H3 探测失败自动换下一个
      input=$(random_sni)
      yellow "已自动换下一个随机 SNI: $input"
    fi
    case "$input" in
      q|quit) echo "已退出，未做任何修改。"; exit 1 ;;
      "") red "SNI 不能为空，请手动输入"; auto=0; continue ;;
    esac
    sni="$input"

    # 与 h3reality 完全相同的三段校验：格式 → DNS → H3 探测
    if validate_sni_h3 "$sni"; then
      return 0
    fi
    red "该 SNI 未通过校验，已拒绝部署: $sni"
    yellow "可参考 https://github.com/lipeiying032/h3-reality-sni 的维护库，或直接回车让脚本随机挑选"
    sni=""
    if [ "$attempt" -ge "$MAX_ATTEMPTS" ]; then
      if [ "$auto" -eq 1 ]; then
        red "随机挑选的 $MAX_ATTEMPTS 个 SNI 均不支持 H3，请手动输入可用 SNI。"
        auto=0
        attempt=0
        continue
      fi
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
    if [ "${#SNI_LIST[@]}" -gt 0 ]; then
      printf "请输入 H2 节点的 serverName（直接回车：从维护库随机挑选 SNI，q/quit 退出）[%d/3]: " "$attempt"
    else
      printf "请输入 H2 节点的 serverName（q/quit 退出）[%d/3]: " "$attempt"
    fi
    read -r input || { echo; die "读取输入失败"; }
    if [ -z "$input" ]; then
      if [ "${#SNI_LIST[@]}" -eq 0 ]; then
        red "serverName 不能为空（SNI 库不可用），请手动输入"
        continue
      fi
      input=$(random_sni)
      yellow "已从 SNI 维护库随机挑选: $input"
    fi
    input=$(echo "$input" | tr 'A-Z' 'a-z' | xargs)
    case "$input" in
      q|quit) echo "已退出，未做任何修改。"; exit 1 ;;
      "") red "serverName 不能为空，请手动输入"; continue ;;
    esac
    sni="$input"
    if ! valid_domain "$sni"; then
      red "SNI 格式不合法（示例: example.com / www.example.com）"
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

# ===== 阶段 3: 内核模式确认（fork 完整 / 官方内核 H2 降级） =====

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
      yellow "已选择官方内核降级模式：只部署 H2（${H2_PORT}）节点，跳过 H3 部分"
      ;;
  esac
}

# 未检测到内核时的引导（①联系作者 ②官方内核 H2 降级）
no_kernel_guide() {
  local ans cand
  echo
  yellow "=========== 内核自动获取失败 ==========="
  yellow "Release 下载与源码编译均未成功（可能网络受限或缺少 Go），需要你手动准备："
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
        red "H3（${H3_PORT}）节点必须使用 xray-h3 fork 内核，官方内核不支持 H3/QUIC REALITY。"
        exit 1
      fi
      DEGRADED=1
      green "使用官方内核降级模式: $XRAY_BIN（仅 H2 ${H2_PORT}，跳过 H3 部分）"
      ;;
    *)
      red "未部署任何内核。H3（${H3_PORT}）节点必须使用 xray-h3 fork 内核，请联系作者获取。"
      exit 1
      ;;
  esac
}

# ===== 阶段 4: 配置生成（fork 完整模式 / 降级模式） =====

# fork 模式：${H2_PORT} H2 + ${H3_PORT} H3 最小可运行模板（新配置生成）
generate_fork_config() {
  local conf_dir
  conf_dir=$(dirname "$CONFIG_PATH")
  mkdir -p "$conf_dir" || die "无法创建配置目录 $conf_dir"
  python3 - "$CONFIG_PATH" "$UUID" "$PRIVATE_KEY" "$SHORT_ID" "$sni" "$H2_PORT" "$H3_PORT" <<'PYEOF' || die "配置模板生成失败"
import json, sys
conf, uuid, priv, sid, sni, h2port, h3port = sys.argv[1:8]
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
            "port": int(h2port),
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
            "port": int(h3port),
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
print("OK: 已生成最小可运行配置（H2 port " + h2port + " + H3 port " + h3port + "）")
PYEOF
  green "配置已生成: $CONFIG_PATH"
}

# 降级模式：仅 ${H2_PORT} H2 + 自签证书（官方内核不支持 fork 的 dest 真证书伪装）
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
  python3 - "$CONFIG_PATH" "$UUID" "$cert" "$key" "$H2_PORT" <<'PYEOF' || die "降级配置生成失败"
import json, sys
conf, uuid, cert, key, h2port = sys.argv[1:6]
cfg = {
    "log": {"loglevel": "warning"},
    "inbounds": [
        {
            "listen": "0.0.0.0",
            "port": int(h2port),
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
print("OK: 已生成 H2 降级配置（仅 port " + h2port + "）")
PYEOF
  green "配置已生成: $CONFIG_PATH"
  yellow "警告: 降级模式使用自签证书（非 REALITY 伪装），仅作为临时 H2 节点；"
  yellow "      正式 H3 部署仍需要 xray-h3 fork 内核。"
}

# ===== 阶段 5: systemd 服务（不存在则创建，ExecStart 不一致则更新） =====
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

# ===== 阶段 6: 安装便携管理命令（首次部署成功后自动执行，幂等） =====
install_h3reality() {
  local dest_dir="${H3REALITY_DIR:-/usr/local/bin}"
  if [ ! -f "$LIB_DIR/h3reality" ] || [ ! -f "$LIB_DIR/h3-lib.sh" ]; then
    yellow "警告: 未找到 h3reality 或 h3-lib.sh（应与本脚本同目录），跳过管理命令安装"
    return 0
  fi
  mkdir -p "$dest_dir"
  cp -a "$LIB_DIR/h3reality" "$dest_dir/h3reality" && chmod +x "$dest_dir/h3reality"
  cp -a "$LIB_DIR/h3-lib.sh" "$dest_dir/h3-lib.sh"
  green "已安装便携管理命令（幂等）: $dest_dir/h3reality"
  yellow "之后可随时执行: h3reality help（status/list/switch/add/remove/link 等）"
}

# ==================== 主流程 ====================

# 1. 内核检测与模式确认
if ! detect_xray; then
  no_kernel_guide
elif [ -z "$XRAY_BIN" ]; then
  no_kernel_guide
else
  confirm_kernel_mode
fi

# 2. 配置路径 + 端口冲突
detect_config_path
check_port_conflicts

# 3. SNI 维护库 + SNI 输入
fetch_sni_list || true
if [ "$DEGRADED" -eq 1 ]; then
  gen_keys
  input_sni_degraded
else
  ensure_probe
  input_sni_fork
fi

# 4. 配置准备（已有配置 → 按特征定位 H3 inbound 修改；没有 → 自动生成）
if [ -f "$CONFIG_PATH" ]; then
  if [ "$DEGRADED" -eq 1 ]; then
    yellow "已存在 $CONFIG_PATH，降级模式跳过配置生成，直接使用现有配置"
  else
    # 确认现有 H3 inbound 结构正常
    find_h3_inbound || die "H3 inbound 结构异常，拒绝继续"
    backup_config "sni-$sni"
    if ! update_sni_routes "$sni"; then
      rollback
      die "修改配置失败，已回滚"
    fi
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

# 5. 配置校验 + systemd 服务 + 重启
if ! run_test; then
  rollback
  die "配置校验失败，已回滚"
fi
green "配置校验通过"

ensure_service
if ! restart_service; then
  rollback
  die "服务重启失败，已回滚"
fi
green "服务已重启并运行"

# 6. 部署验证（fork：${H3_PORT} UDP 监听 + relay 闭环；降级：${H2_PORT} TCP 监听）
if [ "$DEGRADED" -eq 0 ]; then
  if command -v ss >/dev/null 2>&1; then
    LISTEN_INFO=$(ss -ulnp 2>/dev/null | grep ":${H3_PORT} " || true)
  else
    LISTEN_INFO=$(netstat -ulnp 2>/dev/null | grep ":${H3_PORT} " || true)
  fi
  if [ -n "$LISTEN_INFO" ]; then
    green "${H3_PORT} UDP 监听确认:"
    echo "$LISTEN_INFO" | sed 's/^/  /'
  else
    yellow "警告: 未在 ss -ulnp 输出中找到 :${H3_PORT}，请手动确认监听状态"
  fi

  yellow "relay 闭环验证: probe-h3-sni -sni $sni -addr 127.0.0.1:${H3_PORT}"
  if probe_h3 "$sni" "127.0.0.1:${H3_PORT}" 15s; then
    green "relay 闭环验证通过（路由命中，dest 完成握手）: $probe_out"
  else
    yellow "警告: relay 闭环未通过: $probe_out"
    yellow "配置已生效。请检查 dest/$sni 的 443 是否可达、fallbackDestRoutes 是否正确。"
  fi
else
  if command -v ss >/dev/null 2>&1; then
    LISTEN_INFO=$(ss -tlnp 2>/dev/null | grep ":${H2_PORT} " || true)
  else
    LISTEN_INFO=$(netstat -tlnp 2>/dev/null | grep ":${H2_PORT} " || true)
  fi
  if [ -n "$LISTEN_INFO" ]; then
    green "${H2_PORT} TCP 监听确认:"
    echo "$LISTEN_INFO" | sed 's/^/  /'
  else
    yellow "警告: 未在 ss -tlnp 输出中找到 :${H2_PORT}，请手动确认监听状态"
  fi
fi

# 7. 提取客户端参数（生成的新配置已在 gen_keys 中得到）
if [ "$CONFIG_GENERATED" -eq 0 ]; then
  if [ "$DEGRADED" -eq 1 ]; then
    extract_client_params "$H2_PORT"
  else
    extract_client_params "$H3_PORT"
  fi
fi

# 8. 输出：客户端提醒 + VLESS 分享链接 + 安装 h3reality
echo
banner green "部署完成"
if [ "$DEGRADED" -eq 1 ]; then
  echo "  模式:          官方内核 H2 降级（仅 ${H2_PORT}，无 H3）"
  echo "  配置:          $CONFIG_PATH"
  echo "  内核:          $XRAY_BIN"
  echo "  证书:          $(dirname "$CONFIG_PATH")/selfsigned.crt（自签，客户端需 allowInsecure）"
else
  green "H3 inbound（端口 ${H3_PORT}）已切换 SNI -> $sni"
  echo "  当前 dest:        $sni:443"
  echo "  当前 serverNames: [$sni]"
  echo "  路由表条目:       fallbackDestRoutes[$sni] = $sni:443（其余条目未动）"
  if [ -n "$BACKUP" ]; then
    echo "  配置备份:         $BACKUP"
  fi
fi

SERVER_IP=$(get_server_ip)
echo
banner yellow "VLESS 分享链接（可直接导入客户端）"
if [ "$DEGRADED" -eq 1 ]; then
  if [ -n "$UUID" ]; then
    gen_vless_link degraded "$SERVER_IP" "$H2_PORT" "$UUID" "" "" "$sni"
  else
    yellow "警告: 无法生成分享链接（缺少 UUID），请从 $CONFIG_PATH 中手动提取"
  fi
else
  if [ -n "$UUID" ] && [ -n "$PUBLIC_KEY" ] && [ -n "$SHORT_ID" ]; then
    gen_vless_link fork "$SERVER_IP" "$H3_PORT" "$UUID" "$PUBLIC_KEY" "$SHORT_ID" "$sni"
    gen_vless_link fork "$SERVER_IP" "$H2_PORT" "$UUID" "$PUBLIC_KEY" "$SHORT_ID" "$sni" h2
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

# 9. 首次部署成功后自动安装 h3reality 便携管理命令
install_h3reality
