# H3 REALITY Deploy

让 **VLESS + XHTTP + REALITY** 节点在 **QUIC/H3 传输层**与"真实浏览器访问真实网站"不可区分。
本仓库开源三样东西：**完整实现原理文档**、**服务端一键部署脚本**、**H3 支持探测工具**。

> 关于内核：`xray-h3` fork 内核（v26.7.28 + client_random 认证 + uTLS Chrome 指纹 +
> SNI 感知 UDP relay）**不开源**——避免暴露防探测细节。部署脚本会自动检测/引导内核，
> 未安装时给出获取途径（联系作者或官方内核 H2 降级模式）。

---

## 特性

- **隐身认证**：认证载荷藏在 TLS 1.3 ClientHello 的 `random` 字段，与真随机不可区分、不可重放；
- **探测伪装**：无认证的 QUIC 探测流被 SNI 感知的字节级 UDP relay 原样转发到真实站点，
  探测者看到的握手/证书/响应与直连真实站点完全一致；
- **Chrome 指纹**：客户端握手指纹对齐 Chrome（uTLS quicifySpec，5 组 groups、ALPS→h3、TP 干净）；
- **一键部署**：全新 VPS 上 `git clone` 后单条命令完成 SNI 探测、配置生成、systemd 服务、部署验证；
- **探针自给自足**：无 Go 环境也能跑——同目录二进制 → 源码自动编译 → GitHub Release 下载三级兜底；
- **自动引导**：内核检测、server.json 生成、systemd 服务创建、端口冲突检测、VLESS 分享链接输出全自动。

---

## 架构

```
┌──────────── 客户端（fork xray）────────────┐
│ VLESS outbound  xhttp + reality           │
│ serverName=SNI  fp=chrome  alpn=["h3"]    │
│ ClientHello: random=认证载荷（不可区分）    │
└────────────────────┬──────────────────────┘
                     │ QUIC/UDP :8446
                     ▼
┌──────────── 服务端（fork xray）────────────┐
│ ① QUIC 预检：解密 Initial → 提取 ClientHello│
│    认证通过 → AUTH → HTTP/3 → VLESS 数据面  │
│    认证失败 → RELAY → SNI 感知 UDP relay    │
│ ② fallbackDestRoutes[SNI] 精确路由         │
└────────────────────┬──────────────────────┘
                     │
                     ▼
             真实站点（如 ea.com:443）
       探测者视角 = 直连该站点（证书/握手/响应一致）
```

---

## 快速开始（全新 VPS）

```bash
git clone https://github.com/lipeiying032/h3-reality-deploy.git
cd h3-reality-deploy
sudo bash deploy-h3-sni.sh
```

脚本自动完成：

1. 交互输入 SNI（默认 `ea.com`，支持 `q/quit` 退出）；
2. 域名格式校验 + DNS 解析 + **H3 支持探测**——不支持则红色拒绝并建议换 SNI（最多 5 次）；
3. 探测工具自给自足：同目录二进制 → 源码 + Go 自动编译 → GitHub Release 下载；
4. xray 内核自动检测（`/opt/xray/xray-linux-amd64` → `/usr/local/bin/xray` → `PATH`）；
5. 没有 `server.json` → 自动生成最小可运行配置（8443 H2 + 8446 H3，UUID/密钥自动生成）；
6. 没有 systemd 服务 → 自动创建 `xray-h3.service` 并 `enable`；
7. `run -test` 校验 → 重启 → 端口监听 + relay 闭环验证；
8. 输出完整 **VLESS 分享链接**（`vless://...` 含 `sni/pbk/sid/fp=chrome/type=xhttp`），可直接导入客户端。

> 已有旧配置时：只更新 8446 inbound 的 `dest`/`serverNames`/`fallbackDestRoutes[SNI]`，
> 其余 inbound 与 17 条路由条目不动，自动备份后可回滚。

### 手动部署（不想用脚本）

见 [H3-REALITY-README.md](H3-REALITY-README.md) 第 8 章：server.json 完整示例、systemd 服务、
客户端配置（Windows zip）。

---

## 仓库结构

```
h3-reality-deploy/
├── README.md              # 项目主页（本文件）
├── H3-REALITY-README.md   # 完整实现原理文档（12 节：认证/指纹/relay/部署/FAQ）
├── REQUIREMENTS.md        # 开源所需的 GitHub 权限与 Token 导出指南
├── deploy-h3-sni.sh       # 服务端一键部署脚本（自包含引导版）
├── probe-h3-sni.go        # H3 探测工具源码（Go 1.22+，quic-go http3）
├── probe-h3-sni           # 预编译静态二进制（linux/amd64，无 Go 环境直接可用）
├── LICENSE                # MIT
└── .gitignore
```

---

## 文档

- [H3-REALITY-README.md](H3-REALITY-README.md) —— 完整原理：官方为什么走 H2、fork 动机、
  认证机制（client_random）、uTLS Chrome 指纹、预检状态机与 UDP relay、生产部署、FAQ；
- [REQUIREMENTS.md](REQUIREMENTS.md) —— 给作者看的：开源需要提供的 GitHub 权限、
  Token 导出步骤、git 身份配置、Token 交接方式。

---

## 使用说明与免责声明

- 本仓库提供的是**原理文档 + 部署工具**；内核需自行构建或联系作者获取；
- 请遵守所在地区法律法规，仅用于合法用途；
- MIT License，作者 lipeiying032，2026。
