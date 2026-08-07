# H3 REALITY Deploy

让 **VLESS + XHTTP + REALITY** 节点在 **QUIC/H3 传输层**与"真实浏览器访问真实网站"不可区分。
本仓库开源三样东西：**fork 内核源码**（[`core/`](core/)）、**单文件 TUI 客户端**（[`client-tui/`](client-tui/)）与
**完整实现原理文档**（[H3-REALITY-README.md](H3-REALITY-README.md)）。

> 关于内核：完整 fork 内核源码已开源在本仓库 [`core/`](core/)（基于 XTLS/Xray-core
> v26.7.28，MIT 协议，含 REALITY-over-QUIC 全部魔改与完整 vendor/ 依赖，可直接离线构建）。
> **H3 节点必须使用此 fork 内核**（官方内核不支持 REALITY+H3）。

> 关于一键部署脚本：服务端部署/管理脚本（`deploy-h3-sni.sh`、`h3reality`、`h3-lib.sh`、
> H3 探测工具）已拆分到独立仓库
> [h3-reality-deploy-scripts](https://github.com/lipeiying032/h3-reality-deploy-scripts)，
> 全新 VPS 一键部署请前往该仓库。

---

## 特性

- **隐身认证**：认证载荷藏在 TLS 1.3 ClientHello 的 `random` 字段，与真随机不可区分、不可重放；
- **探测伪装**：无认证的 QUIC 探测流被 SNI 感知的字节级 UDP relay 原样转发到真实站点，
  探测者看到的握手/证书/响应与直连真实站点完全一致；
- **Chrome 指纹**：客户端握手指纹对齐 Chrome（uTLS quicifySpec，5 组 groups、ALPS→h3、TP 干净）；
- **一键部署**：全新 VPS 上 curl 下载脚本仓库后单条命令完成 SNI 探测、配置生成、systemd 服务、
  部署验证（脚本见 [h3-reality-deploy-scripts](https://github.com/lipeiying032/h3-reality-deploy-scripts)）。

---

## 架构

```
┌──────────── 客户端（fork xray）────────────┐
│ VLESS outbound  xhttp + reality           │
│ serverName=SNI  fp=chrome  alpn=["h3"]    │
│ ClientHello: random=认证载荷（不可区分）    │
└────────────────────┬──────────────────────┘
                     │ QUIC/UDP :443
                     ▼
┌──────────── 服务端（fork xray）────────────┐
│ ① QUIC 预检：解密 Initial → 提取 ClientHello│
│    认证通过 → AUTH → HTTP/3 → VLESS 数据面  │
│    认证失败 → RELAY → SNI 感知 UDP relay    │
│ ② relay 目标：无认证流原样转发到 dest       │
└────────────────────┬──────────────────────┘
                     │
                     ▼
             真实站点（如 ea.com:443）
       探测者视角 = 直连该站点（证书/握手/响应一致）
```

---

## core/ 内核源码

完整 fork 内核源码已开源在 [`core/`](core/)：基于 XTLS/Xray-core **v26.7.28**（MIT），
包含 `client_random` 认证、uTLS Chrome 指纹、SNI 感知 UDP relay 等全部魔改，
`vendor/` 依赖完整（apernet/quic-go fork + utls + xtls/reality），可离线构建。

主要魔改点：

- **REALITY-over-QUIC**：`client_random` 认证（AES-GCM 32B 填 CH random，与真随机不可区分）；
- **uTLS Chrome 指纹 CH 构造**（`quicifySpec` 常量表 + ALPS h3）；
- **QUIC 预检 + 5-tuple UDP NAT relay**（无认证流原样转发到 dest）；
- **BBR 修复**（`OnPacketsLost`/`OnAppLimited`）+ H3 写聚合（41MB/s）。

构建方法：

```bash
cd core
go build -mod=vendor ./...
# 服务端产物: core/xray
# 交叉编译 Windows 客户端:
GOOS=windows GOARCH=amd64 go build -mod=vendor -o xray-h3-win-amd64.exe ./main
```

> 注意：H3 节点必须用此 fork 内核，官方内核不支持 REALITY+H3。

---

## client-tui/ 客户端

单文件 TUI 客户端：配置管理 + 绕过大陆规则集 + `go:embed` 内置 fork 内核（linux/windows），
构建与使用说明见 [client-tui/README.md](client-tui/README.md)；预编译产物见本仓库 Releases。

---

## 一键部署（服务端）

服务端一键部署与管理脚本已拆分到
[h3-reality-deploy-scripts](https://github.com/lipeiying032/h3-reality-deploy-scripts)：

```bash
git clone https://github.com/lipeiying032/h3-reality-deploy-scripts.git
cd h3-reality-deploy-scripts
sudo bash deploy-h3-sni.sh
```

脚本自动完成：SNI 校验（格式 → DNS → H3 探测）、内核获取（从本仓库 Release 下载
`xray-h3-server-linux-amd64`，或 `core/` 源码编译兜底）、`server.json` 生成/修改、
systemd 服务、部署验证与 VLESS 分享链接输出；部署后自动安装 `h3reality` 便携管理命令。

> 手动部署（不想用脚本）：见 [H3-REALITY-README.md](H3-REALITY-README.md) 第 8 章
> （server.json 完整示例、systemd 服务、客户端配置）。

---

## 仓库结构

```
h3-reality-deploy/
├── README.md              # 项目主页（本文件）
├── H3-REALITY-README.md   # 完整实现原理文档（12 节：认证/指纹/relay/部署/FAQ）
├── REQUIREMENTS.md        # 开源所需的 GitHub 权限与 Token 导出指南
├── core/                  # fork 内核完整源码（v26.7.28 + 全部魔改，含 vendor/，MIT）
├── client-tui/            # 单文件 TUI 客户端（含 README、go:embed 内核）
├── LICENSE                # MIT
└── .gitignore

# 服务端部署脚本已移至 https://github.com/lipeiying032/h3-reality-deploy-scripts
#   ├── deploy-h3-sni.sh   # 服务端一键部署脚本（交互引导，逻辑在 h3-lib.sh）
#   ├── h3-lib.sh          # 公共函数库（deploy 与 h3reality 共享）
#   ├── h3reality          # 便携管理命令（status/list/switch/link 等）
#   ├── probe-h3-sni.go    # H3 探测工具源码（Go 1.22+，quic-go http3）
#   └── probe-h3-sni       # 预编译静态二进制（linux/amd64，无 Go 环境直接可用）
```

---

## 文档

- [H3-REALITY-README.md](H3-REALITY-README.md) —— 完整原理：官方为什么走 H2、fork 动机、
  认证机制（client_random）、uTLS Chrome 指纹、预检状态机与 UDP relay、生产部署、FAQ；
- [client-tui/README.md](client-tui/README.md) —— 客户端构建、配置与使用；
- [REQUIREMENTS.md](REQUIREMENTS.md) —— 给作者看的：开源需要提供的 GitHub 权限、
  Token 导出步骤、git 身份配置、Token 交接方式。

---

## 使用说明与免责声明

- 本仓库开源**原理文档 + fork 内核完整源码**（`core/`，MIT）+ **客户端**（`client-tui/`）；
  内核可按上文「core/ 内核源码」直接构建，无需联系作者获取；
- 一键部署/管理脚本请使用 [h3-reality-deploy-scripts](https://github.com/lipeiying032/h3-reality-deploy-scripts)；
- 请遵守所在地区法律法规，仅用于合法用途；
- MIT License，作者 lipeiying032，2026。
