# H3 REALITY：VLESS + XHTTP + REALITY 在 QUIC/H3 传输层的完整实现

## 1. 项目定位

**让 VLESS + XHTTP + REALITY 节点在 H3/QUIC 传输层与"真实浏览器访问真实网站"不可区分**：
客户端握手指纹对齐 Chrome（uTLS quicifySpec），认证载荷藏进 TLS 1.3 ClientHello 的 random 字段（与真随机不可区分），
服务端对无认证的探测流量做 SNI 感知的字节级 UDP relay——探测者看到的握手、证书、响应与直连真实站点完全一致。

---

## 2. 背景与动机

### 2.1 官方 REALITY + XHTTP 永远走 H2

官方 Xray-core v26.7.28 中，"REALITY + XHTTP" 这个组合在传输层永远是 HTTP/2：

- `transport/internet/reality/config.go` 的 `GetREALITYConfig()` 里 `NextProtos` 默认 `nil`（只有显式配置 `alpn` 才非空）；
- `transport/internet/splithttp/hub.go` 的 `isH3` 判定要求 `tlsConfig.NextProtos` 恰为 `["h3"]`。

两者互斥：REALITY 侧不会主动注入 `h3`，H3 侧必须 ALPN=`h3` 才走 QUIC。结果是官方二进制里
REALITY 节点只能以 H2/XHTTP 形态存在，拿不到 QUIC 的传输特性。

### 2.2 QUIC 探测威胁

UDP 端口（默认 443）直接把 QUIC 服务暴露在公网。GFW 的主动探测对 QUIC 非常廉价：
发一个标准 QUIC Initial（随机 SNI、标准 ClientHello），只要握手能完成、返回行为与真实站点不一致
（自签证书、REALITY 特殊字段、错误码、时序），端口即被标记为代理。

要扛住 QUIC 主动探测，需要同时满足三条：

1. **握手特征无异常**——ClientHello 与真实 Chrome 的 QUIC 指纹一致（session_id=0、5 组 groups、ALPS 指 h3、TP 干净）；
2. **无认证流被原样转发**——探测者的 QUIC 包被字节级 relay 到真实 H3 站点，由真实站点完成握手；
3. **认证不可伪造、不可重放**——服务端仍能区分真客户端与探测者，且凭据在线上不可见。

### 2.3 为什么必须 fork

认证凭据需要一个"隐身载体"，而官方 REALITY 的认证载体（TLS 1.3 `session_id`）在 QUIC 上是强指纹
（见 4.4 节演进史）。实现"隐身认证 + 无认证 relay"需要动三层：

1. **quic-go fork**（`github.com/apernet/quic-go`）：TLS 层改为可插拔 `QUICTLSFactory`，允许把
   REALITY fork 的 TLS 状态机接到 QUIC 握手上；
2. **xtls/reality fork**（`vendor/github.com/xtls/reality/`）：TLS 1.3 客户端握手函数支持把认证载荷
   注入 ClientHello 标准字段（`applyRealityClientHelloRandom`），并导出无连接状态的
   `ClientHelloVerifier` 供预检复用；**客户端跳过 CertificateVerify 签名校验**——服务端持 dest
   真实证书链但不可能持有 dest 私钥，只能配一次性密钥签名（`applyDestCertChain` +
   `newThrowawayKeyForCert`），标准 crypto/tls 客户端无法完成该校验；
3. **xray 桥接**：`transport/internet/tls/reality_quic.go`（客户端侧 `NewRealityQUICFactory` 适配
   qtls.Factory）、`transport/internet/splithttp/` 下的预检状态机与 UDP relay。

---

## 3. 架构总览

```
┌─────────────────────────── 客户端（fork xray，Windows zip / Linux） ───────────────────────────┐
│  VLESS outbound                                                                               │
│    network=xhttp  security=reality  fingerprint=chrome                                        │
│    serverName=SNI  publicKey  shortId  alpn=["h3"]                                            │
│    xhttpSettings: mode=stream-one  enableH3  path=/v1/collect  xPadding 32-96  obfsMode       │
│                                                                                               │
│  HTTP/3 客户端栈（quic-go fork + reality TLS fork via QUICTLSFactory）                         │
│    ClientHello: session_id=0                                                                  │
│                 groups = [0xaaaa(GREASE), 0x11ec(X25519MLKEM768), 0x1d, 0x17, 0x18]           │
│                 ALPS→h3  ALPN=h3  5 组 groups（对齐 Chrome）                                   │
│    random 字段 = AES-GCM(ClientVer + UnixTime + ShortId) 32B（与真随机不可区分）               │
└──────────────────────────────────────────┬────────────────────────────────────────────────────┘
                                           │ QUIC UDP（公网 :443）
                                           ▼
┌─────────────────────────── 服务端（fork xray，XHTTP/3 listener） ─────────────────────────────┐
│  UDP listener :443（sockopt SO_RCVBUF/SO_SNDBUF=8MB，finalmask.quicParams: BBR aggressive）    │
│                                                                                               │
│  ① QUIC 预检（reality_precheck.go / reality_precheck_conn.go）                                │
│     解密 Initial（RFC9001 §5.2）→ CRYPTO 跨包重组 → 提取 ClientHello                          │
│     → ClientHelloVerifier.Verify（random 优先，session_id 回退兼容 TCP）                       │
│        ├─ 通过 → AUTH：缓冲包+后续包进 FIFO 队列 → quic-go → HTTP/3 → VLESS 数据面             │
│        └─ 失败/不可解析 → RELAY：整流原样转发到真实站点                                        │
│                                                                                               │
│  ② SNI 感知 UDP relay（reality_relay.go，5-tuple NAT）                                        │
│     决策链（首包定死）：fallbackDestRoutes[SNI] 精确匹配 → fallbackDest → 静默丢弃             │
│     client──(DialUDP connect, 只收 dest 来源)──► dest :443                                    │
│     dest 应答 ←──(经服务端监听 socket WriteTo 写回, 源地址保持)──client                        │
│     30s ticker 回收 120s 空闲；表上限 65536、per-IP 512；多 IP 故障转移                         │
└──────────────────────────────────────────┬────────────────────────────────────────────────────┘
                                           │
                                           ▼
                                  真实站点（如 ea.com:443）
                                  探测者视角 = 直连该站点（证书/握手/HTTP 响应一致）
```

---

## 4. 认证机制原理（最终形态：client_random）

### 4.1 密钥派生与 AD 构造

客户端与服务端都复用 ClientHello 里**已经存在**的 X25519 key share 做 ECDH，不新增任何扩展：

```
sharedSecret = ECDH(clientKeySharePriv, serverPublicKey)     // X25519
AD           = 完整 ClientHello 原始字节，random 字段(偏移 6..38)置全零
               （偏移：handshake type 1B + length 3B + legacy_version 2B = 6，random 32B）
adHash       = SHA-256(AD)
salt         = adHash[0:20]
nonce        = adHash[20:32]
authKey      = HKDF-SHA256(sharedSecret, salt, info="REALITY")
```

### 4.2 AES-GCM 布局（4 + 4 + 8 + 16）

```
明文 16B:
  [0:3]   ClientVer   = 26.4.17（0x1A 0x04 0x11）
  [3]     0x00（填充）
  [4:8]   UnixTime    = uint32(big-endian)
  [8:16]  ShortId     = 8B short id
密文 32B = AES-128-GCM.Seal(nonce, 明文16B, AD)   // 16B 密文 + 16B tag
         → 恰好填满 TLS 1.3 的 32B random 字段
```

服务端 `verifyClientHelloRandom` 镜像该流程：提取 key share（纯 X25519 或混合
X25519MLKEM768 的尾部 32B）→ ECDH → 把 `hello.original[6:38]` 临时清零做 AD → GCM Open →
校验版本窗口（`MinClientVer`/`MaxClientVer`）、时间偏差（`MaxTimeDiff`）、shortId 白名单。

### 4.3 为什么不可重放、为什么与真随机不可区分

- **不可重放**：AEAD 的 AD 绑定到"这个 ClientHello 去掉 random 后的全部字节"（SNI、key share、
  扩展、顺序、GREASE 全部参与）。把同一个 32B 密文 random 挪到任何一个不同的 ClientHello，
  服务端算出的 AD 就不同 → GCM Open 失败；时间戳 + `MaxTimeDiff` 进一步限制截获重放窗口。
- **与真随机不可区分**：AES-GCM 输出 = 密文（keystream ⊕ 明文）+ 16B tag，key/nonce 均由
  HKDF 从每次握手独立的 ECDH 共享秘密派生。实测 12 条连接：位密度 0.5055 vs 官方客户端
  0.5007、χ² 254.7 vs 249.3、12/12 互异——统计上与真随机无法区分。
- **兼容标准 TLS**：random 参与 TLS 1.3 密钥派生，密文 random 就是协议意义上的 random，
  任何标准实现都正常处理。

### 4.4 演进历史

| 阶段 | 载体 | 结论 |
|---|---|---|
| 早期（v6） | 认证载荷塞 TLS 1.3 legacy `session_id`（32B） | **被否决**：QUIC ClientHello 带非空 session_id 在 Chrome/quic-go 生态从不出现（RFC 9001 §8.4 要求零长度），主动探测一眼识别 |
| 过渡（v7） | HTTP 数据面 `X-Reality-Auth` 头（base64 record） | 可原样重放——数据面 record 不绑定连接，留着比握手层认证更弱 → 客户端删除；服务端保留校验以兼容没有预检的旧部署 |
| 最终（v8+） | **ClientHello random 字段**（32B AES-GCM 恰好填满） | 每个 TLS 1.3 CH 必有 32B random，密文与真随机计算不可区分；AD 绑定整包，不可重放 |

---

## 5. uTLS Chrome 指纹（客户端）

### 5.1 工作流程

`vendor/github.com/xtls/reality/utls_quic_clienthello.go`：

1. fork `Config` 新增 `UtlsClientHelloID`；客户端 `realitySettings.fingerprint="chrome"` 时走
   `makeUtlsClientHello`（xray 侧 `tls.GetFingerprint` 解析）；
2. `UTLSIdToSpec` 取 Chrome 指纹 spec → `quicifySpec` 适配 QUIC 传输；
3. `UConn.ApplyPreset` + `ApplyConfig` → `MarshalClientHello` → fork 的 `unmarshal`
   （`hello.original` 保留原始字节，供 AD 使用）；
4. **私钥映射**：uTLS 的 Chrome 混合 X25519MLKEM768 share 中，可复用的 X25519 分量在
   `MlkemEcdhe`；纯 X25519 情形回退 `Ecdhe`；
5. `applyRealityClientHelloRandom` 注入认证：AD = `original[6:38]` 清零，密文写回
   `original[6:38]` 再上线路由——**服务端零改动**（服务端验证器是通用的：unmarshal 任意
   CH + random 清零）。

### 5.2 quicifySpec 常量表

| 项 | 处理 | 原因 |
|---|---|---|
| cipher suites | 只留 GREASE + `1301/1302/1303` | QUIC 只协商 TLS 1.3 |
| supported_versions | 只留 GREASE + `0x0304` | 同上 |
| session ticket | 删除 | 新连接不带 |
| ALPS / application_settings | 保留，`SupportedProtocols=["h3"]` | **Chrome QUIC CH 带 ALPS 且指向 h3**；uTLS 的 TCP spec 硬编码 h2，必须重指 |
| ALPN | 配置的 `h3` | 服务端按 ALPN 选择 H3 |
| quic_transport_parameters (0x39) | 固定插在 key_share 之后 | 位置可控，与 Chrome 布局一致（指纹工厂会打乱顺序） |
| compress_cert(brotli)、status_request、GREASE ECH | 保留 | 都是 Chrome 指纹的组成部分 |

### 5.3 实测 ClientHello 特征

```
groups      = [0xaaaa (GREASE), 0x11ec (X25519MLKEM768), 0x1d (X25519), 0x17 (P-256), 0x18 (P-384)]
session_id  = 0（零长度）
ALPN        = h3
ALPS        = h3
```

### 5.4 为什么 ALPS 要指 h3

Chrome 的 QUIC ClientHello 中，ALPS（application_settings）的 `supported_protocols` 是它接下来
要协商的 HTTP 版本——对 H3 连接就是 `h3`。uTLS 的 Chrome spec 为 TCP 场景硬编码了 `h2`；
如果原样保留，会出现"Chrome 指纹却宣称 h2 + ALPN h3"的自相矛盾组合，破坏与真实 Chrome 的一致性。

---

## 6. 预检与 SNI 感知 UDP relay（探测伪装核心）

### 6.1 QUIC Initial 解密与 ClientHello 提取（reality_precheck.go）

按 RFC 9001 §5.2 走完整 Initial 解密（技术搬运自 quic-ech-sniffer，**只取解密/提取，与 ECH 无关**）：

1. `deriveInitialSecrets(dcid)`：Initial salt → HKDF-Extract → HKDF-Expand-Label(`"client in"`)
   得到 `key/iv/hp`（注意用 `hkdf.Extract` 直接做 Extract，不能走 `hkdf.New` 的
   Extract-then-Expand）；
2. 头部保护去除：取 PN 样本（PN 起始 + 4）→ AES 加密得到 mask → 还原首字节与 PN；
3. 载荷解密：nonce = `iv XOR PN`（左补零到 12B），AEAD 解出明文；
4. `parseCryptoFrames`：只认 `CRYPTO`（0x06），按 stream offset 记录分片，跳过
   PADDING/PING/ACK；
5. `mergeCryptoFrag` 按 offset 重组（CH 一定从 offset 0 开始）；
6. `extractClientHello`：type 0x01 + 3B length，取完整握手消息（含 4B 头）；
7. `clientHelloServerName`：最小化 SNI 解析（只走固定头 + session_id/cipher/compression
   长度 + 扩展表），与 fork unmarshal 一致。

### 6.2 PENDING → AUTH / RELAY 状态机（reality_precheck_conn.go）

```
首包到达 → 建 PENDING 状态（记录 raw 数据包）
   ├─ 不可解析（非 QUIC v1 / 解密失败）→ RELAY
   ├─ CH 未收齐 → 缓冲（上限 32 包 / 128KB / 超时强制 RELAY）
   └─ CH 收齐 → ClientHelloVerifier.Verify（random 优先，session_id 回退）
        ├─ 通过 → AUTH：缓冲包按到达顺序进 FIFO 队列，quic-go 从队列读
        └─ 失败 → RELAY
决策在首包定死：AUTH/RELAY 后同一客户端地址的所有包走同一路径
```

- 队列 1024 包，满则丢包不阻塞读循环；表上限 65536 状态、per-IP 512；30s 周期回收；
- 预检**只在显式配置了 `fallbackDest` 或 `fallbackDestRoutes`（且服务端有完整认证密钥）时启用**。
  不默认回退到 `Dest`——否则无认证的客户端也会被 RELAY，正常业务全断。

### 6.3 5-tuple UDP NAT（reality_relay.go）

- **防伪造源**：每个客户端流一个 `DialUDP` connect socket，`conn.Read` 只收 dest 来源的包；
- **源地址保持**：dest 的应答经服务端自己的监听 socket `WriteTo` 写回，客户端看到单一源地址
  （服务器 IP:443）；
- **超时回收**：30s ticker，默认 120s 空闲回收（`FallbackTimeout` 可配）；表上限 65536、per-IP
  512、单包 64KB；
- **多 IP 故障转移**：`resolveRelayDest` 启动时解析目标全部 A/AAAA（去重）作候选集；
  `writeToDest` 失败（如 ICMP port unreachable）→ 自动切下一个地址，单个坏 A 记录不再黑洞整个目标；
- **路由决策链**（首包定死）：`fallbackDestRoutes[SNI]` 精确匹配 → `fallbackDest` →
  静默丢弃。

### 6.4 伪装效果

探测者看到的 = 直连真实站点：握手证书、错误码行为、HTTP 响应全部由真实站点产生。
relay 字节级一致铁证：本地闭环中 `client→18445` 的 payload 与 `relay→18447` 的 payload
**IDENTICAL**（逐字节相同）。

---

## 7. 探测伪装效果与错误码判据表

QUIC 的 `CRYPTO_ERROR` 码 = `0x100 + TLS alert`（RFC 9000 §20.1 / RFC 8446）。

| 错误码 | 对应 TLS alert | 实测含义 | 判据 |
|---|---|---|---|
| `0x128` | 40 `handshake_failure` | CF 类 CDN 对"未知 SNI"的拒绝 | **relay 生效**：探测流被原样转给了真实站点，真实站点（如 cloudflare 边缘）拒绝该 SNI |
| `0x133` | — | 服务端自己握手（旧内核特征） | 跑的还不是"预检 relay"内核：没有 relay 时服务端用自己的 REALITY 握手指纹响应探测 |
| `0x150` | 80 `internal_error` | 目标**没有 H3 端点**（如 apple） | 该 SNI 本身不支持 H3（apple.com 超时 / www.apple.com 稳定 0x150），换 SNI 而不是排查服务端 |

配套事实（2026-08 实测）：

- 支持 H3：ea.com、google.com、www.google.com、youtube.com、www.youtube.com、
  facebook.com、www.facebook.com、cloudflare-quic.com、www.cloudflare.com、
  cdn.cloudflare.steamstatic.com、steampipe.akamaized.net、eaassets-a.akamaihd.net、
  ubisoft.com、www.epicgames.com、www.nintendo.com、www.xbox.com；
- 不支持：apple.com（QUIC 超时）、www.apple.com（0x150 稳定）、battle.net、
  playstation.com、xbox.com 裸域（超时）、store.steampowered.com、riotgames.com、
  cdn1.epicgames.com（0x150 拒一切）；
- `:authority` 为 IP 时 Fastly/Akamai 会回 500/400，仍是完整握手——探针必须发 `https://SNI/`
  而不是 IP。

---

## 8. 生产部署形态

### 8.0 从 GitHub 快速部署（全新 VPS）

脚本已做成**自包含引导版**：探针、配置、systemd 服务全部自动搞定，使用者只需：

```bash
# 全新 VPS 一键部署（目录已存在会重新下载并覆盖，等价于更新到最新版）
rm -rf h3-reality-deploy
mkdir -p h3-reality-deploy
curl -fsSL -o h3-reality-deploy.tar.gz https://codeload.github.com/lipeiying032/h3-reality-deploy/tar.gz/refs/heads/main || {
  rm -f h3-reality-deploy.tar.gz
  echo "错误：仓库下载失败，请检查："
  echo "  1. GitHub 网络是否可达（可验证：curl -fsSI https://github.com）"
  echo "  2. 是否被防火墙或代理拦截"
  exit 1
}
tar -xzf h3-reality-deploy.tar.gz --strip-components=1 -C h3-reality-deploy || {
  rm -f h3-reality-deploy.tar.gz
  echo "错误：解压失败，请检查磁盘空间或网络下载是否完整"
  exit 1
}
rm -f h3-reality-deploy.tar.gz
cd h3-reality-deploy
sudo bash deploy-h3-sni.sh
```

全新 VPS 上脚本自动完成（详细说明见 12.2）：

- 探针自给自足：同目录二进制 → 同目录源码 + Go 自动编译 → GitHub Release 下载预编译二进制；
- xray 内核自动检测（`/opt/xray/xray-linux-amd64` → `/usr/local/bin/xray` → `PATH`），
  找不到时黄色警告并给出引导（从仓库 `core/` 源码构建 fork 内核 / 官方内核 H2 降级模式）；
- 没有 `server.json` 自动生成最小可运行配置（默认端口 443：H2 TCP + H3 UDP，非标准端口可用
  `H2_PORT`/`H3_PORT` 环境变量覆盖），UUID/x25519 keypair/shortId 用内核二进制自动生成；
  已有配置按特征定位 H3 inbound，只改其 dest/serverNames/fallbackDestRoutes[SNI]；
- 没有 `xray-h3.service` 自动创建并 `enable`；
- 部署后输出完整 VLESS 分享链接（`vless://...`，含 sni/pbk/sid/fp/type），可直接导入客户端。

> 注意：fork 内核源码已开源在仓库 [`core/`](core/)（v26.7.28 + 全部魔改，MIT）。H3 节点
> 必须使用 fork 内核；若只有官方内核，脚本会走 H2 降级模式（仅部署 H2，自签证书 + 明确警告）。

### 8.1 单节点部署拓扑

| 节点 | 地址 | H2 端口 | H3 端口 |
|------|------|---------|---------|
| 你的服务器 | `YOUR_SERVER_IP` | 443 (TCP) | 443 (UDP) |

默认端口为 443（TCP 与 UDP 可共存）；非标准端口可用环境变量 `H2_PORT`/`H3_PORT` 覆盖
（本项目作者生产环境实际用 8443/8446）。所有节点 H3 inbound 结构相同：示例 SNI = ea.com，
部署时用你自己的 SNI（脚本会自动验证 H3 支持），路由表 17 条。

### 8.2 server.json —— H3 inbound 完整示例（默认端口 443）

```jsonc
// /opt/xray/server.json 中的 H3 inbound（默认端口 443；密钥字段已脱敏，真实值以实际部署为准）
{
  "listen": "0.0.0.0",
  "port": 443,
  "protocol": "vless",
  "settings": {
    "clients": [
      { "id": "REPLACE_WITH_REAL_UUID", "flow": "" }
    ],
    "decryption": "none"
  },
  "streamSettings": {
    "network": "xhttp",
    "security": "reality",
    "sockopt": {
      "customSockopt": [
        { "system": "linux", "network": "udp", "level": "1", "opt": "8",  "value": "8388608", "type": "int" },
        { "system": "linux", "network": "udp", "level": "1", "opt": "7",  "value": "8388608", "type": "int" }
      ]
    },
    "xhttpSettings": {
      "mode": "stream-one",
      "enableH3": true,
      "path": "/v1/collect",
      "noGRPCHeader": true,
      "headers": {
        "accept-encoding": "gzip, deflate, br, zstd",
        "content-type": "application/octet-stream",
        "dnt": ""
      },
      "xPaddingBytes": "32-96",
      "xPaddingObfsMode": true,
      "xPaddingPlacement": "query",
      "xPaddingKey": "cb",
      "xPaddingMethod": "tokenish"
    },
    "realitySettings": {
      "show": false,
      "dest": "ea.com:443",
      "serverNames": [ "ea.com" ],
      "privateKey": "REPLACE_WITH_REAL_PRIVATE_KEY",
      "shortIds": [ "REPLACE_WITH_REAL_SHORT_ID" ],
      "fingerprint": "chrome",
      "alpn": [ "h3" ],
      "fallbackDest": "cloudflare-quic.com:443",
      "fallbackDestRoutes": {
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
        "www.xbox.com": "www.xbox.com:443"
      }
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
        "maxIncomingStreams": 1000
      }
    }
  }
}
```

要点：

- `alpn=["h3"]` 必须显式配置（服务端标准 TLS 栈需要它来启动 H3 与预检）；
- 服务端自己的 TLS 栈只能与"跳过 CertificateVerify 校验"的 fork 客户端完成握手（dest 链 +
  一次性密钥签名）；**标准客户端（含探测者）的握手由 relay 完成**——所以无认证流必须被
  原样转发，探测者看到的是真实站点完成的握手，而不是服务端自己签的假证书；
- `fallbackDest` 必须显式（预检启用开关），`fallbackDestRoutes` 提供 SNI 精确路由；
- `sockopt` UDP 收发缓冲 8MB；`finalmask.quicParams` 配 BBR aggressive + 大窗口；
- H2 inbound 不包含以上任何 H3 专属字段，与官方 H2 REALITY 完全兼容。

### 8.3 systemd 服务

```ini
# /etc/systemd/system/xray-h3.service
[Unit]
Description=Xray Reality H3 Server
After=network.target

[Service]
Type=simple
ExecStart=/opt/xray/xray-linux-amd64 run -c /opt/xray/server.json
Restart=on-failure
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
```

### 8.4 客户端配置（Windows zip）

```jsonc
// VLESS outbound —— 只需把 serverName 换成当前 SNI；keypair/UUID/shortId 不变
{
  "protocol": "vless",
  "settings": {
    "vnext": [
      {
        "address": "YOUR_SERVER_IP",        // 你的服务器公网 IP
        "port": 443,
        "users": [
          {
            "id": "REPLACE_WITH_REAL_UUID",
            "encryption": "none",
            "flow": ""
          }
        ]
      }
    ]
  },
  "streamSettings": {
    "network": "xhttp",
    "security": "reality",
    "realitySettings": {
      "serverName": "ea.com",               // ← 换 SNI 时只改这里
      "fingerprint": "chrome",
      "publicKey": "REPLACE_WITH_REAL_PUBLIC_KEY",
      "shortId": "REPLACE_WITH_REAL_SHORT_ID"
    },
    "sockopt": { /* 与服务器一致的 UDP 缓冲可选 */ },
    "xhttpSettings": {
      "mode": "stream-one",
      "enableH3": true,
      "path": "/v1/collect",
      "noGRPCHeader": true,
      "headers": {
        "accept-encoding": "gzip, deflate, br, zstd",
        "content-type": "application/octet-stream",
        "dnt": ""
      },
      "xPaddingBytes": "32-96",
      "xPaddingObfsMode": true,
      "xPaddingPlacement": "query",
      "xPaddingKey": "cb",
      "xPaddingMethod": "tokenish"
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
        "maxIncomingStreams": 1000
      }
    }
  }
}
```

---

## 9. 版本演进史 v6 → v9

| 版本 | 改了什么 | 为什么 |
|---|---|---|
| **v6** | 首次让 REALITY 跑在 QUIC：认证载荷（X25519 ECDH + HKDF + AES-GCM：版本+时间戳+shortId）塞 TLS 1.3 `session_id`（32B）；`transport/internet/tls/reality_quic.go` 的 `QUICTLSFactory` 桥接；客户端/服务端都用 reality fork 的 TLS 状态机 | 打通 H3 + REALITY 的数据通路（群友 fork 组合） |
| **v7** | 服务端 QUIC 预检 + UDP relay 先行（阶段 1）：`ClientHelloVerifier` 抽取、Initial 解密、AUTH/RELAY；`session_id` 被否决后认证过渡到 HTTP 数据面 `X-Reality-Auth` 头；服务端改标准 crypto/tls 栈（session_id=0、5 组 groups）+ dest 真实证书链（`GetDestCertChain` + 一次性签名密钥）；`forwardToDest` HTTP 反向代理兜底（剥 Alt-Svc）；BBR 修复（`OnPacketsLost`/`OnAppLimited`）；`finalmask.quicParams` 配置体系 | 32B session_id 是强指纹必须去掉；先做服务端 relay，客户端认证后置；标准栈消除握手特征；提升吞吐 |
| **v8** | 阶段 2：认证载荷改放 **ClientHello random 字段**（32B AES-GCM 恰好填满）；客户端删除 `X-Reality-Auth` 头（握手层认证不可重放，数据面 record 可原样重放，留着更弱；服务端保留校验兼容旧客户端）；预检 `Verify` 随机优先 + session_id 回退（兼容 TCP REALITY）；P0 清理死代码（服务端不再需要 QUICTLSFactory） | 认证隐身 + 不可重放，与真随机不可区分 |
| **v9** | SNI 感知 relay：`fallbackDestRoutes`（探测者 SNI 精确匹配路由到对应真实站点，17 条表）；多 IP 故障转移（`resolveRelayDest` 解析全部 A/AAAA 候选，ICMP refused 自动切换）；uTLS Chrome 指纹客户端（当前内核；`quicifySpec`：套件裁 [GREASE,1301,1302,1303]、versions 只 0x0304、去 SessionTicket、ALPS 指 h3、TP 0x39 固定插 key_share 后、保留 compress_cert/status_request/GREASE ECH、`MlkemEcdhe` 私钥映射） | 探测者任何 SNI 看到的行为 = 直连该真实站点；单个坏 A 记录不再黑洞目标；客户端握手指纹对齐真实 Chrome |

---

## 10. 已知坑与经验

- **BBR 降级**：quic-go 的 BBR 需 `congestion=bbr` + `bbrProfile=aggressive` + 大窗口
  （`init/maxStreamReceiveWindow` 等）才能跑满；默认 BBR standard 明显慢；`bbr_sender.go`
  必须实现 `OnPacketsLost`/`OnAppLimited`（v6 的核心提速点），否则拥塞控制空转。
- **shortId hex pad**：xray 配置里 shortId 是 hex 解码（如 `"0a1b2c3d"` = 4 字节），而认证记录
  构造器要求 8 字节——必须补零扩展到 8 字节，否则客户端发不出认证（服务端一路 401/RELAY）。
- **RFC 8879 压缩证书**：uTLS 指纹保留 `compress_cert(brotli)`，与 Chrome 一致；服务端若配置
  压缩证书会参与握手，不要把该扩展从指纹里删掉。
- **SCID 4B**：apernet quic-go fork 默认 `ConnectionIDLength = 4`
  （`protocol.DefaultConnectionIDLength = 4`），Initial 包 SCID 为 4 字节；预检按长度字段解析
  SCID，改连接 ID 长度不影响预检，抓包对特征时注意是 4B 而非 Chrome 的 8B。
- **TP GREASE**：quic-go 自动在 transport parameters 列表首项插入 GREASE 参数
  （ID = `27 + 31*random[0]`、长度 0–15B、随机内容）——这是 QUIC 客户端正常特征，别去掉；
  uTLS 路径把 TP 扩展固定插在 key_share 之后，保证位置与 Chrome 一致。
- **Alt-Svc 剥离**：`forwardToDest` 反向代理转发 dest 的 H1.1 响应时，必须剥离 `Alt-Svc`
  和 hop-by-hop 头——H3 响应里出现"H1.1 才有的 Alt-Svc 广告 dest H3 端点"会暴露代理。
- **apple H3 真相**：apple.com QUIC 超时、www.apple.com 稳定 0x150——apple 没有公网 H3
  端点，**不能**当 SNI 或 dest；GFW 最爱探测 apple SNI，但路由表里保留 apple 条目恰好让探测者
  看到"真实 apple 的拒绝行为"（relay 到 apple 后由 apple 自己拒绝）。

---

## 11. 验证方法

### 11.1 连通性

- 客户端连上后访问测速/下载站，204/200 即通；`curl --http3 https://<SNI>/` 从外部打 443（UDP）
  应看到真实站点的响应（relay 生效）。

### 11.2 抓包特征核对（Wireshark，QUIC + TLS 解密）

| 特征 | 期望 |
|---|---|
| session_id | 0（零长度） |
| supported_groups | 5 组：`[0xaaaa, 0x11ec, 0x1d, 0x17, 0x18]` |
| ALPN / ALPS | h3 / h3 |
| SCID | 4B（fork 默认） |
| TP | 首项 GREASE 参数存在，0x39 扩展在 key_share 之后 |
| random | 32B 密文，与随机样本统计不可区分（位密度 ≈ 0.5、χ² ≈ 250） |

### 11.3 probe 工具

```bash
# 直连公网域名测 H3 支持（部署前必做）
./probe-h3-sni -sni ea.com                 # STATUS: 301（完整握手 = 支持）
./probe-h3-sni -sni apple.com              # ERR: context deadline exceeded（不支持）
./probe-h3-sni -sni www.apple.com          # ERR: ... CRYPTO_ERROR 0x150 ...（不支持）

# 部署后验证 relay 闭环：连本机 443（UDP），SNI 仍用目标域名
./probe-h3-sni -sni ea.com -addr 127.0.0.1:443    # STATUS: 400/301 = 路由命中
```

退出码：0 = 完整握手；1 = 不支持；2 = 参数错误。

### 11.4 错误码判据

见第 7 节表格：`0x128`（relay 生效，CF 拒未知 SNI）、`0x133`（旧内核自己握手）、
`0x150`（目标无 H3 端点）。

---

## 12. 附录

### 12.1 17 条路由表（fallbackDestRoutes JSON）

```json
{
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
  "www.xbox.com": "www.xbox.com:443"
}
```

### 12.2 部署脚本（deploy-h3-sni.sh）与探针

```bash
# 部署（root 直跑；非 root 自动 sudo 重执行）
sudo bash deploy-h3-sni.sh
# 交互输入 SNI（默认 ea.com），流程：
#   格式校验 → DNS 解析 → 探针测 H3 → 支持则改 H3 inbound + 备份 + run -test + 重启 + 验证
#   不支持则红字拒绝并建议换 SNI（最多 5 次，q/quit 退出）
```

脚本行为摘要（自包含引导版）：

- 探针三级获取：①同目录 `probe-h3-sni` 二进制 ②同目录 `probe-h3-sni.go` + 系统有 Go →
  自动 `go build`（优先 `probe-mod/`）③都没有 → 从 GitHub Release 下载预编译二进制
  （`.../releases/latest/download/probe-h3-sni-linux-amd64`）；下载失败给黄色警告并说明
  手动获取方式（脚本内嵌源码，需 Go 1.22+ 编译）；
- 内核检测：`/opt/xray/xray-linux-amd64` → `/usr/local/bin/xray` → `PATH` 中的 `xray`，
  找到后 `version` 校验；找不到 → 黄色警告（提示从仓库 `core/` 源码构建内核）+ 两种引导：
  按 README「core/ 内核源码」自行构建 fork 内核，或已装官方 xray 则走 **H2 降级模式**
  （只部署 H2 + 自签证书，明确提示跳过 H3）；
- 无 `server.json` → 自动生成最小可运行配置：H2（默认端口 443，vless+xhttp+reality，dest
  真证书需 fork 内核）+ H3（默认端口 443 UDP，alpn=h3 + `fallbackDest` + 17 条
  `fallbackDestRoutes`），UUID/privateKey/publicKey/shortId 由内核二进制自动生成；
  非标准端口可用 `H2_PORT`/`H3_PORT` 环境变量覆盖；
- 已有配置 → 按特征定位 H3 inbound（network=xhttp 且 alpn 含 h3），只改其：
  `dest=<SNI>:443`、`serverNames=[<SNI>]`、`fallbackDestRoutes[<SNI>]=<SNI>:443`
  （已有则更新，没有则新增，其余 17 条不动）；不碰其他 inbound；
- 无 `xray-h3.service` → 自动生成并 `daemon-reload` + `enable`；ExecStart 与当前内核/配置
  不一致时自动更新；已一致只 `restart`；
- 端口冲突检测：改配置前用 `ss` 检查 H3（默认 443）UDP / H2（默认 443）TCP，被非 xray
  进程占用时黄色警告 + 询问是否继续（默认继续，覆盖端口说明）；
- 自动备份 `server.json.bak-sni-<SNI>-<时间戳>`；`run -test` 失败或 `systemctl restart
  xray-h3` 失败自动回滚；
- 验证：`ss -ulnp` 确认 H3（默认 443）UDP 监听 + 探针 `-sni <SNI> -addr 127.0.0.1:443`
  验证 relay 闭环（返回 400/任何 HTTP 状态码即路由命中）；
- 完成后提醒客户端只需同步 `serverName`（SNI），keypair/UUID/shortId 不变，并打印完整
  VLESS 分享链接（`vless://...`，含 sni/pbk/sid/fp=chrome/type=xhttp），可直接导入客户端。

### 12.3 常见问题（FAQ）

**Q：探测我 H3 端口（默认 443）返回 0x128，是 relay 坏了？**
A：不是。0x128 = 真实站点（如 CF）对未知 SNI 的拒绝，说明 relay 已经生效、探测流被转给了
真实站点。换个在路由表里的 SNI 再探，应看到完整握手。

**Q：为什么 fallbackDest 不能默认等于 dest？**
A：预检只对"没通过认证"的流 relay。如果无认证流默认也 relay 到 dest（业务 dest），那所有
没带认证的客户端都会被当成探测者转发，正常业务全断。所以预检必须显式开启。

**Q：为什么客户端不再发 X-Reality-Auth 头？**
A：握手层认证（client_random）绑定整包、不可重放；数据面 record 可以被原样重放，留着只会
让攻击面更弱。服务端仍保留校验逻辑以兼容没有预检的旧部署。

**Q：换 SNI 会不会影响 keypair？**
A：不会。SNI 只影响 `dest`/`serverNames`/路由表/客户端 `serverName`；privateKey/publicKey/
UUID/shortId 不变。

**Q：为什么抓包 groups 是 5 组而不是 7 组？**
A：Go 1.26 的标准 crypto/tls 默认多两个 PQ 混合组；fork 显式固定为 Go 1.24/1.25 基线
（X25519MLKEM768 + 4 条经典曲线）+ GREASE，对齐广泛部署的 quic-go/Chrome 客户端形态；
uTLS 路径同样只有 5 组（见 5.3）。
