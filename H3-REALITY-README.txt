# H3 REALITY: VLESS+XHTTP+REALITY在QUIC/H3传输层的实现

## 1. 目的

使得VLESS+XHTTP+H3 REALITY达到流量分析不可区分性(这与隐写术中的不可区分性不同,(我们希望)后者只是前者的必要条件罢了,因为(我们希望)不存在一个多项式时间的区分器能以不可忽略的优势把T_proxy和T_cover区分开,但很遗憾鹦鹉确是反审查中很难避开的一环,而且QUIC特征将会更多,多麻了.):
客户端ClientHello JA3/JA4对齐Chrome(uTLS quicifySpec),认证载荷藏进TLS 1.3 ClientHello的random字段(与伪随机不可区分,这里的不可区分见姚氏伪随机定义,因为不可区分性具有传递性,所以也与真随机不可区分.），
无认证的流量会被转发到fallbackDest,然后把fallbackDest返回的数据给它.(代号relay)
官版Xray-core v26.7.28中,REALITY+XHTTP在传输层是HTTP/2:
transport/internet/reality/config.go里的NextProtos硬编码nil,注释也说should be nil.
transport/internet/splithttp/hub.go中
l.isH3 = len(tlsConfig.NextProtos) == 1 && tlsConfig.NextProtos[0] == "h3"
在匹配["h3"]这个值.当配置文件中有security: "reality"时isH3应该是false.
即使NextProtos是[]string{"h3"},也对这个分支无作用,因为isH3用的是getTLSConfig而不是GetREALITYConfig.
故h3分支没有REALITY(本就挂在net.Listener上的)的接入点,h1/h2分支倒是可以接入.
至于XHTTP: Beyond REALITY那个Discussion(我戏称是上行h3过cdn 下行REALITY,简写H3 REALITY).
个人总结下XHTTP(前置段落):
XHTTP是一种传输方式,采用分包上行和流式下行的思想,分包上行指的是客户端把要上传的数据拆成多个独立的短HTTP POST请求(带序号seq和关联标识UUID)依次发送,不必等待上一个请求完全响应,服务器收到后按序号重组,用来过CDN.(因为传统的长连接和大文件POST上传容易被CDN拦截缓存或断开)
流式下行 服务器通过一个长连接的HTTP GET响应(伪装成SSE(Server-Sent Events)流,同时配置X-Accel-Buffering: no等头信息禁止中间代理缓存数据),持续不断,实时地向客户端推送下载数据.
如果还用官版二进制,REALITY就只会停留在TCP(RAW,gRPC,h1/h2 XHTTP),QUIC依旧TLS.
凡是世界说过的话都是正确的: 关于反审查,越特定于GFW的应对测试就越意淫,意淫程度从高到低: 假设GFW会看你网站并干什么的伪装和回落,假设GFW会验证你证书的fake-tls,假设GFW会主动分析你TLS 指纹的uTLS和naive,流量特征随机化可以说是其中最正常的了.
所以我们的目的是意淫程度最高,最不正常.

### 2.2 QUIC主动探测

UDP端口(8443/8446)直接把代理服务暴露在公网(当然占QUIC的端口是为了伪装成QUIC).GFW要主动探测成本很低:
发一个标准QUIC Initial,只要握手能完成,返回行为与真实站点不一致,端口即被标记为代理.
防QUIC主动探测设计
1. ClientHello中的transport-parameters,legacy_session_id,NamedGroup,ALPS etc.与Chrome一致.
2. relay
3. 防重放.

### 2.3 为什么要fork
官版REALITY把认证载体塞到TLS 1.3中的legacy_session_id里,但主流浏览器在QUIC协议中用的字段legacy_session_id长度是0,况且在其它QUIC客户端的实现中,例如Python库aioquic中有以下代码
580:    legacy_session_id: bytes
718:    legacy_session_id: bytes
1342:            self.legacy_session_id = b""
说明它被硬编码为空字符串.而作者的实现也一样:
uconn.HandshakeState.Hello.SessionId = nil
作者用c.quic != nil 做了分流,applyRealityClientHello才是老路子,applyRealityClientHelloRandom才是我描述的,故不要盲信AI评价,例如我刚开始被Haiku误导了.

quic-go二开
做了一个插口QUICTLSFactory,原来TLS用的是握手引擎被换成了作者自己的.
把阻塞式Read/Write握手换成协程/通道,借鉴了Go标准库里的crypto/tls里的tls.QUICConn,不再赘述.


## 3. 可认证

### 3.2,3.3 client_random与IND$性质
我将用游戏G0,G1,G2,G3来证明,每个游戏之间的差异由已知很难破解的密码学假设所限定.如果每一个差异都可忽略,那么加起来的差异也可忽略,但在理论密码学中,渐进可忽略性只在一族群上成立,安全参数趋向于正无穷大,而这里的优势是一个常数,Curve25519是一个阶为常数的群,所以我给的是优势上界.倘若先入为主以通用攻击复杂度规定安全参数,不可取.(不会难,也不会严谨,享受展示吧,先告诉你我在做什么.)
在applyRealityClientHelloRandom/verifyClientHelloRandom/verifyClientHelloAuth中,密钥材料(以后叫IKM)如下
一对X25519密钥(keySharePrivateKeys.ecdhe,peerPub),
其中keySharePrivateKeys.ecdhe(keys.ecdhe)是客户端的X25519私钥,peerPub是客户端的X25519公钥,分别记作sk_c,pk_c.
服务器公钥Config.PublicKey(c.PublicKey),客户端用于得到共享秘密的公钥;服务器私钥Config.PrivateKey(cfg.PrivateKey),服务端用于恢复共享秘密的私钥.分别记作pk_s,sk_s.
plainText := make([]byte, 16)
plainText[0] = 26
plainText[1] = 4
plainText[2] = 17
binary.BigEndian.PutUint32(plainText[4:], uint32(time.Now().Unix()))
copy(plainText[8:], c.ShortId)
可以看出,plainText共16字节,等于clientVer || Unix... || ShortId,记为M.
authKey(keys.ecdhe.ECDH(publicKey)),X25519的共享秘密(32字节,256比特,所以AES-256-GCM,安全参数\lambda 256),记为Z = pk_s^{sk_c}=g^{sk_s\cdot sk_c},(PS. ECDH方法封装了群的标量乘法,所以看不到幂之类的.)
adHash := sha256.Sum256(associatedData)
(用associated data派生salt) H=SHA-256(AD),哈希前20字节当HKDF的salt,后12字节当AES-GCM的Nonce N.
hkdf.New(sha256.New, authKey, hello.random[:20], []byte("REALITY")).Read(authKey)
此时Z被更新为K_auth.[]byte("REALITY"),可选参数CtxInfo.(上下文信息)
block, _ := aes.NewCipher(authKey)
aead, _ := cipher.NewGCM(block)
hello.random = aead.Seal(nil, adHash[20:32], plainText, associatedData)
用K_auth和Nonce N(adHash[20:32])对M作AEAD.hello.C和T分别为hello.random的前16字节和后16字节.
证明敌手(审查者)无法区分C||T和等长真随机(通过外部物理环境产生(TRNG)的随机字节.即便用了硬件,也很难做到真随机,目前只有基于量子算法生成的随机字节才是真正意义的随机字节.)字节这个命题.
G0启动.(敌手观测到的random(R_0))
R_0 = AES-GCM_{K_auth}(N, M, AD)
G1启动.(规则如下)
DDH假设在X25519上成立.由于pk_s = g^(sk_s),pk_c = g^(sk_c)敌手已知.但敌手不知sk_c,sk_s.
DDH假设指出,给定(g, g^{sk_s}, g^{sk_c}),敌手不可区分g^(sk_s\cdot sk_c) 和一个从群\mathbb{G}中均匀分布抽样的元素Z_rand.任给Z_rand \in \mathbb{G} \Pr[Z=Z_rand]=\frac{1}{\vert{}\mathbb{G}\vert{}},也即每个群元素被选到的概率相等.
将HKDF的IKM从Z = g^(sk_s\cdot sk_c)换到Z_rand.
不可区分的表示,攻击者返回相同猜测结果1的概率差异,假设有一个敌手,他在执行完猜测后,得到的概率差值|\Pr[G_{0}]-\Pr[G_{1}]|为0,这说明,这个攻击者在不同游戏中,输出相同猜测结果的概率是相等的,很明显,这个敌手根本搞不清楚自己处于哪个游戏.安全参数\lambda越大,攻击者越难破坏DDH,这就叫规约.
|\Pr[G_{0}]-\Pr[G_{1}]|\leq \mathrm{Adv}^{\mathrm{DDH}}_{\mathcal{G}}(\lambda)
G2启动
HKDF-SHA256是一个安全的伪随机函数,既然G1中Z_rand已经是随机的了,那把K_auth替换成从\{0,1\}^{128}中均匀分布抽样的密钥K_rand.
敌手区分G1和G2的优势.
\lvert \Pr[G_{1}] - \Pr[G_{2}] \rvert \le \mathrm{Adv}_{\mathrm{HKDF}}^{\mathrm{PRF}}(\lambda)
G3启动
在G2中,使用K_rand执行AES-256-GCM加密,考虑C || T的不可区分性.
密文C的不可区分性
AES-GCM使用CTR模式加密明文,C = M \oplus \mathrm{AES}_{K_{\mathrm{rand}}}(N \parallel \mathrm{counter}),假设AES是一个安全的PRP,且作为PRF使用.在K_rand未知且Nonce N不碰撞(N碰撞的概率为O(q^2/2^{96}))的情况下,密钥流\mathrm{AES}_{K_{\mathrm{rand}}}(\cdot)与真随机比特流不可区分.
T = \mathrm{GHASH}_H(AD, C) \oplus \mathrm{AES}_{K_{\mathrm{rand}}}(N \parallel 0^{31}1)
因为\mathrm{AES}_{K_{\mathrm{rand}}}(N \parallel 0^{31}1)是密钥流的另一个独立输出块,和真随机不可区分,与GHASH的结果进行了异或.根据一次性密码本的完美保密性,(GHASH的结果,基于AD,C算出的哈希值)异或一个与真随机不可区分的掩码(AES单独算出的伪随机掩码)后,得到的标签T同样与真随机字符串不可区分.
将R_2=C||T替换为一个从\{0,1\}^{256}中均匀分布抽样的32字节字符串U_32.所以
\lvert \Pr[G_2] - \Pr[G_3] \rvert \le \mathrm{Adv}_{\mathrm{AES}}^{\mathrm{PRF}}(\lambda) + \frac{q^2}{2^{97}}
根据柯西施瓦茨不等式得到三角不等式.
\lvert \Pr[G_0] - \Pr[G_3] \rvert 
\le \lvert \Pr[G_0] - \Pr[G_1] \rvert + \lvert \Pr[G_1] - \Pr[G_2] \rvert + \lvert \Pr[G_2] - \Pr[G_3] \rvert \\
\le \mathrm{Adv}_{\mathrm{DDH}}(\lambda) + \mathrm{Adv}_{\mathrm{HKDF}}^{\mathrm{PRF}}(\lambda) + \left(\mathrm{Adv}_{\mathrm{AES}}^{\mathrm{PRF}}(\lambda) + \frac{q^2}{2^{97}}\right)
至此,我完成了证明.防重放则留作习题答案略.
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
  （服务器 IP:8446）；
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
git clone https://github.com/lipeiying032/h3-reality-deploy.git
cd h3-reality-deploy
sudo bash deploy-h3-sni.sh
```

全新 VPS 上脚本自动完成（详细说明见 12.2）：

- 探针自给自足：同目录二进制 → 同目录源码 + Go 自动编译 → GitHub Release 下载预编译二进制；
- xray 内核自动检测（`/opt/xray/xray-linux-amd64` → `/usr/local/bin/xray` → `PATH`），
  找不到时黄色警告并给出引导（从仓库 `core/` 源码构建 fork 内核 / 官方内核 H2 降级模式）；
- 没有 `server.json` 自动生成最小可运行配置（8443 H2 + 8446 H3），UUID/x25519 keypair/
  shortId 用内核二进制自动生成；已有配置只改 8446 的 dest/serverNames/fallbackDestRoutes[SNI]；
- 没有 `xray-h3.service` 自动创建并 `enable`；
- 部署后输出完整 VLESS 分享链接（`vless://...`，含 sni/pbk/sid/fp/type），可直接导入客户端。

> 注意：fork 内核源码已开源在仓库 [`core/`](core/)（v26.7.28 + 全部魔改，MIT）。H3（8446）
> 节点必须使用 fork 内核；若只有官方内核，脚本会走 H2 降级模式（仅 8443，自签证书 + 明确警告）。

### 8.1 双 VPS 拓扑

| 节点 | 地址 | H2 | H3 |
|---|---|---|---|
| 主 VPS | `YOUR_MAIN_VPS_IP` | 8443 | 8446 |
| 小 VPS | `YOUR_SMALL_VPS_IP` | 8445 | 8446 |

两台 VPS 的 8446 inbound 结构相同（当前 SNI = ea.com，2026-08-05 更新，路由表 17 条）。

### 8.2 server.json —— 8446 inbound 完整示例

```jsonc
// /opt/xray/server.json 中的 8446 inbound（密钥字段已脱敏，真实值见生产文件）
{
  "listen": "0.0.0.0",
  "port": 8446,
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
- 8443/8445（H2）inbound 不包含以上任何 H3 专属字段，与官方 H2 REALITY 完全兼容。

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
        "address": "YOUR_MAIN_VPS_IP",      // 主 VPS；小 VPS 用 YOUR_SMALL_VPS_IP
        "port": 8446,
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

- 客户端连上后访问测速/下载站，204/200 即通；`curl --http3 https://<SNI>/` 从外部打 8446
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

# 部署后验证 relay 闭环：连本机 8446，SNI 仍用目标域名
./probe-h3-sni -sni ea.com -addr 127.0.0.1:8446   # STATUS: 400/301 = 路由命中
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
#   格式校验 → DNS 解析 → 探针测 H3 → 支持则改 8446 + 备份 + run -test + 重启 + 验证
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
  （只部署 8443 + 自签证书，明确提示跳过 H3）；
- 无 `server.json` → 自动生成最小可运行配置：8443 H2（vless+xhttp+reality，dest 真证书需
  fork 内核）+ 8446 H3（alpn=h3 + `fallbackDest` + 17 条 `fallbackDestRoutes`），
  UUID/privateKey/publicKey/shortId 由内核二进制自动生成；
- 已有配置 → 只改 8446 inbound：`dest=<SNI>:443`、`serverNames=[<SNI>]`、
  `fallbackDestRoutes[<SNI>]=<SNI>:443`（已有则更新，没有则新增，其余 17 条不动）；不碰 8443/8445；
- 无 `xray-h3.service` → 自动生成并 `daemon-reload` + `enable`；ExecStart 与当前内核/配置
  不一致时自动更新；已一致只 `restart`；
- 端口冲突检测：改配置前用 `ss` 检查 8446 UDP / 8443 TCP，被非 xray 进程占用时黄色警告 +
  询问是否继续（默认继续，覆盖端口说明）；
- 自动备份 `server.json.bak-sni-<SNI>-<时间戳>`；`run -test` 失败或 `systemctl restart
  xray-h3` 失败自动回滚；
- 验证：`ss -ulnp` 确认 8446 UDP 监听 + 探针 `-sni <SNI> -addr 127.0.0.1:8446` 验证
  relay 闭环（返回 400/任何 HTTP 状态码即路由命中）；
- 完成后提醒客户端只需同步 `serverName`（SNI），keypair/UUID/shortId 不变，并打印完整
  VLESS 分享链接（`vless://...`，含 sni/pbk/sid/fp=chrome/type=xhttp），可直接导入客户端。

### 12.3 常见问题（FAQ）

**Q：探测我 8446 端口返回 0x128，是 relay 坏了？**
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
