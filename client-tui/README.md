# H3 REALITY Client — 单文件 TUI 客户端

H3-REALITY 项目的最终用户客户端：**一个可执行文件** = 终端交互界面 + fork 内核
（xray-h3-v9，支持 XHTTP stream-one + REALITY + H3/QUIC）+ 绕过大陆规则集
（Loyalsoldier/v2ray-rules-dat 的 `geosite.dat` / `geoip.dat`），全部通过
`go:embed` 打进单个二进制，用户无需下载内核、无需下载规则文件。

- 平台：Windows 10+（amd64）、Linux（amd64）
- 代理端口：SOCKS5 `127.0.0.1:10808`，HTTP `127.0.0.1:10809`
- 规则：绕过大陆 —— 国内域名/国内 IP 直连，其余流量走代理（v2rayN 同款规则组合）

## 快速开始

1. 双击 / 运行 `client-tui-win-amd64.exe`（Windows）或 `./client-tui-linux-amd64`（Linux）。
2. 主菜单选 `[1] 添加配置`，粘贴服务端的 VLESS 分享链接（形如
   `vless://<UUID>@<host>:8446?encryption=none&security=reality&type=xhttp&mode=stream-one&enableH3=1&path=...&sni=...&pbk=...&sid=...#备注`），回车。
   程序自动解析全部参数并校验（UUID / 端口 / REALITY / xhttp / sni / pbk），
   解析失败会红字提示且不保存。
3. `[2] 配置列表` 可查看所有已存配置并切换当前使用哪个；`[5] 删除`、`[6] 重命名`。
4. `[3] 启动代理`：自动释放内嵌内核与规则文件、生成配置并拉起内核子进程，
   显示 `运行中 (PID xxx)` 后即可把浏览器 / 系统代理设为 `127.0.0.1:10808`（SOCKS5）
   或 `127.0.0.1:10809`（HTTP）。内核日志实时输出，同时写入程序目录 `logs/`。
5. `[4] 停止代理`；`[0] 退出`（退出时自动停止代理并清理临时文件）。

## 数据文件

程序目录（可执行文件所在目录）下：

- `configs.json` — 已保存的配置列表（JSON 数组，含解析出的全部字段 + 原始链接）
- `current.json` — 当前选中的配置名
- `configs.lock` — 防并发写锁（异常退出后 30 秒自动过期）
- `logs/` — 每次启动内核的运行日志

运行时内核与规则文件释放到系统临时目录（如 `/tmp/h3-client-*` 或 `%TEMP%\h3-client-*`），
停止/退出时自动删除。

## Windows 控制台说明

程序启动时自动把控制台代码页切到 UTF-8（65001）并开启 ANSI 颜色（cmd / PowerShell
均可用）。若某些旧终端仍显示乱码，可手动执行一次：

```
chcp 65001
```

再运行本程序。

## 绕过大陆规则集

- 规则文件：Loyalsoldier/v2ray-rules-dat 的 `geosite.dat` + `geoip.dat`（release 最新版）
- 路由规则（生成的内核配置 `routing.rules`）：
  1. `geosite:cn` → 直连
  2. `geoip:cn` → 直连
  3. `geosite:geolocation-!cn` → 代理
  4. 其余 `tcp,udp` → 代理（兜底）
- 与 v2rayN「绕过大陆」模式一致：国内直连、国外走代理。

## 从源码构建

构建需要仓库内 `core/` 源码编译出的内核二进制（内核源码已开源，见仓库
[README.md](../README.md)「core/ 内核源码」）：

```bash
# 先用 core/ 源码编译内核（Linux + Windows amd64）
mkdir -p kernel
cd ../core
go build -mod=vendor -o ../client-tui/kernel/xray-h3-v9 ./main
GOOS=windows GOARCH=amd64 go build -mod=vendor -o ../client-tui/kernel/xray-h3-v9-win-amd64.exe ./main
cd ../client-tui

# Linux
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o client-tui-linux-amd64 .

# Windows
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o client-tui-win-amd64.exe .
```

内核源码已开源在 `../core/`；TUI 只做进程管理（释放 → 生成配置 →
`run -c config.json` → 停止时终止），不修改、不重新编译。

## 测试

```bash
go test ./...   # VLESS 解析 / 配置生成单元测试
go vet ./...    # 静态检查
```

## 常见问题

- **端口 10808/10809 被占用**：启动前会自动检测并红字提示，关闭占用程序后重试。
- **启动失败**：红字会附上内核最后 40 行日志；完整日志在 `logs/run-*.log`。
- **连不上目标服务器**：先确认服务端已按 `deploy-h3-sni.sh` 部署、链接参数
  （sni/pbk/sid/path）与服务端一致。
- **首次启动稍慢**：需要把约 75MB 的内核与规则文件从单文件里释放出来，属正常现象。
