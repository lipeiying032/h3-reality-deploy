// probe-h3-sni 是一个极简 HTTP/3 (QUIC) 支持探测工具，用于在部署 H3 REALITY
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
