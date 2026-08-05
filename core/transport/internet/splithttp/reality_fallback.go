package splithttp

import (
	"context"
	gotls "crypto/tls"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/xtls/xray-core/common/errors"
)

// realityFallbackClient is the reverse-proxy client used for unauthenticated
// (active-probe) requests on the C-gamma data plane. The request is forwarded
// verbatim to the configured REALITY dest over TCP TLS, so a prober sees the
// real dest response: the handshake already presents the dest certificate, and
// now the HTTP response (status/headers/body) matches the real dest too.
//
// The client is created once per listener and reused for every forwarded
// request (including its pooled connections). A package-level singleton would
// not work here because the dial target and SNI are listener-config
// properties: multiple inbounds may configure different dests.
func newRealityFallbackClient(dest, destServerName string) *http.Client {
	sni := destServerName
	if sni == "" {
		sni = hostOnly(dest)
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	transport := &http.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// TCP TLS to the dest address; the SNI presented is the dest's
			// server name (www.apple.com) and the certificate is not verified
			// (the proxy does not hold the dest's private key nor its root
			// trust). ALPN is the standard h2/http1.1 set, so the forward hop
			// negotiates whatever the dest supports.
			return gotls.DialWithDialer(dialer, network, addr, &gotls.Config{
				InsecureSkipVerify: true,
				ServerName:         sni,
				NextProtos:         []string{"h2", "http/1.1"},
			})
		},
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 15 * time.Second,
		IdleConnTimeout:       90 * time.Second,
		MaxIdleConns:          128,
		MaxIdleConnsPerHost:   128,
	}
	return &http.Client{Transport: transport}
}

// hostOnly strips the port from a host:port string.
func hostOnly(hostport string) string {
	if host, _, err := net.SplitHostPort(hostport); err == nil {
		return host
	}
	return hostport
}

// hopByHopHeaders are relayed per-connection in HTTP/1.1 and must not be
// copied onto the HTTP/3 response written back to the prober.
var hopByHopHeaders = []string{
	"Connection",
	"Proxy-Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

func isHopByHopHeader(name string) bool {
	for _, h := range hopByHopHeaders {
		if strings.EqualFold(name, h) {
			return true
		}
	}
	return false
}

// forwardToDest relays an unauthenticated request to the REALITY dest and
// streams the dest response back unchanged: status code, headers and body, in
// order, without any proxy marker header. If the dest is unreachable the
// prober sees a bare 502 (no authentication details are leaked).
func (h *requestHandler) forwardToDest(writer http.ResponseWriter, request *http.Request) {
	if h.fallbackClient == nil || h.fallbackDest == "" {
		http.Error(writer, "bad gateway", http.StatusBadGateway)
		return
	}
	outReq := request.Clone(request.Context())
	outReq.URL = &url.URL{
		Scheme:   "https",
		Host:     h.fallbackDest,
		Path:     request.URL.Path,
		RawQuery: request.URL.RawQuery,
	}
	outReq.Host = request.Host
	if outReq.Host == "" {
		outReq.Host = h.fallbackDest
	}
	outReq.RequestURI = ""
	outReq.TransferEncoding = nil

	resp, err := h.fallbackClient.Do(outReq)
	if err != nil {
		errors.LogInfo(context.Background(), "REALITY: fallback forward to ", h.fallbackDest, " failed: ", err)
		http.Error(writer, "bad gateway", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	for name, values := range resp.Header {
		// Alt-Svc advertises the dest's H3 endpoint (e.g. h3=":443"); a probe
		// connected to us over H3 would never see this H1.1-specific header on
		// a direct dest response, so stripping it keeps the forwarded response
		// indistinguishable from a direct one.
		if isHopByHopHeader(name) || strings.EqualFold(name, "Alt-Svc") {
			continue
		}
		for _, value := range values {
			writer.Header().Add(name, value)
		}
	}
	writer.WriteHeader(resp.StatusCode)
	io.Copy(writer, resp.Body)
}
