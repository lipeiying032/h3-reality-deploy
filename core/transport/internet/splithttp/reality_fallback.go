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

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
	"github.com/xtls/xray-core/common/errors"
)

// realityFallbackClient is the reverse-proxy client used for unauthenticated
// (active-probe) requests on the C-gamma data plane. The request is forwarded
// over HTTP/3 to the configured REALITY dest so the outbound protocol stack
// matches the H3 probe. The dest response's status, headers and body are then
// relayed back to the prober.
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
	transport := &http3.Transport{
		TLSClientConfig: &gotls.Config{
			// The proxy is only an HTTP reverse proxy for probe traffic. Do
			// not fail an active probe because the dest uses a private CA;
			// this preserves the prior fallback behavior for private dests.
			InsecureSkipVerify: true,
			ServerName:         sni,
		},
		QUICConfig: &quic.Config{
			HandshakeIdleTimeout: 10 * time.Second,
			MaxIdleTimeout:       90 * time.Second,
			KeepAlivePeriod:      30 * time.Second,
		},
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
		// The upstream's H3 endpoint is the endpoint this request already
		// connected to. Re-advertising it through our fallback response is an
		// unnecessary proxy marker, so strip it before relaying headers.
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
