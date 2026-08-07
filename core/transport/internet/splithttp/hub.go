package splithttp

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	gotls "crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
	goreality "github.com/xtls/reality"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	http_proto "github.com/xtls/xray-core/common/protocol/http"
	"github.com/xtls/xray-core/common/signal/done"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/hysteria/congestion"
	"github.com/xtls/xray-core/transport/internet/hysteria/congestion/bbr"
	"github.com/xtls/xray-core/transport/internet/reality"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tls"
)

type requestHandler struct {
	config         *Config
	host           string
	path           string
	ln             *Listener
	sessionMu      *sync.Mutex
	sessions       sync.Map
	localAddr      net.Addr
	socketSettings *internet.SocketConfig
	// realityAuth, when non-nil, makes X-Reality-Auth verification mandatory
	// for every new QUIC connection (C-gamma data-plane REALITY auth).
	realityAuth *realityAuthVerifier
	// fallbackClient/fallbackDest reverse-proxy unauthenticated (probe)
	// requests to the REALITY dest so active probers see the real dest
	// response instead of a 401.
	fallbackClient *http.Client
	fallbackDest   string
	// handshakeAuthed reports whether the QUIC precheck classified the
	// client address as authenticated (REALITY payload verified in the
	// ClientHello random field). Stage-2 wires it to short-circuit the
	// HTTP-layer X-Reality-Auth check for handshake-authenticated
	// connections.
	handshakeAuthed func(net.Addr) bool
}

// handshakeAuthedRemote reports whether the QUIC precheck already
// authenticated the client at the given remote address (the REALITY payload
// was verified in the ClientHello random field). Connections that passed the
// handshake-level precheck skip the HTTP-layer X-Reality-Auth check; when the
// precheck is not active this always returns false, so the header check stays
// authoritative (legacy clients).
func (h *requestHandler) handshakeAuthedRemote(remoteAddr string) bool {
	if h.handshakeAuthed == nil {
		return false
	}
	addr, err := net.ResolveUDPAddr("udp", remoteAddr)
	if err != nil {
		return false
	}
	return h.handshakeAuthed(addr)
}

type httpSession struct {
	uploadQueue *uploadQueue
	// for as long as the GET request is not opened by the client, this will be
	// open ("undone"), and the session may be expired within a certain TTL.
	// after the client connects, this becomes "done" and the session lives as
	// long as the GET request.
	isFullyConnected *done.Instance
}

func (h *requestHandler) upsertSession(sessionId string) *httpSession {
	// fast path
	currentSessionAny, ok := h.sessions.Load(sessionId)
	if ok {
		return currentSessionAny.(*httpSession)
	}

	// slow path
	h.sessionMu.Lock()
	defer h.sessionMu.Unlock()

	currentSessionAny, ok = h.sessions.Load(sessionId)
	if ok {
		return currentSessionAny.(*httpSession)
	}

	s := &httpSession{
		uploadQueue:      NewUploadQueue(h.ln.config.GetNormalizedScMaxBufferedPosts()),
		isFullyConnected: done.New(),
	}

	h.sessions.Store(sessionId, s)

	shouldReap := done.New()
	go func() {
		time.Sleep(30 * time.Second)
		shouldReap.Close()
	}()
	go func() {
		select {
		case <-shouldReap.Wait():
			h.sessions.Delete(sessionId)
			s.uploadQueue.Close()
		case <-s.isFullyConnected.Wait():
		}
	}()

	return s
}

func (h *requestHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if len(h.host) > 0 && !internet.IsValidHTTPHost(request.Host, h.host) {
		errors.LogInfo(context.Background(), "failed to validate host, request:", request.Host, ", config:", h.host)
		writer.WriteHeader(http.StatusNotFound)
		return
	}

	if !strings.HasPrefix(request.URL.Path, h.path) {
		errors.LogInfo(context.Background(), "failed to validate path, request:", request.URL.Path, ", config:", h.path)
		writer.WriteHeader(http.StatusNotFound)
		return
	}

	// C-gamma data-plane REALITY auth: every new QUIC connection must present
	// a valid X-Reality-Auth record on its first request. Verification runs
	// exactly once per connection; unauthenticated (probe) requests are
	// reverse-proxied to the REALITY dest so the prober sees the real dest
	// response (certificate and content both match). The connection is left
	// open so repeated probe requests on the same connection all see the real
	// dest. TCP/HTTP requests are unaffected (REALITY over TCP keeps its
	// sessionId handshake auth).
	if request.ProtoMajor == 3 && h.realityAuth != nil {
		// Stage-2: connections the QUIC precheck already authenticated via
		// the ClientHello random payload skip the HTTP-layer X-Reality-Auth
		// check entirely (the handshake credential is non-replayable: the
		// AEAD AD binds it to this exact ClientHello and the timestamp
		// window bounds it). The header check stays for deployments without
		// the precheck, keeping legacy clients working.
		if !h.handshakeAuthedRemote(request.RemoteAddr) {
			qc, _ := request.Context().Value(quicConnKey{}).(*quicConnState)
			if qc == nil || !qc.verified.Load() {
				if err := h.realityAuth.verifyHeader(request.Header.Get(XRealityAuthHeader)); err != nil {
					errors.LogInfo(context.Background(), err.Error(), ", forwarding request to dest")
					h.forwardToDest(writer, request)
					return
				}
				if qc != nil {
					qc.verified.Store(true)
				}
			}
		}
	}

	h.config.WriteResponseHeader(writer, request.Method, request.Header)
	length := int(h.config.GetNormalizedXPaddingBytes().rand())
	config := XPaddingConfig{Length: length}

	if h.config.XPaddingObfsMode {
		config.Placement = XPaddingPlacement{
			Placement: h.config.XPaddingPlacement,
			Key:       h.config.XPaddingKey,
			Header:    h.config.XPaddingHeader,
		}
		config.Method = PaddingMethod(h.config.XPaddingMethod)
	} else {
		config.Placement = XPaddingPlacement{
			Placement: PlacementHeader,
			Header:    "X-Padding",
		}
	}

	h.config.ApplyXPaddingToResponse(writer, config)

	if request.Method == "OPTIONS" {
		writer.WriteHeader(http.StatusOK)
		return
	}

	/*
		clientVer := []int{0, 0, 0}
		x_version := strings.Split(request.URL.Query().Get("x_version"), ".")
		for j := 0; j < 3 && len(x_version) > j; j++ {
			clientVer[j], _ = strconv.Atoi(x_version[j])
		}
	*/

	validRange := h.config.GetNormalizedXPaddingBytes()
	paddingValue, paddingPlacement := h.config.ExtractXPaddingFromRequest(request, h.config.XPaddingObfsMode)

	if !h.config.IsPaddingValid(paddingValue, validRange.From, validRange.To, PaddingMethod(h.config.XPaddingMethod)) {
		errors.LogInfo(context.Background(), "invalid padding ("+paddingPlacement+") length:", int32(len(paddingValue)))
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	obfsPaddingAccepted := h.config.XPaddingObfsMode && paddingValue != ""

	sessionId, seqStr := h.config.ExtractMetaFromRequest(request, h.path)

	if sessionId == "" && h.config.Mode != "" && h.config.Mode != "auto" && h.config.Mode != "stream-one" && h.config.Mode != "stream-up" {
		errors.LogInfo(context.Background(), "stream-one mode is not allowed")
		writer.WriteHeader(http.StatusBadRequest)
		return
	}

	var remoteAddr net.Addr
	var err error
	remoteAddr, err = net.ResolveTCPAddr("tcp", request.RemoteAddr)
	if err != nil {
		remoteAddr = &net.TCPAddr{
			IP:   []byte{0, 0, 0, 0},
			Port: 0,
		}
	}
	if request.ProtoMajor == 3 {
		remoteAddr = &net.UDPAddr{
			IP:   remoteAddr.(*net.TCPAddr).IP,
			Port: remoteAddr.(*net.TCPAddr).Port,
		}
	}
	var trustedXFF []string
	if h.socketSettings != nil {
		trustedXFF = h.socketSettings.TrustedXForwardedFor
	}
	remoteAddr = http_proto.ApplyTrustedXForwardedFor(request.Header, trustedXFF, remoteAddr)

	var currentSession *httpSession
	if sessionId != "" {
		currentSession = h.upsertSession(sessionId)
	}
	scMaxEachPostBytes := int(h.ln.config.GetNormalizedScMaxEachPostBytes().To)
	isUplinkRequest := false

	switch request.Method {
	case "GET":
		isUplinkRequest = seqStr != ""
	default:
		isUplinkRequest = true
	}

	uplinkDataKey := h.config.UplinkDataKey

	if isUplinkRequest && sessionId != "" { // stream-up, packet-up
		if seqStr == "" {
			if h.config.Mode != "" && h.config.Mode != "auto" && h.config.Mode != "stream-up" {
				errors.LogInfo(context.Background(), "stream-up mode is not allowed")
				writer.WriteHeader(http.StatusBadRequest)
				return
			}
			httpSC := &httpServerConn{
				Instance:       done.New(),
				Reader:         request.Body,
				ResponseWriter: writer,
			}
			err = currentSession.uploadQueue.Push(Packet{
				Reader: httpSC,
			})
			if err != nil {
				errors.LogInfoInner(context.Background(), err, "failed to upload (PushReader)")
				writer.WriteHeader(http.StatusConflict)
			} else {
				writer.Header().Set("X-Accel-Buffering", "no")
				writer.Header().Set("Cache-Control", "no-store")
				writer.WriteHeader(http.StatusOK)
				scStreamUpServerSecs := h.config.GetNormalizedScStreamUpServerSecs()
				hasLegacyRefererCompatMarker := request.Header.Get("Referer") != ""
				if (hasLegacyRefererCompatMarker || obfsPaddingAccepted) && scStreamUpServerSecs.To > 0 {
					go func() {
						for {
							_, err := httpSC.Write(bytes.Repeat([]byte{'X'}, int(h.config.GetNormalizedXPaddingBytes().rand())))
							if err != nil {
								break
							}
							time.Sleep(time.Duration(scStreamUpServerSecs.rand()) * time.Second)
						}
					}()
				}
				select {
				case <-request.Context().Done():
				case <-httpSC.Wait():
				}
			}
			httpSC.Close()
			return
		}

		if h.config.Mode != "" && h.config.Mode != "auto" && h.config.Mode != "packet-up" {
			errors.LogInfo(context.Background(), "packet-up mode is not allowed")
			writer.WriteHeader(http.StatusBadRequest)
			return
		}

		dataPlacement := h.config.GetNormalizedUplinkDataPlacement()
		var headerPayload []byte
		if dataPlacement == PlacementAuto || dataPlacement == PlacementHeader {
			var headerPayloadChunks []string
			for i := 0; true; i++ {
				chunk := request.Header.Get(fmt.Sprintf("%s-%d", uplinkDataKey, i))
				if chunk == "" {
					break
				}
				headerPayloadChunks = append(headerPayloadChunks, chunk)
			}
			headerPayloadEncoded := strings.Join(headerPayloadChunks, "")
			headerPayload, err = base64.RawURLEncoding.DecodeString(headerPayloadEncoded)
			if err != nil {
				errors.LogInfo(context.Background(), "Invalid base64 in header's payload: ", err.Error())
				writer.WriteHeader(http.StatusBadRequest)
				return
			}
		}

		var cookiePayload []byte
		if dataPlacement == PlacementAuto || dataPlacement == PlacementCookie {
			var cookiePayloadChunks []string
			for i := 0; true; i++ {
				cookieName := fmt.Sprintf("%s_%d", uplinkDataKey, i)
				if c, _ := request.Cookie(cookieName); c != nil {
					cookiePayloadChunks = append(cookiePayloadChunks, c.Value)
				} else {
					break
				}
			}
			cookiePayloadEncoded := strings.Join(cookiePayloadChunks, "")
			cookiePayload, err = base64.RawURLEncoding.DecodeString(cookiePayloadEncoded)
			if err != nil {
				errors.LogInfo(context.Background(), "Invalid base64 in cookies' payload: ", err.Error())
				writer.WriteHeader(http.StatusBadRequest)
				return
			}
		}

		var bodyPayload []byte
		if dataPlacement == PlacementAuto || dataPlacement == PlacementBody {
			var readErr error
			if request.ContentLength > int64(scMaxEachPostBytes) {
				errors.LogInfo(context.Background(), "Too large upload. scMaxEachPostBytes is set to ", scMaxEachPostBytes, "but request size exceed it. Adjust scMaxEachPostBytes on the server to be at least as large as client.")
				writer.WriteHeader(http.StatusRequestEntityTooLarge)
				return
			}
			if request.ContentLength > 0 {
				bodyPayload = make([]byte, request.ContentLength)
				_, readErr = io.ReadFull(request.Body, bodyPayload)
			} else {
				bodyPayload, readErr = buf.ReadAllToBytes(io.LimitReader(request.Body, int64(scMaxEachPostBytes)+1))
			}
			if readErr != nil {
				errors.LogInfoInner(context.Background(), readErr, "failed to read body payload")
				writer.WriteHeader(http.StatusBadRequest)
				return
			}
		}

		var payload []byte
		switch dataPlacement {
		case PlacementHeader:
			payload = headerPayload
		case PlacementCookie:
			payload = cookiePayload
		case PlacementBody:
			payload = bodyPayload
		case PlacementAuto:
			payload = slices.Concat(headerPayload, cookiePayload, bodyPayload)
		}

		if len(payload) > scMaxEachPostBytes {
			errors.LogInfo(context.Background(), "Too large upload. scMaxEachPostBytes is set to ", scMaxEachPostBytes, "but request size exceed it. Adjust scMaxEachPostBytes on the server to be at least as large as client.")
			writer.WriteHeader(http.StatusRequestEntityTooLarge)
			return
		}

		seq, err := strconv.ParseUint(seqStr, 10, 64)
		if err != nil {
			errors.LogInfoInner(context.Background(), err, "failed to upload (ParseUint)")
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}

		err = currentSession.uploadQueue.Push(Packet{
			Payload: payload,
			Seq:     seq,
		})
		if err != nil {
			errors.LogInfoInner(context.Background(), err, "failed to upload (PushPayload)")
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}

		if len(bodyPayload) == 0 {
			// Methods without a body are usually cached by default.
			writer.Header().Set("Cache-Control", "no-store")
		}

		writer.WriteHeader(http.StatusOK)
	} else if request.Method == "GET" || sessionId == "" { // stream-down, stream-one
		if sessionId != "" {
			// after GET is done, the connection is finished. disable automatic
			// session reaping, and handle it in defer
			currentSession.isFullyConnected.Close()
			defer h.sessions.Delete(sessionId)
		}

		// magic header instructs nginx + apache to not buffer response body
		writer.Header().Set("X-Accel-Buffering", "no")
		// A web-compliant header telling all middleboxes to disable caching.
		// Should be able to prevent overloading the cache, or stop CDNs from
		// teeing the response stream into their cache, causing slowdowns.
		writer.Header().Set("Cache-Control", "no-store")

		if !h.config.NoSSEHeader {
			// magic header to make the HTTP middle box consider this as SSE to disable buffer
			writer.Header().Set("Content-Type", "text/event-stream")
		}

		writer.WriteHeader(http.StatusOK)
		writer.(http.Flusher).Flush()

		httpSC := &httpServerConn{
			Instance:       done.New(),
			Reader:         request.Body,
			ResponseWriter: writer,
			isH3:           h.ln.isH3,
		}
		localAddr := h.localAddr
		if la, ok := request.Context().Value(http.LocalAddrContextKey).(net.Addr); ok && la != nil {
			localAddr = la
		}
		conn := splitConn{
			writer:     httpSC,
			reader:     httpSC,
			remoteAddr: remoteAddr,
			localAddr:  localAddr,
		}
		if sessionId != "" { // if not stream-one
			conn.reader = currentSession.uploadQueue
		}

		h.ln.addConn(stat.Connection(&conn))

		// "A ResponseWriter may not be used after [Handler.ServeHTTP] has returned."
		select {
		case <-request.Context().Done():
		case <-httpSC.Wait():
		}

		conn.Close()
	} else {
		errors.LogInfo(context.Background(), "unsupported method: ", request.Method)
		writer.WriteHeader(http.StatusMethodNotAllowed)
	}
}

type httpServerConn struct {
	sync.Mutex
	*done.Instance
	io.Reader // no need to Close request.Body
	http.ResponseWriter

	// H3 write-path aggregation: download data is buffered and written to
	// the QUIC stream in chunks, avoiding a mutex + stream write + Flush per
	// 8KB xray buffer. Disabled for H1/H2 (per-write Flush semantics kept).
	isH3       bool
	writeBuf   []byte
	flushTimer *time.Timer
}

const (
	// h3WriteAggregationThreshold is the buffer size at which aggregated H3
	// download data is written to the QUIC stream.
	h3WriteAggregationThreshold = 32 * 1024
	// h3WriteFlushIdleTimeout flushes partially-filled buffers after a quiet
	// period so small responses and interactive traffic do not stall. Kept
	// short (5ms) so the latency of small responses stays in the same range
	// as the pre-aggregation per-write flush.
	h3WriteFlushIdleTimeout = 5 * time.Millisecond
)

func (c *httpServerConn) Write(b []byte) (int, error) {
	c.Lock()
	defer c.Unlock()
	if c.Done() {
		return 0, io.ErrClosedPipe
	}
	if !c.isH3 {
		n, err := c.ResponseWriter.Write(b)
		if err == nil {
			c.ResponseWriter.(http.Flusher).Flush()
		}
		return n, err
	}
	c.writeBuf = append(c.writeBuf, b...)
	if len(c.writeBuf) >= h3WriteAggregationThreshold {
		if err := c.flushWriteBuf(); err != nil {
			return 0, err
		}
		return len(b), nil
	}
	c.resetFlushTimer()
	return len(b), nil
}

// flushWriteBuf writes the aggregated buffer to the QUIC stream and clears
// the pending idle-flush timer. Caller must hold c.Lock().
func (c *httpServerConn) flushWriteBuf() error {
	if c.flushTimer != nil {
		c.flushTimer.Stop()
		c.flushTimer = nil
	}
	if len(c.writeBuf) == 0 {
		return nil
	}
	_, err := c.ResponseWriter.Write(c.writeBuf)
	c.writeBuf = c.writeBuf[:0]
	return err
}

// resetFlushTimer arms the idle flush for a partially-filled buffer. Caller
// must hold c.Lock().
func (c *httpServerConn) resetFlushTimer() {
	if c.flushTimer != nil {
		return
	}
	c.flushTimer = time.AfterFunc(h3WriteFlushIdleTimeout, func() {
		c.Lock()
		defer c.Unlock()
		c.flushTimer = nil
		if c.Done() {
			return
		}
		c.flushWriteBuf()
	})
}

func (c *httpServerConn) Close() error {
	c.Lock()
	defer c.Unlock()
	if c.isH3 && !c.Done() {
		// Flush the tail before the handler returns so the client receives
		// the final bytes and the stream EOF.
		c.flushWriteBuf()
	}
	return c.Instance.Close()
}

type Listener struct {
	sync.Mutex
	server     http.Server
	h3server   *http3.Server
	listener   net.Listener
	h3listener http3.QUICListener
	config     *Config
	addConn    internet.ConnHandler
	isH3       bool
}

func ListenXH(ctx context.Context, address net.Address, port net.Port, streamSettings *internet.MemoryStreamConfig, addConn internet.ConnHandler) (internet.Listener, error) {
	l := &Listener{
		addConn: addConn,
	}
	l.config = streamSettings.ProtocolSettings.(*Config)
	if l.config != nil {
		if streamSettings.SocketSettings == nil {
			streamSettings.SocketSettings = &internet.SocketConfig{}
		}
	}
	handler := &requestHandler{
		config:         l.config,
		host:           l.config.Host,
		path:           l.config.GetNormalizedPath(),
		ln:             l,
		sessionMu:      &sync.Mutex{},
		sessions:       sync.Map{},
		socketSettings: streamSettings.SocketSettings,
	}
	if r := reality.ConfigFromStreamSettings(streamSettings); r != nil {
		params := r.GetRealityQUICParams()
		handler.realityAuth = newRealityAuthVerifier(params)
		if params.Dest != "" {
			handler.fallbackDest = params.Dest
			handler.fallbackClient = newRealityFallbackClient(params.Dest, params.DestServerName)
		}
	}
	tlsConfig := getTLSConfig(streamSettings)
	l.isH3 = len(tlsConfig.NextProtos) == 1 && tlsConfig.NextProtos[0] == "h3"
	if !l.isH3 {
		if r := reality.ConfigFromStreamSettings(streamSettings); r != nil && len(r.Alpn) == 1 && r.Alpn[0] == "h3" {
			l.isH3 = true
		}
	}

	var err error
	if port == net.Port(0) { // unix
		l.listener, err = internet.ListenSystem(ctx, &net.UnixAddr{
			Name: address.Domain(),
			Net:  "unix",
		}, streamSettings.SocketSettings)
		if err != nil {
			return nil, errors.New("failed to listen UNIX domain socket for XHTTP on ", address).Base(err)
		}
		errors.LogInfo(ctx, "listening UNIX domain socket for XHTTP on ", address)
	} else if l.isH3 { // quic
		Conn, err := internet.ListenSystemPacket(context.Background(), &net.UDPAddr{
			IP:   address.IP(),
			Port: int(port),
		}, streamSettings.SocketSettings)
		if err != nil {
			return nil, errors.New("failed to listen UDP for XHTTP/3 on ", address, ":", port).Base(err)
		}
		if streamSettings.UdpmaskManager != nil {
			newConn, err := streamSettings.UdpmaskManager.WrapPacketConnServer(Conn)
			if err != nil {
				Conn.Close()
				return nil, errors.New("mask err").Base(err)
			}
			Conn = newConn
		}

		// QUIC precheck + probe relay: inspect each client's first QUIC
		// Initial flight, verify the REALITY ClientHello (session_id payload)
		// and relay unauthenticated / unparseable flows verbatim to the
		// single configured dest (classic REALITY semantics: auth failure is
		// always forwarded to dest, never routed by SNI), which completes the
		// handshake. Only active when a dest and full server auth secrets are
		// configured.
		if r := reality.ConfigFromStreamSettings(streamSettings); r != nil {
			params := r.GetRealityQUICParams()
			if params != nil && len(params.PrivateKey) == 32 && len(params.ShortIds) > 0 && params.Dest != "" {
				Conn, err = newRealityPrecheckPacketConn(ctx, Conn, params)
				if err != nil {
					Conn.Close()
					return nil, errors.New("failed to wrap QUIC precheck").Base(err)
				}
				if pc, ok := Conn.(*realityPrecheckPacketConn); ok {
					handler.handshakeAuthed = pc.IsAuthenticated
				}
			}
		}

		quicParams := streamSettings.QuicParams
		if quicParams == nil {
			quicParams = &internet.QuicParams{
				BbrProfile: string(bbr.ProfileStandard),
				UdpHop:     &internet.UdpHop{},
				// Align the default receive windows with sing-quic hysteria
				// (Hy2): Initial=8MB, Max=8MB*5/2=20MB, at both stream and
				// connection level. Only applies when no explicit quicParams
				// are configured.
				InitStreamReceiveWindow: 8 * 1024 * 1024,
				MaxStreamReceiveWindow:  20 * 1024 * 1024,
				InitConnReceiveWindow:   8 * 1024 * 1024,
				MaxConnReceiveWindow:    20 * 1024 * 1024,
			}
		}

		quicConfig := &quic.Config{
			InitialStreamReceiveWindow:     quicParams.InitStreamReceiveWindow,
			MaxStreamReceiveWindow:         quicParams.MaxStreamReceiveWindow,
			InitialConnectionReceiveWindow: quicParams.InitConnReceiveWindow,
			MaxConnectionReceiveWindow:     quicParams.MaxConnReceiveWindow,
			MaxIdleTimeout:                 time.Duration(quicParams.MaxIdleTimeout) * time.Second,
			MaxIncomingStreams:             quicParams.MaxIncomingStreams,
			DisablePathMTUDiscovery:        quicParams.DisablePathMtuDiscovery || (runtime.GOOS != "linux" && runtime.GOOS != "windows" && runtime.GOOS != "darwin"),
		}

		// C-gamma REALITY over QUIC: the handshake carries no REALITY payload.
		// The TLS state machine is the standard crypto/tls (stock ClientHello:
		// session_id=0, no custom extensions, 5 supported groups) with the
		// server presenting the real Dest certificate chain. The sessionId
		// auth is replaced by the HTTP-layer X-Reality-Auth verification in
		// requestHandler.ServeHTTP.
		if r := reality.ConfigFromStreamSettings(streamSettings); r != nil {
			// Standard TLS stack: the server must advertise the h3 ALPN
			// explicitly (the reality fork used to inject it itself).
			if alpn := r.GetRealityQUICParams().Alpn; len(alpn) > 0 {
				tlsConfig.NextProtos = alpn
			}
			if r.H3CertificateFile != "" && r.H3KeyFile != "" {
				// C-gamma XHTTP/3: when the operator configured a
				// certificate+key pair (h3CertificateFile/h3KeyFile), present
				// it. Stock crypto/tls clients verify the TLS 1.3
				// CertificateVerify signature against the leaf public key, so
				// the server must hold the private key of the certificate it
				// presents (a dest chain with a mismatched throwaway key would
				// be rejected). The certificate is typically the same one the
				// configured dest serves.
				if cert, err := gotls.LoadX509KeyPair(r.H3CertificateFile, r.H3KeyFile); err == nil {
					tlsConfig.Certificates = []gotls.Certificate{cert}
				} else {
					errors.LogInfo(ctx, "REALITY: failed to load h3 certificate/key, falling back to dest chain: ", err)
					applyDestCertChain(ctx, tlsConfig, r)
				}
			} else {
				applyDestCertChain(ctx, tlsConfig, r)
			}
		}
		l.h3listener, err = quic.ListenEarly(Conn, tlsConfig, quicConfig)
		if err != nil {
			return nil, errors.New("failed to listen QUIC for XHTTP/3 on ", address, ":", port).Base(err)
		}
		l.h3listener = &QListener{
			QUICListener: l.h3listener,
			quicParams:   quicParams,
		}
		errors.LogInfo(ctx, "listening QUIC for XHTTP/3 on ", address, ":", port)

		handler.localAddr = l.h3listener.Addr()

		l.h3server = &http3.Server{
			Handler:     handler,
			ConnContext: handler.connContext,
		}
		go func() {
			if err := l.h3server.ServeListener(l.h3listener); err != nil {
				errors.LogErrorInner(ctx, err, "failed to serve HTTP/3 for XHTTP/3")
			}
		}()
	} else { // tcp
		l.listener, err = internet.ListenSystem(ctx, &net.TCPAddr{
			IP:   address.IP(),
			Port: int(port),
		}, streamSettings.SocketSettings)
		if err != nil {
			return nil, errors.New("failed to listen TCP for XHTTP on ", address, ":", port).Base(err)
		}
		errors.LogInfo(ctx, "listening TCP for XHTTP on ", address, ":", port)
	}

	if !l.isH3 && streamSettings.TcpmaskManager != nil {
		l.listener, _ = streamSettings.TcpmaskManager.WrapListener(l.listener)
	}

	// tcp/unix (h1/h2)
	if l.listener != nil {
		if config := tls.ConfigFromStreamSettings(streamSettings); config != nil {
			if tlsConfig := config.GetTLSConfig(); tlsConfig != nil {
				l.listener = gotls.NewListener(l.listener, tlsConfig)
			}
		}
		if config := reality.ConfigFromStreamSettings(streamSettings); config != nil {
			l.listener = goreality.NewListener(l.listener, config.GetREALITYConfig())
		}

		handler.localAddr = l.listener.Addr()

		// server can handle both plaintext HTTP/1.1 and h2c
		protocols := new(http.Protocols)
		protocols.SetHTTP1(true)
		protocols.SetUnencryptedHTTP2(true)
		l.server = http.Server{
			Handler:           handler,
			ReadHeaderTimeout: time.Second * 4,
			MaxHeaderBytes:    l.config.GetNormalizedServerMaxHeaderBytes(),
			Protocols:         protocols,
		}
		go func() {
			if err := l.server.Serve(l.listener); err != nil {
				errors.LogErrorInner(ctx, err, "failed to serve HTTP for XHTTP")
			}
		}()
	}

	return l, err
}

// Addr implements net.Listener.Addr().
func (ln *Listener) Addr() net.Addr {
	if ln.h3listener != nil {
		return ln.h3listener.Addr()
	}
	if ln.listener != nil {
		return ln.listener.Addr()
	}
	return nil
}

// Close implements net.Listener.Close().
func (ln *Listener) Close() error {
	if ln.h3server != nil {
		return ln.h3server.Close()
	} else if ln.listener != nil {
		return ln.listener.Close()
	}
	return errors.New("listener does not have an HTTP/3 server or a net.listener")
}

// applyDestCertChain presents Dest's real certificate chain on the QUIC
// listener. The server cannot possess Dest's private key, so CertVerify is
// signed with a throwaway key whose type matches the leaf: the chain is what
// matters for the on-wire fingerprint. This only completes handshakes with
// clients that skip CertVerify verification (REALITY fork clients); stock
// crypto/tls clients need the h3CertificateFile/h3KeyFile pair instead.
func applyDestCertChain(ctx context.Context, tlsConfig *gotls.Config, r *reality.Config) {
	fc := r.GetREALITYConfig()
	if chain := goreality.GetDestCertChain(ctx, fc); len(chain) > 0 {
		if priv, err := newThrowawayKeyForCert(chain[0]); err == nil {
			tlsConfig.Certificates = []gotls.Certificate{{
				Certificate: chain,
				PrivateKey:  priv,
			}}
		}
	}
}

// newThrowawayKeyForCert returns a freshly generated private key whose type
// matches the certificate's public key, so the TLS 1.3 CertificateVerify
// signature algorithm is compatible with the served leaf certificate.
func newThrowawayKeyForCert(der []byte) (crypto.Signer, error) {
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	switch pub := leaf.PublicKey.(type) {
	case *rsa.PublicKey:
		return rsa.GenerateKey(rand.Reader, 2048)
	case *ecdsa.PublicKey:
		return ecdsa.GenerateKey(pub.Curve, rand.Reader)
	case ed25519.PublicKey:
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		return priv, err
	default:
		// Fallback for unknown key types: Ed25519 is always supported by the
		// stock TLS stack.
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		return priv, err
	}
}

func getTLSConfig(streamSettings *internet.MemoryStreamConfig) *gotls.Config {
	config := tls.ConfigFromStreamSettings(streamSettings)
	if config == nil {
		return &gotls.Config{}
	}
	return config.GetTLSConfig()
}

func init() {
	common.Must(internet.RegisterTransportListener(protocolName, ListenXH))
}

type QListener struct {
	http3.QUICListener
	quicParams *internet.QuicParams
}

func (l *QListener) Accept(ctx context.Context) (*quic.Conn, error) {
	conn, err := l.QUICListener.Accept(ctx)
	if err != nil {
		return nil, err
	}
	switch l.quicParams.Congestion {
	case "reno":
	case "", "bbr":
		congestion.UseBBR(conn, bbr.Profile(l.quicParams.BbrProfile))
	case "force-brutal":
		congestion.UseBrutal(conn, l.quicParams.BrutalUp)
	default:
		panic(l.quicParams.Congestion)
	}
	return conn, nil
}
