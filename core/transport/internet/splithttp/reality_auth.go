package splithttp

import (
	"context"
	"encoding/base64"
	"sync/atomic"
	"time"

	"github.com/apernet/quic-go"
	goreality "github.com/xtls/reality"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/transport/internet/tls"
)

// XRealityAuthHeader is the HTTP header that carried the C-gamma data-plane
// REALITY auth record (base64). Stage-2 clients no longer send it — QUIC
// authentication now rides in the ClientHello random field and the precheck
// short-circuits the data-plane check for handshake-authenticated
// connections. The server-side verification is kept for deployments without
// the QUIC precheck, so older clients that still send the header keep
// working.
const XRealityAuthHeader = "X-Reality-Auth"

// realityAuthVerifier validates X-Reality-Auth records on the server side. It
// is only installed when REALITY is configured for the H3 listener, which
// makes data-plane authentication mandatory for every QUIC connection.
type realityAuthVerifier struct {
	privateKey  []byte
	shortIds    map[[8]byte]bool
	minVer      []byte
	maxVer      []byte
	maxTimeDiff time.Duration
}

// newRealityAuthVerifier builds a verifier from the REALITY QUIC parameters.
// It returns nil when no server-side auth secrets are configured.
func newRealityAuthVerifier(params *tls.RealityQUICParams) *realityAuthVerifier {
	if params == nil || len(params.PrivateKey) != 32 || len(params.ShortIds) == 0 {
		return nil
	}
	return &realityAuthVerifier{
		privateKey:  params.PrivateKey,
		shortIds:    params.ShortIds,
		minVer:      params.MinClientVer,
		maxVer:      params.MaxClientVer,
		maxTimeDiff: params.MaxTimeDiff,
	}
}

// verifyHeader checks a base64-encoded auth record. The error semantics match
// the handshake auth: any failure (bad shortId, version outside the window,
// stale timestamp, malformed record) rejects the connection.
func (v *realityAuthVerifier) verifyHeader(encoded string) error {
	if encoded == "" {
		return errors.New("REALITY: missing X-Reality-Auth header")
	}
	record, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return errors.New("REALITY: malformed X-Reality-Auth header")
	}
	return goreality.VerifyAuthRecord(record, v.privateKey, v.shortIds, v.minVer, v.maxVer, v.maxTimeDiff)
}

// quicConnKey is the request-context key for the per-connection state attached
// by the http3.Server.ConnContext hook.
type quicConnKey struct{}

// quicConnState is the per-QUIC-connection state used to enforce data-plane
// auth exactly once per connection.
type quicConnState struct {
	conn     *quic.Conn
	verified atomic.Bool
}

// connContext hooks every new QUIC connection into the request context so the
// request handler can reach the connection (to close it on auth failure) and
// its verified flag.
func (h *requestHandler) connContext(ctx context.Context, conn *quic.Conn) context.Context {
	return context.WithValue(ctx, quicConnKey{}, &quicConnState{conn: conn})
}
