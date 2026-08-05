package tls

import "time"

// RealityQUICParams carries the REALITY-specific parameters used for REALITY
// over QUIC (XHTTP/3) in the C-gamma data-plane-auth design.
//
// The QUIC handshake itself no longer carries any REALITY payload: the TLS
// state machine is the standard crypto/tls, the ClientHello has a zero-length
// session_id and no custom extensions, and the server presents the real Dest
// certificate chain. The REALITY secrets (PrivateKey/ShortIds/PublicKey/
// ShortId and the version/time bounds) are consumed by the HTTP-layer
// data-plane authentication instead.
type RealityQUICParams struct {
	// Server side (data-plane auth verification).
	PrivateKey   []byte
	ShortIds     map[[8]byte]bool
	MinClientVer []byte
	MaxClientVer []byte
	MaxTimeDiff  time.Duration

	// Dest is the QUIC dest used to fetch the real certificate chain the
	// server presents instead of the built-in self-signed certificate.
	// DestServerName is the SNI (certificate domain) for that fetch.
	Dest           string
	DestServerName string

	// Client side (data-plane auth record construction).
	PublicKey []byte
	ShortId   []byte

	// ServerName is the SNI the client sends in the TLS handshake.
	ServerName string
	// Common.
	Alpn []string
	Show bool

	// ServerNames is the full SNI whitelist used by the QUIC precheck to
	// classify incoming Initial packets (all configured server names).
	ServerNames map[string]bool

	// FallbackDest is the UDP target that probe / unauthenticated QUIC flows
	// are relayed to. The precheck relays the client's packets verbatim and
	// the fallback completes the handshake.
	FallbackDest string
	// FallbackDestRoutes maps a prober's ClientHello SNI (exact match) to the
	// real UDP destination that flow is relayed to. Unknown SNIs fall back to
	// FallbackDest. Empty when not configured.
	FallbackDestRoutes map[string]string
	// FallbackTimeout is how long an idle precheck/relay entry is kept alive
	// (default 120s).
	FallbackTimeout time.Duration
}
