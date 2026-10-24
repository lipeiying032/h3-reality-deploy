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

	// Dest is the single REALITY dest (host:port). The server uses it to
	// fetch the real certificate chain it presents instead of the built-in
	// self-signed certificate, and the QUIC precheck relays every probe /
	// unauthenticated flow verbatim to it (classic REALITY semantics: auth
	// failure is always forwarded to Dest, never routed by SNI). Empty means
	// the precheck stays inactive (no relay). DestServerName is the SNI
	// (certificate domain) for the certificate fetch.
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
	// verify the REALITY auth payload in incoming Initial packets (all
	// configured server names).
	ServerNames map[string]bool

	// FallbackTimeout is how long an idle precheck/relay entry is kept alive
	// (default 120s).
	FallbackTimeout time.Duration

	// Optional target-specific HTTP/3 server Initial packet size. Zero keeps
	// quic-go's default. The listener validates the value before narrowing it.
	H3InitialPacketSize uint32
}
