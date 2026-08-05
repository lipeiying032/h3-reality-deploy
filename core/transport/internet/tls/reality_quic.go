package tls

import (
	"context"
	gotls "crypto/tls"
	"os"

	"github.com/apernet/quic-go/qtls"
	goreality "github.com/xtls/reality"
)

// realityQUICFactory adapts the vendored github.com/xtls/reality TLS fork to
// quic-go's qtls.Factory interface. The fork is a clone of crypto/tls whose
// TLS 1.3 client can skip the CertificateVerify signature check, which the
// stock crypto/tls cannot do. This is required by the C-gamma REALITY design:
// the server presents the Dest certificate chain but signs CertificateVerify
// with a throwaway key, so a handshake that verifies the signature can never
// complete.
type realityQUICFactory struct {
	template *goreality.Config
}

// NewRealityQUICFactory returns a qtls.Factory that runs QUIC handshakes on
// the vendored reality fork. The template config carries the REALITY mode
// flags (for C-gamma: DataPlaneAuth=true, which keeps the ClientHello a
// standard TLS 1.3 ClientHello — zero-length session_id, no REALITY payload —
// while skipping CertificateVerify verification). Standard TLS fields
// (ServerName, NextProtos, CurvePreferences, ...) are taken from the
// *tls.Config that quic-go passes per connection.
func NewRealityQUICFactory(template *goreality.Config) qtls.Factory {
	return &realityQUICFactory{template: template}
}

func (f *realityQUICFactory) Client(q *gotls.QUICConfig) qtls.Conn {
	return &realityQUICConn{conn: goreality.QUICClient(&goreality.QUICConfig{
		TLSConfig:           convertTLSConfig(q.TLSConfig, f.template),
		EnableSessionEvents: q.EnableSessionEvents,
	})}
}

func (f *realityQUICFactory) Server(q *gotls.QUICConfig) qtls.Conn {
	return &realityQUICConn{conn: goreality.QUICServer(&goreality.QUICConfig{
		TLSConfig:           convertTLSConfig(q.TLSConfig, f.template),
		EnableSessionEvents: q.EnableSessionEvents,
	})}
}

// convertTLSConfig maps the standard crypto/tls configuration that quic-go
// passes into the vendored reality fork's Config. The fork's Config is the
// crypto/tls Config plus REALITY fields, so every field a QUIC connection
// actually uses is copied by name. Certificate-serving and client-auth
// callbacks are left nil: the C-gamma path never presents a client
// certificate and never uses custom certificate selection on the QUIC side.
func convertTLSConfig(src *gotls.Config, template *goreality.Config) *goreality.Config {
	dst := &goreality.Config{}
	if template != nil {
		dst.DialContext = template.DialContext
		dst.Show = template.Show
		dst.Type = template.Type
		dst.Dest = template.Dest
		dst.DestServerName = template.DestServerName
		dst.Xver = template.Xver
		dst.ServerNames = template.ServerNames
		dst.PrivateKey = template.PrivateKey
		dst.MinClientVer = template.MinClientVer
		dst.MaxClientVer = template.MaxClientVer
		dst.MaxTimeDiff = template.MaxTimeDiff
		dst.ShortIds = template.ShortIds
		dst.PublicKey = template.PublicKey
		dst.ShortId = template.ShortId
		dst.DataPlaneAuth = template.DataPlaneAuth
		dst.UtlsClientHelloID = template.UtlsClientHelloID
		dst.Mldsa65Key = template.Mldsa65Key
		dst.LimitFallbackUpload = template.LimitFallbackUpload
		dst.LimitFallbackDownload = template.LimitFallbackDownload
	}
	if src == nil {
		return dst
	}
	dst.Rand = src.Rand
	dst.Time = src.Time
	dst.RootCAs = src.RootCAs
	dst.NextProtos = src.NextProtos
	dst.ServerName = src.ServerName
	dst.ClientAuth = goreality.ClientAuthType(src.ClientAuth)
	dst.ClientCAs = src.ClientCAs
	dst.InsecureSkipVerify = src.InsecureSkipVerify
	dst.CipherSuites = src.CipherSuites
	dst.PreferServerCipherSuites = src.PreferServerCipherSuites
	dst.SessionTicketsDisabled = src.SessionTicketsDisabled
	dst.SessionTicketKey = src.SessionTicketKey
	dst.MinVersion = src.MinVersion
	dst.MaxVersion = src.MaxVersion
	dst.DynamicRecordSizingDisabled = src.DynamicRecordSizingDisabled
	dst.Renegotiation = goreality.RenegotiationSupport(src.Renegotiation)
	dst.KeyLogWriter = src.KeyLogWriter
	dst.EncryptedClientHelloConfigList = src.EncryptedClientHelloConfigList
	if len(src.CurvePreferences) > 0 {
		dst.CurvePreferences = make([]goreality.CurveID, len(src.CurvePreferences))
		for i, curve := range src.CurvePreferences {
			dst.CurvePreferences[i] = goreality.CurveID(curve)
		}
	}
	return dst
}

// realityQUICConn adapts the fork's QUICConn to quic-go's qtls.Conn
// interface. The event kind/level enums are numeric clones of crypto/tls's, so
// plain conversion is safe. SessionState events are not translated (the fork
// has its own SessionState type); quic-go tolerates a nil SessionState by
// skipping session storage/resumption, which the C-gamma client does not use.
type realityQUICConn struct {
	conn *goreality.QUICConn
}

func (c *realityQUICConn) Start(ctx context.Context) error {
	return c.conn.Start(ctx)
}

func (c *realityQUICConn) NextEvent() qtls.Event {
	ev := c.conn.NextEvent()
	// TEMP debug hook: dump the exact handshake bytes the QUIC client puts
	// into CRYPTO frames (first ClientHello) for on-wire fingerprint
	// verification. Removed after verification.
	if os.Getenv("REALITY_DUMP_CH") != "" && ev.Kind == goreality.QUICWriteData &&
		len(ev.Data) > 0 && ev.Data[0] == 0x01 {
		f, err := os.OpenFile(os.Getenv("REALITY_DUMP_CH"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		if err == nil {
			f.Write(ev.Data)
			f.Close()
		}
	}
	return qtls.Event{
		Kind:  gotls.QUICEventKind(ev.Kind),
		Level: gotls.QUICEncryptionLevel(ev.Level),
		Data:  ev.Data,
		Suite: ev.Suite,
		Err:   ev.Err,
	}
}

func (c *realityQUICConn) HandleData(level gotls.QUICEncryptionLevel, data []byte) error {
	return c.conn.HandleData(goreality.QUICEncryptionLevel(level), data)
}

func (c *realityQUICConn) SetTransportParameters(params []byte) {
	c.conn.SetTransportParameters(params)
}

func (c *realityQUICConn) Close() error {
	return c.conn.Close()
}

func (c *realityQUICConn) ConnectionState() gotls.ConnectionState {
	state := c.conn.ConnectionState()
	return gotls.ConnectionState{
		Version:                     state.Version,
		HandshakeComplete:           state.HandshakeComplete,
		DidResume:                   state.DidResume,
		CipherSuite:                 state.CipherSuite,
		CurveID:                     gotls.CurveID(state.CurveID),
		NegotiatedProtocol:          state.NegotiatedProtocol,
		NegotiatedProtocolIsMutual:  state.NegotiatedProtocolIsMutual,
		ServerName:                  state.ServerName,
		PeerCertificates:            state.PeerCertificates,
		VerifiedChains:              state.VerifiedChains,
		SignedCertificateTimestamps: state.SignedCertificateTimestamps,
		OCSPResponse:                state.OCSPResponse,
		TLSUnique:                   state.TLSUnique,
		ECHAccepted:                 state.ECHAccepted,
		HelloRetryRequest:           state.HelloRetryRequest,
	}
}
