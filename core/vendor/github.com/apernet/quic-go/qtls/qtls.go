package qtls

import (
	"context"
	"crypto/tls"
)

// Event is the small QUIC/TLS event surface used by quic-go.
type Event struct {
	Kind         tls.QUICEventKind
	Level        tls.QUICEncryptionLevel
	Data         []byte
	Suite        uint16
	SessionState *tls.SessionState
	Err          error
}

const QUICErrorEvent tls.QUICEventKind = 10

// Conn is a QUIC TLS state machine.
type Conn interface {
	Start(context.Context) error
	NextEvent() Event
	HandleData(tls.QUICEncryptionLevel, []byte) error
	SetTransportParameters([]byte)
	Close() error
	ConnectionState() tls.ConnectionState
}

// Factory creates QUIC TLS state machines.
type Factory interface {
	Client(*tls.QUICConfig) Conn
	Server(*tls.QUICConfig) Conn
}
