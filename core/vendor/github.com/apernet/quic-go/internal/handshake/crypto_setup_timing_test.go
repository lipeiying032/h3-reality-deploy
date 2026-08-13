package handshake

import (
	"context"
	"crypto/tls"
	"testing"

	"github.com/apernet/quic-go/internal/protocol"
	"github.com/apernet/quic-go/internal/utils"
	"github.com/apernet/quic-go/internal/wire"
	"github.com/apernet/quic-go/qtls"
)

func TestClientFinalFlightPacingHoldsAndReleasesInOrder(t *testing.T) {
	finished := []byte{0x14, 0x00, 0x00, 0x20}
	h := newTimingTestCryptoSetup(t, true, []qtls.Event{
		{Kind: tls.QUICWriteData, Level: tls.QUICEncryptionLevelHandshake, Data: finished},
		{Kind: tls.QUICSetWriteSecret, Level: tls.QUICEncryptionLevelApplication, Suite: tls.TLS_AES_128_GCM_SHA256, Data: make([]byte, 32)},
		{Kind: tls.QUICHandshakeDone},
		{Kind: tls.QUICSetReadSecret, Level: tls.QUICEncryptionLevelApplication, Suite: tls.TLS_AES_128_GCM_SHA256, Data: make([]byte, 32)},
	})
	if err := h.handleMessage(nil, protocol.EncryptionHandshake); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Get1RTTSealer(); err != ErrKeysNotYetAvailable {
		t.Fatalf("1-RTT sealer error = %v, want ErrKeysNotYetAvailable", err)
	}
	if _, err := h.Get1RTTOpener(); err != ErrKeysNotYetAvailable {
		t.Fatalf("1-RTT opener error = %v, want ErrKeysNotYetAvailable", err)
	}
	if event := h.NextEvent(); event.Kind != EventClientFinalFlightPending {
		t.Fatalf("event = %s, want EventClientFinalFlightPending", event.Kind)
	}
	finished[0] = 0xff
	if got := h.pendingClientFinalFlight[0].Data[0]; got != 0x14 {
		t.Fatalf("held Client Finished was not copied: got %#x", got)
	}

	if err := h.ReleaseClientFinalFlight(); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Get1RTTSealer(); err != nil {
		t.Fatalf("1-RTT sealer unavailable after release: %v", err)
	}
	if _, err := h.Get1RTTOpener(); err != nil {
		t.Fatalf("1-RTT opener unavailable after release: %v", err)
	}
	want := []EventKind{EventWriteHandshakeData, EventHandshakeComplete, EventReceivedReadKeys}
	for _, kind := range want {
		if event := h.NextEvent(); event.Kind != kind {
			t.Fatalf("event = %s, want %s", event.Kind, kind)
		}
	}
	if event := h.NextEvent(); event.Kind != EventNoEvent {
		t.Fatalf("event = %s after release, want EventNoEvent", event.Kind)
	}
	if err := h.ReleaseClientFinalFlight(); err != nil {
		t.Fatalf("second release = %v, want no-op", err)
	}
}

func TestClientFinalFlightPacingOffKeepsCurrentBehavior(t *testing.T) {
	h := newTimingTestCryptoSetup(t, false, []qtls.Event{
		{Kind: tls.QUICWriteData, Level: tls.QUICEncryptionLevelHandshake, Data: []byte{0x14}},
		{Kind: tls.QUICSetWriteSecret, Level: tls.QUICEncryptionLevelApplication, Suite: tls.TLS_AES_128_GCM_SHA256, Data: make([]byte, 32)},
		{Kind: tls.QUICHandshakeDone},
		{Kind: tls.QUICSetReadSecret, Level: tls.QUICEncryptionLevelApplication, Suite: tls.TLS_AES_128_GCM_SHA256, Data: make([]byte, 32)},
	})
	if err := h.handleMessage(nil, protocol.EncryptionHandshake); err != nil {
		t.Fatal(err)
	}
	if h.clientFinalFlightPending.Load() {
		t.Fatal("profile-off handshake unexpectedly held final flight")
	}
	if _, err := h.Get1RTTSealer(); err != nil {
		t.Fatalf("profile-off 1-RTT sealer unavailable: %v", err)
	}
	if _, err := h.Get1RTTOpener(); err != nil {
		t.Fatalf("profile-off 1-RTT opener unavailable: %v", err)
	}
	if event := h.NextEvent(); event.Kind == EventClientFinalFlightPending {
		t.Fatal("profile-off handshake emitted pending event")
	}
}

func TestClientFinalFlightPacingBypasses0RTT(t *testing.T) {
	h := newTimingTestCryptoSetup(t, true, []qtls.Event{
		{Kind: tls.QUICWriteData, Level: tls.QUICEncryptionLevelHandshake, Data: []byte{0x14}},
		{Kind: tls.QUICSetWriteSecret, Level: tls.QUICEncryptionLevelApplication, Suite: tls.TLS_AES_128_GCM_SHA256, Data: make([]byte, 32)},
		{Kind: tls.QUICHandshakeDone},
		{Kind: tls.QUICSetReadSecret, Level: tls.QUICEncryptionLevelApplication, Suite: tls.TLS_AES_128_GCM_SHA256, Data: make([]byte, 32)},
	})
	h.used0RTT.Store(true)
	if err := h.handleMessage(nil, protocol.EncryptionHandshake); err != nil {
		t.Fatal(err)
	}
	if h.clientFinalFlightPending.Load() {
		t.Fatal("0-RTT handshake unexpectedly held final flight")
	}
	if _, err := h.Get1RTTSealer(); err != nil {
		t.Fatalf("0-RTT bypass did not install 1-RTT sealer: %v", err)
	}
}

func newTimingTestCryptoSetup(t *testing.T, pacing bool, events []qtls.Event) *cryptoSetup {
	t.Helper()
	h := newCryptoSetup(
		protocol.ParseConnectionID([]byte{1}),
		&wire.TransportParameters{},
		utils.NewRTTStats(),
		nil,
		utils.DefaultLogger,
		protocol.PerspectiveClient,
		protocol.Version1,
	)
	h.paceClientFinalFlight = pacing
	h.conn = &timingTestQUICConn{events: events}
	return h
}

type timingTestQUICConn struct {
	events []qtls.Event
}

func (*timingTestQUICConn) Start(context.Context) error { return nil }
func (c *timingTestQUICConn) NextEvent() qtls.Event {
	if len(c.events) == 0 {
		return qtls.Event{Kind: tls.QUICNoEvent}
	}
	event := c.events[0]
	c.events[0] = qtls.Event{}
	c.events = c.events[1:]
	return event
}
func (*timingTestQUICConn) HandleData(tls.QUICEncryptionLevel, []byte) error { return nil }
func (*timingTestQUICConn) SetTransportParameters([]byte)                    {}
func (*timingTestQUICConn) Close() error                                     { return nil }
func (*timingTestQUICConn) ConnectionState() tls.ConnectionState             { return tls.ConnectionState{} }
