package quic

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	cryptorand "crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/apernet/quic-go/internal/handshake"
	"github.com/apernet/quic-go/internal/monotime"
	"github.com/apernet/quic-go/internal/protocol"
	"github.com/apernet/quic-go/internal/wire"
)

func TestChrome133Initial1RTTDelayBounds(t *testing.T) {
	for random := uint64(0); random < 100_000; random++ {
		delay := chrome133Initial1RTTDelay(random)
		if delay < 5*time.Millisecond || delay > 220*time.Millisecond {
			t.Fatalf("delay %s outside profile bounds", delay)
		}
	}
}

func TestChrome133Initial1RTTDelaySamplerIsBounded(t *testing.T) {
	sampler := newChrome133Initial1RTTDelaySampler()
	if sampler == nil {
		t.Skip("crypto/rand unavailable")
	}
	for range 10_000 {
		delay := sampler()
		if delay < 5*time.Millisecond || delay > 220*time.Millisecond {
			t.Fatalf("delay %s outside profile bounds", delay)
		}
	}
}

func TestChrome133Initial1RTTPacingConfigIsOptInAndCloneSafe(t *testing.T) {
	sampler := func() time.Duration { return 64 * time.Millisecond }
	config := &Config{
		ChromeInitial1RTTPacing: true,
		initial1RTTDelaySampler: sampler,
	}
	populated := populateConfig(config)
	if !populated.ChromeInitial1RTTPacing {
		t.Fatal("timing profile was lost while populating config")
	}
	if got := populated.initial1RTTDelaySampler(); got != 64*time.Millisecond {
		t.Fatalf("injected sampler = %s, want 64ms", got)
	}
	if populateConfig(&Config{}).ChromeInitial1RTTPacing {
		t.Fatal("timing profile must default to disabled")
	}
}

func TestChrome133Initial1RTTPacingArmsFromFirstPeerPacket(t *testing.T) {
	now := monotime.Now()
	c := &Conn{
		config:                  &Config{HandshakeIdleTimeout: time.Second},
		creationTime:            now.Add(-time.Millisecond),
		firstPeerPacketTime:     now.Add(-10 * time.Millisecond),
		initial1RTTDelaySampler: func() time.Duration { return 50 * time.Millisecond },
	}
	c.armClientFinalFlightPacing(now)
	want := c.firstPeerPacketTime.Add(50 * time.Millisecond)
	if c.handshakePacingDeadline != want {
		t.Fatalf("deadline = %v, want %v", c.handshakePacingDeadline, want)
	}
}

func TestChrome133Initial1RTTPacingCapsAndFailsOpen(t *testing.T) {
	now := monotime.Now()
	testCases := []struct {
		name          string
		creation      monotime.Time
		origin        monotime.Time
		handshakeIdle time.Duration
		delay         time.Duration
		want          monotime.Time
	}{
		{
			name:          "hard cap",
			creation:      now.Add(-time.Millisecond),
			origin:        now,
			handshakeIdle: 2 * time.Second,
			delay:         time.Second,
			want:          now.Add(chromeInitial1RTTDelayHardCap),
		},
		{
			name:          "half handshake idle timeout",
			creation:      now,
			origin:        now,
			handshakeIdle: 100 * time.Millisecond,
			delay:         200 * time.Millisecond,
			want:          now.Add(50 * time.Millisecond),
		},
		{
			name:          "already beyond target",
			creation:      now.Add(-time.Millisecond),
			origin:        now.Add(-100 * time.Millisecond),
			handshakeIdle: time.Second,
			delay:         25 * time.Millisecond,
			want:          now,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			c := &Conn{
				config:                  &Config{HandshakeIdleTimeout: tc.handshakeIdle},
				creationTime:            tc.creation,
				firstPeerPacketTime:     tc.origin,
				initial1RTTDelaySampler: func() time.Duration { return tc.delay },
			}
			c.armClientFinalFlightPacing(now)
			if c.handshakePacingDeadline != tc.want {
				t.Fatalf("deadline = %v, want %v", c.handshakePacingDeadline, tc.want)
			}
		})
	}
}

func TestChrome133Initial1RTTPacingReleasesFinalFlightOnce(t *testing.T) {
	handler := &finalFlightTestHandler{events: []handshake.Event{{Kind: handshake.EventHandshakeComplete}}}
	c := &Conn{
		cryptoStreamHandler:     handler,
		handshakePacingDeadline: monotime.Now(),
		initialStream:           newInitialCryptoStream(true, false),
		handshakeStream:         newCryptoStream(),
		cryptoStreamManager:     newCryptoStreamManager(newInitialCryptoStream(true, false), newCryptoStream(), newCryptoStream()),
	}
	completed, err := c.releaseClientFinalFlight(monotime.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !completed || !c.handshakeComplete {
		t.Fatal("final flight did not complete the handshake")
	}
	if handler.releases != 1 {
		t.Fatalf("release count = %d, want 1", handler.releases)
	}
	if c.handshakePacingDeadline != 0 {
		t.Fatalf("deadline = %v, want zero", c.handshakePacingDeadline)
	}
	completed, err = c.releaseClientFinalFlight(monotime.Now())
	if err != nil {
		t.Fatal(err)
	}
	if completed || handler.releases != 1 {
		t.Fatal("second release must be a no-op")
	}
}

func TestChrome133Initial1RTTPacingDelaysFirstShortHeader(t *testing.T) {
	serverTLS := newTimingTestTLSConfig(t)
	listener, err := ListenAddr("127.0.0.1:0", serverTLS, &Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	acceptCtx, cancelAccept := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancelAccept()
	accepted := make(chan *Conn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		conn, err := listener.Accept(acceptCtx)
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- conn
	}()

	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		t.Fatal(err)
	}
	defer udpConn.Close()
	packetConn := &timingPacketConn{PacketConn: udpConn, firstShortHeader: make(chan struct{})}
	const targetDelay = 80 * time.Millisecond
	dialCtx, cancelDial := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancelDial()
	client, err := Dial(dialCtx, packetConn, listener.Addr(), &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"timing-test"},
	}, &Config{
		ChromeInitial1RTTPacing: true,
		initial1RTTDelaySampler: func() time.Duration {
			return targetDelay
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseWithError(0, "test complete")
	select {
	case server := <-accepted:
		defer server.CloseWithError(0, "test complete")
	case err := <-acceptErr:
		t.Fatal(err)
	case <-dialCtx.Done():
		t.Fatal(dialCtx.Err())
	}

	stream, err := client.OpenStreamSync(dialCtx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Write([]byte("timing")); err != nil {
		t.Fatal(err)
	}
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-packetConn.firstShortHeader:
	case <-time.After(2 * time.Second):
		t.Fatal("client did not emit a short-header packet")
	}
	firstPeer, firstShort := packetConn.times()
	if firstPeer.IsZero() || firstShort.IsZero() {
		t.Fatalf("incomplete timing sample: first peer %s, first short header %s", firstPeer, firstShort)
	}
	if elapsed := firstShort.Sub(firstPeer); elapsed < targetDelay-10*time.Millisecond {
		t.Fatalf("first short-header delay = %s, want at least %s", elapsed, targetDelay-10*time.Millisecond)
	}
}

type finalFlightTestHandler struct {
	events   []handshake.Event
	releases int
}

func (*finalFlightTestHandler) StartHandshake(context.Context) error            { return nil }
func (*finalFlightTestHandler) ChangeConnectionID(protocol.ConnectionID)        {}
func (*finalFlightTestHandler) SetLargest1RTTAcked(protocol.PacketNumber) error { return nil }
func (*finalFlightTestHandler) SetHandshakeConfirmed()                          {}
func (*finalFlightTestHandler) GetSessionTicket() ([]byte, error)               { return nil, nil }
func (h *finalFlightTestHandler) NextEvent() handshake.Event {
	if len(h.events) == 0 {
		return handshake.Event{Kind: handshake.EventNoEvent}
	}
	event := h.events[0]
	h.events = h.events[1:]
	return event
}
func (*finalFlightTestHandler) DiscardInitialKeys()                                  {}
func (*finalFlightTestHandler) HandleMessage([]byte, protocol.EncryptionLevel) error { return nil }
func (h *finalFlightTestHandler) ReleaseClientFinalFlight() error                    { h.releases++; return nil }
func (*finalFlightTestHandler) Close() error                                         { return nil }
func (*finalFlightTestHandler) ConnectionState() handshake.ConnectionState {
	return handshake.ConnectionState{}
}

var _ io.Closer = (*finalFlightTestHandler)(nil)

type timingPacketConn struct {
	net.PacketConn
	mu               sync.Mutex
	firstPeerPacket  time.Time
	firstShortPacket time.Time
	firstShortHeader chan struct{}
	shortOnce        sync.Once
}

func (c *timingPacketConn) ReadFrom(data []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(data)
	if err == nil && n > 0 {
		c.mu.Lock()
		if c.firstPeerPacket.IsZero() {
			c.firstPeerPacket = time.Now()
		}
		c.mu.Unlock()
	}
	return n, addr, err
}

func (c *timingPacketConn) WriteTo(data []byte, addr net.Addr) (int, error) {
	if containsShortHeaderPacket(data) {
		c.mu.Lock()
		if c.firstShortPacket.IsZero() {
			c.firstShortPacket = time.Now()
			c.shortOnce.Do(func() { close(c.firstShortHeader) })
		}
		c.mu.Unlock()
	}
	return c.PacketConn.WriteTo(data, addr)
}

func (c *timingPacketConn) times() (time.Time, time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.firstPeerPacket, c.firstShortPacket
}

func containsShortHeaderPacket(data []byte) bool {
	for len(data) > 0 {
		if !wire.IsLongHeaderPacket(data[0]) {
			return true
		}
		_, _, remaining, err := wire.ParsePacket(data)
		if err != nil {
			return false
		}
		data = remaining
	}
	return false
}

func newTimingTestTLSConfig(t *testing.T) *tls.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), cryptorand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := cryptorand.Int(cryptorand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "timing-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"timing-test"},
	}
	der, err := x509.CreateCertificate(cryptorand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		NextProtos:   []string{"timing-test"},
	}
}
