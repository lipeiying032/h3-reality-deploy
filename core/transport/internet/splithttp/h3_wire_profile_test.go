package splithttp

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/apernet/quic-go"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	xraytls "github.com/xtls/xray-core/transport/internet/tls"
)

func TestParseH3WireProfile(t *testing.T) {
	tests := []struct {
		name      string
		params    *xraytls.RealityQUICParams
		wantSize  uint16
		wantCID   int
		wantError bool
	}{
		{name: "nil"},
		{name: "default", params: &xraytls.RealityQUICParams{}},
		{name: "target", params: &xraytls.RealityQUICParams{H3InitialPacketSize: 1200, H3ConnectionIDLength: 20}, wantSize: 1200, wantCID: 20},
		{name: "minimum cid", params: &xraytls.RealityQUICParams{H3ConnectionIDLength: 1}, wantCID: 1},
		{name: "maximum packet", params: &xraytls.RealityQUICParams{H3InitialPacketSize: 1452}, wantSize: 1452},
		{name: "below minimum", params: &xraytls.RealityQUICParams{H3InitialPacketSize: 1199}, wantError: true},
		{name: "above maximum", params: &xraytls.RealityQUICParams{H3InitialPacketSize: 1453}, wantError: true},
		{name: "cid above maximum", params: &xraytls.RealityQUICParams{H3ConnectionIDLength: 21}, wantError: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := parseH3WireProfile(test.params)
			if (err != nil) != test.wantError {
				t.Fatalf("parseH3WireProfile() error = %v, wantError %v", err, test.wantError)
			}
			if err == nil && (got.initialPacketSize != test.wantSize || got.connectionIDLength != test.wantCID) {
				t.Fatalf("parseH3WireProfile() = %+v, want size=%d cid=%d", got, test.wantSize, test.wantCID)
			}
		})
	}
}

type initialSizeRecordingPacketConn struct {
	net.PacketConn
	mu     sync.Mutex
	writes [][]byte
}

func (c *initialSizeRecordingPacketConn) WriteTo(payload []byte, addr net.Addr) (int, error) {
	c.mu.Lock()
	c.writes = append(c.writes, append([]byte(nil), payload...))
	c.mu.Unlock()
	return c.PacketConn.WriteTo(payload, addr)
}

func (c *initialSizeRecordingPacketConn) lengths() []int {
	c.mu.Lock()
	defer c.mu.Unlock()
	lengths := make([]int, len(c.writes))
	for i := range c.writes {
		lengths[i] = len(c.writes[i])
	}
	return lengths
}

func (c *initialSizeRecordingPacketConn) snapshot() [][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	result := make([][]byte, len(c.writes))
	for i := range c.writes {
		result[i] = append([]byte(nil), c.writes[i]...)
	}
	return result
}

func firstInitialSCIDLen(datagram []byte) (int, bool) {
	if len(datagram) < 7 || datagram[0]&0xf0 != 0xc0 {
		return 0, false
	}
	dcidLen := int(datagram[5])
	if dcidLen > 20 || len(datagram) < 7+dcidLen {
		return 0, false
	}
	scidLen := int(datagram[6+dcidLen])
	if scidLen > 20 || len(datagram) < 7+dcidLen+scidLen {
		return 0, false
	}
	return scidLen, true
}

func TestH3ServerWireProfile(t *testing.T) {
	generated, _ := cert.MustGenerate(nil, cert.DNSNames("localhost"))
	certPEM, keyPEM := generated.ToPEM()
	keyPair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name       string
		packetSize uint16
		cidLength  int
		wantSize   int
		wantCID    int
	}{
		{name: "default", wantSize: 1280, wantCID: 4},
		{name: "configured", packetSize: 1200, cidLength: 20, wantSize: 1200, wantCID: 20},
	} {
		t.Run(test.name, func(t *testing.T) {
			serverSocket, err := net.ListenPacket("udp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			serverPackets := &initialSizeRecordingPacketConn{PacketConn: serverSocket}
			serverTransport := &quic.Transport{Conn: serverPackets, ConnectionIDLength: test.cidLength}
			listener, err := serverTransport.ListenEarly(
				&tls.Config{Certificates: []tls.Certificate{keyPair}, NextProtos: []string{"h3-initial-size-test"}},
				&quic.Config{InitialPacketSize: test.packetSize},
			)
			if err != nil {
				serverSocket.Close()
				t.Fatal(err)
			}
			t.Cleanup(func() {
				listener.Close()
				serverTransport.Close()
				serverSocket.Close()
			})

			acceptResult := make(chan error, 1)
			go func() {
				conn, acceptErr := listener.Accept(context.Background())
				if acceptErr == nil {
					select {
					case <-conn.HandshakeComplete():
					case <-time.After(5 * time.Second):
						acceptErr = errors.New("server handshake timeout")
					}
				}
				acceptResult <- acceptErr
			}()

			clientSocket, err := net.ListenPacket("udp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			clientTransport := &quic.Transport{Conn: clientSocket}
			t.Cleanup(func() {
				clientTransport.Close()
				clientSocket.Close()
			})
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			clientConn, err := clientTransport.Dial(ctx, serverSocket.LocalAddr(), &tls.Config{
				InsecureSkipVerify: true,
				NextProtos:         []string{"h3-initial-size-test"},
			}, &quic.Config{})
			if err != nil {
				t.Fatal(err)
			}
			defer clientConn.CloseWithError(0, "test complete")
			if err := <-acceptResult; err != nil {
				t.Fatal(err)
			}

			lengths := serverPackets.lengths()
			var gotCID int
			for _, datagram := range serverPackets.snapshot() {
				if cidLength, ok := firstInitialSCIDLen(datagram); ok {
					gotCID = cidLength
				}
			}
			if gotCID != test.wantCID {
				t.Fatalf("server Initial SCID length = %d, want %d", gotCID, test.wantCID)
			}
			for _, length := range lengths {
				if length == test.wantSize {
					return
				}
			}
			t.Fatalf("no server Initial datagram of %d bytes in lengths %v", test.wantSize, lengths)
		})
	}
}

type countingQUICListener struct {
	closed atomic.Int32
}

func (*countingQUICListener) Accept(context.Context) (*quic.Conn, error) {
	return nil, errors.New("not accepting")
}
func (*countingQUICListener) Addr() net.Addr { return &net.UDPAddr{} }
func (l *countingQUICListener) Close() error {
	l.closed.Add(1)
	return nil
}

type countingPacketConn struct {
	closed atomic.Int32
}

func (*countingPacketConn) ReadFrom([]byte) (int, net.Addr, error) {
	return 0, nil, errors.New("not reading")
}
func (*countingPacketConn) WriteTo([]byte, net.Addr) (int, error) {
	return 0, errors.New("not writing")
}
func (*countingPacketConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (*countingPacketConn) SetDeadline(time.Time) error      { return nil }
func (*countingPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (*countingPacketConn) SetWriteDeadline(time.Time) error { return nil }
func (c *countingPacketConn) Close() error {
	c.closed.Add(1)
	return nil
}

func TestQListenerCloseIsIdempotent(t *testing.T) {
	listener := &countingQUICListener{}
	packetConn := &countingPacketConn{}
	qListener := &QListener{QUICListener: listener, packetConn: packetConn}

	if err := qListener.Close(); err != nil {
		t.Fatal(err)
	}
	if err := qListener.Close(); err != nil {
		t.Fatal(err)
	}
	if got := listener.closed.Load(); got != 1 {
		t.Fatalf("listener Close called %d times, want 1", got)
	}
	if got := packetConn.closed.Load(); got != 1 {
		t.Fatalf("packet conn Close called %d times, want 1", got)
	}
}
