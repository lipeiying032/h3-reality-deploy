package splithttp

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/apernet/quic-go"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	xraytls "github.com/xtls/xray-core/transport/internet/tls"
)

func TestParseH3WireProfileInitialPacketSize(t *testing.T) {
	tests := []struct {
		name      string
		params    *xraytls.RealityQUICParams
		want      uint16
		wantError bool
	}{
		{name: "nil"},
		{name: "default", params: &xraytls.RealityQUICParams{}},
		{name: "minimum", params: &xraytls.RealityQUICParams{H3InitialPacketSize: 1200}, want: 1200},
		{name: "maximum", params: &xraytls.RealityQUICParams{H3InitialPacketSize: 1452}, want: 1452},
		{name: "below minimum", params: &xraytls.RealityQUICParams{H3InitialPacketSize: 1199}, wantError: true},
		{name: "above maximum", params: &xraytls.RealityQUICParams{H3InitialPacketSize: 1453}, wantError: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := parseH3WireProfile(test.params)
			if (err != nil) != test.wantError {
				t.Fatalf("parseH3WireProfile() error = %v, wantError %v", err, test.wantError)
			}
			if err == nil && got.initialPacketSize != test.want {
				t.Fatalf("initialPacketSize = %d, want %d", got.initialPacketSize, test.want)
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

func TestH3ServerInitialPacketSize(t *testing.T) {
	generated, _ := cert.MustGenerate(nil, cert.DNSNames("localhost"))
	certPEM, keyPEM := generated.ToPEM()
	keyPair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name       string
		packetSize uint16
		wantSize   int
	}{
		{name: "default", wantSize: 1280},
		{name: "configured", packetSize: 1200, wantSize: 1200},
	} {
		t.Run(test.name, func(t *testing.T) {
			serverSocket, err := net.ListenPacket("udp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			serverPackets := &initialSizeRecordingPacketConn{PacketConn: serverSocket}
			serverTransport := &quic.Transport{Conn: serverPackets}
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
			for _, length := range lengths {
				if length == test.wantSize {
					return
				}
			}
			t.Fatalf("no server Initial datagram of %d bytes in lengths %v", test.wantSize, lengths)
		})
	}
}
