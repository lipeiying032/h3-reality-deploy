package splithttp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	gotls "crypto/tls"
	"crypto/x509"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
)

func TestForwardToDestUsesHTTP3(t *testing.T) {
	serverConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1)},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	sawH3 := false
	server := &http3.Server{
		Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			sawH3 = request.ProtoMajor == 3
			writer.Header().Set("X-Forward-Test", "h3")
			writer.WriteHeader(http.StatusOK)
			_, _ = writer.Write([]byte("h3-ok"))
		}),
	}
	listener, err := quic.ListenEarly(serverConn, &gotls.Config{
		Certificates: []gotls.Certificate{{
			Certificate: [][]byte{der},
			PrivateKey:  key,
		}},
		NextProtos: []string{http3.NextProtoH3},
	}, &quic.Config{
		HandshakeIdleTimeout: time.Second,
		MaxIdleTimeout:       3 * time.Second,
	})
	if err != nil {
		serverConn.Close()
		t.Fatal(err)
	}

	go func() {
		_ = server.ServeListener(listener)
	}()
	t.Cleanup(func() {
		_ = server.Close()
		_ = listener.Close()
		_ = serverConn.Close()
	})

	dest := serverConn.LocalAddr().String()
	handler := &requestHandler{
		fallbackClient: newRealityFallbackClient(dest, "localhost"),
		fallbackDest:   dest,
	}
	request := httptest.NewRequest(http.MethodGet, "https://original.example/path?q=1", nil)
	recorder := httptest.NewRecorder()

	handler.forwardToDest(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %q, want 200", recorder.Code, recorder.Body.String())
	}
	if got := recorder.Header().Get("X-Forward-Test"); got != "h3" {
		t.Fatalf("X-Forward-Test = %q, want h3", got)
	}
	if got := recorder.Body.String(); got != "h3-ok" {
		t.Fatalf("body = %q, want h3-ok", got)
	}
	if !sawH3 {
		t.Fatal("fallback request did not reach the destination over HTTP/3")
	}
}
