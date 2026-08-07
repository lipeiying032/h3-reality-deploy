package splithttp

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"net"
	"testing"
	"time"

	goreality "github.com/xtls/reality"
	"github.com/xtls/xray-core/transport/internet/tls"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// buildTestClientHelloBody assembles a raw TLS 1.3 ClientHello handshake
// message (with the 4-byte header) for SNI "www.apple.com" with a X25519 key
// share. random must be 32 bytes; sessionID nil produces a zero-length
// session_id (QUIC-style).
func buildTestClientHelloBody(random, sessionID, ephPub []byte) []byte {
	return buildTestClientHelloBodySNI(random, sessionID, ephPub, "www.apple.com")
}

// buildTestClientHelloBodySNI is buildTestClientHelloBody with an explicit
// SNI, used by the SNI route-selection tests.
func buildTestClientHelloBodySNI(random, sessionID, ephPub []byte, sni string) []byte {
	body := make([]byte, 0, 256)
	body = binary.BigEndian.AppendUint16(body, 0x0303) // legacy_version
	body = append(body, random...)
	if sessionID != nil {
		body = append(body, 0x20) // session_id len 32 (zeroed; sealed later)
		body = append(body, sessionID...)
	} else {
		body = append(body, 0x00)
	}
	body = binary.BigEndian.AppendUint16(body, 2) // cipher_suites len
	body = binary.BigEndian.AppendUint16(body, 0x1301)
	body = append(body, 0x01, 0x00) // compression

	exts := make([]byte, 0, 128)
	// supported_groups
	exts = binary.BigEndian.AppendUint16(exts, 0x000a)
	exts = binary.BigEndian.AppendUint16(exts, 4)
	exts = binary.BigEndian.AppendUint16(exts, 2)
	exts = binary.BigEndian.AppendUint16(exts, 0x001d)
	// key_share: client_shares = group(2) + key_exchange_len(2) + data(32)
	exts = binary.BigEndian.AppendUint16(exts, 0x0033)
	exts = binary.BigEndian.AppendUint16(exts, 2+36)
	exts = binary.BigEndian.AppendUint16(exts, 36)
	exts = binary.BigEndian.AppendUint16(exts, 0x001d)
	exts = binary.BigEndian.AppendUint16(exts, 32)
	exts = append(exts, ephPub...)
	// server_name
	sniBytes := []byte(sni)
	exts = binary.BigEndian.AppendUint16(exts, 0x0000)
	exts = binary.BigEndian.AppendUint16(exts, uint16(5+len(sniBytes)))
	exts = binary.BigEndian.AppendUint16(exts, uint16(3+len(sniBytes)))
	exts = append(exts, 0x00)
	exts = binary.BigEndian.AppendUint16(exts, uint16(len(sniBytes)))
	exts = append(exts, sniBytes...)
	// supported_versions (list length is 1 byte)
	exts = binary.BigEndian.AppendUint16(exts, 0x002b)
	exts = binary.BigEndian.AppendUint16(exts, 3)
	exts = append(exts, 0x02)
	exts = binary.BigEndian.AppendUint16(exts, 0x0304)
	body = binary.BigEndian.AppendUint16(body, uint16(len(exts)))
	body = append(body, exts...)

	msg := make([]byte, 0, 4+len(body))
	msg = append(msg, 0x01) // typeClientHello
	msg = append(msg, byte(len(body)>>16), byte(len(body)>>8), byte(len(body)))
	msg = append(msg, body...)
	return msg
}

// testClientHello builds a raw TLS 1.3 ClientHello handshake message (with
// the 4-byte header) for SNI "www.apple.com" with a X25519 key share. When
// sessionIDPayload is non-nil (16 bytes: ver||ts||shortId), it is sealed into
// a 32-byte session_id exactly like the stage-1 REALITY client does (AD = the
// full handshake message with a zeroed session_id); otherwise the session_id
// is empty (probe-style).
func testClientHello(t *testing.T, ephPriv, serverPub []byte, sessionIDPayload []byte) []byte {
	t.Helper()
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		t.Fatal(err)
	}
	ephPub, err := curve25519.X25519(ephPriv, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}

	if sessionIDPayload == nil {
		return buildTestClientHelloBody(random, nil, ephPub)
	}

	// AD = msg with a zeroed session_id (bytes right after the session_id
	// length byte), matching what the server zeroes in place before Open.
	msg := buildTestClientHelloBody(random, make([]byte, 32), ephPub)
	shared, err := curve25519.X25519(ephPriv, serverPub)
	if err != nil {
		t.Fatal(err)
	}
	authKey := make([]byte, 32)
	if _, err = hkdf.New(sha256.New, shared, random[:20], []byte("REALITY")).Read(authKey); err != nil {
		t.Fatal(err)
	}
	block, _ := aes.NewCipher(authKey)
	aead, _ := cipher.NewGCM(block)
	cipherText := aead.Seal(nil, random[20:], sessionIDPayload, msg)

	sidOff := 4 + 2 + 32 + 1 // header + legacy_version + random + session_id len
	out := make([]byte, 0, len(msg)+len(cipherText)-32)
	out = append(out, msg[:sidOff]...)
	out = append(out, cipherText...)
	out = append(out, msg[sidOff+32:]...)
	return out
}

// testClientHelloRandom builds a raw TLS 1.3 ClientHello whose random field
// carries the stage-2 REALITY auth payload (mirror of
// applyRealityClientHelloRandom). payload is the 16-byte plaintext
// (ver3||0||ts||shortId); when nil the random stays true random (probe-style,
// no auth).
func testClientHelloRandom(t *testing.T, ephPriv, serverPub []byte, payload []byte) []byte {
	t.Helper()
	ephPub, err := curve25519.X25519(ephPriv, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		t.Fatal(err)
	}
	if payload == nil {
		return buildTestClientHelloBody(random, nil, ephPub)
	}

	// AD = the full handshake message with the random field zeroed; salt and
	// nonce come from SHA-256(AD), exactly like the fork client.
	msg := buildTestClientHelloBody(make([]byte, 32), nil, ephPub)
	shared, err := curve25519.X25519(ephPriv, serverPub)
	if err != nil {
		t.Fatal(err)
	}
	authKey := make([]byte, 32)
	adHash := sha256.Sum256(msg)
	if _, err = hkdf.New(sha256.New, shared, adHash[:20], []byte("REALITY")).Read(authKey); err != nil {
		t.Fatal(err)
	}
	block, _ := aes.NewCipher(authKey)
	aead, _ := cipher.NewGCM(block)
	cipherText := aead.Seal(nil, adHash[20:32], payload, msg)
	if len(cipherText) != 32 {
		t.Fatalf("random ciphertext is %d bytes, want 32", len(cipherText))
	}

	out := make([]byte, 0, len(msg))
	out = append(out, msg[:6]...)    // header + legacy_version
	out = append(out, cipherText...) // random field
	out = append(out, msg[38:]...)
	return out
}

// testClientHelloSNI builds a probe-style (no auth payload) ClientHello with
// an explicit SNI, used by the SNI route-selection tests.
func testClientHelloSNI(t *testing.T, ephPriv, serverPub []byte, sni string) []byte {
	t.Helper()
	ephPub, err := curve25519.X25519(ephPriv, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		t.Fatal(err)
	}
	return buildTestClientHelloBodySNI(random, nil, ephPub, sni)
}

func appendVarint(dst []byte, v uint64) []byte {
	switch {
	case v < 64:
		return append(dst, byte(v))
	case v < 16384:
		return binary.BigEndian.AppendUint16(dst, uint16(v)|0x4000)
	case v < 1<<30:
		return binary.BigEndian.AppendUint32(dst, uint32(v)|0x80000000)
	default:
		return binary.BigEndian.AppendUint64(dst, v|0xC000000000000000)
	}
}

// testInitialPacket crafts a QUIC v1 Initial datagram carrying a CRYPTO frame
// with the given TLS handshake bytes, using the client-side mirror of
// parseQUICInitial's key schedule.
func testInitialPacket(t *testing.T, payload []byte) []byte {
	t.Helper()
	dcid := []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	scid := []byte{0x99, 0xaa, 0xbb, 0xcc}
	key, iv, hp := deriveInitialSecrets(dcid)

	frames := make([]byte, 0, len(payload)+16)
	frames = append(frames, 0x06) // CRYPTO
	frames = appendVarint(frames, 0)
	frames = appendVarint(frames, uint64(len(payload)))
	frames = append(frames, payload...)

	pkt := make([]byte, 0, 128)
	pkt = append(pkt, 0xc0) // long header, Initial, 1-byte PN
	pkt = binary.BigEndian.AppendUint32(pkt, 1)
	pkt = append(pkt, byte(len(dcid)))
	pkt = append(pkt, dcid...)
	pkt = append(pkt, byte(len(scid)))
	pkt = append(pkt, scid...)
	pkt = append(pkt, 0x00) // token len 0
	pkt = appendVarint(pkt, uint64(1+len(frames)+16))
	pnStart := len(pkt)
	pkt = append(pkt, 0x00) // PN = 0

	block, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCM(block)
	nonce := make([]byte, 12)
	copy(nonce, iv)
	cipherText := aead.Seal(nil, nonce, frames, pkt)
	pkt = append(pkt, cipherText...)

	// header protection (sample starts 4 bytes after the PN field start)
	sample := pkt[pnStart+4 : pnStart+4+16]
	blockHP, _ := aes.NewCipher(hp)
	mask := make([]byte, 16)
	blockHP.Encrypt(mask, sample)
	pkt[0] ^= mask[0] & 0x0f
	pkt[pnStart] ^= mask[1]
	return pkt
}

func TestParseQUICInitialRoundTrip(t *testing.T) {
	hello := []byte{0x01, 0x00, 0x00, 0x03, 0xaa, 0xbb, 0xcc}
	pkt := testInitialPacket(t, hello)
	parsed, err := parseQUICInitial(pkt)
	if err != nil {
		t.Fatalf("parseQUICInitial: %v", err)
	}
	var buf []byte
	for _, frag := range parseCryptoFrames(parsed.Payload) {
		buf = mergeCryptoFrag(buf, frag)
	}
	ch := extractClientHello(buf)
	if ch == nil || string(ch) != string(hello) {
		t.Fatalf("extractClientHello = %x, want %x", ch, hello)
	}
}

func newTestVerifier(serverPriv []byte, shortIDs map[[8]byte]bool) *goreality.ClientHelloVerifier {
	return &goreality.ClientHelloVerifier{Cfg: &goreality.Config{
		ServerNames:  map[string]bool{"www.apple.com": true},
		PrivateKey:   serverPriv,
		MinClientVer: []byte{26, 3, 27},
		MaxClientVer: []byte{26, 4, 17},
		ShortIds:     shortIDs,
	}}
}

func TestClientHelloVerifier(t *testing.T) {
	serverPriv := make([]byte, 32)
	serverPub, err := curve25519.X25519(serverPriv, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	var shortID [8]byte
	copy(shortID[:], []byte{0xde, 0x08, 0x5a, 0xa9, 0, 0, 0, 0})
	verifier := newTestVerifier(serverPriv, map[[8]byte]bool{shortID: true})

	ephPriv := make([]byte, 32)
	rand.Read(ephPriv)
	probe := testClientHello(t, ephPriv, serverPub, nil)
	if err := verifier.Verify(probe); err == nil {
		t.Fatal("probe ClientHello (no session_id) unexpectedly verified")
	}

	ephPriv2 := make([]byte, 32)
	rand.Read(ephPriv2)
	payload := make([]byte, 16)
	payload[0], payload[1], payload[2] = 26, 4, 17
	binary.BigEndian.PutUint32(payload[4:], uint32(time.Now().Unix()))
	copy(payload[8:], shortID[:])
	if err := verifier.Verify(testClientHello(t, ephPriv2, serverPub, payload)); err != nil {
		t.Fatalf("authenticated ClientHello rejected: %v", err)
	}

	payloadBad := make([]byte, 16)
	payloadBad[0], payloadBad[1], payloadBad[2] = 26, 4, 17
	binary.BigEndian.PutUint32(payloadBad[4:], uint32(time.Now().Unix()))
	copy(payloadBad[8:], []byte{0xde, 0xad, 0xbe, 0xef, 0, 0, 0, 0})
	if err := verifier.Verify(testClientHello(t, ephPriv2, serverPub, payloadBad)); err == nil {
		t.Fatal("bad-shortId ClientHello unexpectedly verified")
	}
}

func TestClientHelloVerifierRandom(t *testing.T) {
	serverPriv := make([]byte, 32)
	serverPub, err := curve25519.X25519(serverPriv, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	var shortID [8]byte
	copy(shortID[:], []byte{0xde, 0x08, 0x5a, 0xa9, 0, 0, 0, 0})
	verifier := newTestVerifier(serverPriv, map[[8]byte]bool{shortID: true})

	// 1. No auth (probe): true random in the random field -> RELAY.
	ephPriv := make([]byte, 32)
	rand.Read(ephPriv)
	if err := verifier.Verify(testClientHelloRandom(t, ephPriv, serverPub, nil)); err == nil {
		t.Fatal("probe ClientHello (no random auth) unexpectedly verified")
	}

	// 2. Valid random auth -> AUTH.
	ephPriv2 := make([]byte, 32)
	rand.Read(ephPriv2)
	payload := make([]byte, 16)
	payload[0], payload[1], payload[2] = 26, 4, 17
	binary.BigEndian.PutUint32(payload[4:], uint32(time.Now().Unix()))
	copy(payload[8:], shortID[:])
	authed := testClientHelloRandom(t, ephPriv2, serverPub, payload)
	if err := verifier.Verify(authed); err != nil {
		t.Fatalf("authenticated ClientHello (random) rejected: %v", err)
	}
	// The ciphertext is exactly 32 bytes, so the ClientHello layout is
	// byte-for-byte identical to a plain hello (the random slot is full).
	ephPub2, _ := curve25519.X25519(ephPriv2, curve25519.Basepoint)
	baseline := buildTestClientHelloBody(make([]byte, 32), nil, ephPub2)
	if len(authed) != len(baseline) {
		t.Fatalf("random-auth ClientHello length %d != plain hello length %d (random slot must stay 32 bytes)", len(authed), len(baseline))
	}

	// 3. Bad shortId -> RELAY.
	payloadBad := make([]byte, 16)
	payloadBad[0], payloadBad[1], payloadBad[2] = 26, 4, 17
	binary.BigEndian.PutUint32(payloadBad[4:], uint32(time.Now().Unix()))
	copy(payloadBad[8:], []byte{0xde, 0xad, 0xbe, 0xef, 0, 0, 0, 0})
	if err := verifier.Verify(testClientHelloRandom(t, ephPriv2, serverPub, payloadBad)); err == nil {
		t.Fatal("bad-shortId ClientHello (random) unexpectedly verified")
	}

	// 4. The session_id path (stage-1) must still verify (backward compat).
	ephPriv3 := make([]byte, 32)
	rand.Read(ephPriv3)
	payload3 := make([]byte, 16)
	payload3[0], payload3[1], payload3[2] = 26, 4, 17
	binary.BigEndian.PutUint32(payload3[4:], uint32(time.Now().Unix()))
	copy(payload3[8:], shortID[:])
	if err := verifier.Verify(testClientHello(t, ephPriv3, serverPub, payload3)); err != nil {
		t.Fatalf("stage-1 session_id ClientHello no longer verifies: %v", err)
	}
}

func TestPrecheckPacketConnDecisions(t *testing.T) {
	serverPriv := make([]byte, 32)
	serverPub, _ := curve25519.X25519(serverPriv, curve25519.Basepoint)
	var shortID [8]byte
	copy(shortID[:], []byte{0xde, 0x08, 0x5a, 0xa9, 0, 0, 0, 0})

	serverConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer serverConn.Close()
	destConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer destConn.Close()

	params := &tls.RealityQUICParams{
		PrivateKey:      serverPriv,
		ShortIds:        map[[8]byte]bool{shortID: true},
		ServerNames:     map[string]bool{"www.apple.com": true},
		Dest:            destConn.LocalAddr().String(),
		FallbackTimeout: 5 * time.Second,
	}
	wrapped, err := newRealityPrecheckPacketConn(context.Background(), serverConn, params)
	if err != nil {
		t.Fatal(err)
	}
	defer wrapped.Close()
	w := wrapped.(*realityPrecheckPacketConn)

	mkClient := func() (*net.UDPConn, net.Addr) {
		c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		return c, c.LocalAddr()
	}

	// 1. Probe ClientHello (no session_id) -> RELAY to dest, packet kept.
	probeClient, probeAddr := mkClient()
	ephPriv := make([]byte, 32)
	rand.Read(ephPriv)
	probePkt := testInitialPacket(t, testClientHello(t, ephPriv, serverPub, nil))
	if _, err := probeClient.WriteToUDP(probePkt, serverConn.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatal(err)
	}
	destConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 2048)
	n, _, err := destConn.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("dest did not receive relayed probe: %v", err)
	}
	if n != len(probePkt) || string(buf[:n]) != string(probePkt) {
		t.Fatalf("relayed probe packet corrupted: got %d bytes, want %d", n, len(probePkt))
	}
	if w.IsAuthenticated(probeAddr) {
		t.Fatal("probe client marked authenticated")
	}

	// 2. REALITY ClientHello -> AUTH, packet served via ReadFrom.
	authClient, authAddr := mkClient()
	ephPriv2 := make([]byte, 32)
	rand.Read(ephPriv2)
	payload := make([]byte, 16)
	payload[0], payload[1], payload[2] = 26, 4, 17
	binary.BigEndian.PutUint32(payload[4:], uint32(time.Now().Unix()))
	copy(payload[8:], shortID[:])
	authPkt := testInitialPacket(t, testClientHello(t, ephPriv2, serverPub, payload))
	if _, err := authClient.WriteToUDP(authPkt, serverConn.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatal(err)
	}

	type readResult struct {
		n    int
		data []byte
		err  error
	}
	ch := make(chan readResult, 1)
	go func() {
		rbuf := make([]byte, 2048)
		n, _, err := wrapped.ReadFrom(rbuf)
		data := make([]byte, n)
		copy(data, rbuf[:n])
		ch <- readResult{n, data, err}
	}()
	select {
	case rr := <-ch:
		if rr.err != nil {
			t.Fatalf("ReadFrom: %v", rr.err)
		}
		if rr.n != len(authPkt) || string(rr.data) != string(authPkt) {
			t.Fatalf("AUTH packet mismatch: got %d bytes, want %d", rr.n, len(authPkt))
		}
	case <-time.After(3 * time.Second):
		t.Fatal("ReadFrom did not return AUTH packet")
	}
	if !w.IsAuthenticated(authAddr) {
		t.Fatal("authenticated client not marked AUTH")
	}

	// 3. Stage-2 ClientHello (auth in the random field) -> AUTH.
	randClient, randAddr := mkClient()
	ephPriv3 := make([]byte, 32)
	rand.Read(ephPriv3)
	payload2 := make([]byte, 16)
	payload2[0], payload2[1], payload2[2] = 26, 4, 17
	binary.BigEndian.PutUint32(payload2[4:], uint32(time.Now().Unix()))
	copy(payload2[8:], shortID[:])
	randPkt := testInitialPacket(t, testClientHelloRandom(t, ephPriv3, serverPub, payload2))
	if _, err := randClient.WriteToUDP(randPkt, serverConn.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatal(err)
	}
	ch2 := make(chan readResult, 1)
	go func() {
		rbuf := make([]byte, 2048)
		n, _, err := wrapped.ReadFrom(rbuf)
		data := make([]byte, n)
		copy(data, rbuf[:n])
		ch2 <- readResult{n, data, err}
	}()
	select {
	case rr := <-ch2:
		if rr.err != nil {
			t.Fatalf("ReadFrom (random auth): %v", rr.err)
		}
		if rr.n != len(randPkt) || string(rr.data) != string(randPkt) {
			t.Fatalf("AUTH packet (random auth) mismatch: got %d bytes, want %d", rr.n, len(randPkt))
		}
	case <-time.After(3 * time.Second):
		t.Fatal("ReadFrom did not return AUTH packet (random auth)")
	}
	if !w.IsAuthenticated(randAddr) {
		t.Fatal("random-auth client not marked AUTH")
	}
}

// relayedProbe is a helper that sends one probe-style Initial datagram with
// the given SNI and returns the raw datagram that the precheck relayed.
type relayedProbe struct {
	data []byte
	conn *net.UDPConn
}

// expectRelay reads one datagram from conn and returns it; it fails the test
// when conn receives nothing within the deadline.
func expectRelay(t *testing.T, conn *net.UDPConn) []byte {
	t.Helper()
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 2048)
	n, _, err := conn.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("expected relayed packet on %s: %v", conn.LocalAddr(), err)
	}
	return buf[:n]
}

// expectNoRelay asserts conn receives nothing within a short window.
func expectNoRelay(t *testing.T, conn *net.UDPConn) {
	t.Helper()
	conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	buf := make([]byte, 2048)
	if n, _, err := conn.ReadFromUDP(buf); err == nil {
		t.Fatalf("unexpected packet (%d bytes) on %s", n, conn.LocalAddr())
	}
}

// TestPrecheckSingleDestRelay verifies the classic REALITY QUIC relay
// semantics: every probe flow — a known serverNames SNI, a different SNI, an
// unknown SNI — is forwarded verbatim to the single configured dest (auth
// failure is never routed by SNI; the real site rejects a mismatched SNI
// itself). Only REALITY-authenticated ClientHellos stay on the proxy path.
// The destination is pinned per client flow at the first packet.
func TestPrecheckSingleDestRelay(t *testing.T) {
	serverPriv := make([]byte, 32)
	serverPub, _ := curve25519.X25519(serverPriv, curve25519.Basepoint)
	var shortID [8]byte
	copy(shortID[:], []byte{0xde, 0x08, 0x5a, 0xa9, 0, 0, 0, 0})

	serverConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer serverConn.Close()
	destConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer destConn.Close()

	params := &tls.RealityQUICParams{
		PrivateKey:      serverPriv,
		ShortIds:        map[[8]byte]bool{shortID: true},
		ServerNames:     map[string]bool{"www.apple.com": true},
		Dest:            destConn.LocalAddr().String(),
		FallbackTimeout: 5 * time.Second,
	}
	wrapped, err := newRealityPrecheckPacketConn(context.Background(), serverConn, params)
	if err != nil {
		t.Fatal(err)
	}
	defer wrapped.Close()
	w := wrapped.(*realityPrecheckPacketConn)

	mkClient := func() (*net.UDPConn, net.Addr) {
		c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		return c, c.LocalAddr()
	}
	sendProbe := func(client *net.UDPConn, sni string) []byte {
		t.Helper()
		ephPriv := make([]byte, 32)
		rand.Read(ephPriv)
		pkt := testInitialPacket(t, testClientHelloSNI(t, ephPriv, serverPub, sni))
		if _, err := client.WriteToUDP(pkt, serverConn.LocalAddr().(*net.UDPAddr)); err != nil {
			t.Fatal(err)
		}
		return pkt
	}

	// 1. Probe with the configured serverNames SNI -> relayed verbatim to
	// dest (SNI does not select any special target).
	client1, _ := mkClient()
	pkt1 := sendProbe(client1, "www.apple.com")
	if got := expectRelay(t, destConn); !bytes.Equal(got, pkt1) {
		t.Fatalf("dest relayed packet corrupted: got %d bytes, want %d", len(got), len(pkt1))
	}
	if w.IsAuthenticated(client1.LocalAddr()) {
		t.Fatal("probe client marked authenticated")
	}

	// 2. Same client, later packet with a different SNI: the target stays
	// pinned to dest (no per-SNI routing).
	pkt1b := sendProbe(client1, "google.com")
	if got := expectRelay(t, destConn); !bytes.Equal(got, pkt1b) {
		t.Fatalf("pinned relay target not kept: got %d bytes, want %d", len(got), len(pkt1b))
	}

	// 3. Fresh client, different SNI -> still dest.
	client2, _ := mkClient()
	pkt2 := sendProbe(client2, "google.com")
	if got := expectRelay(t, destConn); !bytes.Equal(got, pkt2) {
		t.Fatalf("dest relayed packet corrupted: got %d bytes, want %d", len(got), len(pkt2))
	}

	// 4. Unknown SNI -> still dest (classic REALITY: the real site rejects a
	// mismatched SNI by itself).
	client3, _ := mkClient()
	pkt3 := sendProbe(client3, "unknown.example.com")
	if got := expectRelay(t, destConn); !bytes.Equal(got, pkt3) {
		t.Fatalf("dest relayed packet corrupted: got %d bytes, want %d", len(got), len(pkt3))
	}

	// 5. Authenticated (stage-2 random auth) ClientHello still goes AUTH.
	authClient, _ := mkClient()
	ephPriv4 := make([]byte, 32)
	rand.Read(ephPriv4)
	payload := make([]byte, 16)
	payload[0], payload[1], payload[2] = 26, 4, 17
	binary.BigEndian.PutUint32(payload[4:], uint32(time.Now().Unix()))
	copy(payload[8:], shortID[:])
	authPkt := testInitialPacket(t, testClientHelloRandom(t, ephPriv4, serverPub, payload))
	if _, err := authClient.WriteToUDP(authPkt, serverConn.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatal(err)
	}
	ch := make(chan []byte, 1)
	go func() {
		rbuf := make([]byte, 2048)
		n, _, err := wrapped.ReadFrom(rbuf)
		if err == nil {
			ch <- rbuf[:n]
		}
	}()
	select {
	case got := <-ch:
		if !bytes.Equal(got, authPkt) {
			t.Fatalf("AUTH packet mismatch: got %d bytes, want %d", len(got), len(authPkt))
		}
	case <-time.After(3 * time.Second):
		t.Fatal("ReadFrom did not return AUTH packet")
	}
	// The auth flow never touches the relay.
	expectNoRelay(t, destConn)
}

// TestPrecheckInactiveWithoutDest verifies the precheck is a no-op when no
// Dest is configured: the wrapper is not installed and the underlying conn is
// returned unchanged, so unauthenticated flows are neither relayed nor
// classified.
func TestPrecheckInactiveWithoutDest(t *testing.T) {
	serverPriv := make([]byte, 32)
	var shortID [8]byte
	copy(shortID[:], []byte{0xde, 0x08, 0x5a, 0xa9, 0, 0, 0, 0})

	serverConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer serverConn.Close()

	params := &tls.RealityQUICParams{
		PrivateKey:      serverPriv,
		ShortIds:        map[[8]byte]bool{shortID: true},
		ServerNames:     map[string]bool{"www.apple.com": true},
		FallbackTimeout: 5 * time.Second,
	}
	wrapped, err := newRealityPrecheckPacketConn(context.Background(), serverConn, params)
	if err != nil {
		t.Fatal(err)
	}
	if wrapped != net.PacketConn(serverConn) {
		wrapped.Close()
		t.Fatal("precheck wrapped the conn despite empty Dest; want no-op")
	}
}
