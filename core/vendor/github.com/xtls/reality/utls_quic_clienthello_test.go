package reality

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"testing"

	utls "github.com/refraction-networking/utls"
)

var testShortID = [8]byte{0xde, 0x08, 0x5a, 0xa9}

// extensionIDs parses the raw ClientHello and returns the extension IDs in
// wire order.
func extensionIDs(raw []byte) []uint16 {
	if len(raw) < 4 {
		return nil
	}
	p := raw[4:]
	if len(p) < 2+32 {
		return nil
	}
	p = p[2+32:]
	if len(p) < 1 {
		return nil
	}
	sidLen := int(p[0])
	p = p[1:]
	if len(p) < sidLen {
		return nil
	}
	p = p[sidLen:]
	if len(p) < 2 {
		return nil
	}
	csLen := int(p[0])<<8 | int(p[1])
	p = p[2:]
	if len(p) < csLen {
		return nil
	}
	p = p[csLen:]
	if len(p) < 2 {
		return nil
	}
	compLen := int(p[0])
	p = p[1:]
	if len(p) < compLen {
		return nil
	}
	p = p[compLen:]
	if len(p) < 2 {
		return nil
	}
	extLen := int(p[0])<<8 | int(p[1])
	p = p[2:]
	if len(p) < extLen {
		return nil
	}
	var ids []uint16
	for len(p) >= 4 {
		id := uint16(p[0])<<8 | uint16(p[1])
		l := int(p[2])<<8 | int(p[3])
		p = p[4:]
		ids = append(ids, id)
		if len(p) < l {
			break
		}
		p = p[l:]
	}
	return ids
}

// buildBaselineChrome returns the stock uTLS Chrome 133 ClientHello (no QUIC
// adjustments) parsed into the fork's message type.
func buildBaselineChrome(t *testing.T) *clientHelloMsg {
	t.Helper()
	spec, err := utls.UTLSIdToSpec(utls.HelloChrome_Auto)
	if err != nil {
		t.Fatal(err)
	}
	uconn := utls.UClient(nil, &utls.Config{
		ServerName:         "www.apple.com",
		InsecureSkipVerify: true,
		NextProtos:         []string{"h3"},
	}, utls.HelloChrome_Auto)
	if err := uconn.ApplyPreset(&spec); err != nil {
		t.Fatal(err)
	}
	if err := uconn.ApplyConfig(); err != nil {
		t.Fatal(err)
	}
	if err := uconn.MarshalClientHello(); err != nil {
		t.Fatal(err)
	}
	var hello clientHelloMsg
	if !hello.unmarshal(uconn.HandshakeState.Hello.Raw) {
		t.Fatal("failed to unmarshal baseline ClientHello")
	}
	return &hello
}

func TestMakeUtlsClientHelloFingerprint(t *testing.T) {
	serverPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serverCfg := &Config{
		PrivateKey:  serverPriv.Bytes(),
		ServerNames: map[string]bool{"www.apple.com": true},
		ShortIds:    map[[8]byte]bool{testShortID: true},
	}
	clientCfg := &Config{
		ServerName:         "www.apple.com",
		InsecureSkipVerify: true,
		NextProtos:         []string{"h3"},
		DataPlaneAuth:      true,
		PublicKey:          serverPriv.PublicKey().Bytes(),
		ShortId:            testShortID[:],
		UtlsClientHelloID:  &utls.HelloChrome_Auto,
	}

	qc := QUICClient(&QUICConfig{TLSConfig: clientCfg})
	tp := []byte{0x04, 0x03, 0x02, 0x01, 0x11, 0x04} // arbitrary TP bytes
	qc.SetTransportParameters(tp)
	hello, keys, err := qc.conn.makeUtlsClientHello()
	if err != nil {
		t.Fatalf("makeUtlsClientHello: %v", err)
	}
	if keys == nil || keys.ecdhe == nil {
		t.Fatal("no ecdhe key share")
	}

	baseline := buildBaselineChrome(t)
	var sb strings.Builder
	writeFingerprintTable(&sb, baseline, hello, tp)

	// --- assertions ---
	if len(hello.sessionId) != 0 {
		t.Errorf("session_id length = %d, want 0", len(hello.sessionId))
	}
	// GREASE values are randomized per connection; only their shape is
	// fixed (RFC 8701). The suite/version lists must be GREASE + TLS 1.3.
	if len(hello.cipherSuites) != 4 || !isGREASEUint16(hello.cipherSuites[0]) ||
		!slices.Equal(hello.cipherSuites[1:], []uint16{0x1301, 0x1302, 0x1303}) {
		t.Errorf("cipher_suites = %x, want [GREASE 1301 1302 1303]", hello.cipherSuites)
	}
	if len(hello.supportedVersions) != 2 || !isGREASEUint16(hello.supportedVersions[0]) ||
		hello.supportedVersions[1] != 0x0304 {
		t.Errorf("supported_versions = %x, want [GREASE 0304]", hello.supportedVersions)
	}
	if !slices.Equal(hello.alpnProtocols, []string{"h3"}) {
		t.Errorf("ALPN = %v, want [h3]", hello.alpnProtocols)
	}
	ids := extensionIDs(hello.original)
	if slices.Contains(ids, 0x0023) {
		t.Error("session_ticket extension present in QUIC ClientHello")
	}
	if !slices.Contains(ids, 0x44cd) {
		t.Errorf("ALPS/application_settings (0x44cd) extension missing from QUIC ClientHello (ids=%x)", ids)
	}
	if !slices.Contains(ids, 0x001b) {
		t.Error("compress_certificate extension missing")
	}
	if !slices.Contains(ids, 0x0005) {
		t.Error("status_request extension missing")
	}
	if !slices.Contains(ids, 0x0012) {
		t.Error("signed_certificate_timestamp extension missing")
	}
	if !slices.Contains(ids, 0x0017) {
		t.Error("extended_master_secret extension missing")
	}
	tpIdx := slices.Index(ids, 0x0039)
	if tpIdx < 0 {
		t.Fatal("quic_transport_parameters extension missing")
	}
	ksIdx := slices.Index(ids, 0x0033)
	if ksIdx < 0 {
		t.Fatal("key_share extension missing")
	}
	if tpIdx != ksIdx+1 {
		t.Errorf("quic_transport_parameters at index %d, want immediately after key_share (%d)", tpIdx, ksIdx)
	}
	// groups must contain GREASE + X25519MLKEM768 + X25519 + P-256 + P-384
	for _, g := range []CurveID{X25519MLKEM768, X25519, CurveP256, CurveP384} {
		if !slices.Contains(hello.supportedCurves, g) {
			t.Errorf("supported_groups missing %v", g)
		}
	}
	// key_share set: GREASE + X25519MLKEM768 + X25519
	if len(hello.keyShares) != 3 {
		t.Errorf("key_share count = %d, want 3", len(hello.keyShares))
	}
	// the REALITY payload must seal into the random field and be verifiable
	// server-side with the raw bytes as AD.
	if len(hello.random) != 32 {
		t.Fatalf("random length = %d, want 32", len(hello.random))
	}
	if !bytes.Equal(hello.original[6:38], hello.random) {
		t.Error("wire random bytes (original[6:38]) differ from hello.random")
	}
	auth, err := verifyClientHelloRandom(hello.clone(), serverCfg)
	if err != nil {
		t.Errorf("server-side verifyClientHelloRandom failed: %v", err)
	} else if auth == nil || auth.clientShortId != testShortID {
		t.Errorf("verifyClientHelloRandom returned unexpected auth: %+v", auth)
	}
	// and a field re-marshal must NOT be used as AD: prove the wire bytes are
	// the original (marshal shortcut).
	out, err := hello.marshal()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, hello.original) {
		t.Error("marshal() does not return the original wire bytes")
	}

	fmt.Print(sb.String())
}

// writeFingerprintTable prints the baseline (uTLS Chrome 133 TCP-style) vs the
// QUIC product ClientHello side by side.
func writeFingerprintTable(w *strings.Builder, baseline, product *clientHelloMsg, tp []byte) {
	fmt.Fprintf(w, "=== ClientHello fingerprint comparison ===\n")
	fmt.Fprintf(w, "baseline: uTLS HelloChrome_Auto (Chrome 133 spec, TCP-style)\n")
	fmt.Fprintf(w, "product : QUIC ClientHello via makeUtlsClientHello (fingerprint=chrome)\n\n")
	row := func(name, b, p string) {
		fmt.Fprintf(w, "%-28s | %-46s | %s\n", name, b, p)
	}
	row("field", "baseline", "product")
	row("session_id_len", fmt.Sprint(len(baseline.sessionId)), fmt.Sprint(len(product.sessionId)))
	row("cipher_suites", fmt.Sprintf("%x", baseline.cipherSuites), fmt.Sprintf("%x", product.cipherSuites))
	row("supported_versions", fmt.Sprintf("%x", baseline.supportedVersions), fmt.Sprintf("%x", product.supportedVersions))
	row("ALPN", fmt.Sprint(baseline.alpnProtocols), fmt.Sprint(product.alpnProtocols))
	row("supported_groups", fmt.Sprintf("%x", baseline.supportedCurves), fmt.Sprintf("%x", product.supportedCurves))
	ksh := func(h *clientHelloMsg) string {
		var b strings.Builder
		for i, ks := range h.keyShares {
			if i > 0 {
				b.WriteString(", ")
			}
			fmt.Fprintf(&b, "%x(len=%d)", ks.group, len(ks.data))
		}
		return b.String()
	}
	row("key_share groups", ksh(baseline), ksh(product))
	row("sigalgs", fmt.Sprintf("%x", baseline.supportedSignatureAlgorithms), fmt.Sprintf("%x", product.supportedSignatureAlgorithms))
	row("sigalgs_cert", fmt.Sprintf("%x", baseline.supportedSignatureAlgorithmsCert), fmt.Sprintf("%x", product.supportedSignatureAlgorithmsCert))
	row("compress_cert(brotli)", "present", "present")
	row("session_ticket", "present", "absent")
	row("ALPS(0x44cd)", "present (h2)", "present (h3)")
	row("TP(0x0039)", "absent", fmt.Sprintf("present, %d bytes", len(tp)))
	row("ext order", fmt.Sprintf("%x", extensionIDs(baseline.original)), fmt.Sprintf("%x", extensionIDs(product.original)))
	fmt.Fprintf(w, "\nproduct raw ClientHello: %s\n", hex.EncodeToString(product.original))
	fmt.Fprintf(w, "wire random (original[6:38]): %s\n", hex.EncodeToString(product.original[6:38]))
}
