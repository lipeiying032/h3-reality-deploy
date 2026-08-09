package splithttp

// QUIC Initial decryption (RFC 9001 Section 5.2) and TLS ClientHello
// extraction used by the XHTTP/3 REALITY precheck. The decrypt/extract
// helpers are ported from the quic-ech-sniffer prototype
// (/root/quic-ech-sniffer/main.go); only the decryption and ClientHello
// extraction are taken, ECH detection is intentionally excluded.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"golang.org/x/crypto/hkdf"
)

// quicInitialSalt is the RFC 9001 Section 5.2 Initial salt for QUIC v1.
var quicInitialSalt = []byte{
	0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3,
	0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
	0xcc, 0xbb, 0x7f, 0x0a,
}

// hkdfExtract performs HKDF-Extract ONLY (RFC 5869 Section 2.2). Note that
// hkdf.New() performs Extract-THEN-Expand; using it here would add a spurious
// Expand step and produce the wrong initial_secret, so hkdf.Extract is used
// directly.
func hkdfExtract(salt, ikm []byte) []byte {
	return hkdf.Extract(sha256.New, ikm, salt)
}

// hkdfExpandLabel implements RFC 8446 Section 7.1 HKDF-Expand-Label.
func hkdfExpandLabel(secret []byte, label string, context []byte, length int) []byte {
	// HkdfLabel = length(2) + label_len(1) + "tls13 " + label + context_len(1) + context
	hklabel := make([]byte, 0, 2+1+6+len(label)+1+len(context))
	hklabel = binary.BigEndian.AppendUint16(hklabel, uint16(length))
	hklabel = append(hklabel, byte(6+len(label)))
	hklabel = append(hklabel, []byte("tls13 ")...)
	hklabel = append(hklabel, []byte(label)...)
	hklabel = append(hklabel, byte(len(context)))
	hklabel = append(hklabel, context...)

	h := hkdf.Expand(sha256.New, secret, hklabel)
	out := make([]byte, length)
	n, err := h.Read(out)
	if err != nil || n != length {
		panic("hkdf expand failed")
	}
	return out
}

// deriveInitialSecrets derives the QUIC Initial packet keys (RFC 9001 Section
// 5.2) from the connection's Destination Connection ID.
func deriveInitialSecrets(dcid []byte) (key, iv, hp []byte) {
	initialSecret := hkdfExtract(quicInitialSalt, dcid)
	clientIn := hkdfExpandLabel(initialSecret, "client in", nil, 32)

	key = hkdfExpandLabel(clientIn, "quic key", nil, 16)
	iv = hkdfExpandLabel(clientIn, "quic iv", nil, 12)
	hp = hkdfExpandLabel(clientIn, "quic hp", nil, 16)
	return
}

// readVarint decodes a QUIC variable-length integer (RFC 9000 Section 16).
func readVarint(data []byte) (uint64, int) {
	if len(data) == 0 {
		return 0, 0
	}
	first := data[0]
	switch first >> 6 {
	case 0:
		return uint64(first), 1
	case 1:
		if len(data) < 2 {
			return 0, 0
		}
		return uint64(binary.BigEndian.Uint16(data)) & 0x3FFF, 2
	case 2:
		if len(data) < 4 {
			return 0, 0
		}
		return uint64(binary.BigEndian.Uint32(data)) & 0x3FFFFFFF, 4
	case 3:
		if len(data) < 8 {
			return 0, 0
		}
		return binary.BigEndian.Uint64(data) & 0x3FFFFFFFFFFFFFFF, 8
	}
	return 0, 0
}

// initialPkt holds a parsed and decrypted QUIC Initial packet.
type initialPkt struct {
	DCID    []byte
	SCID    []byte
	Payload []byte
	PN      uint64
}

// parseQUICInitial parses one QUIC Initial packet (long header, type 0x00,
// QUIC v1), removes header protection, decrypts the payload and returns the
// plaintext payload plus the connection IDs and packet number. data is
// mutated in place during header protection removal / decryption, so callers
// must pass a disposable copy when the original datagram is still needed.
func parseQUICInitial(data []byte) (*initialPkt, error) {
	var p initialPkt

	if len(data) < 6 {
		return nil, fmt.Errorf("packet too short")
	}

	// Check long header and Initial type (0xC0 with 1-byte PN)
	firstByte := data[0]
	if firstByte&0x80 == 0 {
		return nil, fmt.Errorf("not a long header")
	}
	pktType := (firstByte >> 4) & 0x03
	if pktType != 0 {
		return nil, fmt.Errorf("not an Initial packet (type=%d)", pktType)
	}

	// Version (4 bytes) — only handle QUIC v1
	if len(data) < 5 {
		return nil, fmt.Errorf("packet too short for version")
	}
	if v := binary.BigEndian.Uint32(data[1:5]); v != 1 {
		return nil, fmt.Errorf("not QUIC v1 (version=%d)", v)
	}

	offset := 5

	// DCID Length and DCID
	if offset >= len(data) {
		return nil, fmt.Errorf("truncated at DCID length")
	}
	dcidLen := int(data[offset])
	offset++
	if offset+dcidLen > len(data) {
		return nil, fmt.Errorf("truncated at DCID")
	}
	p.DCID = make([]byte, dcidLen)
	copy(p.DCID, data[offset:offset+dcidLen])
	offset += dcidLen

	// SCID Length and SCID
	if offset >= len(data) {
		return nil, fmt.Errorf("truncated at SCID length")
	}
	scidLen := int(data[offset])
	offset++
	if offset+scidLen > len(data) {
		return nil, fmt.Errorf("truncated at SCID")
	}
	p.SCID = make([]byte, scidLen)
	copy(p.SCID, data[offset:offset+scidLen])
	offset += scidLen

	// Token Length (varint) and Token
	if offset >= len(data) {
		return nil, fmt.Errorf("truncated at token length")
	}
	tokenLen, varintBytes := readVarint(data[offset:])
	offset += varintBytes
	if offset+int(tokenLen) > len(data) {
		return nil, fmt.Errorf("truncated at token")
	}
	offset += int(tokenLen)

	// Length (varint) of remaining packet
	if offset >= len(data) {
		return nil, fmt.Errorf("truncated at length")
	}
	_, varintBytes = readVarint(data[offset:])
	offset += varintBytes

	// offset now points to start of Packet Number field
	pnStart := offset

	// Derive keys
	key, iv, hp := deriveInitialSecrets(p.DCID)

	// The sample for header protection starts at the 4th byte after the start
	// of the Packet Number field.
	sampleOffset := pnStart + 4
	if sampleOffset+16 > len(data) {
		return nil, fmt.Errorf("packet too short for header protection sample")
	}
	sample := make([]byte, 16)
	copy(sample, data[sampleOffset:])

	block, _ := aes.NewCipher(hp)
	mask := make([]byte, 16)
	block.Encrypt(mask, sample)

	// Unprotect first byte
	data[0] = data[0] ^ (mask[0] & 0x0f)

	// Re-read pnLen from unprotected first byte
	pnLen := int(data[0]&0x03) + 1

	// Unprotect packet number bytes
	if pnStart+pnLen > len(data) {
		return nil, fmt.Errorf("packet number extends beyond data")
	}
	for i := 0; i < pnLen; i++ {
		data[pnStart+i] ^= mask[1+i]
	}

	// Read packet number
	p.PN = 0
	for i := 0; i < pnLen; i++ {
		p.PN = (p.PN << 8) | uint64(data[pnStart+i])
	}

	offset = pnStart + pnLen

	// Decrypt payload (offset now points past packet number)
	if offset+16 >= len(data) {
		return nil, fmt.Errorf("payload too short")
	}

	ciphertext := data[offset:]
	authTag := ciphertext[len(ciphertext)-16:]
	ciphertext = ciphertext[:len(ciphertext)-16]

	// Build the header (associated data) for AEAD — everything before offset
	headerForAEAD := data[:offset]

	block2, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCM(block2)

	// Build nonce: iv XOR packet_number (left-padded to 12 bytes)
	nonce := make([]byte, 12)
	copy(nonce, iv)
	pnPadded := make([]byte, 12)
	binary.BigEndian.PutUint64(pnPadded[4:], p.PN)
	for i := 0; i < 12; i++ {
		nonce[i] ^= pnPadded[i]
	}

	// Combine ciphertext + auth tag for AEAD decryption
	combined := append(ciphertext, authTag...)
	plaintext, err := aead.Open(nil, nonce, combined, headerForAEAD)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	p.Payload = plaintext
	return &p, nil
}

// cryptoFrag is one CRYPTO frame's (offset, data) within a decrypted payload.
type cryptoFrag struct {
	off  int
	data []byte
}

type cryptoRange struct {
	start int
	end   int
}

// cryptoReassembler tracks both CRYPTO stream bytes and the ranges that have
// actually arrived. The backing slice can contain zero-filled gaps after an
// out-of-order fragment, so its length alone must never be used as evidence
// that a ClientHello is complete.
type cryptoReassembler struct {
	data    []byte
	covered []cryptoRange
}

func (r *cryptoReassembler) add(frag cryptoFrag) {
	if frag.off < 0 || len(frag.data) == 0 {
		return
	}
	end := frag.off + len(frag.data)
	if end < frag.off { // integer overflow
		return
	}
	if end > len(r.data) {
		grown := make([]byte, end)
		copy(grown, r.data)
		r.data = grown
	}
	copy(r.data[frag.off:end], frag.data)

	next := cryptoRange{start: frag.off, end: end}
	merged := make([]cryptoRange, 0, len(r.covered)+1)
	inserted := false
	for _, current := range r.covered {
		switch {
		case current.end < next.start:
			merged = append(merged, current)
		case next.end < current.start:
			if !inserted {
				merged = append(merged, next)
				inserted = true
			}
			merged = append(merged, current)
		default:
			if current.start < next.start {
				next.start = current.start
			}
			if current.end > next.end {
				next.end = current.end
			}
		}
	}
	if !inserted {
		merged = append(merged, next)
	}
	r.covered = merged
}

// contiguous returns only the received prefix starting at CRYPTO offset 0.
func (r *cryptoReassembler) contiguous() []byte {
	if len(r.covered) == 0 || r.covered[0].start != 0 {
		return nil
	}
	return r.data[:r.covered[0].end]
}

// parseCryptoFrames extracts all CRYPTO frames (frame type 0x06) from a
// decrypted QUIC payload. CRYPTO frames carry the TLS handshake stream (RFC
// 9001 Section 4.1) and may be fragmented across packets and offset
// arbitrarily, so each fragment is returned with its stream offset. Frame
// types that end the scan (unknown types, padding) stop the walk; the tail of
// an Initial payload is normally padding anyway.
func parseCryptoFrames(payload []byte) []cryptoFrag {
	var frags []cryptoFrag
	offset := 0

	for offset < len(payload) {
		frameType := payload[offset]
		offset++

		switch frameType {
		case 0x00: // PADDING
			// single byte, keep scanning
		case 0x01: // PING
			// no payload
		case 0x02, 0x03: // ACK
			n := skipAckFrame(payload[offset:], frameType == 0x03)
			if n < 0 {
				return frags
			}
			offset += n
		case 0x06: // CRYPTO
			fragOff, n1 := readVarint(payload[offset:])
			offset += n1
			fragLen, n2 := readVarint(payload[offset:])
			offset += n2
			if offset+int(fragLen) > len(payload) {
				return frags
			}
			frags = append(frags, cryptoFrag{off: int(fragOff), data: payload[offset : offset+int(fragLen)]})
			offset += int(fragLen)
		default:
			return frags
		}
	}
	return frags
}

// skipAckFrame returns the number of bytes an ACK frame (frame type 0x02/0x03,
// RFC 9000 Section 19.3) occupies, or -1 when the payload is truncated.
func skipAckFrame(data []byte, hasECN bool) int {
	offset := 0
	read := func() (uint64, bool) {
		value, n := readVarint(data[offset:])
		if n == 0 {
			return 0, false
		}
		offset += n
		return value, true
	}
	// Largest Acknowledged (varint)
	if _, ok := read(); !ok {
		return -1
	}
	// ACK Delay (varint)
	if _, ok := read(); !ok {
		return -1
	}
	// ACK Range Count (varint)
	count, ok := read()
	if !ok {
		return -1
	}
	// First ACK Range (varint)
	if _, ok := read(); !ok {
		return -1
	}
	// Additional ACK Ranges: each has gap + ack_range
	for i := uint64(0); i < count; i++ {
		if _, ok := read(); !ok {
			return -1
		}
		if _, ok := read(); !ok {
			return -1
		}
	}
	if hasECN {
		// ECT(0), ECT(1), and ECN-CE counts.
		for i := 0; i < 3; i++ {
			if _, ok := read(); !ok {
				return -1
			}
		}
	}
	return offset
}

// extractClientHello returns the complete TLS ClientHello handshake message
// (type byte + 3-byte length + body, i.e. including the 4-byte header) from
// the reassembled CRYPTO stream, or nil when the message is not complete yet
// or is not a ClientHello.
func extractClientHello(cryptoData []byte) []byte {
	// Handshake: Type(1) + Length(3)
	if len(cryptoData) < 4 {
		return nil
	}
	if cryptoData[0] != 0x01 { // ClientHello
		return nil
	}
	hsLen := int(cryptoData[1])<<16 | int(cryptoData[2])<<8 | int(cryptoData[3])
	if hsLen <= 0 {
		return nil
	}
	if 4+hsLen > len(cryptoData) {
		return nil
	}
	return cryptoData[:4+hsLen]
}
