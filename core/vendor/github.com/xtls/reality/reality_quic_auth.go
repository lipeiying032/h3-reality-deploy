package reality

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"slices"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

func (c *Config) applyRealityClientHello(hello *clientHelloMsg, keys *keySharePrivateKeys) error {
	// Data-plane-auth mode on non-QUIC transports (TCP/H2 C-gamma): keep
	// the ClientHello standard — zero-length session_id, no REALITY
	// payload. QUIC C-gamma never reaches this function: makeClientHello
	// routes QUIC + DataPlaneAuth to applyRealityClientHelloRandom, which
	// seals the payload into the random field instead.
	if c.DataPlaneAuth {
		return nil
	}
	if len(c.PublicKey) == 0 && len(c.ShortId) == 0 {
		return nil
	}
	if len(c.PublicKey) != 32 {
		return errors.New("REALITY: publicKey == nil")
	}
	if keys == nil || keys.ecdhe == nil {
		return errors.New("REALITY: TLS 1.3 X25519 key share is unavailable")
	}
	publicKey, err := ecdh.X25519().NewPublicKey(c.PublicKey)
	if err != nil {
		return errors.New("REALITY: publicKey == nil")
	}
	authKey, err := keys.ecdhe.ECDH(publicKey)
	if err != nil || authKey == nil {
		return errors.New("REALITY: sharedKey == nil")
	}
	if _, err = hkdf.New(sha256.New, authKey, hello.random[:20], []byte("REALITY")).Read(authKey); err != nil {
		return err
	}

	plainText := make([]byte, 32)
	hello.sessionId = make([]byte, 32)
	associatedData, err := hello.marshal()
	if err != nil {
		return err
	}

	plainText[0] = 26
	plainText[1] = 4
	plainText[2] = 17
	binary.BigEndian.PutUint32(plainText[4:], uint32(time.Now().Unix()))
	copy(plainText[8:], c.ShortId)

	block, _ := aes.NewCipher(authKey)
	aead, _ := cipher.NewGCM(block)
	hello.sessionId = aead.Seal(plainText[:0], hello.random[20:], plainText[:16], associatedData)
	return nil
}

// applyRealityClientHelloRandom injects the REALITY authentication payload
// into the ClientHello random field instead of the session_id (QUIC
// C-gamma stage-2). The 16-byte plaintext (client version || unix
// timestamp || short id) is AES-GCM sealed into exactly 32 bytes — the
// size of the TLS 1.3 random — so the random field stays
// computationally indistinguishable from true randomness while carrying
// a verifiable credential.
//
// The X25519 key share already present in the ClientHello (keys.ecdhe)
// is used for the ECDH, so the server recovers the shared secret from
// the key_share extension alone. The associated data is the marshaled
// ClientHello with the random field zeroed, which is exactly the bytes
// the server sees when it zeroes the random in place before
// verification; both sides derive the HKDF salt and the GCM nonce from
// SHA-256 of that AD. The ciphertext then replaces the random and
// travels in the real ClientHello, participating in the TLS transcript
// like any random value.
func (c *Config) applyRealityClientHelloRandom(hello *clientHelloMsg, keys *keySharePrivateKeys) error {
	if len(c.PublicKey) == 0 && len(c.ShortId) == 0 {
		return nil
	}
	if len(c.PublicKey) != 32 {
		return errors.New("REALITY: publicKey == nil")
	}
	if keys == nil || keys.ecdhe == nil {
		return errors.New("REALITY: TLS 1.3 X25519 key share is unavailable")
	}
	publicKey, err := ecdh.X25519().NewPublicKey(c.PublicKey)
	if err != nil {
		return errors.New("REALITY: publicKey == nil")
	}
	authKey, err := keys.ecdhe.ECDH(publicKey)
	if err != nil || authKey == nil {
		return errors.New("REALITY: sharedKey == nil")
	}

	// AD = the ClientHello with the random field zeroed; salt and nonce
	// are derived from SHA-256(AD) so both endpoints agree without
	// carrying any extra state in the handshake. When the hello carries
	// original wire bytes (the uTLS path), the AD is a copy of those raw
	// bytes with the random field zeroed at its fixed offset (handshake
	// type 1 + length 3 + legacy_version 2 => bytes 6..38), mirroring
	// verifyClientHelloRandom exactly. Field re-marshaling is never used
	// as AD here: it would drop GREASE, unknown extensions and the
	// original extension order, making the two endpoints disagree.
	random := hello.random
	var associatedData []byte
	if len(hello.original) >= 38 {
		associatedData = slices.Clone(hello.original)
		for i := 6; i < 38; i++ {
			associatedData[i] = 0
		}
	} else {
		hello.random = make([]byte, 32)
		associatedData, err = hello.marshal()
		if err != nil {
			hello.random = random
			return err
		}
	}
	adHash := sha256.Sum256(associatedData)
	if _, err = hkdf.New(sha256.New, authKey, adHash[:20], []byte("REALITY")).Read(authKey); err != nil {
		hello.random = random
		return err
	}

	plainText := make([]byte, 16)
	plainText[0] = 26
	plainText[1] = 4
	plainText[2] = 17
	binary.BigEndian.PutUint32(plainText[4:], uint32(time.Now().Unix()))
	copy(plainText[8:], c.ShortId)

	block, _ := aes.NewCipher(authKey)
	aead, _ := cipher.NewGCM(block)
	hello.random = aead.Seal(nil, adHash[20:32], plainText, associatedData)
	if len(hello.random) != 32 {
		hello.random = random
		return errors.New("REALITY: random ciphertext must be exactly 32 bytes")
	}
	// The bytes actually sent come from hello.original when present (the
	// marshal shortcut), so the ciphertext must also be written back into
	// the raw bytes at the random offset for the wire to carry it.
	if len(hello.original) >= 38 {
		copy(hello.original[6:38], hello.random)
	}
	return nil
}

func (c *Conn) acceptRealityClientHello(hello *clientHelloMsg) error {
	if c.config == nil || len(c.config.PrivateKey) == 0 || len(c.config.ShortIds) == 0 {
		return nil
	}
	if c.vers != VersionTLS13 {
		return errors.New("REALITY: unsupported TLS version")
	}
	if err := verifyClientHello(hello, c.config); err != nil {
		return err
	}
	auth := hello.auth
	c.AuthKey = auth.authKey
	c.ClientVer = auth.clientVer
	c.ClientTime = auth.clientTime
	c.ClientShortId = auth.clientShortId
	return nil
}

// clientHelloAuth is the outcome of a successful REALITY ClientHello
// verification: the derived auth key plus the authenticated client metadata
// (version, timestamp, short id) recovered from the encrypted session_id
// payload.
type clientHelloAuth struct {
	authKey       []byte
	clientVer     [3]byte
	clientTime    time.Time
	clientShortId [8]byte
}

// verifyClientHello authenticates the REALITY payload carried in a TLS 1.3
// ClientHello against cfg. It performs the complete check shared by the QUIC
// server handshake and the XHTTP/3 QUIC precheck:
//
//  1. SNI whitelist (cfg.ServerNames)
//  2. session_id length must be 32
//  3. X25519 (or X25519MLKEM768 hybrid) key share extraction
//  4. ECDH + HKDF auth key derivation
//  5. AEAD open with the raw ClientHello bytes as associated data (the
//     session_id is temporarily zeroed in place — it aliases hello.original —
//     matching what the client sealed with)
//  6. client version / timestamp / shortId validation (v6 semantics)
//
// On success the authenticated metadata is recorded on hello.auth; on any
// failure hello.sessionId is restored and an error is returned.
func verifyClientHello(hello *clientHelloMsg, cfg *Config) error {
	if cfg == nil || len(cfg.PrivateKey) == 0 || len(cfg.ShortIds) == 0 {
		return nil
	}
	auth, err := verifyClientHelloAuth(hello, cfg)
	if err != nil {
		return err
	}
	hello.auth = auth
	return nil
}

func verifyClientHelloAuth(hello *clientHelloMsg, cfg *Config) (*clientHelloAuth, error) {
	if !cfg.ServerNames[hello.serverName] {
		return nil, errors.New("REALITY: server name mismatch")
	}
	if len(hello.sessionId) != 32 {
		return nil, errors.New("REALITY: missing client session id")
	}

	peerPub := extractClientKeyShare(hello)
	if peerPub == nil {
		return nil, errors.New("REALITY: missing X25519 key share")
	}

	authKey, err := curve25519.X25519(cfg.PrivateKey, peerPub)
	if err != nil || authKey == nil {
		return nil, errors.New("REALITY: sharedKey == nil")
	}
	if _, err = hkdf.New(sha256.New, authKey, hello.random[:20], []byte("REALITY")).Read(authKey); err != nil {
		return nil, err
	}

	cipherText := make([]byte, 32)
	plainText := make([]byte, 32)
	copy(cipherText, hello.sessionId)
	copy(hello.sessionId, plainText)
	block, _ := aes.NewCipher(authKey)
	aead, _ := cipher.NewGCM(block)
	if _, err = aead.Open(plainText[:0], hello.random[20:], cipherText, hello.original); err != nil {
		copy(hello.sessionId, cipherText)
		return nil, err
	}
	copy(hello.sessionId, cipherText)

	auth := &clientHelloAuth{
		authKey:    authKey,
		clientTime: time.Unix(int64(binary.BigEndian.Uint32(plainText[4:])), 0),
	}
	copy(auth.clientVer[:], plainText)
	copy(auth.clientShortId[:], plainText[8:])
	if (cfg.MinClientVer != nil && Value(auth.clientVer[:]...) < Value(cfg.MinClientVer...)) ||
		(cfg.MaxClientVer != nil && Value(auth.clientVer[:]...) > Value(cfg.MaxClientVer...)) ||
		(cfg.MaxTimeDiff != 0 && time.Since(auth.clientTime).Abs() > cfg.MaxTimeDiff) ||
		!cfg.ShortIds[auth.clientShortId] {
		return nil, errors.New("REALITY: authentication failed")
	}
	return auth, nil
}

// extractClientKeyShare returns the X25519 public key from the
// ClientHello's key shares: the raw X25519 share, or the trailing X25519
// component of the X25519MLKEM768 hybrid share. It returns nil when no
// usable share is present.
func extractClientKeyShare(hello *clientHelloMsg) []byte {
	for _, keyShare := range hello.keyShares {
		if keyShare.group == X25519 && len(keyShare.data) == 32 {
			return keyShare.data
		}
		if keyShare.group == X25519MLKEM768 && len(keyShare.data) >= 32 {
			return keyShare.data[len(keyShare.data)-32:]
		}
	}
	return nil
}

// verifyClientHelloRandom authenticates a REALITY payload sealed into the
// ClientHello random field (the stage-2 QUIC auth). It mirrors
// applyRealityClientHelloRandom:
//
//  1. SNI whitelist (cfg.ServerNames)
//  2. X25519 (or X25519MLKEM768 hybrid) key share extraction
//  3. ECDH + HKDF auth key derivation
//  4. AEAD open with the raw ClientHello bytes as associated data, the
//     random field temporarily zeroed in place (it aliases
//     hello.original) — the salt and nonce come from SHA-256 of that AD,
//     exactly as the client derived them
//  5. client version / timestamp / shortId validation (v6 semantics)
//
// On success the authenticated metadata is returned; the random field is
// restored before returning in every path.
func verifyClientHelloRandom(hello *clientHelloMsg, cfg *Config) (*clientHelloAuth, error) {
	if cfg == nil || len(cfg.PrivateKey) == 0 || len(cfg.ShortIds) == 0 {
		return nil, nil
	}
	if !cfg.ServerNames[hello.serverName] {
		return nil, errors.New("REALITY: server name mismatch")
	}
	peerPub := extractClientKeyShare(hello)
	if peerPub == nil {
		return nil, errors.New("REALITY: missing X25519 key share")
	}

	authKey, err := curve25519.X25519(cfg.PrivateKey, peerPub)
	if err != nil || authKey == nil {
		return nil, errors.New("REALITY: sharedKey == nil")
	}

	// AD = the raw ClientHello with the random field zeroed. The random
	// sits at a fixed offset: handshake type(1) + length(3) +
	// legacy_version(2) + random(32) -> bytes 6..38.
	if len(hello.original) < 38 {
		return nil, errors.New("REALITY: malformed ClientHello")
	}
	randomStart, randomEnd := 6, 38
	// hello.random aliases hello.original[6:38]: save the ciphertext before
	// zeroing the random in place to build the AD.
	cipherText := make([]byte, 32)
	copy(cipherText, hello.random)
	origRandom := make([]byte, 32)
	copy(origRandom, hello.original[randomStart:randomEnd])
	for i := randomStart; i < randomEnd; i++ {
		hello.original[i] = 0
	}
	adHash := sha256.Sum256(hello.original)
	if _, err = hkdf.New(sha256.New, authKey, adHash[:20], []byte("REALITY")).Read(authKey); err != nil {
		copy(hello.original[randomStart:randomEnd], origRandom)
		return nil, err
	}

	plainText := make([]byte, 32)
	block, _ := aes.NewCipher(authKey)
	aead, _ := cipher.NewGCM(block)
	_, err = aead.Open(plainText[:0], adHash[20:32], cipherText, hello.original)
	copy(hello.original[randomStart:randomEnd], origRandom)
	if err != nil {
		return nil, err
	}

	auth := &clientHelloAuth{
		authKey:    authKey,
		clientTime: time.Unix(int64(binary.BigEndian.Uint32(plainText[4:])), 0),
	}
	copy(auth.clientVer[:], plainText)
	copy(auth.clientShortId[:], plainText[8:])
	if (cfg.MinClientVer != nil && Value(auth.clientVer[:]...) < Value(cfg.MinClientVer...)) ||
		(cfg.MaxClientVer != nil && Value(auth.clientVer[:]...) > Value(cfg.MaxClientVer...)) ||
		(cfg.MaxTimeDiff != 0 && time.Since(auth.clientTime).Abs() > cfg.MaxTimeDiff) ||
		!cfg.ShortIds[auth.clientShortId] {
		return nil, errors.New("REALITY: authentication failed")
	}
	return auth, nil
}

// ClientHelloVerifier validates a raw TLS ClientHello handshake message
// (including its 4-byte header: type byte + 24-bit length) against a REALITY
// server Config, without any connection state. It is used by the XHTTP/3 QUIC
// precheck to classify incoming QUIC Initial packets before they reach
// quic-go.
type ClientHelloVerifier struct {
	Cfg *Config
}

// Verify runs the full REALITY ClientHello authentication (SNI whitelist,
// session_id payload, key share, ECDH+HKDF, AEAD, version/time/shortId) on a
// raw TLS ClientHello handshake message. It returns nil when the ClientHello
// carries a valid REALITY payload for Cfg.
func (v *ClientHelloVerifier) Verify(rawHandshakeMsg []byte) error {
	if v == nil || v.Cfg == nil {
		return nil
	}
	var hello clientHelloMsg
	if !hello.unmarshal(rawHandshakeMsg) {
		return errors.New("REALITY: failed to unmarshal ClientHello")
	}
	// Stage-2 QUIC mode: the authentication payload lives in the random
	// field. Try it first; the session_id branch below stays as a
	// backward-compatible fallback for TCP REALITY / older clients.
	if auth, err := verifyClientHelloRandom(&hello, v.Cfg); err == nil {
		if auth != nil {
			hello.auth = auth
		}
		return nil
	}
	return verifyClientHello(&hello, v.Cfg)
}

// ---------------------------------------------------------------------------
// C-gamma data-plane authentication records (legacy).
//
// Stage-1 carried REALITY auth at the HTTP layer ("X-Reality-Auth" header);
// stage-2 moved QUIC auth back into the TLS ClientHello random field (see
// applyRealityClientHelloRandom / verifyClientHelloRandom), and stage-2
// clients no longer send the header. These record helpers are kept so servers
// without the QUIC precheck can still verify the header from legacy clients:
// the record is a self-contained X25519 ECDH + HKDF + AES-GCM blob
//
//	record = ephPub(32) || salt(20) || nonce(12) || AES-GCM ciphertext(32)
//
// with plaintext ver[3] || 0x00 || unix-ts(4) || shortId(8) and
// authKey = HKDF-SHA256(shared, salt, "REALITY").
// ---------------------------------------------------------------------------

// authRecordLen is the length of a data-plane auth record:
// ephPub(32) + salt(20) + nonce(12) + ciphertext(16+16).
const authRecordLen = 32 + 20 + 12 + 32

// BuildAuthRecord constructs a data-plane REALITY auth record for the client
// side. ephPriv is a fresh X25519 private key (32 bytes), serverPub is the
// server's REALITY public key (32 bytes), shortId is the 8-byte client short
// id and clientVer is the 3-byte client version (e.g. {26, 4, 17}).
func BuildAuthRecord(ephPriv, serverPub, shortId, clientVer []byte) ([]byte, error) {
	if len(ephPriv) != 32 {
		return nil, errors.New("REALITY: ephemeral private key must be 32 bytes")
	}
	if len(serverPub) != 32 {
		return nil, errors.New("REALITY: publicKey == nil")
	}
	if len(shortId) != 8 {
		return nil, errors.New("REALITY: shortId must be 8 bytes")
	}
	if len(clientVer) != 3 {
		return nil, errors.New("REALITY: client version must be 3 bytes")
	}

	ephPub, err := curve25519.X25519(ephPriv, curve25519.Basepoint)
	if err != nil {
		return nil, errors.New("REALITY: invalid ephemeral private key")
	}
	authKey, err := curve25519.X25519(ephPriv, serverPub)
	if err != nil || authKey == nil {
		return nil, errors.New("REALITY: sharedKey == nil")
	}

	salt := make([]byte, 20)
	nonce := make([]byte, 12)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	if _, err = hkdf.New(sha256.New, authKey, salt, []byte("REALITY")).Read(authKey); err != nil {
		return nil, err
	}

	plainText := make([]byte, 16)
	copy(plainText[0:3], clientVer)
	binary.BigEndian.PutUint32(plainText[4:], uint32(time.Now().Unix()))
	copy(plainText[8:], shortId)

	block, _ := aes.NewCipher(authKey)
	aead, _ := cipher.NewGCM(block)
	cipherText := aead.Seal(nil, nonce, plainText, nil)

	record := make([]byte, 0, authRecordLen)
	record = append(record, ephPub...)
	record = append(record, salt...)
	record = append(record, nonce...)
	record = append(record, cipherText...)
	return record, nil
}

// VerifyAuthRecord validates a data-plane REALITY auth record on the server
// side. record must be produced by BuildAuthRecord. privateKey is the server's
// REALITY private key; shortIds is the set of accepted 8-byte short ids.
// minVer/maxVer (3 bytes, nil = unbounded) bound the client version and
// maxTimeDiff (0 = disabled) bounds the client timestamp skew. The returned
// error carries the same semantics as the handshake auth:
// "REALITY: authentication failed" for shortId/version/time mismatches.
func VerifyAuthRecord(record, privateKey []byte, shortIds map[[8]byte]bool, minVer, maxVer []byte, maxTimeDiff time.Duration) error {
	if len(record) != authRecordLen {
		return errors.New("REALITY: malformed auth record")
	}
	if len(privateKey) != 32 {
		return errors.New("REALITY: privateKey == nil")
	}
	ephPub := record[:32]
	salt := record[32:52]
	nonce := record[52:64]
	cipherText := record[64:]

	authKey, err := curve25519.X25519(privateKey, ephPub)
	if err != nil || authKey == nil {
		return errors.New("REALITY: sharedKey == nil")
	}
	if _, err = hkdf.New(sha256.New, authKey, salt, []byte("REALITY")).Read(authKey); err != nil {
		return err
	}

	plainText := make([]byte, 16)
	block, _ := aes.NewCipher(authKey)
	aead, _ := cipher.NewGCM(block)
	if _, err = aead.Open(plainText[:0], nonce, cipherText, nil); err != nil {
		return err
	}

	var clientVer [3]byte
	copy(clientVer[:], plainText[0:3])
	clientTime := time.Unix(int64(binary.BigEndian.Uint32(plainText[4:])), 0)
	var clientShortId [8]byte
	copy(clientShortId[:], plainText[8:])
	if (minVer != nil && Value(clientVer[:]...) < Value(minVer...)) ||
		(maxVer != nil && Value(clientVer[:]...) > Value(maxVer...)) ||
		(maxTimeDiff != 0 && time.Since(clientTime).Abs() > maxTimeDiff) ||
		!shortIds[clientShortId] {
		return errors.New("REALITY: authentication failed")
	}
	return nil
}
