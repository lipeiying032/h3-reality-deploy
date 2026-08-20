package reality

import (
	"errors"
	"slices"

	utls "github.com/refraction-networking/utls"
)

// makeUtlsClientHello builds the QUIC ClientHello from a uTLS fingerprint.
//
// uTLS is used purely as a ClientHello constructor and private-key source:
// the fingerprint spec (HelloChrome_Auto etc.) is adapted for the QUIC
// transport by quicifySpec, uTLS generates the wire bytes and the key-share
// private keys, and this fork's QUIC connection state machine (clientHandshake
// and friends) runs the rest of the handshake unchanged. The REALITY
// data-plane-auth payload is sealed into the random field afterwards, exactly
// as the standard path does.
func (c *Conn) makeUtlsClientHello() (*clientHelloMsg, *keySharePrivateKeys, error) {
	if c.quic == nil {
		return nil, nil, errors.New("tls: UtlsClientHelloID is only supported for QUIC connections")
	}

	// quic-go calls SetTransportParameters before Start, so the parameters
	// are always available by the time the ClientHello is built.
	tp, err := c.quicGetTransportParameters()
	if err != nil {
		return nil, nil, err
	}
	if tp == nil {
		tp = []byte{}
	}

	spec, err := utls.UTLSIdToSpec(*c.config.UtlsClientHelloID)
	if err != nil {
		return nil, nil, err
	}
	quicifySpec(&spec, c.config.NextProtos, tp)

	uconn := utls.UClient(nil, &utls.Config{
		Rand:               c.config.Rand,
		ServerName:         c.config.ServerName,
		InsecureSkipVerify: true,
		NextProtos:         c.config.NextProtos,
	}, *c.config.UtlsClientHelloID)
	if err := uconn.ApplyPreset(&spec); err != nil {
		return nil, nil, err
	}
	if err := uconn.ApplyConfig(); err != nil {
		return nil, nil, err
	}
	// RFC 9001, Section 8.4: QUIC ClientHellos carry a zero-length
	// session_id.
	uconn.HandshakeState.Hello.SessionId = nil
	if err := uconn.MarshalClientHello(); err != nil {
		return nil, nil, err
	}

	raw := append([]byte(nil), uconn.HandshakeState.Hello.Raw...)
	var hello clientHelloMsg
	if !hello.unmarshal(raw) {
		return nil, nil, errors.New("tls: failed to unmarshal uTLS ClientHello")
	}

	// Map the uTLS key-share private keys onto the fork's representation.
	// Chrome's hybrid X25519MLKEM768 share carries the reusable X25519
	// component in MlkemEcdhe, which also covers the plain X25519 case via
	// the fallback to Ecdhe.
	var keyShareKeys *keySharePrivateKeys
	if ks := uconn.HandshakeState.State13.KeyShareKeys; ks != nil {
		keyShareKeys = &keySharePrivateKeys{mlkem: ks.Mlkem}
		if ks.MlkemEcdhe != nil {
			keyShareKeys.ecdhe = ks.MlkemEcdhe
		} else {
			keyShareKeys.ecdhe = ks.Ecdhe
		}
	}
	if keyShareKeys == nil || keyShareKeys.ecdhe == nil {
		return nil, nil, errors.New("tls: uTLS ClientHello produced no usable key share")
	}

	// QUIC C-gamma stage-2: seal the REALITY payload into the random field
	// (original-aware AD; see applyRealityClientHelloRandom).
	if c.config.DataPlaneAuth {
		if err := c.config.applyRealityClientHelloRandom(&hello, keyShareKeys); err != nil {
			return nil, nil, err
		}
	}
	return &hello, keyShareKeys, nil
}

// quicifySpec adapts a uTLS ClientHelloSpec to the QUIC transport (RFC 9001,
// Sections 4 and 8):
//
//   - cipher suites are trimmed to the three TLS 1.3 suites (QUIC only
//     negotiates TLS 1.3), without GREASE;
//   - GREASE is removed from supported_groups, supported_versions and
//     key_share, while preserving Chrome's hybrid and X25519 shares;
//   - rsa_pkcs1_sha1 is appended to signature_algorithms;
//   - the session-ticket extension is removed (fresh connection);
//   - TCP compatibility extensions and the two explicit GREASE extensions are
//     removed, matching Chrome's smaller QUIC-specific extension set;
//   - ALPS/application_settings is kept (Chrome QUIC ClientHellos carry it)
//     with supported_protocols set to the configured h3 ALPN, matching the
//     real Chrome wire shape (the uTLS spec hardcodes "h2" for TCP);
//   - ALPN is set to the configured protocols (h3);
//   - the quic_transport_parameters extension is injected right after
//     key_share, a position this function controls (the fingerprint factory
//     has already shuffled the list).
//
// Everything else in the fingerprint — compress_cert(brotli), GREASE-ECH and
// extension ordering — is preserved.
func quicifySpec(spec *utls.ClientHelloSpec, nextProtos []string, tp []byte) {
	cipherSuites := make([]uint16, 0, 3)
	for _, id := range spec.CipherSuites {
		switch id {
		case utls.TLS_AES_128_GCM_SHA256, utls.TLS_AES_256_GCM_SHA384, utls.TLS_CHACHA20_POLY1305_SHA256:
			cipherSuites = append(cipherSuites, id)
		}
	}
	spec.CipherSuites = cipherSuites

	exts := make([]utls.TLSExtension, 0, len(spec.Extensions))
	keyShareIdx := -1
	for _, ext := range spec.Extensions {
		switch e := ext.(type) {
		case *utls.SessionTicketExtension:
			// Fresh QUIC connections send no session ticket.
			continue
		case *utls.ExtendedMasterSecretExtension,
			*utls.RenegotiationInfoExtension,
			*utls.StatusRequestExtension,
			*utls.SupportedPointsExtension,
			*utls.SCTExtension,
			*utls.UtlsGREASEExtension:
			// Chrome's QUIC ClientHello omits the legacy TCP compatibility
			// extensions and doesn't send standalone GREASE extensions.
			continue
		case *utls.ApplicationSettingsExtension:
			// Chrome sends ALPS over QUIC too, advertising the negotiated
			// h3 protocol. Keep the extension and repoint it at h3.
			e.SupportedProtocols = []string{"h3"}
		case *utls.ApplicationSettingsExtensionNew:
			e.SupportedProtocols = []string{"h3"}
		case *utls.SupportedCurvesExtension:
			e.Curves = slices.DeleteFunc(e.Curves, func(curve utls.CurveID) bool {
				return isGREASEUint16(uint16(curve))
			})
		case *utls.SignatureAlgorithmsExtension:
			if !slices.Contains(e.SupportedSignatureAlgorithms, utls.PKCS1WithSHA1) {
				e.SupportedSignatureAlgorithms = append(e.SupportedSignatureAlgorithms, utls.PKCS1WithSHA1)
			}
		case *utls.SupportedVersionsExtension:
			e.Versions = []uint16{utls.VersionTLS13}
		case *utls.ALPNExtension:
			e.AlpnProtocols = append([]string(nil), nextProtos...)
		case *utls.KeyShareExtension:
			e.KeyShares = slices.DeleteFunc(e.KeyShares, func(share utls.KeyShare) bool {
				return isGREASEUint16(uint16(share.Group))
			})
			keyShareIdx = len(exts)
		}
		exts = append(exts, ext)
	}
	spec.Extensions = exts

	// Inject quic_transport_parameters (0x0039) right after key_share, or
	// at the end of the extension list when the fingerprint has no key_share.
	insertAt := len(exts)
	if keyShareIdx >= 0 {
		insertAt = keyShareIdx + 1
	}
	spec.Extensions = slices.Insert(exts, insertAt, utls.TLSExtension(&utls.GenericExtension{Id: extensionQUICTransportParameters, Data: tp}))
}

// isGREASEUint16 reports whether v is a GREASE value (RFC 8701): both bytes
// are equal and the low nibble of each is 0xa.
func isGREASEUint16(v uint16) bool {
	return v&0x0f0f == 0x0a0a && v>>8 == v&0xff
}
