package quic

import (
	"testing"

	"github.com/apernet/quic-go/internal/protocol"
	"github.com/apernet/quic-go/internal/wire"
)

func TestChromeInitialConnectionIDLengths(t *testing.T) {
	config := &Config{InitialDCIDLength: 8}
	dest, err := generateInitialConnectionID(config)
	if err != nil {
		t.Fatal(err)
	}
	transport := &Transport{UseZeroLengthConnectionIDs: true}
	src, err := protocol.GenerateConnectionID(transport.configuredConnectionIDLength(false))
	if err != nil {
		t.Fatal(err)
	}

	header := &wire.ExtendedHeader{}
	header.Type = protocol.PacketTypeInitial
	header.Version = protocol.Version1
	header.DestConnectionID = dest
	header.SrcConnectionID = src
	header.PacketNumberLen = protocol.PacketNumberLen1
	header.Length = 17 // one-byte packet number plus a 16-byte AEAD tag
	raw, err := header.Append(nil, protocol.Version1)
	if err != nil {
		t.Fatal(err)
	}
	raw = append(raw, make([]byte, 16)...)
	parsed, _, _, err := wire.ParsePacket(raw)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.SrcConnectionID.Len() != 0 {
		t.Errorf("Initial SCID length = %d, want 0", parsed.SrcConnectionID.Len())
	}
	if parsed.DestConnectionID.Len() != 8 {
		t.Errorf("Initial DCID length = %d, want 8", parsed.DestConnectionID.Len())
	}
}

func TestInitialDCIDLengthValidation(t *testing.T) {
	for _, length := range []int{1, 7, 21} {
		if err := validateConfig(&Config{InitialDCIDLength: length}); err == nil {
			t.Errorf("length %d accepted", length)
		}
	}
	for _, length := range []int{0, 8, 20} {
		if err := validateConfig(&Config{InitialDCIDLength: length}); err != nil {
			t.Errorf("length %d rejected: %v", length, err)
		}
	}
}
