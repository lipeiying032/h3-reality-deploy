package quic

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"

	"github.com/apernet/quic-go/internal/protocol"
	"github.com/apernet/quic-go/internal/wire"
	"github.com/apernet/quic-go/quicvarint"
)

func parseTransportParameters(t *testing.T, data []byte) map[uint64][]byte {
	t.Helper()
	params := make(map[uint64][]byte)
	for len(data) > 0 {
		id, n, err := quicvarint.Parse(data)
		if err != nil {
			t.Fatal(err)
		}
		data = data[n:]
		length, n, err := quicvarint.Parse(data)
		if err != nil {
			t.Fatal(err)
		}
		data = data[n:]
		if uint64(len(data)) < length {
			t.Fatalf("transport parameter %#x length %d exceeds remaining %d", id, length, len(data))
		}
		if _, ok := params[id]; ok {
			t.Fatalf("duplicate transport parameter %#x", id)
		}
		params[id] = append([]byte(nil), data[:length]...)
		data = data[length:]
	}
	return params
}

func transportParameterVarint(t *testing.T, params map[uint64][]byte, id uint64) uint64 {
	t.Helper()
	value, ok := params[id]
	if !ok {
		t.Fatalf("transport parameter %#x missing", id)
	}
	got, n, err := quicvarint.Parse(value)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(value) {
		t.Fatalf("transport parameter %#x has trailing bytes", id)
	}
	return got
}

func TestChromeTransportParameters(t *testing.T) {
	tp := &wire.TransportParameters{}
	applyChromeTransportParameters(tp, protocol.Version1)
	params := parseTransportParameters(t, tp.Marshal(protocol.PerspectiveClient))

	wantVarints := map[uint64]uint64{
		0x1:  30000,
		0x3:  1472,
		0x4:  15728640,
		0x5:  6291456,
		0x6:  6291456,
		0x7:  6291456,
		0x8:  100,
		0x9:  103,
		0x20: 65536,
	}
	for id, want := range wantVarints {
		if got := transportParameterVarint(t, params, id); got != want {
			t.Errorf("transport parameter %#x = %d, want %d", id, got, want)
		}
	}
	if _, ok := params[0xb]; ok {
		t.Error("max_ack_delay (0xb) must be omitted")
	}
	if _, ok := params[0xe]; ok {
		t.Error("active_connection_id_limit (0xe) must be omitted")
	}
	wantVersionInfo := make([]byte, 0, 8)
	wantVersionInfo = binary.BigEndian.AppendUint32(wantVersionInfo, uint32(protocol.Version1))
	wantVersionInfo = binary.BigEndian.AppendUint32(wantVersionInfo, uint32(protocol.Version1))
	if !bytes.Equal(params[0x11], wantVersionInfo) {
		t.Errorf("version_information = %x, want %x", params[0x11], wantVersionInfo)
	}
	if !bytes.Equal(params[0x3128], []byte("ORIG")) {
		t.Errorf("google_connection_options = %q, want ORIG", params[0x3128])
	}
	if tp.MaxIdleTimeout != 30*time.Second {
		t.Errorf("MaxIdleTimeout = %s, want 30s", tp.MaxIdleTimeout)
	}
}
