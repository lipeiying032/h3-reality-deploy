package quic

import (
	"bytes"
	"slices"
	"testing"

	"github.com/apernet/quic-go/internal/ackhandler"
	"github.com/apernet/quic-go/internal/handshake"
	"github.com/apernet/quic-go/internal/monotime"
	"github.com/apernet/quic-go/internal/protocol"
	"github.com/apernet/quic-go/internal/wire"
)

type chromeTestSealer struct{}

func (chromeTestSealer) Seal(dst, src []byte, _ protocol.PacketNumber, _ []byte) []byte {
	dst = append(dst, src...)
	return append(dst, make([]byte, 16)...)
}
func (chromeTestSealer) EncryptHeader([]byte, *byte, []byte) {}
func (chromeTestSealer) Overhead() int                       { return 16 }

type chromeTestSealingManager struct{}

func (chromeTestSealingManager) GetInitialSealer() (handshake.LongHeaderSealer, error) {
	return chromeTestSealer{}, nil
}
func (chromeTestSealingManager) GetHandshakeSealer() (handshake.LongHeaderSealer, error) {
	return nil, handshake.ErrKeysNotYetAvailable
}
func (chromeTestSealingManager) Get0RTTSealer() (handshake.LongHeaderSealer, error) {
	return nil, handshake.ErrKeysNotYetAvailable
}
func (chromeTestSealingManager) Get1RTTSealer() (handshake.ShortHeaderSealer, error) {
	return nil, handshake.ErrKeysNotYetAvailable
}

type chromeTestPacketNumberManager struct{ next protocol.PacketNumber }

func (m *chromeTestPacketNumberManager) PeekPacketNumber(protocol.EncryptionLevel) (protocol.PacketNumber, protocol.PacketNumberLen) {
	return m.next, protocol.PacketNumberLen2
}
func (m *chromeTestPacketNumberManager) PopPacketNumber(protocol.EncryptionLevel) protocol.PacketNumber {
	pn := m.next
	m.next++
	return pn
}

type chromeTestAckSource struct{}

func (chromeTestAckSource) GetAckFrame(protocol.EncryptionLevel, monotime.Time, bool) *wire.AckFrame {
	return nil
}

func TestChromeInitialCryptoFrameOrder(t *testing.T) {
	clientHello := make([]byte, 1700)
	clientHello[0] = 1
	bodyLen := len(clientHello) - 4
	clientHello[1] = byte(bodyLen >> 16)
	clientHello[2] = byte(bodyLen >> 8)
	clientHello[3] = byte(bodyLen)
	for i := 4; i < len(clientHello); i++ {
		clientHello[i] = byte(i%251 + 1)
	}

	stream := newInitialCryptoStream(true, true)
	if _, err := stream.Write(clientHello[:800]); err != nil {
		t.Fatal(err)
	}
	if stream.HasData() {
		t.Fatal("partial ClientHello became writable")
	}
	if _, err := stream.Write(clientHello[800:]); err != nil {
		t.Fatal(err)
	}

	var offsets []protocol.ByteCount
	reconstructed := make([]byte, len(clientHello))
	packetBudget := protocol.ByteCount(1180)
	remaining := packetBudget
	packets := 1
	for stream.HasData() {
		frame := stream.PopCryptoFrame(remaining - 1) // reserve PING
		if frame == nil {
			packets++
			remaining = packetBudget
			continue
		}
		offsets = append(offsets, frame.Offset)
		copy(reconstructed[frame.Offset:], frame.Data)
		remaining -= frame.Length(protocol.Version1) + 1
	}
	wantOffsets := []protocol.ByteCount{929, 1534, 75, 1527, 1054, 0, 1335}
	if !slices.Equal(offsets, wantOffsets) {
		t.Errorf("CRYPTO offsets = %v, want %v", offsets, wantOffsets)
	}
	if !bytes.Equal(reconstructed, clientHello) {
		t.Error("scrambled CRYPTO frames did not reconstruct the ClientHello")
	}
	if packets < 2 {
		t.Error("test ClientHello unexpectedly fit in one Initial packet")
	}
}

func TestChromeInitialInterleavesPingAndPadding(t *testing.T) {
	crypto1 := &wire.CryptoFrame{Offset: 929, Data: []byte{1, 2}}
	crypto2 := &wire.CryptoFrame{Offset: 1534, Data: []byte{3, 4}}
	ping := &wire.PingFrame{}
	pl := payload{
		frames: []ackhandler.Frame{
			{Frame: crypto1},
			{Frame: ping},
			{Frame: crypto2},
		},
		length:             crypto1.Length(protocol.Version1) + ping.Length(protocol.Version1) + crypto2.Length(protocol.Version1),
		preserveFrameOrder: true,
		interleavePadding:  true,
	}
	packer := &packetPacker{}
	raw, err := packer.appendPacketPayload(nil, pl, 8, protocol.Version1)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != int(pl.length)+8 {
		t.Fatalf("payload length = %d, want %d", len(raw), int(pl.length)+8)
	}
	// Eight PADDING bytes are split across the four gaps around three frames.
	if !bytes.Equal(raw[:2], []byte{0, 0}) {
		t.Errorf("leading PADDING = %x, want 0000", raw[:2])
	}
	firstLen := int(crypto1.Length(protocol.Version1))
	if !bytes.Equal(raw[2+firstLen:2+firstLen+2], []byte{0, 0}) {
		t.Error("PADDING was not inserted between the first CRYPTO and PING frames")
	}
}

func TestChromeInitialPacketPackerSizeAndFrames(t *testing.T) {
	clientHello := make([]byte, 1700)
	clientHello[0] = 1
	bodyLen := len(clientHello) - 4
	clientHello[1] = byte(bodyLen >> 16)
	clientHello[2] = byte(bodyLen >> 8)
	clientHello[3] = byte(bodyLen)
	stream := newInitialCryptoStream(true, true)
	if _, err := stream.Write(clientHello); err != nil {
		t.Fatal(err)
	}
	dest, err := protocol.GenerateConnectionID(8)
	if err != nil {
		t.Fatal(err)
	}
	packer := newPacketPacker(
		protocol.ConnectionID{},
		func() protocol.ConnectionID { return dest },
		stream,
		newCryptoStream(),
		&chromeTestPacketNumberManager{},
		newRetransmissionQueue(),
		chromeTestSealingManager{},
		nil,
		chromeTestAckSource{},
		nil,
		protocol.PerspectiveClient,
	)
	packet, err := packer.PackCoalescedPacket(false, 1250, monotime.Now(), protocol.Version1)
	if err != nil {
		t.Fatal(err)
	}
	if packet == nil {
		t.Fatal("no Initial packet packed")
	}
	defer packet.buffer.Release()
	if len(packet.buffer.Data) != 1250 {
		t.Errorf("IPv4 Initial UDP payload = %d, want 1250", len(packet.buffer.Data))
	}
	if len(packet.longHdrPackets) != 1 {
		t.Fatalf("long header packet count = %d, want 1", len(packet.longHdrPackets))
	}
	var offsets []protocol.ByteCount
	for i, frame := range packet.longHdrPackets[0].frames {
		if i%2 == 0 {
			cryptoFrame, ok := frame.Frame.(*wire.CryptoFrame)
			if !ok {
				t.Fatalf("frame %d = %T, want CRYPTO", i, frame.Frame)
			}
			offsets = append(offsets, cryptoFrame.Offset)
		} else if _, ok := frame.Frame.(*wire.PingFrame); !ok {
			t.Fatalf("frame %d = %T, want PING", i, frame.Frame)
		}
	}
	if want := []protocol.ByteCount{929, 1534, 75, 1527}; !slices.Equal(offsets, want) {
		t.Errorf("first Initial CRYPTO offsets = %v, want %v", offsets, want)
	}
}
