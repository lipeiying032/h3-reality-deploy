package quic

import (
	"bytes"
	"fmt"
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

func newChromeTestClientHello(size int) []byte {
	clientHello := make([]byte, size)
	clientHello[0] = 1
	bodyLen := len(clientHello) - 4
	clientHello[1] = byte(bodyLen >> 16)
	clientHello[2] = byte(bodyLen >> 8)
	clientHello[3] = byte(bodyLen)
	for i := 4; i < len(clientHello); i++ {
		clientHello[i] = byte(i%251 + 1)
	}
	return clientHello
}

func TestChromeInitialCryptoFramesRandomizeAndReassemble(t *testing.T) {
	const connections = 100
	clientHello := newChromeTestClientHello(1700)
	sequences := make(map[string]struct{}, connections)
	packetDistributions := make(map[string]struct{})
	var totalChunks, twoPacketFlights int

	for conn := range connections {
		stream := newInitialCryptoStream(true, true)
		splitAt := 500 + conn%900
		if _, err := stream.Write(clientHello[:splitAt]); err != nil {
			t.Fatal(err)
		}
		if stream.HasData() {
			t.Fatal("partial ClientHello became writable")
		}
		if _, err := stream.Write(clientHello[splitAt:]); err != nil {
			t.Fatal(err)
		}

		var offsets []protocol.ByteCount
		var lengths, framesPerPacket []int
		reconstructed := make([]byte, len(clientHello))
		for stream.HasData() {
			remaining := protocol.ByteCount(1180)
			var packetFrames int
			for stream.HasData() {
				frame := stream.PopCryptoFrame(remaining - 1) // reserve PING
				if frame == nil {
					break
				}
				offsets = append(offsets, frame.Offset)
				lengths = append(lengths, len(frame.Data))
				copy(reconstructed[frame.Offset:], frame.Data)
				remaining -= frame.Length(protocol.Version1) + 1
				packetFrames++
			}
			if packetFrames == 0 {
				t.Fatal("no randomized CRYPTO frame fit in an empty Initial packet")
			}
			framesPerPacket = append(framesPerPacket, packetFrames)
		}

		if count := len(offsets); count < chromeMinCryptoChunks || count > chromeMaxCryptoChunks {
			t.Fatalf("CRYPTO frame count = %d, want %d..%d", count, chromeMinCryptoChunks, chromeMaxCryptoChunks)
		}
		if !bytes.Equal(reconstructed, clientHello) {
			t.Fatal("randomized CRYPTO frames did not reconstruct the ClientHello")
		}
		if len(framesPerPacket) < 2 || len(framesPerPacket) > 3 {
			t.Fatalf("Initial packet count = %d, want 2 or 3", len(framesPerPacket))
		}
		if len(framesPerPacket) == 2 {
			twoPacketFlights++
		}
		totalChunks += len(offsets)
		sequences[fmt.Sprintf("%v/%v", offsets, lengths)] = struct{}{}
		packetDistributions[fmt.Sprint(framesPerPacket)] = struct{}{}
	}

	mean := float64(totalChunks) / connections
	if mean < 12.5 || mean > 15.5 {
		t.Errorf("mean CRYPTO frame count = %.2f, want approximately 14", mean)
	}
	if len(sequences) < connections/2 {
		t.Errorf("only %d/%d randomized CRYPTO sequences were distinct", len(sequences), connections)
	}
	if len(packetDistributions) < 2 {
		t.Errorf("CRYPTO packet distribution did not vary: %v", packetDistributions)
	}
	if twoPacketFlights < 95 {
		t.Errorf("only %d/%d first flights used two Initial packets", twoPacketFlights, connections)
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
	clientHello := newChromeTestClientHello(1700)
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
	reconstructed := make([]byte, len(clientHello))
	var packets, cryptoFrames int
	for stream.HasData() {
		packet, err := packer.PackCoalescedPacket(false, 1250, monotime.Now(), protocol.Version1)
		if err != nil {
			t.Fatal(err)
		}
		if packet == nil {
			t.Fatal("no Initial packet packed")
		}
		if len(packet.buffer.Data) != 1250 {
			t.Errorf("IPv4 Initial UDP payload = %d, want 1250", len(packet.buffer.Data))
		}
		if len(packet.longHdrPackets) != 1 {
			t.Fatalf("long header packet count = %d, want 1", len(packet.longHdrPackets))
		}
		for i, frame := range packet.longHdrPackets[0].frames {
			if i%2 == 0 {
				cryptoFrame, ok := frame.Frame.(*wire.CryptoFrame)
				if !ok {
					t.Fatalf("frame %d = %T, want CRYPTO", i, frame.Frame)
				}
				copy(reconstructed[cryptoFrame.Offset:], cryptoFrame.Data)
				cryptoFrames++
			} else if _, ok := frame.Frame.(*wire.PingFrame); !ok {
				t.Fatalf("frame %d = %T, want PING", i, frame.Frame)
			}
		}
		packet.buffer.Release()
		packets++
	}
	if packets < 2 || packets > 3 {
		t.Errorf("Initial packet count = %d, want 2 or 3", packets)
	}
	if cryptoFrames < chromeMinCryptoChunks || cryptoFrames > chromeMaxCryptoChunks {
		t.Errorf("CRYPTO frame count = %d, want %d..%d", cryptoFrames, chromeMinCryptoChunks, chromeMaxCryptoChunks)
	}
	if !bytes.Equal(reconstructed, clientHello) {
		t.Error("packed CRYPTO frames did not reconstruct the ClientHello")
	}
}
