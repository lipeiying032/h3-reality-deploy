package quic

import (
	"bytes"
	"fmt"
	"math/rand/v2"
	"testing"

	"github.com/apernet/quic-go/internal/ackhandler"
	"github.com/apernet/quic-go/internal/handshake"
	"github.com/apernet/quic-go/internal/monotime"
	"github.com/apernet/quic-go/internal/protocol"
	"github.com/apernet/quic-go/internal/utils"
	"github.com/apernet/quic-go/internal/wire"
	"github.com/apernet/quic-go/quicvarint"
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

func parseChromeTestPayload(payload []byte) (int, []int, error) {
	var pings int
	var paddingRuns []int
	for len(payload) > 0 {
		switch payload[0] {
		case 0: // PADDING
			var run int
			for run < len(payload) && payload[run] == 0 {
				run++
			}
			paddingRuns = append(paddingRuns, run)
			payload = payload[run:]
		case 1: // PING
			pings++
			payload = payload[1:]
		case 6: // CRYPTO
			payload = payload[1:]
			_, n, err := quicvarint.Parse(payload)
			if err != nil {
				return 0, nil, err
			}
			payload = payload[n:]
			dataLen, n, err := quicvarint.Parse(payload)
			if err != nil {
				return 0, nil, err
			}
			payload = payload[n:]
			if dataLen > uint64(len(payload)) {
				return 0, nil, fmt.Errorf("CRYPTO length %d exceeds %d-byte payload", dataLen, len(payload))
			}
			payload = payload[dataLen:]
		default:
			return 0, nil, fmt.Errorf("unexpected frame type %#x", payload[0])
		}
	}
	return pings, paddingRuns, nil
}

func TestChromeInitialInterleavesPingAndPadding(t *testing.T) {
	crypto1 := &wire.CryptoFrame{Offset: 929, Data: []byte{2, 3}}
	crypto2 := &wire.CryptoFrame{Offset: 1534, Data: []byte{4, 5}}
	pl := payload{
		frames: []ackhandler.Frame{
			{Frame: crypto1},
			{Frame: &wire.PingFrame{}},
			{Frame: &wire.PingFrame{}},
			{Frame: crypto2},
			{Frame: &wire.PingFrame{}},
		},
		length:             crypto1.Length(protocol.Version1) + crypto2.Length(protocol.Version1) + 3,
		preserveFrameOrder: true,
		paddingRuns:        5,
	}
	packer := &packetPacker{rand: *rand.New(rand.NewPCG(1, 2))}
	layouts := make(map[string]struct{})
	for range 20 {
		raw, err := packer.appendPacketPayload(nil, pl, 97, protocol.Version1)
		if err != nil {
			t.Fatal(err)
		}
		if len(raw) != int(pl.length)+97 {
			t.Fatalf("payload length = %d, want %d", len(raw), int(pl.length)+97)
		}
		pings, runs, err := parseChromeTestPayload(raw)
		if err != nil {
			t.Fatal(err)
		}
		if pings != 3 {
			t.Fatalf("PING count = %d, want 3", pings)
		}
		if len(runs) != 5 {
			t.Fatalf("PADDING run count = %d, want 5", len(runs))
		}
		var total, minRun, maxRun int
		minRun = runs[0]
		for _, run := range runs {
			total += run
			minRun = min(minRun, run)
			maxRun = max(maxRun, run)
		}
		if total != 97 {
			t.Fatalf("PADDING total = %d, want 97", total)
		}
		if maxRun-minRun < 10 {
			t.Errorf("PADDING lengths are too uniform: %v", runs)
		}
		layouts[fmt.Sprint(runs)] = struct{}{}
	}
	if len(layouts) < 10 {
		t.Errorf("only %d/20 PADDING length layouts were distinct", len(layouts))
	}
}

func TestChromeInitialPacketNumberStartsAtOne(t *testing.T) {
	initialPN := clientInitialPacketNumber(&Config{ChromeTransportParameters: true})
	if initialPN != 1 {
		t.Fatalf("Chrome Initial packet number = %d, want 1", initialPN)
	}
	if pn := clientInitialPacketNumber(&Config{}); pn != 0 {
		t.Fatalf("default Initial packet number = %d, want 0", pn)
	}

	handler := ackhandler.NewSentPacketHandler(
		initialPN,
		1250,
		utils.NewRTTStats(),
		&utils.ConnectionStats{},
		false,
		false,
		func(protocol.PacketNumber) {},
		protocol.PerspectiveClient,
		nil,
		utils.DefaultLogger,
	)
	for want := protocol.PacketNumber(1); want <= 3; want++ {
		peeked, pnLen := handler.PeekPacketNumber(protocol.EncryptionInitial)
		if peeked != want {
			t.Fatalf("peeked Initial packet number = %d, want %d", peeked, want)
		}
		wantLen := protocol.PacketNumberLen2
		if want == 1 {
			wantLen = protocol.PacketNumberLen1
		}
		if pnLen != wantLen {
			t.Errorf("Initial packet number %d uses %d bytes, want %d", want, pnLen, wantLen)
		}
		if popped := handler.PopPacketNumber(protocol.EncryptionInitial); popped != want {
			t.Fatalf("popped Initial packet number = %d, want %d", popped, want)
		}
	}
	for _, level := range []protocol.EncryptionLevel{protocol.EncryptionHandshake, protocol.Encryption1RTT} {
		if pn, _ := handler.PeekPacketNumber(level); pn != 0 {
			t.Errorf("%s packet number = %d, want 0", level, pn)
		}
	}
}

func TestChromeInitialPacketPackerSizeAndFrames(t *testing.T) {
	const connections = 100
	clientHello := newChromeTestClientHello(1700)
	pingTotals := make(map[int]struct{})
	paddingRunTotals := make(map[int]struct{})
	layouts := make(map[string]struct{})

	for conn := range connections {
		packetSize := protocol.ByteCount(1250)
		if conn%2 == 1 {
			packetSize = 1230
		}
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
		var packets, cryptoFrames, totalPings, totalPaddingRuns int
		var pingsPerPacket, runsPerPacket []int
		var runLengths []int
		for stream.HasData() {
			packet, err := packer.PackCoalescedPacket(false, packetSize, monotime.Now(), protocol.Version1)
			if err != nil {
				t.Fatal(err)
			}
			if packet == nil {
				t.Fatal("no Initial packet packed")
			}
			if len(packet.buffer.Data) != int(packetSize) {
				t.Errorf("Initial UDP payload = %d, want %d", len(packet.buffer.Data), packetSize)
			}
			if len(packet.longHdrPackets) != 1 {
				t.Fatalf("long header packet count = %d, want 1", len(packet.longHdrPackets))
			}
			longPacket := packet.longHdrPackets[0]
			for _, frame := range longPacket.frames {
				if cryptoFrame, ok := frame.Frame.(*wire.CryptoFrame); ok {
					copy(reconstructed[cryptoFrame.Offset:], cryptoFrame.Data)
					cryptoFrames++
				}
			}

			headerLen := int(longPacket.header.GetLength(protocol.Version1))
			payload := packet.buffer.Data[headerLen : len(packet.buffer.Data)-chromeTestSealer{}.Overhead()]
			pings, runs, err := parseChromeTestPayload(payload)
			if err != nil {
				t.Fatal(err)
			}
			if pings == 0 {
				t.Error("Initial packet contains no PING")
			}
			if len(runs) == 0 {
				t.Error("Initial packet contains no PADDING run")
			}
			totalPings += pings
			totalPaddingRuns += len(runs)
			pingsPerPacket = append(pingsPerPacket, pings)
			runsPerPacket = append(runsPerPacket, len(runs))
			runLengths = append(runLengths, runs...)
			packet.buffer.Release()
			packets++
		}
		if packets < 2 || packets > 3 {
			t.Errorf("Initial packet count = %d, want 2 or 3", packets)
		}
		if cryptoFrames < chromeMinCryptoChunks || cryptoFrames > chromeMaxCryptoChunks {
			t.Errorf("CRYPTO frame count = %d, want %d..%d", cryptoFrames, chromeMinCryptoChunks, chromeMaxCryptoChunks)
		}
		if totalPings < chromeMinInitialPings || totalPings > chromeMaxInitialPings {
			t.Errorf("PING total = %d, want %d..%d", totalPings, chromeMinInitialPings, chromeMaxInitialPings)
		}
		if totalPaddingRuns < chromeMinInitialPaddingRuns || totalPaddingRuns > chromeMaxInitialPaddingRuns {
			t.Errorf("PADDING run total = %d, want %d..%d", totalPaddingRuns, chromeMinInitialPaddingRuns, chromeMaxInitialPaddingRuns)
		}
		if !bytes.Equal(reconstructed, clientHello) {
			t.Error("packed CRYPTO frames did not reconstruct the ClientHello")
		}
		minRun, maxRun := runLengths[0], runLengths[0]
		for _, run := range runLengths[1:] {
			minRun = min(minRun, run)
			maxRun = max(maxRun, run)
		}
		if maxRun-minRun < 10 {
			t.Errorf("PADDING runs are too uniform: %v", runLengths)
		}
		pingTotals[totalPings] = struct{}{}
		paddingRunTotals[totalPaddingRuns] = struct{}{}
		layouts[fmt.Sprintf("%v/%v/%v", pingsPerPacket, runsPerPacket, runLengths)] = struct{}{}
	}
	if len(pingTotals) < 6 {
		t.Errorf("only %d PING totals observed across %d connections", len(pingTotals), connections)
	}
	if len(paddingRunTotals) < 4 {
		t.Errorf("only %d PADDING run totals observed across %d connections", len(paddingRunTotals), connections)
	}
	if len(layouts) < connections/2 {
		t.Errorf("only %d/%d PING/PADDING layouts were distinct", len(layouts), connections)
	}
}
