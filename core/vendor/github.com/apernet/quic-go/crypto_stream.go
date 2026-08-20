package quic

import (
	crand "crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"os"
	"slices"
	"strconv"

	"github.com/apernet/quic-go/internal/protocol"
	"github.com/apernet/quic-go/internal/qerr"
	"github.com/apernet/quic-go/internal/wire"
)

const disableClientHelloScramblingEnv = "QUIC_GO_DISABLE_CLIENTHELLO_SCRAMBLING"

const (
	chromeMinCryptoChunks = 9
	chromeMaxCryptoChunks = 19
)

// The baseCryptoStream is used by the cryptoStream and the initialCryptoStream.
// This allows us to implement different logic for PopCryptoFrame for the two streams.
type baseCryptoStream struct {
	queue frameSorter

	highestOffset protocol.ByteCount
	finished      bool

	writeOffset protocol.ByteCount
	writeBuf    []byte
}

func newCryptoStream() *cryptoStream {
	return &cryptoStream{baseCryptoStream{queue: *newFrameSorter()}}
}

func (s *baseCryptoStream) HandleCryptoFrame(f *wire.CryptoFrame) error {
	highestOffset := f.Offset + protocol.ByteCount(len(f.Data))
	if maxOffset := highestOffset; maxOffset > protocol.MaxCryptoStreamOffset {
		return &qerr.TransportError{
			ErrorCode:    qerr.CryptoBufferExceeded,
			ErrorMessage: fmt.Sprintf("received invalid offset %d on crypto stream, maximum allowed %d", maxOffset, protocol.MaxCryptoStreamOffset),
		}
	}
	if s.finished {
		if highestOffset > s.highestOffset {
			// reject crypto data received after this stream was already finished
			return &qerr.TransportError{
				ErrorCode:    qerr.ProtocolViolation,
				ErrorMessage: "received crypto data after change of encryption level",
			}
		}
		// ignore data with a smaller offset than the highest received
		// could e.g. be a retransmission
		return nil
	}
	s.highestOffset = max(s.highestOffset, highestOffset)
	return s.queue.Push(f.Data, f.Offset, nil)
}

// GetCryptoData retrieves data that was received in CRYPTO frames
func (s *baseCryptoStream) GetCryptoData() []byte {
	_, data, _ := s.queue.Pop()
	return data
}

func (s *baseCryptoStream) Finish() error {
	if s.queue.HasMoreData() {
		return &qerr.TransportError{
			ErrorCode:    qerr.ProtocolViolation,
			ErrorMessage: "encryption level changed, but crypto stream has more data to read",
		}
	}
	s.finished = true
	return nil
}

// Writes writes data that should be sent out in CRYPTO frames
func (s *baseCryptoStream) Write(p []byte) (int, error) {
	s.writeBuf = append(s.writeBuf, p...)
	return len(p), nil
}

func (s *baseCryptoStream) HasData() bool {
	return len(s.writeBuf) > 0
}

func (s *baseCryptoStream) PopCryptoFrame(maxLen protocol.ByteCount) *wire.CryptoFrame {
	f := &wire.CryptoFrame{Offset: s.writeOffset}
	n := min(f.MaxDataLen(maxLen), protocol.ByteCount(len(s.writeBuf)))
	if n <= 0 {
		return nil
	}
	f.Data = s.writeBuf[:n]
	s.writeBuf = s.writeBuf[n:]
	s.writeOffset += n
	return f
}

type cryptoStream struct {
	baseCryptoStream
}

type clientHelloCut struct {
	start protocol.ByteCount
	end   protocol.ByteCount
}

type initialCryptoStream struct {
	baseCryptoStream

	scramble        bool
	chrome          bool
	chromeDone      bool
	chromeChunks    []clientHelloCut
	chromeChunkNext int
	chromeRand      *rand.Rand
	end             protocol.ByteCount
	cuts            [2]clientHelloCut
}

func newInitialCryptoStream(isClient, chrome bool) *initialCryptoStream {
	var scramble bool
	var chromeRand *rand.Rand
	if isClient && !chrome {
		disabled, err := strconv.ParseBool(os.Getenv(disableClientHelloScramblingEnv))
		scramble = err != nil || !disabled
	} else if isClient && chrome {
		var seed [32]byte
		_, _ = crand.Read(seed[:])
		chromeRand = rand.New(rand.NewChaCha8(seed))
	}
	s := &initialCryptoStream{
		baseCryptoStream: baseCryptoStream{queue: *newFrameSorter()},
		scramble:         scramble,
		chrome:           isClient && chrome,
		chromeRand:       chromeRand,
		end:              protocol.InvalidByteCount,
	}
	for i := range len(s.cuts) {
		s.cuts[i].start = protocol.InvalidByteCount
		s.cuts[i].end = protocol.InvalidByteCount
	}
	return s
}

func (s *initialCryptoStream) HasData() bool {
	if s.chrome && !s.chromeDone {
		return len(s.chromeChunks) > 0 && s.chromeChunkNext < len(s.chromeChunks)
	}
	// The ClientHello might be written in multiple parts.
	// In order to correctly split the ClientHello, we need the entire ClientHello has been queued.
	if s.scramble && s.writeOffset == 0 && s.cuts[0].start == protocol.InvalidByteCount {
		return false
	}
	return s.baseCryptoStream.HasData()
}

func (s *initialCryptoStream) Write(p []byte) (int, error) {
	s.writeBuf = append(s.writeBuf, p...)
	if s.chrome && !s.chromeDone {
		if len(s.chromeChunks) > 0 || len(s.writeBuf) < 4 {
			return len(p), nil
		}
		if s.writeBuf[0] != 1 {
			return len(p), errors.New("expected a TLS ClientHello on the Initial crypto stream")
		}
		clientHelloLen := 4 + (int(s.writeBuf[1]) << 16) + (int(s.writeBuf[2]) << 8) + int(s.writeBuf[3])
		if len(s.writeBuf) < clientHelloLen {
			return len(p), nil
		}
		s.end = protocol.ByteCount(clientHelloLen)
		s.prepareChromeChunks()
		return len(p), nil
	}
	if !s.scramble {
		return len(p), nil
	}
	if s.cuts[0].start == protocol.InvalidByteCount {
		sniPos, sniLen, echPos, err := findSNIAndECH(s.writeBuf)
		if errors.Is(err, io.ErrUnexpectedEOF) {
			return len(p), nil
		}
		if err != nil {
			return len(p), err
		}
		if sniPos == -1 && echPos == -1 {
			// Neither SNI nor ECH found.
			// There's nothing to scramble.
			s.scramble = false
			return len(p), nil
		}
		s.end = protocol.ByteCount(len(s.writeBuf))
		s.cuts[0].start = protocol.ByteCount(sniPos + sniLen/2) // right in the middle
		s.cuts[0].end = protocol.ByteCount(sniPos + sniLen)
		if echPos > 0 {
			// ECH extension found, cut the ECH extension type value (a uint16) in half
			start := protocol.ByteCount(echPos + 1)
			s.cuts[1].start = start
			// cut somewhere (16 bytes), most likely in the ECH extension value
			s.cuts[1].end = min(start+16, s.end)
		}
		slices.SortFunc(s.cuts[:], func(a, b clientHelloCut) int {
			if a.start == protocol.InvalidByteCount {
				return 1
			}
			if a.start > b.start {
				return 1
			}
			return -1
		})
	}
	return len(p), nil
}

func (s *initialCryptoStream) PopCryptoFrame(maxLen protocol.ByteCount) *wire.CryptoFrame {
	if s.chrome && !s.chromeDone {
		if s.chromeChunkNext >= len(s.chromeChunks) {
			s.finishChromeChunks()
			return s.baseCryptoStream.PopCryptoFrame(maxLen)
		}
		chunk := &s.chromeChunks[s.chromeChunkNext]
		f := &wire.CryptoFrame{Offset: chunk.start, Data: s.writeBuf[chunk.start:chunk.end]}
		// Keep Chrome's observed boundaries intact. Every configured chunk is
		// smaller than a full Initial payload; if it doesn't fit in the current
		// packet, let the packer start a new packet instead of splitting it.
		if f.Length(protocol.Version1) > maxLen {
			return nil
		}
		s.chromeChunkNext++
		if s.chromeChunkNext == len(s.chromeChunks) {
			s.finishChromeChunks()
		}
		return f
	}
	if !s.scramble {
		return s.baseCryptoStream.PopCryptoFrame(maxLen)
	}

	// send out the skipped parts
	if s.writeOffset == s.end {
		var foundCuts bool
		var f *wire.CryptoFrame
		for i, c := range s.cuts {
			if c.start == protocol.InvalidByteCount {
				continue
			}
			foundCuts = true
			if f != nil {
				break
			}
			f = &wire.CryptoFrame{Offset: c.start}
			n := min(f.MaxDataLen(maxLen), c.end-c.start)
			if n <= 0 {
				return nil
			}
			f.Data = s.writeBuf[c.start : c.start+n]
			s.cuts[i].start += n
			if s.cuts[i].start == c.end {
				s.cuts[i].start = protocol.InvalidByteCount
				s.cuts[i].end = protocol.InvalidByteCount
				foundCuts = false
			}
		}
		if !foundCuts {
			// no more cuts found, we're done sending out everything up until s.end
			s.writeBuf = s.writeBuf[s.end:]
			s.end = protocol.InvalidByteCount
			s.scramble = false
		}
		return f
	}

	nextCut := clientHelloCut{start: protocol.InvalidByteCount, end: protocol.InvalidByteCount}
	for _, c := range s.cuts {
		if c.start == protocol.InvalidByteCount {
			continue
		}
		if c.start > s.writeOffset {
			nextCut = c
			break
		}
	}
	f := &wire.CryptoFrame{Offset: s.writeOffset}
	maxOffset := nextCut.start
	if maxOffset == protocol.InvalidByteCount {
		maxOffset = s.end
	}
	n := min(f.MaxDataLen(maxLen), maxOffset-s.writeOffset)
	if n <= 0 {
		return nil
	}
	f.Data = s.writeBuf[s.writeOffset : s.writeOffset+n]
	// Don't reslice the writeBuf yet.
	// This is done once all parts have been sent out.
	s.writeOffset += n
	if s.writeOffset == nextCut.start {
		s.writeOffset = nextCut.end
	}

	return f
}

func (s *initialCryptoStream) finishChromeChunks() {
	s.writeBuf = s.writeBuf[s.end:]
	s.writeOffset = s.end
	s.end = protocol.InvalidByteCount
	s.chromeDone = true
}

func (s *initialCryptoStream) prepareChromeChunks() {
	numChunks := chromeMinCryptoChunks + s.chromeRand.IntN(chromeMaxCryptoChunks-chromeMinCryptoChunks+1)
	// A real ClientHello is much larger than the observed chunk count. Keep the
	// fallback well-defined for synthetic or malformed tiny handshakes as well.
	if end := int(s.end); numChunks > end {
		numChunks = end
	}

	// Allocate the contiguous ClientHello ranges using bounded random weights.
	// Bounding the weights keeps every range small enough that the first flight
	// normally occupies two Initial packets, without producing equal-sized cuts.
	weights := make([]int, numChunks)
	var totalWeight int
	for i := range weights {
		weights[i] = 50 + s.chromeRand.IntN(101)
		totalWeight += weights[i]
	}

	remaining := int(s.end)
	remainingWeight := totalWeight
	start := protocol.ByteCount(0)
	for i, weight := range weights {
		chunksAfter := numChunks - i - 1
		chunkLen := remaining
		if chunksAfter > 0 {
			chunkLen = remaining * weight / remainingWeight
			chunkLen = max(1, min(chunkLen, remaining-chunksAfter))
		}
		end := start + protocol.ByteCount(chunkLen)
		s.chromeChunks = append(s.chromeChunks, clientHelloCut{start: start, end: end})
		start = end
		remaining -= chunkLen
		remainingWeight -= weight
	}
	s.chromeRand.Shuffle(len(s.chromeChunks), func(i, j int) {
		s.chromeChunks[i], s.chromeChunks[j] = s.chromeChunks[j], s.chromeChunks[i]
	})
}
