package quic

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/apernet/quic-go/internal/protocol"
)

func TestM2ChromeInitialHeadTailAcrossClientHelloLengths(t *testing.T) {
	const samples = 1000
	layouts := make(map[string]struct{}, samples)

	for i := range samples {
		size := 1500 + i
		clientHello := newChromeTestClientHello(size)
		stream := newInitialCryptoStream(true, true)
		if _, err := stream.Write(clientHello); err != nil {
			t.Fatalf("sample %d: Write: %v", i, err)
		}
		stream.prepareChromeChunks(1215)

		chunks := stream.chromeChunks
		if len(chunks) < 3 {
			t.Fatalf("sample %d: got %d chunks, want head + tail + middle", i, len(chunks))
		}
		head, tail := chunks[0], chunks[1]
		if head.start != 0 || head.end < 55 || head.end > 86 {
			t.Fatalf("sample %d: head = [%d,%d), want [0,55..86)", i, head.start, head.end)
		}
		if tail.end != protocol.ByteCount(size) || tail.start <= head.end {
			t.Fatalf("sample %d: head/tail = [%d,%d) + [%d,%d), want a middle gap and tail ending at %d", i, head.start, head.end, tail.start, tail.end, size)
		}

		next := head.end
		for chunkIndex, middle := range chunks[2:] {
			if middle.start != next || middle.end <= middle.start || middle.end > tail.start {
				t.Fatalf("sample %d: middle chunk %d = [%d,%d), want contiguous coverage from %d to %d", i, chunkIndex, middle.start, middle.end, next, tail.start)
			}
			next = middle.end
		}
		if next != tail.start {
			t.Fatalf("sample %d: middle coverage ends at %d, want %d", i, next, tail.start)
		}

		reconstructed := make([]byte, size)
		for stream.HasData() {
			frame := stream.PopCryptoFrame(4096)
			if frame == nil {
				t.Fatalf("sample %d: prepared CRYPTO frame did not fit", i)
			}
			copy(reconstructed[frame.Offset:], frame.Data)
		}
		if !bytes.Equal(reconstructed, clientHello) {
			t.Fatalf("sample %d: reconstructed ClientHello differs", i)
		}
		layouts[fmt.Sprintf("%d/%d/%d", size, head.end, tail.start)] = struct{}{}
	}

	if len(layouts) < samples/2 {
		t.Fatalf("layout diversity = %d/%d, want at least %d", len(layouts), samples, samples/2)
	}
}
