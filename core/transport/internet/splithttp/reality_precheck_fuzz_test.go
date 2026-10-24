package splithttp

import "testing"

func FuzzParseQUICInitial(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0xc0, 0, 0, 0, 1, 0, 0})
	f.Fuzz(func(t *testing.T, data []byte) {
		work := append([]byte(nil), data...)
		_, _ = parseQUICInitial(work)
	})
}

func FuzzParseCryptoFrames(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0, 1, 0x06, 0, 1, 0xaa})
	f.Fuzz(func(t *testing.T, data []byte) {
		frags, err := parseCryptoFrames(data)
		if err != nil {
			return
		}
		var r cryptoReassembler
		for _, frag := range frags {
			if err := r.add(frag); err != nil {
				return
			}
		}
		_, _ = r.clientHello()
	})
}
