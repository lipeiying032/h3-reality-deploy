package wire

import "testing"

func TestChromeGREASETransportParameterLength(t *testing.T) {
	for randomByte := range 256 {
		if got, want := chromeGREASEValueLength(byte(randomByte)), byte(randomByte%16); got != want {
			t.Errorf("random byte %d produced length %d, want %d", randomByte, got, want)
		}
	}
}
