package quic

import (
	cryptorand "crypto/rand"
	"encoding/binary"
	"time"
)

// chromeInitial1RTTDelayHardCap is a fail-open bound, not a browser timing
// promise. The opt-in profile never holds a final TLS flight past this point.
const chromeInitial1RTTDelayHardCap = 250 * time.Millisecond

type initial1RTTDelaySampler func() time.Duration

// newChrome133Initial1RTTDelaySampler creates a connection-private sampler.
// The profile deliberately has a small fast path and a bounded main/tail
// mixture instead of a fixed sleep. Failure to obtain entropy disables the
// profile for this connection, which is safer than manufacturing a predictable
// timing spike.
func newChrome133Initial1RTTDelaySampler() initial1RTTDelaySampler {
	var seed [8]byte
	if _, err := cryptorand.Read(seed[:]); err != nil {
		return nil
	}
	state := binary.BigEndian.Uint64(seed[:])
	return func() time.Duration {
		state += 0x9e3779b97f4a7c15
		z := state
		z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9
		z = (z ^ (z >> 27)) * 0x94d049bb133111eb
		return chrome133Initial1RTTDelay(z ^ (z >> 31))
	}
}

func chrome133Initial1RTTDelay(random uint64) time.Duration {
	switch random % 12 {
	case 0, 1:
		return boundedChromeInitial1RTTDelay(random>>8, 5*time.Millisecond, 15*time.Millisecond)
	case 2, 3, 4, 5, 6, 7, 8:
		return boundedChromeInitial1RTTDelay(random>>8, 25*time.Millisecond, 90*time.Millisecond)
	case 9, 10:
		return boundedChromeInitial1RTTDelay(random>>8, 90*time.Millisecond, 150*time.Millisecond)
	default:
		return boundedChromeInitial1RTTDelay(random>>8, 150*time.Millisecond, 220*time.Millisecond)
	}
}

func boundedChromeInitial1RTTDelay(random uint64, min, max time.Duration) time.Duration {
	spanMicros := uint64((max - min) / time.Microsecond)
	return min + time.Duration(random%(spanMicros+1))*time.Microsecond
}
