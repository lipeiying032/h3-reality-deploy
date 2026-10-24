package splithttp

import (
	"fmt"

	"github.com/xtls/xray-core/transport/internet/tls"
)

const (
	quicMinInitialPacketSize = 1200
	// Keep this in sync with quic-go/internal/protocol.MaxPacketBufferSize.
	quicMaxPacketBufferSize = 1452
)

type h3WireProfile struct {
	initialPacketSize uint16
}

func parseH3WireProfile(params *tls.RealityQUICParams) (h3WireProfile, error) {
	if params == nil {
		return h3WireProfile{}, nil
	}
	var profile h3WireProfile
	if size := params.H3InitialPacketSize; size != 0 {
		if size < quicMinInitialPacketSize || size > quicMaxPacketBufferSize {
			return h3WireProfile{}, fmt.Errorf("invalid REALITY h3_initial_packet_size %d: must be between %d and %d", size, quicMinInitialPacketSize, quicMaxPacketBufferSize)
		}
		profile.initialPacketSize = uint16(size)
	}
	return profile, nil
}
