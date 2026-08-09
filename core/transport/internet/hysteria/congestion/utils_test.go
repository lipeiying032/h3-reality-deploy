package congestion

import (
	"testing"

	"github.com/apernet/quic-go"
	quiccongestion "github.com/apernet/quic-go/congestion"
	"github.com/stretchr/testify/require"
)

func TestConfiguredInitialPacketSize(t *testing.T) {
	const chromeIPv4InitialPacketSize = uint16(1250)

	require.Equal(t,
		quiccongestion.ByteCount(chromeIPv4InitialPacketSize),
		configuredInitialPacketSize(&quic.Config{InitialPacketSize: chromeIPv4InitialPacketSize}),
	)
	require.Equal(t, quiccongestion.ByteCount(quiccongestion.InitialPacketSize), configuredInitialPacketSize(&quic.Config{}))
	require.Equal(t, quiccongestion.ByteCount(quiccongestion.InitialPacketSize), configuredInitialPacketSize(nil))
}
