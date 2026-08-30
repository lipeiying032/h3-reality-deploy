package splithttp

import (
	"net"
	"testing"
)

func TestChromeInitialPacketSize(t *testing.T) {
	if got := chromeInitialPacketSize(net.ParseIP("192.0.2.1")); got != 1250 {
		t.Errorf("IPv4 Initial packet size = %d, want 1250", got)
	}
	if got := chromeInitialPacketSize(net.ParseIP("2001:db8::1")); got != 1230 {
		t.Errorf("IPv6 Initial packet size = %d, want 1230", got)
	}
}
