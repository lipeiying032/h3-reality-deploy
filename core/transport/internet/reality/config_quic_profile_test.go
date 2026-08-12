package reality

import "testing"

func TestGetRealityQUICParamsWireProfile(t *testing.T) {
	config := &Config{H3InitialPacketSize: 1200, H3ConnectionIdLength: 20}
	params := config.GetRealityQUICParams()
	if params.H3InitialPacketSize != 1200 {
		t.Fatalf("H3InitialPacketSize = %d, want 1200", params.H3InitialPacketSize)
	}
	if params.H3ConnectionIDLength != 20 {
		t.Fatalf("H3ConnectionIDLength = %d, want 20", params.H3ConnectionIDLength)
	}
}
