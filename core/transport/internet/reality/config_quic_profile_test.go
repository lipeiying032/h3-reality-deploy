package reality

import "testing"

func TestGetRealityQUICParamsInitialPacketSize(t *testing.T) {
	config := &Config{H3InitialPacketSize: 1200}
	params := config.GetRealityQUICParams()
	if params.H3InitialPacketSize != 1200 {
		t.Fatalf("H3InitialPacketSize = %d, want 1200", params.H3InitialPacketSize)
	}
}
