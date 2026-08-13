package reality

import (
	"testing"

	"google.golang.org/protobuf/proto"
)

func TestH3ClientTimingChrome133ConfigRoundTrip(t *testing.T) {
	encoded, err := proto.Marshal(&Config{H3ClientTimingChrome133: true})
	if err != nil {
		t.Fatal(err)
	}
	var decoded Config
	if err := proto.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if !decoded.GetH3ClientTimingChrome133() {
		t.Fatal("h3_client_timing_chrome133 did not survive protobuf round trip")
	}
	if (&Config{}).GetH3ClientTimingChrome133() {
		t.Fatal("h3_client_timing_chrome133 must default to false")
	}
}
