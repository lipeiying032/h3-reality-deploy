package splithttp

import (
	"testing"

	utls "github.com/refraction-networking/utls"
	"github.com/xtls/xray-core/transport/internet/reality"
)

func TestH3ClientTimingChrome133Gate(t *testing.T) {
	chrome133 := utls.HelloChrome_133
	chrome131 := utls.HelloChrome_131
	firefox := utls.HelloFirefox_120
	testCases := []struct {
		name   string
		config *reality.Config
		id     *utls.ClientHelloID
		want   bool
	}{
		{name: "off", config: &reality.Config{}, id: &chrome133},
		{name: "chrome 133", config: &reality.Config{H3ClientTimingChrome133: true}, id: &chrome133, want: true},
		{name: "chrome 131", config: &reality.Config{H3ClientTimingChrome133: true}, id: &chrome131},
		{name: "firefox", config: &reality.Config{H3ClientTimingChrome133: true}, id: &firefox},
		{name: "missing fingerprint", config: &reality.Config{H3ClientTimingChrome133: true}},
		{name: "missing config", id: &chrome133},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if got := shouldEnableH3ClientTimingChrome133(tc.config, tc.id); got != tc.want {
				t.Fatalf("shouldEnableH3ClientTimingChrome133() = %t, want %t", got, tc.want)
			}
		})
	}
}
