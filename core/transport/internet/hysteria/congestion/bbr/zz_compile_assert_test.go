package bbr

import (
	"github.com/apernet/quic-go/congestion"
)

// Compile-time assertion: bbrSender must satisfy the fork's CongestionControlEx.
var _ congestion.CongestionControlEx = (*bbrSender)(nil)
