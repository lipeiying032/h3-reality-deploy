package quic

// chromePTOEnabler deliberately stays narrower than ackhandler's public
// interface. The Chrome profile is configured by the QUIC transport before
// the connection run loop starts, without changing generic quic-go callers.
type chromePTOEnabler interface {
	EnableChromePTO()
}

func enableChromePTO(conn *wrappedConn) {
	if enabler, ok := conn.sentPacketHandler.(chromePTOEnabler); ok {
		enabler.EnableChromePTO()
	}
}
