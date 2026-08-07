package splithttp

import (
	"net"
	"strings"
	"testing"
	"time"
)

// reserveClosedUDPPort returns a UDP address on 127.0.0.1 that has no
// listener, so a connected UDP socket to it gets ICMP port unreachable
// ("connection refused") once the kernel delivers the error.
func reserveClosedUDPPort(t *testing.T) *net.UDPAddr {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	addr := conn.LocalAddr().(*net.UDPAddr)
	conn.Close()
	return addr
}

// TestRealityRelayFailoverOnRefused verifies that writeToDest fails a flow
// over to the next resolved address when the current one refuses datagrams
// (ICMP port unreachable), so a single dead A record does not black-hole the
// destination.
func TestRealityRelayFailoverOnRefused(t *testing.T) {
	dead := reserveClosedUDPPort(t)
	live, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer live.Close()
	liveAddr := live.LocalAddr().(*net.UDPAddr)

	serverConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer serverConn.Close()
	relay, err := newRealityRelay(serverConn, "", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer relay.Close()

	entry := &relayEntry{
		clientAddr:     &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 39999},
		destCandidates: []*net.UDPAddr{dead, liveAddr},
	}

	// Prime the dead socket so the kernel learns of the ICMP refusal.
	relay.writeToDest(entry, []byte("probe-prime"))

	got := make([]byte, 1500)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		relay.writeToDest(entry, []byte("probe-retry"))
		live.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		n, _, err := live.ReadFrom(got)
		if err == nil {
			if string(got[:n]) != "probe-retry" {
				t.Fatalf("live listener got %q, want %q", got[:n], "probe-retry")
			}
			if entry.destIdx != 1 {
				t.Fatalf("destIdx = %d, want 1 (failed over to second candidate)", entry.destIdx)
			}
			if entry.destConn == nil || entry.destConn.RemoteAddr().String() != liveAddr.String() {
				t.Fatalf("destConn = %v, want %v", entry.destConn, liveAddr)
			}
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("failover never reached the live address")
}

// TestResolveRelayDest verifies the destination resolver returns IP literals
// unchanged and never an empty set.
func TestResolveRelayDest(t *testing.T) {
	dests, err := resolveRelayDest("127.0.0.1:443")
	if err != nil {
		t.Fatal(err)
	}
	if len(dests) != 1 || dests[0].String() != "127.0.0.1:443" {
		t.Fatalf("resolveRelayDest(127.0.0.1:443) = %v, want [127.0.0.1:443]", dests)
	}

	dests, err = resolveRelayDest("localhost:443")
	if err != nil {
		t.Fatal(err)
	}
	if len(dests) == 0 {
		t.Fatal("resolveRelayDest(localhost:443) returned no candidates")
	}
	for _, d := range dests {
		if !strings.HasSuffix(d.String(), ":443") {
			t.Fatalf("candidate %v does not carry the destination port", d)
		}
	}
}
