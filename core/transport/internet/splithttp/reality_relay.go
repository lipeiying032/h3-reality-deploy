package splithttp

// UDP NAT relay for QUIC flows that the XHTTP/3 REALITY precheck decides to
// fall back (probe / unauthenticated traffic). Client datagrams are forwarded
// verbatim to the single configured dest (classic REALITY semantics: auth
// failure is always relayed to dest, never routed by SNI), and the
// destination's replies are written back to the client from the server's own
// listening socket, so the client sees a single, consistent source address.
// The destination set is fixed when a flow's first packet is classified;
// every later packet of the same flow uses the same targets.
//
// Each configured destination hostname is resolved to all of its A/AAAA
// addresses at startup (DNS order, deduplicated), and a flow fails over to the
// next address when a write to the current one errors (e.g. ICMP port
// unreachable / "connection refused", which happens when the resolved address
// has no QUIC listener on UDP 443). A single broken A record therefore no
// longer black-holes the whole destination.

import (
	stderrors "errors"
	"net"
	"sync"
	"syscall"
	"time"

	"github.com/xtls/xray-core/common/errors"
)

const (
	// realityRelayMaxEntries caps the number of concurrent relayed client
	// flows, preventing a flood of spoofed sources from exhausting memory.
	realityRelayMaxEntries = 65536
	// realityRelayMaxPerIP caps the number of concurrent relayed flows per
	// client IP.
	realityRelayMaxPerIP = 512
	// realityRelayScanPeriod is how often idle entries are swept.
	realityRelayScanPeriod = 30 * time.Second
	// realityRelayBufferSize is the max UDP datagram size relayed.
	realityRelayBufferSize = 65536
)

// relayEntry is one client -> dest flow.
type relayEntry struct {
	clientAddr     net.Addr
	destCandidates []*net.UDPAddr
	destIdx        int
	destConn       *net.UDPConn
	lastSeen       time.Time
}

// realityRelay relays UDP datagrams between client addresses and their chosen
// destination. Each client address gets its own UDP socket to the destination,
// so the destination sees one connection per relayed client.
type realityRelay struct {
	serverConn net.PacketConn
	// dest is the single destination set every relayed (probe /
	// unauthenticated) flow is forwarded to; nil means such flows are
	// dropped (no dest configured).
	dest    []*net.UDPAddr
	timeout time.Duration

	mu      sync.Mutex
	entries map[string]*relayEntry
	perIP   map[string]int

	closeOnce sync.Once
	closed    chan struct{}
}

// newRealityRelay builds a UDP relay that forwards client datagrams to the
// single dest and writes the destination's replies back through serverConn
// (the server's own listening socket, so replies keep the same source
// address the client dialed). dest may be empty (relayed flows are then
// dropped); an invalid dest is an error. timeout is the idle lifetime of an
// entry; <= 0 defaults to 120s.
func newRealityRelay(serverConn net.PacketConn, dest string, timeout time.Duration) (*realityRelay, error) {
	var destAddrs []*net.UDPAddr
	if dest != "" {
		var err error
		destAddrs, err = resolveRelayDest(dest)
		if err != nil {
			return nil, errors.New("REALITY: invalid dest ", dest, ": ", err)
		}
	}
	if timeout <= 0 {
		timeout = 120 * time.Second
	}
	r := &realityRelay{
		serverConn: serverConn,
		dest:       destAddrs,
		timeout:    timeout,
		entries:    make(map[string]*relayEntry),
		perIP:      make(map[string]int),
		closed:     make(chan struct{}),
	}
	go r.reapLoop()
	return r, nil
}

// resolveRelayDest resolves a host:port destination to all of its A/AAAA
// addresses (DNS order, deduplicated), so a single broken address does not
// black-hole the destination. IP literals resolve to themselves. A lookup
// that yields no usable address is an error.
func resolveRelayDest(hostport string) ([]*net.UDPAddr, error) {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		return nil, err
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]bool, len(ips))
	dests := make([]*net.UDPAddr, 0, len(ips))
	for _, ip := range ips {
		key := ip.String()
		if seen[key] {
			continue
		}
		seen[key] = true
		addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(ip.String(), port))
		if err != nil {
			continue
		}
		dests = append(dests, addr)
	}
	if len(dests) == 0 {
		return nil, errors.New("REALITY: no usable address for ", hostport)
	}
	return dests, nil
}

// relayClientToDest forwards one client datagram (unmodified) to dest,
// creating the per-client socket on first use. A nil dest set drops the
// datagram (no destination configured for this flow).
func (r *realityRelay) relayClientToDest(addr net.Addr, dest []*net.UDPAddr, data []byte) {
	if len(dest) == 0 {
		return
	}
	key := addr.String()
	r.mu.Lock()
	entry, ok := r.entries[key]
	if ok {
		entry.lastSeen = time.Now()
		r.mu.Unlock()
		r.writeToDest(entry, data)
		return
	}
	if len(r.entries) >= realityRelayMaxEntries || r.perIP[addrIPKey(addr)] >= realityRelayMaxPerIP {
		// Table full or per-IP limit reached: drop rather than grow unbounded.
		r.mu.Unlock()
		return
	}
	entry = &relayEntry{clientAddr: cloneAddr(addr), destCandidates: dest, lastSeen: time.Now()}
	r.entries[key] = entry
	r.perIP[addrIPKey(addr)]++
	r.mu.Unlock()

	r.writeToDest(entry, data)
}

func (r *realityRelay) writeToDest(entry *relayEntry, data []byte) {
	for {
		if entry.destConn == nil {
			if entry.destIdx >= len(entry.destCandidates) {
				return // every candidate refused this datagram; drop
			}
			conn, err := net.DialUDP("udp", nil, entry.destCandidates[entry.destIdx])
			if err != nil {
				entry.destIdx++
				continue
			}
			entry.destConn = conn
			go r.destToClient(entry, conn)
		}
		if _, err := entry.destConn.Write(data); err != nil {
			// ICMP port unreachable ("connection refused") and similar hard
			// errors mean the current address has no QUIC listener: fail over
			// to the next resolved address for this flow.
			errors.LogErrorInner(nil, err, "REALITY: relay write to dest failed for ", entry.clientAddr.String(), ", trying next address")
			entry.destConn.Close()
			entry.destConn = nil
			entry.destIdx++
			continue
		}
		return
	}
}

// destToClient reads replies from the dest socket for one client and
// writes them back through the server's listening socket. It exits when the
// entry is reaped or the relay is closed (the socket close unblocks Read). A
// read-side ICMP port-unreachable ("connection refused") also closes the
// socket so the flow's next client datagram fails over to the next resolved
// address immediately instead of waiting for another ICMP.
func (r *realityRelay) destToClient(entry *relayEntry, conn *net.UDPConn) {
	buf := make([]byte, realityRelayBufferSize)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			if stderrors.Is(err, syscall.ECONNREFUSED) {
				conn.Close()
			}
			return
		}
		if _, err := r.serverConn.WriteTo(buf[:n], entry.clientAddr); err != nil {
			return
		}
	}
}

// reapLoop periodically closes and removes entries idle for longer than the
// configured timeout.
func (r *realityRelay) reapLoop() {
	ticker := time.NewTicker(realityRelayScanPeriod)
	defer ticker.Stop()
	for {
		select {
		case <-r.closed:
			return
		case <-ticker.C:
			r.reap()
		}
	}
}

func (r *realityRelay) reap() {
	now := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()
	for key, entry := range r.entries {
		if now.Sub(entry.lastSeen) > r.timeout {
			delete(r.entries, key)
			r.perIP[addrIPKey(entry.clientAddr)]--
			entry.destConn.Close()
		}
	}
}

// Close tears down all relayed flows and stops the reaper.
func (r *realityRelay) Close() error {
	r.closeOnce.Do(func() {
		close(r.closed)
		r.mu.Lock()
		for key, entry := range r.entries {
			delete(r.entries, key)
			entry.destConn.Close()
		}
		r.perIP = make(map[string]int)
		r.mu.Unlock()
	})
	return nil
}

// addrIPKey returns the normalized client IP string used for per-IP limits.
func addrIPKey(addr net.Addr) string {
	var ip net.IP
	switch a := addr.(type) {
	case *net.UDPAddr:
		ip = a.IP
	case *net.TCPAddr:
		ip = a.IP
	default:
		host, _, err := net.SplitHostPort(addr.String())
		if err != nil {
			return addr.String()
		}
		ip = net.ParseIP(host)
	}
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	return ip.String()
}

// cloneAddr snapshots a net.Addr so a reused address object held by the
// underlying packet conn cannot be mutated underneath us.
func cloneAddr(addr net.Addr) net.Addr {
	if a, ok := addr.(*net.UDPAddr); ok {
		c := *a
		if a.IP != nil {
			c.IP = append(net.IP(nil), a.IP...)
		}
		return &c
	}
	return addr
}
