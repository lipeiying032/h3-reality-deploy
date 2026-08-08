package splithttp

// realityPrecheckPacketConn wraps the XHTTP/3 UDP listener and classifies
// each client's first QUIC Initial flight before quic-go sees it:
//
//   - PENDING: decrypt Initial packets, reassemble the TLS ClientHello from
//     CRYPTO frames, verify the REALITY session_id payload. The raw datagrams
//     are buffered until the decision is made so no packet is lost.
//   - AUTH:    verification passed — all (buffered + subsequent) packets are
//     handed to quic-go through an internal FIFO queue.
//   - RELAY:   verification failed or decryption failed for a complete QUIC
//     Initial. The flow is treated as a probe and every packet is relayed
//     verbatim to the single configured dest (classic REALITY semantics: auth
//     failure is always forwarded to dest, never routed by SNI; serverNames
//     only gates auth). Without a configured dest such flows are dropped. The
//     target is fixed at the first packet's decision; the destination
//     completes the handshake and the real site rejects a mismatched SNI by
//     itself.
//
// Datagrams that cannot be a complete QUIC v1 Initial (short headers,
// 0-RTT/Handshake/Retry, version negotiation, truncated headers and garbage)
// are dropped while a flow is unknown or PENDING. AUTH and RELAY decisions
// are sticky, so their subsequent datagrams are never reclassified.
//
// The wrapper runs its own read loop on the underlying conn; quic-go's
// ReadFrom is served from the AUTH queue so it is never blocked by precheck
// work.

import (
	"context"
	"encoding/binary"
	"net"
	"sync"
	"time"

	goreality "github.com/xtls/reality"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/transport/internet/tls"
)

const (
	// precheckMaxStates caps the number of tracked client states.
	precheckMaxStates = 65536
	// precheckMaxPerIP caps tracked client states per client IP.
	precheckMaxPerIP = 512
	// precheckQueueSize is the AUTH packet queue depth served to quic-go.
	precheckQueueSize = 1024
	// precheckMaxPendingPkts / precheckMaxPendingBytes bound how much raw
	// data is held while a ClientHello is still incomplete; exceeding either
	// forces a RELAY decision.
	precheckMaxPendingPkts  = 32
	precheckMaxPendingBytes = 128 * 1024
	// precheckScanPeriod is how often stale states are reaped.
	precheckScanPeriod = 30 * time.Second
	// precheckDropLogInterval bounds diagnostic output from high-rate junk
	// traffic. Drop notices are debug-level and shared across all clients.
	precheckDropLogInterval = 5 * time.Second
)

type precheckState int

const (
	precheckPending precheckState = iota
	precheckAuth
	precheckRelay
)

// precheckClientState tracks one client address. The reassembly fields are
// only touched by the wrapper's read loop; the reaper only deletes map
// entries.
type precheckClientState struct {
	state     precheckState
	lastSeen  time.Time
	firstSeen time.Time
	ip        string
	// relayDest is the destination set pinned for this flow at the RELAY
	// decision (all resolved addresses of the configured dest). It is only
	// touched by the read loop, alongside state. nil means the flow is
	// dropped (no dest configured).
	relayDest    []*net.UDPAddr
	cryptoBuf    []byte
	pending      [][]byte // raw datagrams held until the decision is made
	pendingBytes int
}

type queuedPacket struct {
	data []byte
	addr net.Addr
}

type realityPrecheckPacketConn struct {
	net.PacketConn // the wrapped (post-udpmask) conn; also the relay's server socket
	ctx            context.Context
	params         *tls.RealityQUICParams
	verifier       *goreality.ClientHelloVerifier
	relay          *realityRelay

	mu     sync.Mutex
	states map[string]*precheckClientState
	perIP  map[string]int

	queue     chan queuedPacket
	closed    chan struct{}
	closeOnce sync.Once

	dropLogMu         sync.Mutex
	dropLogNext       time.Time
	dropLogSuppressed uint64
}

// newRealityPrecheckPacketConn wraps conn with the QUIC precheck + UDP relay.
// It is a no-op (returns conn) when no Dest is configured. The returned conn
// owns the relay: Close tears both down.
func newRealityPrecheckPacketConn(ctx context.Context, conn net.PacketConn, params *tls.RealityQUICParams) (net.PacketConn, error) {
	if params == nil || params.Dest == "" {
		return conn, nil
	}
	relay, err := newRealityRelay(conn, params.Dest, params.FallbackTimeout)
	if err != nil {
		return nil, err
	}
	var verifier *goreality.ClientHelloVerifier
	if len(params.PrivateKey) == 32 && len(params.ShortIds) > 0 {
		verifier = &goreality.ClientHelloVerifier{Cfg: &goreality.Config{
			ServerNames:  params.ServerNames,
			PrivateKey:   params.PrivateKey,
			MinClientVer: params.MinClientVer,
			MaxClientVer: params.MaxClientVer,
			MaxTimeDiff:  params.MaxTimeDiff,
			ShortIds:     params.ShortIds,
		}}
	}
	c := &realityPrecheckPacketConn{
		PacketConn: conn,
		ctx:        ctx,
		params:     params,
		verifier:   verifier,
		relay:      relay,
		states:     make(map[string]*precheckClientState),
		perIP:      make(map[string]int),
		queue:      make(chan queuedPacket, precheckQueueSize),
		closed:     make(chan struct{}),
	}
	go c.readLoop()
	go c.reapLoop()
	return c, nil
}

// ReadFrom serves quic-go from the AUTH packet queue.
func (c *realityPrecheckPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case qp := <-c.queue:
		n := copy(p, qp.data)
		return n, qp.addr, nil
	case <-c.closed:
		return 0, nil, net.ErrClosed
	}
}

// WriteTo passes writes (quic-go replies to AUTH clients) straight through to
// the wrapped conn.
func (c *realityPrecheckPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	return c.PacketConn.WriteTo(p, addr)
}

// SetReadDeadline / SetWriteDeadline / SetDeadline forward to the wrapped
// conn so quic-go can unblock the underlying socket on close.
func (c *realityPrecheckPacketConn) SetReadDeadline(t time.Time) error {
	return c.PacketConn.SetReadDeadline(t)
}

func (c *realityPrecheckPacketConn) SetWriteDeadline(t time.Time) error {
	return c.PacketConn.SetWriteDeadline(t)
}

func (c *realityPrecheckPacketConn) SetDeadline(t time.Time) error {
	return c.PacketConn.SetDeadline(t)
}

// Close stops the read loop, tears down the relay and closes the wrapped
// conn.
func (c *realityPrecheckPacketConn) Close() error {
	c.closeOnce.Do(func() {
		close(c.closed)
		c.relay.Close()
		c.mu.Lock()
		c.states = make(map[string]*precheckClientState)
		c.perIP = make(map[string]int)
		c.mu.Unlock()
	})
	return c.PacketConn.Close()
}

// IsAuthenticated reports whether the client address has passed the REALITY
// ClientHello precheck (AUTH state). It is wired to requestHandler.
// handshakeAuthed for the stage-2 data-plane auth integration.
func (c *realityPrecheckPacketConn) IsAuthenticated(clientAddr net.Addr) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	st := c.states[clientAddr.String()]
	return st != nil && st.state == precheckAuth
}

func (c *realityPrecheckPacketConn) relayTimeout() time.Duration {
	if c.params == nil || c.params.FallbackTimeout <= 0 {
		return 120 * time.Second
	}
	return c.params.FallbackTimeout
}

// readLoop owns the underlying conn's read side. handlePacket classifies
// obvious non-Initial traffic before copying the reusable read buffer.
func (c *realityPrecheckPacketConn) readLoop() {
	buf := make([]byte, 65536)
	for {
		n, addr, err := c.PacketConn.ReadFrom(buf)
		if err != nil {
			c.Close()
			return
		}
		c.handlePacket(buf[:n], addr)
	}
}

// obviousNonInitialV1 performs the allocation-free checks that are safe
// before parsing variable-length fields. It is only used for unknown and
// PENDING flows; AUTH and RELAY flows have sticky decisions.
func obviousNonInitialV1(data []byte) bool {
	if len(data) < 6 {
		return true
	}
	firstByte := data[0]
	if firstByte&0x80 == 0 || firstByte&0x40 == 0 {
		return true
	}
	if (firstByte>>4)&0x03 != 0 {
		return true
	}
	return binary.BigEndian.Uint32(data[1:5]) != 1
}

func (c *realityPrecheckPacketConn) forgetEmptyPending(addr net.Addr, st *precheckClientState) {
	key := addr.String()
	c.mu.Lock()
	if c.states[key] == st && st.state == precheckPending && len(st.pending) == 0 && len(st.cryptoBuf) == 0 {
		delete(c.states, key)
		if c.perIP[st.ip] <= 1 {
			delete(c.perIP, st.ip)
		} else {
			c.perIP[st.ip]--
		}
	}
	c.mu.Unlock()
}

func cloneDatagram(data []byte) []byte {
	cloned := make([]byte, len(data))
	copy(cloned, data)
	return cloned
}

// confirmedNonInitial applies the complete parser to Initial-shaped traffic.
// The parser mutates its input, so this slow path uses a disposable copy.
func confirmedNonInitial(data []byte) (bool, error) {
	_, err := parseQUICInitial(cloneDatagram(data))
	return isNotQUICInitial(err), err
}

func (c *realityPrecheckPacketConn) logNonInitialDrop(addr net.Addr, reason error) {
	now := time.Now()
	c.dropLogMu.Lock()
	if now.Before(c.dropLogNext) {
		c.dropLogSuppressed++
		c.dropLogMu.Unlock()
		return
	}
	suppressed := c.dropLogSuppressed
	c.dropLogSuppressed = 0
	c.dropLogNext = now.Add(precheckDropLogInterval)
	c.dropLogMu.Unlock()

	if reason == nil {
		errors.LogDebug(c.ctx, "REALITY: QUIC precheck dropped obvious non-Initial packet from ", addr.String(), " (suppressed since last log: ", suppressed, ")")
		return
	}
	errors.LogDebug(c.ctx, "REALITY: QUIC precheck dropped non-Initial packet from ", addr.String(), ": ", reason, " (suppressed since last log: ", suppressed, ")")
}

func (c *realityPrecheckPacketConn) handlePacket(data []byte, addr net.Addr) {
	key := addr.String()
	c.mu.Lock()
	st := c.states[key]
	if st == nil || st.state == precheckPending {
		if obviousNonInitialV1(data) {
			c.mu.Unlock()
			c.logNonInitialDrop(addr, nil)
			return
		}
	}
	if st == nil {
		if len(c.states) >= precheckMaxStates || c.perIP[addrIPKey(addr)] >= precheckMaxPerIP {
			c.mu.Unlock()
			// At capacity, only complete Initials keep the legacy fallback.
			// Initial-shaped but structurally invalid traffic is still dropped.
			if nonInitial, err := confirmedNonInitial(data); nonInitial {
				c.logNonInitialDrop(addr, err)
				return
			}
			c.relay.relayClientToDest(addr, c.relay.dest, data)
			return
		}
		st = &precheckClientState{state: precheckPending, lastSeen: time.Now(), firstSeen: time.Now(), ip: addrIPKey(addr)}
		c.states[key] = st
		c.perIP[st.ip]++
	}
	st.lastSeen = time.Now()
	state := st.state
	c.mu.Unlock()

	// The read buffer is reused after handlePacket returns. Obvious drops have
	// already returned, so retain one owned copy for queues and pending state.
	data = cloneDatagram(data)
	switch state {
	case precheckAuth:
		c.enqueue(data, addr)
	case precheckRelay:
		c.relay.relayClientToDest(addr, st.relayDest, data)
	default:
		c.decidePending(st, data, addr)
	}
}

// decidePending processes one datagram while the ClientHello is still being
// reassembled, then either keeps waiting (buffering the datagram), marks the
// client AUTH (flushing everything to the quic-go queue) or marks it RELAY
// (flushing everything to the dest).
func (c *realityPrecheckPacketConn) decidePending(st *precheckClientState, data []byte, addr net.Addr) {
	work := make([]byte, len(data))
	copy(work, data)
	pkt, err := parseQUICInitial(work)
	if err != nil {
		if isNotQUICInitial(err) {
			// A first junk packet must not reserve state-table capacity. Keep a
			// state only when a previous Initial contributed buffered data.
			c.forgetEmptyPending(addr, st)
			c.logNonInitialDrop(addr, err)
			return
		}
		errors.LogInfo(c.ctx, "REALITY: QUIC precheck RELAY for ", addr.String(), " (unparseable: ", err, ")")
		c.relayDecision(st, data, addr)
		return
	}
	for _, frag := range parseCryptoFrames(pkt.Payload) {
		st.cryptoBuf = mergeCryptoFrag(st.cryptoBuf, frag)
	}
	hello := extractClientHello(st.cryptoBuf)
	if hello == nil {
		// ClientHello incomplete: hold the datagram and wait for more Initials.
		if len(st.pending) >= precheckMaxPendingPkts || st.pendingBytes >= precheckMaxPendingBytes ||
			time.Since(st.firstSeen) > c.relayTimeout() {
			errors.LogInfo(c.ctx, "REALITY: QUIC precheck RELAY for ", addr.String(), " (ClientHello incomplete)")
			c.relayDecision(st, data, addr)
			return
		}
		st.pending = append(st.pending, data)
		st.pendingBytes += len(data)
		return
	}
	if c.verifier == nil || c.verifier.Verify(hello) != nil {
		errors.LogInfo(c.ctx, "REALITY: QUIC precheck RELAY for ", addr.String())
		c.relayDecision(st, data, addr)
		return
	}
	errors.LogInfo(c.ctx, "REALITY: QUIC precheck AUTH for ", addr.String())
	c.mu.Lock()
	st.state = precheckAuth
	c.mu.Unlock()
	c.flushPending(st, data, addr, false)
}

// relayDecision marks the client RELAY, pins the flow's destination (the
// single configured dest, nil = drop) and forwards all buffered datagrams
// plus the current one to that destination (no packet is dropped for a
// configured destination).
func (c *realityPrecheckPacketConn) relayDecision(st *precheckClientState, data []byte, addr net.Addr) {
	target := c.relay.dest
	c.mu.Lock()
	st.state = precheckRelay
	st.relayDest = target
	c.mu.Unlock()
	if len(target) == 0 {
		errors.LogInfo(c.ctx, "REALITY: QUIC precheck DROP for ", addr.String(), " (no dest configured)")
		st.pending = nil
		st.pendingBytes = 0
		return
	}
	c.flushPending(st, data, addr, true)
}

// flushPending delivers the buffered datagrams (in arrival order) plus the
// current one either to the quic-go queue (toRelay=false) or to the relay
// (toRelay=true).
func (c *realityPrecheckPacketConn) flushPending(st *precheckClientState, data []byte, addr net.Addr, toRelay bool) {
	for _, p := range st.pending {
		if toRelay {
			c.relay.relayClientToDest(addr, st.relayDest, p)
		} else {
			c.enqueue(p, addr)
		}
	}
	st.pending = nil
	st.pendingBytes = 0
	if toRelay {
		c.relay.relayClientToDest(addr, st.relayDest, data)
	} else {
		c.enqueue(data, addr)
	}
}

// enqueue hands one AUTH datagram to quic-go. When the queue is full the
// datagram is dropped rather than blocking the read loop.
func (c *realityPrecheckPacketConn) enqueue(data []byte, addr net.Addr) {
	qp := queuedPacket{data: data, addr: cloneAddr(addr)}
	select {
	case c.queue <- qp:
	case <-c.closed:
	default:
	}
}

// reapLoop removes client states idle for longer than the relay timeout.
// Buffered PENDING datagrams of a dead client are dropped (its QUIC
// connection is unrecoverable by then).
func (c *realityPrecheckPacketConn) reapLoop() {
	interval := precheckScanPeriod
	if t := c.relayTimeout(); t > 0 && t/2 < interval {
		interval = t / 2
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-c.closed:
			return
		case now := <-ticker.C:
			c.mu.Lock()
			for key, st := range c.states {
				if now.Sub(st.lastSeen) > c.relayTimeout() {
					delete(c.states, key)
					if c.perIP[st.ip] <= 1 {
						delete(c.perIP, st.ip)
					} else {
						c.perIP[st.ip]--
					}
				}
			}
			c.mu.Unlock()
		}
	}
}
