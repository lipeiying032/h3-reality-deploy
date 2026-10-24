package ackhandler

import (
	"testing"
	"time"

	"github.com/apernet/quic-go/internal/monotime"
	"github.com/apernet/quic-go/internal/protocol"
	"github.com/apernet/quic-go/internal/utils"
	"github.com/apernet/quic-go/internal/wire"
)

func newChromePTOTestHandler(initialPN protocol.PacketNumber) (*sentPacketHandler, *utils.RTTStats) {
	rttStats := utils.NewRTTStats()
	stats := &utils.ConnectionStats{}
	h := NewSentPacketHandler(
		initialPN,
		protocol.InitialPacketSize,
		rttStats,
		stats,
		false,
		false,
		nil,
		protocol.PerspectiveClient,
		nil,
		utils.DefaultLogger,
	).(*sentPacketHandler)
	return h, rttStats
}

func sendInitialPing(h *sentPacketHandler, now monotime.Time) protocol.PacketNumber {
	pn := h.PopPacketNumber(protocol.EncryptionInitial)
	h.SentPacket(
		now,
		pn,
		protocol.InvalidPacketNumber,
		nil,
		[]Frame{{Frame: &wire.PingFrame{}}},
		protocol.EncryptionInitial,
		protocol.ECNNon,
		protocol.InitialPacketSize,
		false,
		false,
	)
	return pn
}

func TestChromePTOInitialRTTAndBackoff(t *testing.T) {
	h, rttStats := newChromePTOTestHandler(1)
	if got := h.getScaledPTO(false); got != 200*time.Millisecond {
		t.Fatalf("generic initial PTO = %s, want 200ms", got)
	}
	h.EnableChromePTO()
	if got := h.getScaledPTO(false); got != 300*time.Millisecond {
		t.Fatalf("Chrome initial PTO = %s, want 300ms", got)
	}

	rttStats.SetInitialRTT(180 * time.Millisecond)
	if got := h.getScaledPTO(false); got != 540*time.Millisecond {
		t.Fatalf("Chrome restored-RTT PTO = %s, want 540ms", got)
	}
	h.ptoCount = 1
	if got := h.getScaledPTO(false); got != 1080*time.Millisecond {
		t.Fatalf("Chrome backed-off PTO = %s, want 1.08s", got)
	}

	h.ptoCount = 0
	rttStats.UpdateRTT(80*time.Millisecond, 0)
	if got, want := h.getScaledPTO(false), rttStats.PTO(false); got != want {
		t.Fatalf("measured Chrome PTO = %s, want standard %s", got, want)
	}
}

func TestChromePTOUsesOneProbeAndSkipsInitialPacketNumber(t *testing.T) {
	h, _ := newChromePTOTestHandler(1)
	h.EnableChromePTO()
	now := monotime.Now()
	if pn := sendInitialPing(h, now); pn != 1 {
		t.Fatalf("first PN = %d, want 1", pn)
	}
	if pn := sendInitialPing(h, now); pn != 2 {
		t.Fatalf("second PN = %d, want 2", pn)
	}
	deadline := h.GetLossDetectionTimeout()
	if got := deadline.Sub(now); got != 300*time.Millisecond {
		t.Fatalf("loss detection timeout = %s, want 300ms", got)
	}
	if err := h.OnLossDetectionTimeout(deadline); err != nil {
		t.Fatal(err)
	}
	if h.numProbesToSend != 1 || h.ptoMode != SendPTOInitial {
		t.Fatalf("PTO state = probes %d mode %s, want 1 Initial", h.numProbesToSend, h.ptoMode)
	}
	if pn, _ := h.PeekPacketNumber(protocol.EncryptionInitial); pn != 4 {
		t.Fatalf("probe PN = %d, want 4 (PN 3 skipped)", pn)
	}
	if pn := sendInitialPing(h, deadline); pn != 4 {
		t.Fatalf("sent probe PN = %d, want 4", pn)
	}
	if h.numProbesToSend != 0 {
		t.Fatalf("probe credit after one packet = %d, want 0", h.numProbesToSend)
	}

	_, err := h.ReceivedAck(&wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 3, Largest: 3}}}, protocol.EncryptionInitial, deadline.Add(time.Millisecond))
	if err == nil {
		t.Fatal("ACK for skipped Initial PN was accepted")
	}
}

func TestGenericPTOStillUsesTwoInitialProbesWithoutSkip(t *testing.T) {
	h, _ := newChromePTOTestHandler(0)
	now := monotime.Now()
	if pn := sendInitialPing(h, now); pn != 0 {
		t.Fatalf("first PN = %d, want 0", pn)
	}
	if pn := sendInitialPing(h, now); pn != 1 {
		t.Fatalf("second PN = %d, want 1", pn)
	}
	deadline := h.GetLossDetectionTimeout()
	if got := deadline.Sub(now); got != 200*time.Millisecond {
		t.Fatalf("generic timeout = %s, want 200ms", got)
	}
	if err := h.OnLossDetectionTimeout(deadline); err != nil {
		t.Fatal(err)
	}
	if h.numProbesToSend != 2 || h.ptoMode != SendPTOInitial {
		t.Fatalf("generic PTO = probes %d mode %s, want 2 Initial", h.numProbesToSend, h.ptoMode)
	}
	if pn, _ := h.PeekPacketNumber(protocol.EncryptionInitial); pn != 2 {
		t.Fatalf("generic next PN = %d, want 2", pn)
	}
}

func TestChromePTOWithoutBytesInFlightStillSkips(t *testing.T) {
	h, _ := newChromePTOTestHandler(1)
	h.EnableChromePTO()
	if err := h.OnLossDetectionTimeout(monotime.Now()); err != nil {
		t.Fatal(err)
	}
	if h.numProbesToSend != 1 || h.ptoMode != SendPTOInitial {
		t.Fatalf("PTO state = probes %d mode %s", h.numProbesToSend, h.ptoMode)
	}
	if pn, _ := h.PeekPacketNumber(protocol.EncryptionInitial); pn != 2 {
		t.Fatalf("next PN = %d, want 2 after skipping 1", pn)
	}
}
