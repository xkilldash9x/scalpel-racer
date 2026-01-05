// FILENAME: internal/packet/fuzz_test.go
//go:build linux

package packet

import (
	"testing"

	"go.uber.org/zap"
)

// FuzzEvaluatePacket hammers the packet decoding and flow tracking logic.
// We want to ensure that random garbage bytes don't cause panics in gopacket layers
// or your slice tracking logic.
func FuzzEvaluatePacket(f *testing.F) {
	// 1. Seed Corpus
	// Empty packet
	f.Add([]byte{})
	// Valid-ish TCP packet (from your helper)
	f.Add(buildPacket(&testing.T{}, 80))
	// Random garbage
	f.Add([]byte("HTTP/1.1 200 OK\r\n\r\n"))
	f.Add([]byte{0xff, 0xff, 0xff, 0xff})

	f.Fuzz(func(t *testing.T, payload []byte) {
		// Setup a lightweight controller (no NFQUEUE connection needed for pure logic)
		c := &Controller{
			TargetIP:    "127.0.0.1",
			TargetPort:  80,
			Concurrency: 5,
			Logger:      zap.NewNop(),
			heldIDs:     make([]uint32, 0, 5),
			seenFlows:   make(map[string]struct{}),
			releaseChan: make(chan struct{}),
		}

		// We don't care about the return value (verdict), only that it doesn't panic.
		_ = c.evaluatePacket(12345, payload)

		// Clean up any timers created to avoid leaking goroutines during fuzzing
		c.mu.Lock()
		if c.flushTimer != nil {
			c.flushTimer.Stop()
		}
		c.mu.Unlock()
	})
}
