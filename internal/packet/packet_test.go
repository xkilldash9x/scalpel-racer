// FILENAME: internal/packet/packet_test.go
//go:build linux

package packet

import (
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"sync"
	"testing"
	"time"

	"github.com/florianl/go-nfqueue/v2"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"go.uber.org/zap"
)

// -- Mocks --

type MockQueue struct {
	RegisterError error
	VerdictError  error
	Verdicts      map[uint32]int
	// Hook captures the callback function so tests can simulate packet arrival
	Hook nfqueue.HookFunc
	mu   sync.Mutex
}

func (m *MockQueue) RegisterWithErrorFunc(ctx context.Context, fn nfqueue.HookFunc, errFn nfqueue.ErrorFunc) error {
	m.mu.Lock()
	m.Hook = fn
	m.mu.Unlock()

	if m.RegisterError != nil {
		return m.RegisterError
	}
	// Simulate blocking until context done
	<-ctx.Done()
	return nil
}

func (m *MockQueue) SetVerdict(id uint32, verdict int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Verdicts == nil {
		m.Verdicts = make(map[uint32]int)
	}
	m.Verdicts[id] = verdict
	return m.VerdictError
}

func (m *MockQueue) Close() {}

// mockExecCommand simulates exec.Command behaviors for tests
func mockExecCommand(command string, args ...string) *exec.Cmd {
	cs := []string{"-test.run=TestHelperProcess", "--", command}
	cs = append(cs, args...)
	cmd := exec.Command(os.Args[0], cs...)
	cmd.Env = []string{"GO_WANT_HELPER_PROCESS=1", "GO_HELPER_FAIL=" + os.Getenv("GO_HELPER_FAIL")}
	return cmd
}

// TestHelperProcess is the fake binary execution
func TestHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		return
	}
	if os.Getenv("GO_HELPER_FAIL") == "1" {
		os.Exit(1)
	}
	os.Exit(0)
}

// -- Helpers --

// buildPacket constructs a raw byte slice representing a TCP packet from a specific port.
// This supports testing distinct flows (src port + src ip).
func buildPacket(t *testing.T, port int) []byte {
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    net.IP{127, 0, 0, 1},
		DstIP:    net.IP{127, 0, 0, 1},
	}

	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(port),
		DstPort: 80,
	}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatalf("checksum setup fail: %v", err)
	}

	// Always append data payload as logic now likely ignores empty packets or treats them differently
	if err := gopacket.SerializeLayers(buf, opts, ip, tcp, gopacket.Payload([]byte("DATA"))); err != nil {
		t.Fatalf("packet serialization failed: %v", err)
	}
	return buf.Bytes()
}

// -- Tests --

func TestFlowLogic(t *testing.T) {
	oldExec := execCommand
	defer func() { execCommand = oldExec }()
	execCommand = mockExecCommand

	mockQ := &MockQueue{}
	// Concurrency of 2 means we need 2 unique flows to trigger the release
	c := NewController("127.0.0.1", 80, 2, zap.NewNop())
	c.nfq = mockQ

	// Flow 1: Port 100. Should Hold (Wait).
	pkt1 := buildPacket(t, 100)
	if verdict := c.evaluatePacket(1, pkt1); verdict != -1 {
		t.Errorf("Expected hold for flow 1, got %d", verdict)
	}

	// Flow 1 Retransmission. Should Hold (Wait) and NOT increment flow count.
	// This verifies we are tracking unique flows, not just raw packet counts.
	if verdict := c.evaluatePacket(2, pkt1); verdict != -1 {
		t.Errorf("Expected hold for flow 1 retransmission, got %d", verdict)
	}

	c.mu.Lock()
	if len(c.seenFlows) != 1 {
		t.Errorf("Flow count should be 1, got %d", len(c.seenFlows))
	}
	c.mu.Unlock()

	// Flow 2: Port 101. Should Trigger Release.
	pkt2 := buildPacket(t, 101)
	// This call triggers release logic because unique flows (2) >= concurrency (2)
	if verdict := c.evaluatePacket(3, pkt2); verdict != -1 {
		t.Errorf("Expected hold logic execution (returning -1 while triggering async release), got %d", verdict)
	}

	// Verify Barrier Release
	// We wait briefly to ensure the goroutine fired by evaluatePacket has closed the channel
	time.Sleep(10 * time.Millisecond)

	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.releaseChan:
		// Success: Channel is closed
	default:
		t.Error("Barrier release channel was not closed")
	}

	if len(c.heldIDs) != 0 {
		t.Errorf("Held IDs not cleared after release, count is %d", len(c.heldIDs))
	}
}

func TestController_Lifecycle(t *testing.T) {
	oldExec := execCommand
	oldOpen := nfqueueOpen
	defer func() {
		execCommand = oldExec
		nfqueueOpen = oldOpen
	}()

	execCommand = mockExecCommand
	logger := zap.NewNop()

	t.Run("Startup Success", func(t *testing.T) {
		nfqueueOpen = func(c *nfqueue.Config) (PacketQueue, error) {
			return &MockQueue{}, nil
		}
		c := NewController("1.2.3.4", 80, 5, logger)
		// Start is async now, so it shouldn't block
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		if err := c.Start(ctx); err != nil {
			t.Errorf("Start failed: %v", err)
		}
		// Give the goroutine a moment to 'start' (coverage check)
		time.Sleep(10 * time.Millisecond)
		c.Close()
	})

	t.Run("Iptables Failure", func(t *testing.T) {
		os.Setenv("GO_HELPER_FAIL", "1")
		defer os.Unsetenv("GO_HELPER_FAIL")

		c := NewController("1.2.3.4", 80, 5, logger)
		if err := c.Start(context.Background()); err == nil {
			t.Error("Expected error on iptables failure")
		}
	})

	t.Run("Queue Open Failure", func(t *testing.T) {
		os.Setenv("GO_HELPER_FAIL", "0")
		nfqueueOpen = func(c *nfqueue.Config) (PacketQueue, error) {
			return nil, errors.New("kernel busy")
		}

		c := NewController("1.2.3.4", 80, 5, logger)
		if err := c.Start(context.Background()); err == nil {
			t.Error("Expected error on queue open failure")
		}
	})
}

// TestController_Callback_Integration verifies the hook registration and execution path
func TestController_Callback_Integration(t *testing.T) {
	oldExec := execCommand
	oldOpen := nfqueueOpen
	defer func() {
		execCommand = oldExec
		nfqueueOpen = oldOpen
	}()
	execCommand = mockExecCommand
	logger := zap.NewNop()

	mockQ := &MockQueue{}
	nfqueueOpen = func(c *nfqueue.Config) (PacketQueue, error) {
		return mockQ, nil
	}

	// Concurrency 1 means the first packet immediately releases
	c := NewController("127.0.0.1", 80, 1, logger)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := c.Start(ctx); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	// Wait briefly for goroutine to register hook
	time.Sleep(50 * time.Millisecond)

	mockQ.mu.Lock()
	hook := mockQ.Hook
	mockQ.mu.Unlock()

	if hook == nil {
		t.Fatal("Hook was not registered")
	}

	// Simulate incoming packet via the hook
	pktData := buildPacket(t, 12345)
	pktID := uint32(9999)
	attr := nfqueue.Attribute{
		PacketID: &pktID,
		Payload:  &pktData,
	}

	// Invoke the callback directly
	hook(attr)

	// Check if verdict was set (Accept because Concurrency=1 triggers release immediately)
	mockQ.mu.Lock()
	verdict, exists := mockQ.Verdicts[9999]
	mockQ.mu.Unlock()

	if !exists {
		t.Error("Expected verdict to be set via callback")
	}
	if verdict != nfqueue.NfAccept {
		t.Errorf("Expected Accept verdict after trigger, got %d", verdict)
	}
}

func TestController_ReleaseAll(t *testing.T) {
	mockQ := &MockQueue{}
	c := NewController("127.0.0.1", 80, 10, zap.NewNop())
	c.nfq = mockQ

	c.heldIDs = append(c.heldIDs, 999)
	c.ReleaseAll()

	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.heldIDs) != 0 {
		t.Error("ReleaseAll failed to clear held IDs")
	}
	if mockQ.Verdicts[999] != nfqueue.NfAccept {
		t.Error("ReleaseAll did not set Accept verdict")
	}
}
