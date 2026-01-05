// FILENAME: internal/packet/controller_linux.go
//go:build linux

package packet

import (
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"runtime/debug"
	"sync"
	"time"

	"github.com/florianl/go-nfqueue/v2"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"go.uber.org/zap"
)

const QueueNum = 99

var (
	execCommand = exec.Command
	nfqueueOpen = func(c *nfqueue.Config) (PacketQueue, error) {
		nf, err := nfqueue.Open(c)
		if err != nil {
			return nil, err
		}
		return &realPacketQueue{nf}, nil
	}
)

// PacketQueue abstracts the NFQUEUE interaction.
type PacketQueue interface {
	RegisterWithErrorFunc(ctx context.Context, fn nfqueue.HookFunc, errFn nfqueue.ErrorFunc) error
	SetVerdict(id uint32, verdict int) error
	Close()
}

type realPacketQueue struct {
	q *nfqueue.Nfqueue
}

func (r *realPacketQueue) RegisterWithErrorFunc(ctx context.Context, fn nfqueue.HookFunc, errFn nfqueue.ErrorFunc) error {
	return r.q.RegisterWithErrorFunc(ctx, fn, errFn)
}
func (r *realPacketQueue) SetVerdict(id uint32, verdict int) error {
	return r.q.SetVerdict(id, verdict)
}
func (r *realPacketQueue) Close() {
	r.q.Close()
}

// Controller implements "First-Sequence Sync" using Linux NFQUEUE.
type Controller struct {
	TargetIP    string
	TargetPort  int
	Concurrency int
	Logger      *zap.Logger

	nfq         PacketQueue
	heldIDs     []uint32
	seenFlows   map[string]struct{} // Track unique flows by SrcIP:SrcPort
	mu          sync.Mutex
	releaseChan chan struct{}
	closed      bool

	flushTimer *time.Timer
}

func NewController(ip string, port int, concurrency int, logger *zap.Logger) *Controller {
	return &Controller{
		TargetIP:    ip,
		TargetPort:  port,
		Concurrency: concurrency,
		Logger:      logger,
		heldIDs:     make([]uint32, 0, concurrency),
		seenFlows:   make(map[string]struct{}),
		releaseChan: make(chan struct{}),
	}
}

func (c *Controller) Start(ctx context.Context) error {
	c.cleanupRules()

	// 1. iptables Rule
	// Queue TCP packets for the target. Fail-open (bypass) if userspace crashes.
	ruleArgs := []string{
		"-I", "OUTPUT", "1",
		"-p", "tcp",
		"-d", c.TargetIP,
		"--dport", fmt.Sprintf("%d", c.TargetPort),
		"-j", "NFQUEUE",
		"--queue-num", fmt.Sprintf("%d", QueueNum),
		"--queue-bypass",
	}

	c.Logger.Info("Applying First-Sequence Sync iptables rule", zap.Strings("args", ruleArgs))

	if err := execCommand("iptables", ruleArgs...).Run(); err != nil {
		return fmt.Errorf("failed to add iptables rule: %w", err)
	}

	// 2. Open NFQUEUE
	config := nfqueue.Config{
		NfQueue:      uint16(QueueNum),
		MaxPacketLen: 0xFFFF,
		MaxQueueLen:  4096,
		Copymode:     nfqueue.NfQnlCopyPacket,
		WriteTimeout: 5 * time.Millisecond,
	}

	nf, err := nfqueueOpen(&config)
	if err != nil {
		c.cleanupRules()
		return fmt.Errorf("failed to open nfqueue: %w", err)
	}
	c.nfq = nf

	// 3. Register Callback
	fn := func(a nfqueue.Attribute) int {
		defer func() {
			if r := recover(); r != nil {
				c.Logger.Error("Panic in NFQUEUE callback",
					zap.Any("panic", r),
					zap.String("stack", string(debug.Stack())))
			}
		}()

		if a.PacketID == nil {
			return 0
		}
		id := *a.PacketID

		var payload []byte
		if a.Payload != nil {
			payload = *a.Payload
		}

		verdict := c.evaluatePacket(id, payload)

		// If evaluate returns -1, we are holding the packet (no verdict).
		if verdict != -1 {
			if err := c.nfq.SetVerdict(id, verdict); err != nil {
				c.Logger.Debug("failed to set verdict", zap.Error(err))
			}
		}
		return 0
	}

	go func() {
		// Pin to OS thread for stability
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		if err := nf.RegisterWithErrorFunc(ctx, fn, func(e error) int {
			c.Logger.Debug("nfqueue error", zap.Error(e))
			return 0
		}); err != nil {
			c.Logger.Error("nfqueue register failed", zap.Error(err))
		}
	}()

	return nil
}

// evaluatePacket determines if the packet is the start of a new flow.
func (c *Controller) evaluatePacket(id uint32, payload []byte) int {
	if len(payload) == 0 {
		return nfqueue.NfAccept
	}

	// OPTIMIZATION: Decode logic
	var ip4 layers.IPv4
	var ip6 layers.IPv6
	var tcp layers.TCP

	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeIPv4, &ip4, &tcp)
	parser.IgnoreUnsupported = true
	decoded := []gopacket.LayerType{}

	if err := parser.DecodeLayers(payload, &decoded); err != nil {
		// Fallback IPv6
		parser = gopacket.NewDecodingLayerParser(layers.LayerTypeIPv6, &ip6, &tcp)
		parser.IgnoreUnsupported = true
		_ = parser.DecodeLayers(payload, &decoded)
	}

	hasTCP := false
	var srcKey string

	for _, layerType := range decoded {
		if layerType == layers.LayerTypeTCP {
			hasTCP = true
		}
		if layerType == layers.LayerTypeIPv4 {
			srcKey = fmt.Sprintf("%s:%d", ip4.SrcIP, tcp.SrcPort)
		}
		if layerType == layers.LayerTypeIPv6 {
			srcKey = fmt.Sprintf("%s:%d", ip6.SrcIP, tcp.SrcPort)
		}
	}

	if !hasTCP {
		return nfqueue.NfAccept
	}

	// First-Sequence Logic: strictly hold packets that contain payload.
	// Allow handshakes (SYN) and empty ACKs to pass.
	if len(tcp.Payload) == 0 {
		return nfqueue.NfAccept
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nfqueue.NfAccept
	}

	// If barrier broken, pass everything
	select {
	case <-c.releaseChan:
		return nfqueue.NfAccept
	default:
	}

	// FIX: We intentionally removed the "allow if seen" check here.
	// If the barrier is up, we MUST hold all packets, including retransmissions.
	// If we let a retransmission through, the server processes it and the race fails.

	// New Flow or Retransmission: Hold it.
	c.heldIDs = append(c.heldIDs, id)
	c.seenFlows[srcKey] = struct{}{}

	// Safety Timer: If we don't reach full concurrency quickly, release to avoid deadlock.
	if len(c.heldIDs) == 1 {
		c.flushTimer = time.AfterFunc(200*time.Millisecond, c.ReleaseAll)
	}

	// Trigger Check
	if len(c.seenFlows) >= c.Concurrency {
		if c.flushTimer != nil {
			c.flushTimer.Stop()
		}
		c.triggerReleaseLocked()
	}

	return -1 // NF_QUEUE/Hold
}

func (c *Controller) triggerReleaseLocked() {
	select {
	case <-c.releaseChan:
		return
	default:
		close(c.releaseChan)
	}

	c.Logger.Info("NFQUEUE Barrier Reached - Releasing",
		zap.Int("packets", len(c.heldIDs)),
		zap.Int("flows", len(c.seenFlows)))

	// OPTIMIZATION: Burst Release
	// Spawn a single goroutine locked to an OS thread to flood the verdicts.
	// This avoids scheduler overhead associated with spawning N goroutines.
	idsToRelease := make([]uint32, len(c.heldIDs))
	copy(idsToRelease, c.heldIDs)

	go func(ids []uint32) {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		for _, id := range ids {
			// NF_ACCEPT = 1
			if err := c.nfq.SetVerdict(id, nfqueue.NfAccept); err != nil {
				// Suppress errors during burst to avoid I/O blocking logic
			}
		}
	}(idsToRelease)

	c.heldIDs = nil
	// Keep seenFlows populated so retransmissions/tail packets aren't re-queued (logic handled by releaseChan check)
}

func (c *Controller) ReleaseAll() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.closed {
		c.triggerReleaseLocked()
	}
}

func (c *Controller) Close() {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed = true
	if c.flushTimer != nil {
		c.flushTimer.Stop()
	}
	c.triggerReleaseLocked()
	c.mu.Unlock()

	if c.nfq != nil {
		c.nfq.Close()
	}
	c.cleanupRules()
}

func (c *Controller) cleanupRules() {
	ruleArgs := []string{
		"-D", "OUTPUT",
		"-p", "tcp",
		"-d", c.TargetIP,
		"--dport", fmt.Sprintf("%d", c.TargetPort),
		"-j", "NFQUEUE",
		"--queue-num", fmt.Sprintf("%d", QueueNum),
		"--queue-bypass",
	}
	_ = execCommand("iptables", ruleArgs...).Run()
}
