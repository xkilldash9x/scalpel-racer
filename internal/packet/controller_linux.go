// FILENAME: internal/packet/controller_linux.go
//go:build linux

package packet

import (
	"context"
	"fmt"
	"os/exec"
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

	// Bypass ensures traffic flows if we crash.
	// Filter strictly for SYN,PSH,ACK packets to reduce noise if needed,
	// but for now, we keep it broad to catch the data payload.
	ruleArgs := []string{
		"-I", "OUTPUT", "1",
		"-p", "tcp",
		"-d", c.TargetIP,
		"--dport", fmt.Sprintf("%d", c.TargetPort),
		"-j", "NFQUEUE",
		"--queue-num", fmt.Sprintf("%d", QueueNum),
		"--queue-bypass",
	}

	c.Logger.Info("Applying iptables rule", zap.Strings("args", ruleArgs))

	if err := execCommand("iptables", ruleArgs...).Run(); err != nil {
		return fmt.Errorf("failed to add iptables rule: %w", err)
	}

	config := nfqueue.Config{
		NfQueue:      uint16(QueueNum),
		MaxPacketLen: 0xFFFF,
		MaxQueueLen:  1024,
		Copymode:     nfqueue.NfQnlCopyPacket,
		WriteTimeout: 15 * time.Millisecond,
	}

	nf, err := nfqueueOpen(&config)
	if err != nil {
		c.cleanupRules()
		return fmt.Errorf("failed to open nfqueue: %w", err)
	}
	c.nfq = nf

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
		if verdict != -1 {
			if err := c.nfq.SetVerdict(id, verdict); err != nil {
				c.Logger.Error("failed to set verdict", zap.Error(err))
			}
		}
		return 0
	}

	go func() {
		if err := nf.RegisterWithErrorFunc(ctx, fn, func(e error) int {
			c.Logger.Debug("nfqueue error", zap.Error(e))
			return 0
		}); err != nil {
			c.Logger.Error("nfqueue register failed", zap.Error(err))
		}
	}()

	return nil
}

func (c *Controller) evaluatePacket(id uint32, payload []byte) int {
	// OPTIMIZATION: Decode packet OUTSIDE the lock.
	// Decoding is CPU intensive. Doing it inside the lock increases the critical section
	// duration, increasing jitter for the release burst. "Attosecond" level precision
	// requires minimal locking.

	if len(payload) == 0 {
		return nfqueue.NfAccept
	}

	// FIX: Use a loose parser that ignores unsupported trailing data.
	// We decode IPv4 first, but check for IPv6 if v4 fails.
	decoder := gopacket.NewDecodingLayerParser(layers.LayerTypeIPv4)
	decoder.IgnoreUnsupported = true
	var ip4 layers.IPv4
	var ip6 layers.IPv6
	var tcp layers.TCP
	decoded := []gopacket.LayerType{}

	// Attempt IPv4 first
	decoder.SetDecodingLayerContainer(gopacket.DecodingLayerArray(nil))
	decoder.AddDecodingLayer(&ip4)
	decoder.AddDecodingLayer(&tcp)

	err := decoder.DecodeLayers(payload, &decoded)
	if err != nil {
		// Fallback: Try IPv6
		decoder = gopacket.NewDecodingLayerParser(layers.LayerTypeIPv6)
		decoder.IgnoreUnsupported = true
		decoder.AddDecodingLayer(&ip6)
		decoder.AddDecodingLayer(&tcp)
		decoded = []gopacket.LayerType{}
		_ = decoder.DecodeLayers(payload, &decoded)
	}

	hasTCP := false
	var srcIP string
	var srcPort layers.TCPPort

	for _, layerType := range decoded {
		if layerType == layers.LayerTypeTCP {
			hasTCP = true
			srcPort = tcp.SrcPort
		}
		if layerType == layers.LayerTypeIPv4 {
			srcIP = ip4.SrcIP.String()
		}
		if layerType == layers.LayerTypeIPv6 {
			srcIP = ip6.SrcIP.String()
		}
	}

	if !hasTCP {
		// Just accept non-TCP traffic for this target without logging to avoid noise
		return nfqueue.NfAccept
	}

	// Pre-calculate flow ID to avoid allocating inside the lock if possible,
	// though string creation is still overhead.
	// Note: We only care about holding DATA packets.
	isDataPacket := len(tcp.Payload) > 0

	if !isDataPacket {
		return nfqueue.NfAccept
	}

	flowID := fmt.Sprintf("%s:%d", srcIP, srcPort)

	// --- CRITICAL SECTION START ---
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nfqueue.NfAccept
	}

	select {
	case <-c.releaseChan:
		return nfqueue.NfAccept
	default:
	}

	if len(c.heldIDs) == 0 {
		// Safety Valve: 100ms max hold time.
		// If fewer than Concurrency flows arrive (e.g., failed connects),
		// this ensures we don't hold the healthy ones forever.
		c.flushTimer = time.AfterFunc(100*time.Millisecond, c.ReleaseAll)
	}

	c.heldIDs = append(c.heldIDs, id)

	if _, seen := c.seenFlows[flowID]; !seen {
		c.seenFlows[flowID] = struct{}{}
	}

	if len(c.seenFlows) >= c.Concurrency {
		if c.flushTimer != nil {
			c.flushTimer.Stop()
		}
		c.triggerReleaseLocked()
	}
	return -1 // NF_DROP/NF_QUEUE (Wait)
}

func (c *Controller) triggerReleaseLocked() {
	select {
	case <-c.releaseChan:
		return
	default:
		close(c.releaseChan)
	}

	c.Logger.Info("Barrier reached!", zap.Int("held_packets", len(c.heldIDs)), zap.Int("flows", len(c.seenFlows)))

	// OPTIMIZATION: Parallel Verdict Release
	// We spawn a goroutine per packet to flood the kernel with verdicts simultaneously,
	// achieving tighter "on-wire" synchronization than sequential syscalls.
	var wg sync.WaitGroup
	for _, id := range c.heldIDs {
		wg.Add(1)
		go func(packetID uint32) {
			defer wg.Done()
			if err := c.nfq.SetVerdict(packetID, nfqueue.NfAccept); err != nil {
				// Log debug only to avoid spamming if socket closes during release
				c.Logger.Debug("failed to release packet", zap.Uint32("id", packetID), zap.Error(err))
			}
		}(id)
	}

	// Wait for syscalls to initiate to ensure state consistency
	wg.Wait()

	c.heldIDs = nil
	c.seenFlows = make(map[string]struct{})
}

func (c *Controller) ReleaseAll() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}
	c.triggerReleaseLocked()
}

func (c *Controller) Close() {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed = true
	// Ensure timer is stopped
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
	// Ignore errors during cleanup
	_ = execCommand("iptables", ruleArgs...).Run()
}
