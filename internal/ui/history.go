// FILENAME: internal/ui/history.go
package ui

import (
	"os"
	"runtime"
	"sync"

	"github.com/xkilldash9x/scalpel-racer/internal/models"
	"go.uber.org/zap"
)

const (
	// BodyOffloadThreshold is the size (in bytes) at which we offload request bodies to disk.
	BodyOffloadThreshold = 10 * 1024 // 10KB
)

type StoredRequest struct {
	Req    *models.CapturedRequest
	OnDisk bool
}

type RequestHistory struct {
	buffer []*StoredRequest
	head   int
	size   int
	limit  int
	logger *zap.Logger
	mu     sync.RWMutex
}

func NewRequestHistory(limit int, logger *zap.Logger) *RequestHistory {
	return &RequestHistory{
		buffer: make([]*StoredRequest, limit),
		limit:  limit,
		logger: logger,
	}
}

// Add inserts a request into the history ring buffer.
// It handles disk offloading for large bodies and is thread-safe.
func (h *RequestHistory) Add(req *models.CapturedRequest) {
	h.mu.Lock()
	defer h.mu.Unlock()

	stored := &StoredRequest{Req: req}

	// Offload to disk if body is large
	if len(req.Body) > BodyOffloadThreshold {
		// Use os.CreateTemp for safe temporary file creation
		tmpfile, err := os.CreateTemp("", "scalpel-body-*.bin")
		if err != nil {
			h.logger.Error("Failed to create temp file for body offload", zap.Error(err))
			// Fallback: Keep in RAM if disk offload fails
		} else {
			// Write and Close immediately to flush buffers and release handle.
			_, writeErr := tmpfile.Write(req.Body)
			closeErr := tmpfile.Close()

			if writeErr != nil {
				h.logger.Error("Failed to write to temp file for body offload", zap.Error(writeErr))
				_ = os.Remove(tmpfile.Name())
			} else if closeErr != nil {
				h.logger.Error("Failed to close temp file", zap.Error(closeErr))
				_ = os.Remove(tmpfile.Name())
			} else {
				h.logger.Info("Offloaded large request body to disk", zap.String("path", tmpfile.Name()))
				req.OffloadPath = tmpfile.Name()
				req.Body = nil // Clear from memory to free RAM
				stored.OnDisk = true
			}
		}
	}

	// Ring Buffer Overwrite Logic
	// Note: We do NOT delete the old file here. If we delete the file associated
	// with the evicted item, we risk crashing the UI if the user is currently
	// viewing or editing that specific request (dangling reference).
	// We rely on Close() to clean up all temp files on exit.

	h.buffer[h.head] = stored
	h.head = (h.head + 1) % h.limit
	if h.size < h.limit {
		h.size++
	}
}

// GetMeta returns the storage wrapper safely.
func (h *RequestHistory) GetMeta(index int) *StoredRequest {
	h.mu.RLock()
	defer h.mu.RUnlock()

	if h.size == 0 {
		return nil
	}

	// Safety: Ensure index is within the logical size of the history
	if index < 0 || index >= h.size {
		return nil
	}

	start := (h.head - h.size + h.limit) % h.limit
	realIdx := (start + index) % h.limit

	if realIdx < 0 || realIdx >= len(h.buffer) {
		return nil
	}
	return h.buffer[realIdx]
}

// List returns a slice of pointers to the requests in the history.
func (h *RequestHistory) List() []*models.CapturedRequest {
	h.mu.RLock()
	defer h.mu.RUnlock()

	out := make([]*models.CapturedRequest, h.size)
	start := (h.head - h.size + h.limit) % h.limit
	for i := 0; i < h.size; i++ {
		idx := (start + i) % h.limit
		if h.buffer[idx] != nil {
			out[i] = h.buffer[idx].Req
		}
	}
	return out
}

// Close cleans up all temporary files created during the session.
func (h *RequestHistory) Close() {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.logger.Info("Cleaning up temporary files...")
	// We iterate the entire buffer, not just the active size, just in case
	// artifacts remain.
	for _, item := range h.buffer {
		if item != nil && item.OnDisk && item.Req.OffloadPath != "" {
			_ = os.Remove(item.Req.OffloadPath)
		}
	}
	runtime.GC()
}
