// FILENAME: internal/ui/history.go
package ui

import (
	"os"
	"runtime"

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
}

func NewRequestHistory(limit int, logger *zap.Logger) *RequestHistory {
	return &RequestHistory{
		buffer: make([]*StoredRequest, limit),
		limit:  limit,
		logger: logger,
	}
}

func (h *RequestHistory) Add(req *models.CapturedRequest) {
	stored := &StoredRequest{Req: req}

	// Offload to disk if body is large
	if len(req.Body) > BodyOffloadThreshold {
		// -- Usage of os.CreateTemp replaces deprecated ioutil.TempFile --
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
				os.Remove(tmpfile.Name())
			} else if closeErr != nil {
				h.logger.Error("Failed to close temp file", zap.Error(closeErr))
				os.Remove(tmpfile.Name())
			} else {
				h.logger.Info("Offloaded large request body to disk", zap.String("path", tmpfile.Name()))
				req.OffloadPath = tmpfile.Name()
				req.Body = nil // Clear from memory to free RAM
				stored.OnDisk = true
			}
		}
	}

	// Ring Buffer Overwrite Logic
	existing := h.buffer[h.head]
	if existing != nil && existing.OnDisk {
		// Clean up the old file if we are evicting it from history
		if existing.Req.OffloadPath != "" {
			os.Remove(existing.Req.OffloadPath)
		}
	}

	h.buffer[h.head] = stored
	h.head = (h.head + 1) % h.limit
	if h.size < h.limit {
		h.size++
	}
}

// GetMeta returns the storage wrapper.
// We use this to check if we need to perform an async load.
func (h *RequestHistory) GetMeta(index int) *StoredRequest {
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

func (h *RequestHistory) List() []*models.CapturedRequest {
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

func (h *RequestHistory) Close() {
	h.logger.Info("Cleaning up temporary files...")
	for _, item := range h.buffer {
		if item != nil && item.OnDisk && item.Req.OffloadPath != "" {
			os.Remove(item.Req.OffloadPath)
		}
	}
	runtime.GC()
}
