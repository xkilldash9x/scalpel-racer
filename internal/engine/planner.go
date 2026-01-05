// FILENAME: internal/engine/planner.go
package engine

import (
	"bytes"
	"fmt"
	"net/http"
	"strconv"

	"github.com/xkilldash9x/scalpel-cli/pkg/customhttp"
	"github.com/xkilldash9x/scalpel-racer/internal/models"
)

// SyncMarker denotes the boundary for synchronization barriers in the payload.
const SyncMarker = "{{SYNC}}"

// RacePlan encapsulates the calculated strategy for a staged attack.
type RacePlan struct {
	WireStages   [][]byte
	CleanRequest *http.Request
}

// PlanH1Attack performs the pure logic of analyzing a capture and calculating
// the wire-level split points.
func PlanH1Attack(reqSpec *models.CapturedRequest) (*RacePlan, error) {
	// 1. Logic: Split body by marker to get clean chunks
	rawBody := reqSpec.Body
	if rawBody == nil {
		rawBody = []byte{}
	}
	markerBytes := []byte(SyncMarker)
	bodyChunks := bytes.Split(rawBody, markerBytes)

	// 2. Logic: Reconstruct "clean" body and Request Object
	req, err := constructCleanRequest(reqSpec, bodyChunks)
	if err != nil {
		return nil, err
	}

	// 3. Logic: Serialize to Wire Format using customhttp
	rawBytes, err := customhttp.SerializeRequest(req)
	if err != nil {
		return nil, fmt.Errorf("serialization failed: %w", err)
	}

	// 4. Logic: Map Stages
	wireStages, err := calculateWireStages(rawBytes, bodyChunks)
	if err != nil {
		return nil, err
	}

	return &RacePlan{
		WireStages:   wireStages,
		CleanRequest: req,
	}, nil
}

// constructCleanRequest creates a standard http.Request without the sync markers.
func constructCleanRequest(reqSpec *models.CapturedRequest, bodyChunks [][]byte) (*http.Request, error) {
	method := reqSpec.Method
	if method == "" {
		method = "POST"
	}

	cleanBody := bytes.Join(bodyChunks, []byte{})

	req, err := http.NewRequest(method, reqSpec.URL, bytes.NewReader(cleanBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("User-Agent", "Scalpel-Racer/Go-H1")
	// Correctly set Content-Length for the stripped body
	req.ContentLength = int64(len(cleanBody))

	// Apply headers from capture with strict validation
	for k, v := range reqSpec.Headers {
		canonical := http.CanonicalHeaderKey(k)

		// BUG FIX: Strip connection-control headers that disrupt pipelining.
		// If captured request has "Connection: close", pipelining fails immediately.
		if canonical == "Content-Length" || canonical == "Transfer-Encoding" || canonical == "Connection" {
			if canonical == "Content-Length" {
				// Parse just to validate format, but don't use the value
				if _, err := strconv.ParseInt(v, 10, 64); err != nil {
					return nil, fmt.Errorf("invalid Content-Length header: %w", err)
				}
			}
			continue
		}

		req.Header.Set(k, v)
	}

	// BUG FIX: Enforce Keep-Alive to ensure the socket remains open for subsequent packet stages.
	req.Header.Set("Connection", "keep-alive")

	return req, nil
}

func calculateWireStages(rawBytes []byte, bodyChunks [][]byte) ([][]byte, error) {
	headerSep := []byte("\r\n\r\n")
	bodyStartIdx := bytes.Index(rawBytes, headerSep)
	if bodyStartIdx == -1 {
		return nil, fmt.Errorf("invalid HTTP serialization: missing header terminator")
	}
	bodyStartIdx += len(headerSep)

	if len(bodyChunks) <= 1 {
		// Fallback: Last-Byte Sync
		if len(rawBytes) < 2 {
			return nil, fmt.Errorf("payload too small to split")
		}
		splitIdx := len(rawBytes) - 1
		return [][]byte{
			rawBytes[:splitIdx],
			rawBytes[splitIdx:],
		}, nil
	}

	wireStages := make([][]byte, len(bodyChunks))
	firstChunkLen := len(bodyChunks[0])
	if bodyStartIdx+firstChunkLen > len(rawBytes) {
		return nil, fmt.Errorf("invariant violation: serialization length mismatch")
	}

	wireStages[0] = rawBytes[:bodyStartIdx+firstChunkLen]

	currentOffset := bodyStartIdx + firstChunkLen
	for i := 1; i < len(bodyChunks); i++ {
		chunkLen := len(bodyChunks[i])
		if currentOffset+chunkLen > len(rawBytes) {
			return nil, fmt.Errorf("invariant violation: chunk %d out of bounds", i)
		}
		wireStages[i] = rawBytes[currentOffset : currentOffset+chunkLen]
		currentOffset += chunkLen
	}

	return wireStages, nil
}
