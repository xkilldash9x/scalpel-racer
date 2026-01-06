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
	// OPTIMIZATION: We pass the body chunks to calculate length, but we do NOT
	// join them immediately into a massive buffer for serialization.
	req, cleanBody, err := constructCleanRequest(reqSpec, bodyChunks)
	if err != nil {
		return nil, err
	}

	// 3. Logic: Serialize Header-Only to Wire Format
	// Optimization: We manually set ContentLength and provide NoBody to serialization.
	// This gives us the wire-formatted headers. We then append the body chunks manually.
	// This avoids allocating a buffer size of (Headers + Body) just to slice it up again.
	headerBytes, err := customhttp.SerializeRequest(req)
	if err != nil {
		return nil, fmt.Errorf("serialization failed: %w", err)
	}

	// 4. Logic: Map Stages
	// We append the first body chunk to the headers to form the first stage.
	wireStages := make([][]byte, len(bodyChunks))

	// Stage 0: Headers + Chunk 0
	wireStages[0] = append(headerBytes, bodyChunks[0]...)

	// Subsequent Stages: Chunk N
	for i := 1; i < len(bodyChunks); i++ {
		wireStages[i] = bodyChunks[i]
	}

	// Re-attach the full body to the request object for the caller (logic layer),
	// even though we used a NoBody request for the wire serialization.
	req.Body = http.NoBody
	// Note: We leave req.Body as NoBody or reset it if needed by caller.
	// We recreate the CleanRequest for higher-level logic that expects a readable body.
	req, _ = http.NewRequest(req.Method, req.URL.String(), bytes.NewReader(cleanBody))
	req.ContentLength = int64(len(cleanBody))
	for k, v := range reqSpec.Headers {
		req.Header.Set(k, v)
	}

	return &RacePlan{
		WireStages:   wireStages,
		CleanRequest: req,
	}, nil
}

// constructCleanRequest creates a standard http.Request without the sync markers.
// It returns the request (with NoBody but correct Content-Length) and the clean bytes.
func constructCleanRequest(reqSpec *models.CapturedRequest, bodyChunks [][]byte) (*http.Request, []byte, error) {
	method := reqSpec.Method
	if method == "" {
		method = "POST"
	}

	cleanBody := bytes.Join(bodyChunks, []byte{})
	totalLen := int64(len(cleanBody))

	// Create request with NoBody to prevent SerializeRequest from consuming a reader
	// or allocating memory for the body.
	req, err := http.NewRequest(method, reqSpec.URL, http.NoBody)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("User-Agent", "Scalpel-Racer/Go-H1")
	// Correctly set Content-Length for the stripped body.
	req.ContentLength = totalLen

	// Apply headers from capture with strict validation
	for k, v := range reqSpec.Headers {
		canonical := http.CanonicalHeaderKey(k)

		// Explicitly set Host property from headers if present
		if canonical == "Host" {
			req.Host = v
		}

		// BUG FIX: Strip connection-control headers that disrupt pipelining.
		if canonical == "Content-Length" || canonical == "Transfer-Encoding" || canonical == "Connection" {
			// Validate format if it's Content-Length, even if we ignore the value for the override.
			// This ensures we catch malformed input as expected by the tests.
			if canonical == "Content-Length" {
				if _, err := strconv.ParseInt(v, 10, 64); err != nil {
					return nil, nil, fmt.Errorf("invalid Content-Length header: %w", err)
				}
			}
			continue
		}
		req.Header.Set(k, v)
	}

	// BUG FIX: Enforce Keep-Alive to ensure the socket remains open for subsequent packet stages.
	req.Header.Set("Connection", "keep-alive")

	return req, cleanBody, nil
}
