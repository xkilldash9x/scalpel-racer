package proxy

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"testing"
)

// TestBufferedConn_MemorySafety validates that the Peek method strictly returns
// a copy of the underlying buffer. Accessing the underlying slice directly is
// a vector for data corruption in high-throughput proxies.
func TestBufferedConn_MemorySafety(t *testing.T) {
	// Generate a deterministic payload
	payload := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, 0x02, 0x03}
	reader := bufio.NewReader(bytes.NewReader(payload))
	// Mock connection not required for this logic test
	bc := NewBufferedConn(nil, reader)

	// Peek into the buffer
	peekSize := 4
	peeked, err := bc.Peek(peekSize)
	if err != nil {
		t.Fatalf("unexpected peek error: %v", err)
	}

	// 1. Mutation Test
	// We deliberately corrupt the peeked slice. If this modifies the original
	// buffer, the implementation is unsafe.
	peeked[0] = 0xFF
	peeked[1] = 0xFF

	// Read the actual data from the reader
	buffer := make([]byte, peekSize)
	n, err := bc.Read(buffer)
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}

	if n != peekSize {
		t.Errorf("short read: expected %d, got %d", peekSize, n)
	}

	// 2. Verification
	// The data read must match the original payload, NOT the mutated peek.
	expected := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	if !bytes.Equal(buffer, expected) {
		t.Fatalf("Memory violation: Peek returned a reference, not a copy.\nExpected: %X\nGot:      %X", expected, buffer)
	}
}

// TestBufferedConn_BoundaryChecks ensures the buffer handles peeks larger than
// the internal bufio size gracefully (or errors appropriately) and handles
// multiple read/peek cycles.
func TestBufferedConn_BoundaryChecks(t *testing.T) {
	// 4KB payload
	data := make([]byte, 4096)
	rand.Read(data)

	reader := bufio.NewReaderSize(bytes.NewReader(data), 1024) // Force small buffer
	bc := NewBufferedConn(nil, reader)

	// Attempt to peek larger than the bufio internal buffer.
	// bufio.Reader.Peek returns an error if n > buffer size.
	// Our wrapper should propagate this error or handle it, but never panic.
	_, err := bc.Peek(2048)
	if err != bufio.ErrBufferFull {
		t.Errorf("Expected bufio.ErrBufferFull for oversized peek, got: %v", err)
	}

	// Read small chunk
	buf := make([]byte, 512)
	bc.Read(buf)

	// Peek again to ensure state is maintained
	peeked, err := bc.Peek(10)
	if err != nil {
		t.Fatalf("subsequent peek failed: %v", err)
	}

	if !bytes.Equal(peeked, data[512:522]) {
		t.Errorf("buffer alignment lost after read")
	}
}
