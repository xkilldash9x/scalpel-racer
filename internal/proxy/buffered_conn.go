// FILENAME: internal/proxy/buffered_conn.go
package proxy

import (
	"bufio"
	"net"
)

// BufferedConn wraps a net.Conn and a bufio.Reader.
// It prioritizes reading from the bufio.Reader (to consume buffered bytes)
// before reading from the underlying connection. This is essential for
// handling protocol upgrades (e.g., HTTP CONNECT -> TLS) where the initial
// peeking might have buffered the start of the handshake.
type BufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func NewBufferedConn(c net.Conn, r *bufio.Reader) *BufferedConn {
	return &BufferedConn{
		Conn: c,
		r:    r,
	}
}

func (b *BufferedConn) Read(p []byte) (n int, err error) {
	return b.r.Read(p)
}

// Peek returns the next n bytes without advancing the reader.
// distinct from bufio.Peek, this method returns a COPY of the bytes.
// This ensures that the caller cannot hold a reference to the underlying
// buffer, preventing data corruption if the caller retains the slice
// after a subsequent Read() call.
func (b *BufferedConn) Peek(n int) ([]byte, error) {
	// Get the raw slice from bufio (unsafe to hold past next Read)
	peeked, err := b.r.Peek(n)

	// If we got any data, clone it to a new slice
	if len(peeked) > 0 {
		clone := make([]byte, len(peeked))
		copy(clone, peeked)
		return clone, err
	}

	return nil, err
}
