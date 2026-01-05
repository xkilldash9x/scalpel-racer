// FILENAME: internal/proxy/sanitizer.go
package proxy

import (
	"net/http"
	"strings"
)

// RFC 9113 Hop-by-hop headers that must be stripped by intermediaries.
var hopByHopHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",
	"Trailers",
	"Transfer-Encoding",
	"Upgrade",
	// ADDED: HTTP/2 Specific headers
	"HTTP2-Settings",
	"Priority",
}

// SanitizeHeadersRFC9113 removes connection-specific headers to ensure
// protocol compliance when forwarding requests.
func SanitizeHeadersRFC9113(h http.Header) {
	// remove headers explicitly listed in the Connection header
	if c := h.Get("Connection"); c != "" {
		for _, f := range strings.Split(c, ",") {
			h.Del(strings.TrimSpace(f))
		}
	}

	// remove standard hop-by-hop headers
	for _, header := range hopByHopHeaders {
		h.Del(header)
	}
}

// SanitizeHeadersForLog visually redacts sensitive keys in the provided map.
// This modifies the map in place (used for ephemeral logging maps).
func SanitizeHeadersForLog(h map[string]string) {
	sensitive := []string{"Authorization", "Cookie", "Set-Cookie", "X-Auth-Token"}
	for _, key := range sensitive {
		// Case insensitive check
		for k := range h {
			if strings.EqualFold(key, k) {
				h[k] = "[REDACTED]"
			}
		}
	}
}
