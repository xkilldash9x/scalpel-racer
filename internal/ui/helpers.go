// FILENAME: internal/ui/helpers.go
package ui

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/xkilldash9x/scalpel-racer/internal/models"
)

// RequestToText converts a captured request to a string for the editor.
func RequestToText(r *models.CapturedRequest) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("%s %s %s\n", r.Method, r.URL, r.Protocol))

	// Deterministic Header Order
	keys := make([]string, 0, len(r.Headers))
	for k := range r.Headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		b.WriteString(fmt.Sprintf("%s: %s\n", k, r.Headers[k]))
	}
	b.WriteString("\n")
	b.Write(r.Body)
	return b.String()
}

// TextToRequest parses the editor content back into a CapturedRequest.
func TextToRequest(text string, original *models.CapturedRequest) (*models.CapturedRequest, error) {
	req := &models.CapturedRequest{Headers: make(map[string]string)}
	reader := bufio.NewReader(strings.NewReader(text))
	line, err := reader.ReadString('\n')
	if err != nil {
		return nil, err
	}
	parts := strings.Fields(line)
	if len(parts) < 3 {
		return nil, fmt.Errorf("invalid request line")
	}
	req.Method, req.URL, req.Protocol = parts[0], parts[1], parts[2]
	for {
		l, err := reader.ReadString('\n')
		if err != nil || strings.TrimSpace(l) == "" {
			break
		}
		p := strings.SplitN(l, ":", 2)
		if len(p) == 2 {
			req.Headers[strings.TrimSpace(p[0])] = strings.TrimSpace(p[1])
		}
	}
	req.Body, _ = io.ReadAll(reader)

	// Context Restoration: Host
	if _, ok := req.Headers["Host"]; !ok {
		if original != nil {
			if h, ok := original.Headers["Host"]; ok {
				req.Headers["Host"] = h
			}
		}
	}

	// Context Restoration: Scheme/URL
	if original != nil && !strings.HasPrefix(req.URL, "http") {
		origURL, err := url.Parse(original.URL)
		if err == nil && origURL.Scheme != "" {
			path := req.URL
			if !strings.HasPrefix(path, "/") {
				path = "/" + path
			}
			host := req.Headers["Host"]
			if host == "" {
				host = origURL.Host
			}
			req.URL = fmt.Sprintf("%s://%s%s", origURL.Scheme, host, path)
		}
	}

	// Fix Content-Length
	if len(req.Body) > 0 {
		req.Headers["Content-Length"] = strconv.Itoa(len(req.Body))
	} else if _, ok := req.Headers["Content-Length"]; ok {
		req.Headers["Content-Length"] = "0"
	}

	return req, nil
}

// ResolveTargetIPAndPort extracts target details for packet manipulation.
func ResolveTargetIPAndPort(req *models.CapturedRequest, r Resolver) (string, int) {
	host := req.Headers["Host"]
	if host == "" {
		if u, err := url.Parse(req.URL); err == nil {
			host = u.Host
		}
	}

	var hostPort int
	hostname := host
	if h, portStr, err := net.SplitHostPort(host); err == nil {
		hostname = h
		if p, err := strconv.Atoi(portStr); err == nil {
			hostPort = p
		}
	}

	if hostname == "" {
		return "", 0
	}

	ips, _ := r.LookupIP(hostname)
	var targetIP string
	for _, ip := range ips {
		if ip.To4() != nil {
			targetIP = ip.String()
			break
		}
	}
	if targetIP == "" && len(ips) > 0 {
		targetIP = ips[0].String()
	}

	if targetIP == "" {
		return "", 0
	}

	port := 80
	if u, err := url.Parse(req.URL); err == nil {
		if u.Scheme == "https" {
			port = 443
		}
	}
	if hostPort != 0 {
		port = hostPort
	}
	if u, err := url.Parse(req.URL); err == nil {
		if u.Port() != "" {
			if p, err := strconv.Atoi(u.Port()); err == nil {
				port = p
			}
		}
	}

	return targetIP, port
}

// clean sanitizes strings for display in the UI (handles newlines, non-printable chars, and truncation)
func clean(s string, maxLen int) string {
	if maxLen < 0 {
		return ""
	}
	// Replace standard whitespace
	s = strings.ReplaceAll(s, "\t", "  ")
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.ReplaceAll(s, "\n", " ")

	// Replace non-printable characters
	s = strings.Map(func(r rune) rune {
		if r < 32 {
			return '·'
		}
		return r
	}, s)

	// Truncate
	if maxLen > 0 && len(s) > maxLen {
		if maxLen < 3 {
			return s[:maxLen]
		}
		return s[:maxLen-3] + "..."
	}
	return s
}

// -- Helpers Backward Compatibility for Tests --
func requestToText(r *models.CapturedRequest) string { return RequestToText(r) }
func textToRequest(t string, o *models.CapturedRequest) (*models.CapturedRequest, error) {
	return TextToRequest(t, o)
}
func resolveTargetIPAndPort(r *models.CapturedRequest, res Resolver) (string, int) {
	return ResolveTargetIPAndPort(r, res)
}
