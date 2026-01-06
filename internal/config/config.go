// FILENAME: internal/config/config.go
package config

import (
	"time"

	"github.com/charmbracelet/lipgloss"
)

// Global Configuration
const (
	// Network & Proxy
	DefaultProxyPort      = 8080
	MaxCaptureSize        = 10 * 1024 * 1024 // 10MB
	ProxyTimeout          = 30 * time.Second
	ProxyKeepAlive        = 30 * time.Second
	IdleConnTimeout       = 90 * time.Second
	MaxIdleConns          = 100
	BodyOffloadThreshold  = 10 * 1024 // 10KB
	ProxyHandshakeTimeout = 10 * time.Second

	// Engine
	DefaultConcurrency = 20
	DefaultStrategy    = "h2"
	RaceTimeout        = 45 * time.Second
	H1RequestTimeout   = 20 * time.Second
	H2RequestTimeout   = 15 * time.Second
	H3RequestTimeout   = 30 * time.Second
	SpinBarrierCheck   = 1024 // Iterations before checking context for safety

	// History
	MaxHistorySize = 1000
)

// UI Colors (Palette)
var (
	ColorFocus  = lipgloss.Color("39")  // Vivid Blue
	ColorAccent = lipgloss.Color("212") // Pink
	ColorErr    = lipgloss.Color("196") // Red
	ColorWarn   = lipgloss.Color("214") // Orange
	ColorOk     = lipgloss.Color("42")  // Green
	ColorSub    = lipgloss.Color("240") // Dark Grey
)
