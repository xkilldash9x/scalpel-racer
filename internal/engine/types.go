// FILENAME: internal/engine/types.go
package engine

import (
	"go.uber.org/zap"
)

// Racer is the core service for executing synchronization attacks.
type Racer struct {
	Factory ClientFactory
	Logger  *zap.Logger
}

// NewRacer creates a racer with the provided factory.
func NewRacer(f ClientFactory, logger *zap.Logger) *Racer {
	return &Racer{
		Factory: f,
		Logger:  logger,
	}
}
