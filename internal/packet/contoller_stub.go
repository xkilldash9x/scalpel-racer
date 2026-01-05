// FILENAME: internal/packet/controller_stub.go
//go:build !linux

package packet

import (
	"context"
	"fmt"

	"go.uber.org/zap"
)

type Controller struct{}

func NewController(ip string, port int, concurrency int, logger *zap.Logger) *Controller {
	return &Controller{}
}
func (c *Controller) Start(ctx context.Context) error {
	return fmt.Errorf("First-Seq strategy requires Linux and NFQUEUE support")
}
func (c *Controller) ReleaseAll() {}
func (c *Controller) Close()      {}
