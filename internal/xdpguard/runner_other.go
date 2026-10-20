//go:build !linux

package xdpguard

import (
	"context"
	"fmt"
)

func Run(ctx context.Context, c Config) error {
	return fmt.Errorf("fess-xdp requires Linux 5.15+; ordinary FESS works without XDP")
}
