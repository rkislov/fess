package routing

import (
	"context"
	"time"
)

type backendTimeoutsKey struct{}

// BackendTimeouts carries per-request upstream timeout settings from routing.
type BackendTimeouts struct {
	Timeout     time.Duration // 0 = no extra deadline
	IdleTimeout time.Duration // 0 = use transport default
}

// WithBackendTimeouts returns ctx with upstream timeout settings for the gateway transport.
func WithBackendTimeouts(ctx context.Context, t BackendTimeouts) context.Context {
	return context.WithValue(ctx, backendTimeoutsKey{}, t)
}

// BackendTimeoutsFromContext returns per-backend timeouts when set on the request context.
func BackendTimeoutsFromContext(ctx context.Context) (BackendTimeouts, bool) {
	v, ok := ctx.Value(backendTimeoutsKey{}).(BackendTimeouts)
	return v, ok
}

// TimeoutsFromSeconds builds BackendTimeouts from DB/API seconds (0 = unset).
func TimeoutsFromSeconds(timeoutSec, idleTimeoutSec int) BackendTimeouts {
	var t BackendTimeouts
	if timeoutSec > 0 {
		t.Timeout = time.Duration(timeoutSec) * time.Second
	}
	if idleTimeoutSec > 0 {
		t.IdleTimeout = time.Duration(idleTimeoutSec) * time.Second
	}
	return t
}
