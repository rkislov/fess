package routing

import (
	"context"
	"testing"
	"time"
)

func TestTimeoutsFromSeconds(t *testing.T) {
	t.Parallel()
	got := TimeoutsFromSeconds(30, 120)
	if got.Timeout != 30*time.Second {
		t.Fatalf("timeout: got %v", got.Timeout)
	}
	if got.IdleTimeout != 120*time.Second {
		t.Fatalf("idle: got %v", got.IdleTimeout)
	}
	zero := TimeoutsFromSeconds(0, 0)
	if zero.Timeout != 0 || zero.IdleTimeout != 0 {
		t.Fatalf("zero: %+v", zero)
	}
}

func TestBackendTimeoutsContext(t *testing.T) {
	t.Parallel()
	ctx := WithBackendTimeouts(context.Background(), BackendTimeouts{Timeout: time.Second})
	got, ok := BackendTimeoutsFromContext(ctx)
	if !ok || got.Timeout != time.Second {
		t.Fatalf("got %+v ok=%v", got, ok)
	}
}
