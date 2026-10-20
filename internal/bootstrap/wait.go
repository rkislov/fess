package bootstrap

import (
	"context"
	"fmt"
	"log"
	"time"
)

// RetryUntil calls fn until it returns nil or ctx is done. Logs each failure.
func RetryUntil(ctx context.Context, desc string, interval time.Duration, fn func() error) error {
	var last error
	for attempt := 1; ; attempt++ {
		err := fn()
		if err == nil {
			if attempt > 1 {
				log.Printf("%s: ready after %d attempt(s)", desc, attempt)
			}
			return nil
		}
		last = err
		select {
		case <-ctx.Done():
			return fmt.Errorf("%s: %w (last error: %v)", desc, ctx.Err(), last)
		case <-time.After(interval):
			if attempt == 1 || attempt%10 == 0 {
				log.Printf("%s: waiting (attempt %d): %v", desc, attempt, last)
			}
		}
	}
}
