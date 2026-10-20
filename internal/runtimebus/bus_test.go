package runtimebus

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestAtomicCountersExpiryAndNotifications(t *testing.T) {
	ctx := context.Background()
	c := New()
	defer c.Close()
	s := c.Subscribe(ctx, "policies")
	defer s.Close()
	if err := c.Publish(ctx, "policies", "reload").Err(); err != nil {
		t.Fatal(err)
	}
	select {
	case msg := <-s.Channel():
		if msg.Payload != "reload" {
			t.Fatal(msg)
		}
	case <-time.After(time.Second):
		t.Fatal("notification lost")
	}
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p := c.Pipeline()
			p.Incr(ctx, "counter")
			p.Expire(ctx, "counter", 30*time.Millisecond)
			if _, err := p.Exec(ctx); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	p := c.Pipeline()
	n := p.Incr(ctx, "counter")
	p.Expire(ctx, "counter", 30*time.Millisecond)
	p.Exec(ctx)
	if n.n != 101 {
		t.Fatalf("lost increments: %d", n.n)
	}
	time.Sleep(50 * time.Millisecond)
	p = c.Pipeline()
	n = p.Incr(ctx, "counter")
	p.Expire(ctx, "counter", time.Second)
	p.Exec(ctx)
	if n.n != 1 {
		t.Fatalf("counter not expired: %d", n.n)
	}
}
