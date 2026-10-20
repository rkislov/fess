// Package runtimebus provides process-local notifications and expiring counters.
// All FESS components share one Client. No network service is involved.
package runtimebus

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
)

type entry struct {
	value   int64
	expires time.Time
}
type Client struct {
	mu       sync.Mutex
	values   map[string]entry
	subs     map[*Subscription]bool
	done     chan struct{}
	once     sync.Once
	watchers sync.WaitGroup
}
type Message struct{ Channel, Payload string }
type Subscription struct {
	client     *Client
	channels   map[string]bool
	ch         chan *Message
	once       sync.Once
	registered bool
}
type Result struct {
	n   int64
	err error
}

func (r *Result) Err() error             { return r.err }
func (r *Result) Result() (int64, error) { return r.n, r.err }
func (r *Result) Int64() (int64, error)  { return r.n, r.err }
func New() *Client {
	c := &Client{values: make(map[string]entry), subs: make(map[*Subscription]bool), done: make(chan struct{})}
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-c.done:
				return
			case now := <-t.C:
				c.mu.Lock()
				for k, v := range c.values {
					if !v.expires.IsZero() && !now.Before(v.expires) {
						delete(c.values, k)
					}
				}
				c.mu.Unlock()
			}
		}
	}()
	return c
}
func (c *Client) Close() error {
	c.once.Do(func() {
		close(c.done)
		c.mu.Lock()
		for s, open := range c.subs {
			if open {
				close(s.ch)
				c.subs[s] = false
			}
		}
		c.mu.Unlock()
		c.watchers.Wait()
	})
	return nil
}

func (c *Client) get(key string) entry {
	e := c.values[key]
	if !e.expires.IsZero() && !time.Now().Before(e.expires) {
		delete(c.values, key)
		return entry{}
	}
	return e
}
func (c *Client) GetSet(ctx context.Context, key string, value any) *Result {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return &Result{err: err}
	}
	old := c.get(key)
	n, err := strconv.ParseInt(fmt.Sprint(value), 10, 64)
	if err != nil {
		return &Result{err: err}
	}
	c.values[key] = entry{value: n}
	return &Result{n: old.value}
}
func (c *Client) Expire(ctx context.Context, key string, ttl time.Duration) *Result {
	c.mu.Lock()
	defer c.mu.Unlock()
	e := c.get(key)
	e.expires = time.Now().Add(ttl)
	c.values[key] = e
	return &Result{err: ctx.Err()}
}
func (c *Client) Del(ctx context.Context, keys ...string) *Result {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, k := range keys {
		delete(c.values, k)
	}
	return &Result{err: ctx.Err()}
}

type ScanResult struct{ keys []string }
type Iterator struct {
	keys []string
	i    int
}

func (c *Client) Scan(ctx context.Context, cursor uint64, pattern string, count int64) *ScanResult {
	c.mu.Lock()
	defer c.mu.Unlock()
	var keys []string
	prefix := strings.TrimSuffix(pattern, "*")
	for k := range c.values {
		if strings.HasPrefix(k, prefix) {
			keys = append(keys, k)
		}
	}
	return &ScanResult{keys}
}
func (s *ScanResult) Iterator() *Iterator { return &Iterator{keys: s.keys} }
func (i *Iterator) Next(ctx context.Context) bool {
	if ctx.Err() != nil || i.i >= len(i.keys) {
		return false
	}
	i.i++
	return true
}
func (i *Iterator) Val() string { return i.keys[i.i-1] }
func (c *Client) Subscribe(ctx context.Context, channels ...string) *Subscription {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := &Subscription{client: c, channels: map[string]bool{}, ch: make(chan *Message, 128)}
	for _, v := range channels {
		s.channels[v] = true
	}
	select {
	case <-c.done:
		close(s.ch)
	default:
		c.subs[s] = true
		s.registered = true
		c.watchers.Add(1)
	}
	return s
}
func (s *Subscription) Channel() <-chan *Message { return s.ch }
func (s *Subscription) Close() error {
	s.once.Do(func() {
		s.client.mu.Lock()
		if s.client.subs[s] {
			close(s.ch)
		}
		delete(s.client.subs, s)
		s.client.mu.Unlock()
		if s.registered {
			s.client.watchers.Done()
		}
	})
	return nil
}

func (c *Client) Publish(ctx context.Context, channel string, payload any) *Result {
	c.mu.Lock()
	defer c.mu.Unlock()
	for s, open := range c.subs {
		if open && s.channels[channel] {
			select {
			case s.ch <- &Message{Channel: channel, Payload: fmt.Sprint(payload)}:
			case <-ctx.Done():
				return &Result{err: ctx.Err()}
			case <-c.done:
				return &Result{err: errors.New("runtime closed")}
			}
		}
	}
	return &Result{}
}

type operation struct {
	key    string
	ttl    time.Duration
	result *Result
}
type Pipeline struct {
	client *Client
	ops    []operation
}

func (c *Client) Pipeline() *Pipeline { return &Pipeline{client: c} }
func (p *Pipeline) Incr(ctx context.Context, key string) *Result {
	r := &Result{}
	p.ops = append(p.ops, operation{key: key, result: r})
	return r
}
func (p *Pipeline) Expire(ctx context.Context, key string, ttl time.Duration) *Result {
	r := &Result{}
	p.ops = append(p.ops, operation{key: key, ttl: ttl, result: r})
	return r
}
func (p *Pipeline) Exec(ctx context.Context) ([]*Result, error) {
	c := p.client
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	out := make([]*Result, 0, len(p.ops))
	for _, op := range p.ops {
		e := c.get(op.key)
		if op.ttl == 0 {
			e.value++
		} else {
			e.expires = time.Now().Add(op.ttl)
		}
		c.values[op.key] = e
		op.result.n = e.value
		out = append(out, op.result)
	}
	p.ops = nil
	return out, nil
}
