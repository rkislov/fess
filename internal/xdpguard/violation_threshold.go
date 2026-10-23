package xdpguard

import (
	"container/list"
	"net/netip"
	"time"
)

type violationEntry struct {
	ip      netip.Addr
	started time.Time
	count   uint32
}

// violationThreshold is owned by the single socket reader. LRU bounds memory
// even when WAF block events arrive from many distinct addresses.
type violationThreshold struct {
	min      uint32
	window   time.Duration
	capacity int
	entries  map[netip.Addr]*list.Element
	lru      *list.List
}

func newViolationThreshold(min, seconds uint32, capacity int) *violationThreshold {
	if min == 0 {
		min = 1
	}
	if seconds == 0 {
		seconds = 60
	}
	return &violationThreshold{min: min, window: time.Duration(seconds) * time.Second, capacity: capacity, entries: make(map[netip.Addr]*list.Element), lru: list.New()}
}
func (v *violationThreshold) record(ip netip.Addr, now time.Time) bool {
	if v.min <= 1 {
		return true
	}
	e := v.entries[ip]
	if e == nil {
		if len(v.entries) >= v.capacity {
			old := v.lru.Back()
			delete(v.entries, old.Value.(*violationEntry).ip)
			v.lru.Remove(old)
		}
		e = v.lru.PushFront(&violationEntry{ip: ip, started: now})
		v.entries[ip] = e
	}
	item := e.Value.(*violationEntry)
	v.lru.MoveToFront(e)
	if now.Sub(item.started) >= v.window {
		item.started = now
		item.count = 0
	}
	item.count++
	if item.count >= v.min {
		item.count = 0
		item.started = now
		return true
	}
	return false
}
