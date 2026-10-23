package xdpguard

import (
	"net/netip"
	"testing"
	"time"
)

func TestViolationThresholdWindowAndMemoryBound(t *testing.T) {
	v := newViolationThreshold(3, 30, 2)
	a := netip.MustParseAddr("192.0.2.1")
	b := netip.MustParseAddr("192.0.2.2")
	c := netip.MustParseAddr("192.0.2.3")
	now := time.Now()
	if v.record(a, now) || v.record(a, now.Add(time.Second)) || !v.record(a, now.Add(2*time.Second)) {
		t.Fatal("threshold not enforced")
	}
	if v.record(a, now.Add(3*time.Second)) {
		t.Fatal("count not reset after ban")
	}
	if v.record(a, now.Add(32*time.Second)) || v.record(a, now.Add(33*time.Second)) {
		t.Fatal("expired window retained old violations")
	}
	if !v.record(a, now.Add(34*time.Second)) {
		t.Fatal("new window did not count")
	}
	v.record(b, now)
	v.record(c, now)
	if len(v.entries) != 2 || v.entries[a] != nil {
		t.Fatal("LRU did not bound source state")
	}
	if v.record(a, now) {
		t.Fatal("evicted source inherited another source's violations")
	}
	if !newViolationThreshold(0, 0, 2).record(a, now) {
		t.Fatal("legacy single-event default changed")
	}
}
