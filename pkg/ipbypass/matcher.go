package ipbypass

import (
	"net/netip"
	"strings"
	"time"

	"fence/pkg/threatfeed"
)

// Entry is one bypass row loaded from Postgres.
type Entry struct {
	CIDR      string
	ExpiresAt *time.Time
}

// Matcher holds active bypass prefixes and single IPs.
type Matcher struct {
	m *threatfeed.Matcher
}

func NewMatcher(entries []Entry, now time.Time) (*Matcher, error) {
	var lines []string
	for _, e := range entries {
		if e.ExpiresAt != nil && !e.ExpiresAt.After(now) {
			continue
		}
		c := strings.TrimSpace(e.CIDR)
		if c != "" {
			lines = append(lines, c)
		}
	}
	if len(lines) == 0 {
		return &Matcher{}, nil
	}
	m, err := threatfeed.NewMatcher(lines)
	if err != nil {
		return nil, err
	}
	return &Matcher{m: m}, nil
}

func (m *Matcher) Contains(clientHost string) bool {
	if m == nil || m.m == nil {
		return false
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(clientHost))
	if err != nil || !addr.IsValid() {
		return false
	}
	return m.m.Contains(addr.Unmap())
}

func (m *Matcher) Size() int {
	if m == nil || m.m == nil {
		return 0
	}
	return m.m.Size()
}
