package threatfeed

import (
	"fmt"
	"net/netip"
	"strings"
)

// Matcher holds IPv4/IPv6 singles and prefixes for fast lookup.
type Matcher struct {
	singles map[netip.Addr]struct{}
	nets    []netip.Prefix
}

// NewMatcher builds a matcher from normalized indicator strings (IP or CIDR).
func NewMatcher(rows []string) (*Matcher, error) {
	singles := make(map[netip.Addr]struct{})
	var nets []netip.Prefix
	for _, raw := range rows {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if strings.Contains(raw, "/") {
			p, err := netip.ParsePrefix(raw)
			if err != nil {
				return nil, fmt.Errorf("prefix %q: %w", raw, err)
			}
			p = p.Masked()
			nets = append(nets, p)
			continue
		}
		a, err := netip.ParseAddr(raw)
		if err != nil {
			return nil, fmt.Errorf("addr %q: %w", raw, err)
		}
		singles[a] = struct{}{}
	}
	return &Matcher{singles: singles, nets: nets}, nil
}

// Contains reports whether addr matches any stored IP or prefix.
func (m *Matcher) Contains(addr netip.Addr) bool {
	if m == nil {
		return false
	}
	addr = addr.Unmap()
	if _, ok := m.singles[addr]; ok {
		return true
	}
	for _, p := range m.nets {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

func (m *Matcher) Size() int {
	if m == nil {
		return 0
	}
	return len(m.singles) + len(m.nets)
}
