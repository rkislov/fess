package threatfeed

import (
	"net/netip"
	"strings"
)

// ValidIPCIDR returns only normalized parsable IPs and CIDRs.
func ValidIPCIDR(lines []string) []string {
	var out []string
	for _, s := range lines {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if strings.Contains(s, "/") {
			p, err := netip.ParsePrefix(s)
			if err != nil {
				continue
			}
			out = append(out, p.Masked().String())
			continue
		}
		a, err := netip.ParseAddr(s)
		if err != nil {
			continue
		}
		out = append(out, a.Unmap().String())
	}
	return out
}
