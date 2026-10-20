package botprotection

import (
	"fmt"
	"strconv"
	"strings"
)

// ParseASNList parses ASN numbers (one per line: 15169 or AS15169).
func ParseASNList(body []byte) ([]uint, error) {
	var out []uint
	seen := make(map[uint]struct{})
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		s := strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToUpper(s), "AS") {
			s = strings.TrimSpace(s[2:])
		}
		n, err := strconv.ParseUint(s, 10, 32)
		if err != nil || n == 0 {
			return nil, fmt.Errorf("invalid ASN line: %q", line)
		}
		u := uint(n)
		if _, ok := seen[u]; ok {
			continue
		}
		seen[u] = struct{}{}
		out = append(out, u)
	}
	return out, nil
}
