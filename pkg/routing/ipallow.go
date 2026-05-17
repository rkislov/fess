package routing

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
)

const (
	IPAllowNone    = "none"
	IPAllowPrivate = "private"
	IPAllowCustom  = "custom"
)

// PrivateNetworkPrefixes are RFC1918, loopback, link-local, and IPv6 ULA/link-local.
var PrivateNetworkPrefixes = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
}

// ParseAllowedCIDRsJSON decodes a JSON array of CIDR or host strings.
func ParseAllowedCIDRsJSON(raw string) ([]netip.Prefix, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "[]" || raw == "null" {
		return nil, nil
	}
	var list []string
	if err := json.Unmarshal([]byte(raw), &list); err != nil {
		return nil, fmt.Errorf("allowed_cidrs: %w", err)
	}
	return ParsePrefixList(list)
}

// ParsePrefixList parses CIDR strings or single IPs into prefixes.
func ParsePrefixList(list []string) ([]netip.Prefix, error) {
	if len(list) == 0 {
		return nil, nil
	}
	var out []netip.Prefix
	for _, raw := range list {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		var pfx netip.Prefix
		var err error
		if strings.Contains(raw, "/") {
			pfx, err = netip.ParsePrefix(raw)
			if err != nil {
				return nil, fmt.Errorf("%q: %w", raw, err)
			}
			pfx = pfx.Masked()
		} else {
			a, aerr := netip.ParseAddr(raw)
			if aerr != nil {
				return nil, fmt.Errorf("%q: %w", raw, aerr)
			}
			a = a.Unmap()
			bits := 32
			if a.Is6() {
				bits = 128
			}
			pfx = netip.PrefixFrom(a, bits)
			if !pfx.IsValid() {
				return nil, fmt.Errorf("%q: invalid prefix", raw)
			}
		}
		out = append(out, pfx)
	}
	return out, nil
}

// EncodeAllowedCIDRsJSON stores a CIDR list for the DB column.
func EncodeAllowedCIDRsJSON(list []string) (string, error) {
	if len(list) == 0 {
		return "[]", nil
	}
	b, err := json.Marshal(list)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// ClientIPAllowed reports whether clientHost may use a backend with the given IP gate.
func ClientIPAllowed(clientHost, mode string, custom []netip.Prefix) bool {
	mode = strings.TrimSpace(strings.ToLower(mode))
	if mode == "" || mode == IPAllowNone {
		return true
	}
	addr, ok := parseClientAddr(clientHost)
	if !ok {
		return false
	}
	var prefixes []netip.Prefix
	switch mode {
	case IPAllowPrivate:
		prefixes = PrivateNetworkPrefixes
	case IPAllowCustom:
		prefixes = custom
	default:
		return true
	}
	return prefixListContains(prefixes, addr)
}

func parseClientAddr(host string) (netip.Addr, bool) {
	host = strings.TrimSpace(host)
	if host == "" {
		return netip.Addr{}, false
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, false
	}
	a = a.Unmap()
	return a, a.IsValid()
}

func prefixListContains(list []netip.Prefix, addr netip.Addr) bool {
	for _, p := range list {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}
