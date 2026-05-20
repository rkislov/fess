package threatfeed

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
)

const (
	ThreatFoxProvider     = "threatfox"
	ThreatFoxAPIEndpoint  = "https://threatfox-api.abuse.ch/api/v1/"
	ThreatFoxFullExportV2 = "https://threatfox-api.abuse.ch/v2/files/exports/%s/full.csv.zip"
)

// ExtractIPsFromThreatFoxIOC returns parsable IPs/CIDRs from a ThreatFox IOC value and type.
func ExtractIPsFromThreatFoxIOC(ioc, iocType string) []string {
	ioc = strings.TrimSpace(ioc)
	if ioc == "" {
		return nil
	}
	t := strings.ToLower(strings.TrimSpace(iocType))
	switch t {
	case "ip":
		if a, ok := normalizeThreatFoxIP(ioc); ok {
			return []string{a}
		}
	case "ip:port":
		host, _, err := net.SplitHostPort(ioc)
		if err != nil {
			if i := strings.LastIndex(ioc, ":"); i > 0 {
				host = ioc[:i]
			} else {
				return nil
			}
		}
		if a, ok := normalizeThreatFoxIP(host); ok {
			return []string{a}
		}
	}
	return nil
}

func normalizeThreatFoxIP(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", false
	}
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return "", false
		}
		return p.Masked().String(), true
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return "", false
	}
	return a.Unmap().String(), true
}

// IPsFromThreatFoxCSV parses ThreatFox export CSV into IP/CIDR strings only (legacy helper).
func IPsFromThreatFoxCSV(body []byte) ([]string, error) {
	p, err := ParseThreatFoxCSV(body)
	if err != nil {
		return nil, err
	}
	if len(p.IPs) == 0 {
		return nil, fmt.Errorf("threatfox csv: no IP/CIDR indicators found")
	}
	return p.IPs, nil
}

type threatFoxAPIEnvelope struct {
	QueryStatus string              `json:"query_status"`
	Data        []threatFoxAPIEntry `json:"data"`
}

type threatFoxAPIEntry struct {
	IOC     string `json:"ioc"`
	IOCType string `json:"ioc_type"`
}

// IPsFromThreatFoxAPI parses Community API get_iocs JSON into IPs only (legacy helper).
func IPsFromThreatFoxAPI(body []byte) ([]string, error) {
	p, err := ParseThreatFoxAPI(body)
	if err != nil {
		return nil, err
	}
	if len(p.IPs) == 0 {
		return nil, fmt.Errorf("threatfox api: no IP/CIDR indicators in response")
	}
	return p.IPs, nil
}

func rowsToParsed(list []string) []ParsedRow {
	out := make([]ParsedRow, 0, len(list))
	for _, s := range list {
		out = append(out, ParsedRow{Indicator: s})
	}
	return out
}
