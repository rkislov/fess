package threatfeed

import (
	"encoding/json"
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
			// fallback: last colon for simple IPv4:port
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

// IPsFromThreatFoxCSV parses ThreatFox export CSV (full or recent) into IP/CIDR strings.
func IPsFromThreatFoxCSV(body []byte) ([]string, error) {
	rows, err := ParseCSV(body, "ioc_value", "")
	if err != nil {
		return nil, err
	}
	var raw []string
	for _, row := range rows {
		val := strings.TrimSpace(row.Indicator)
		if val == "" {
			continue
		}
		// CSV rows are IOC values; infer type from shape when not tagged.
		if strings.Contains(val, ":") && !strings.Contains(val, "/") {
			if host, _, err := net.SplitHostPort(val); err == nil {
				raw = append(raw, ExtractIPsFromThreatFoxIOC(host, "ip")...)
				continue
			}
		}
		if a, ok := normalizeThreatFoxIP(val); ok {
			raw = append(raw, a)
			continue
		}
		raw = append(raw, ExtractIPsFromThreatFoxIOC(val, "ip:port")...)
	}
	ips := ValidIPCIDR(UniqueIndicators(rowsToParsed(raw)))
	if len(ips) == 0 {
		return nil, fmt.Errorf("threatfox csv: no IP/CIDR indicators found")
	}
	return ips, nil
}

func rowsToParsed(list []string) []ParsedRow {
	out := make([]ParsedRow, 0, len(list))
	for _, s := range list {
		out = append(out, ParsedRow{Indicator: s})
	}
	return out
}

type threatFoxAPIEnvelope struct {
	QueryStatus string              `json:"query_status"`
	Data        []threatFoxAPIEntry `json:"data"`
}

type threatFoxAPIEntry struct {
	IOC     string `json:"ioc"`
	IOCType string `json:"ioc_type"`
}

// IPsFromThreatFoxAPI parses Community API get_iocs JSON response.
func IPsFromThreatFoxAPI(body []byte) ([]string, error) {
	var env threatFoxAPIEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, err
	}
	if env.QueryStatus != "" && env.QueryStatus != "ok" {
		return nil, fmt.Errorf("threatfox api: query_status=%s", env.QueryStatus)
	}
	var raw []string
	for _, e := range env.Data {
		raw = append(raw, ExtractIPsFromThreatFoxIOC(e.IOC, e.IOCType)...)
	}
	ips := ValidIPCIDR(UniqueIndicators(rowsToParsed(raw)))
	if len(ips) == 0 {
		return nil, fmt.Errorf("threatfox api: no IP/CIDR indicators in response")
	}
	return ips, nil
}
