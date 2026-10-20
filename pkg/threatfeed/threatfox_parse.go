package threatfeed

import (
	"encoding/json"
	"fmt"
	"strings"
)

// ThreatFoxParsed holds network and file-hash indicators extracted from ThreatFox.
type ThreatFoxParsed struct {
	IPs    []string
	Hashes []string
}

func (p ThreatFoxParsed) Total() int {
	return len(p.IPs) + len(p.Hashes)
}

// ParseThreatFoxIOCRow extracts IPs and file hashes from one IOC row.
func ParseThreatFoxIOCRow(ioc, iocType string) ThreatFoxParsed {
	var out ThreatFoxParsed
	ioc = strings.TrimSpace(ioc)
	if ioc == "" {
		return out
	}
	if h := ExtractHashFromThreatFoxIOC(ioc, iocType); h != "" {
		out.Hashes = []string{h}
		return out
	}
	out.IPs = ExtractIPsFromThreatFoxIOC(ioc, iocType)
	return out
}

func mergeThreatFoxParsed(dst *ThreatFoxParsed, add ThreatFoxParsed) {
	dst.IPs = append(dst.IPs, add.IPs...)
	dst.Hashes = append(dst.Hashes, add.Hashes...)
}

// ExtractHashFromThreatFoxIOC returns normalized MD5/SHA256 hex from IOC value and type.
func ExtractHashFromThreatFoxIOC(ioc, iocType string) string {
	ioc = strings.TrimSpace(ioc)
	if ioc == "" {
		return ""
	}
	t := strings.ToLower(strings.TrimSpace(iocType))
	switch t {
	case "sha256_hash", "sha256":
		return NormalizeFileHash(ioc)
	case "md5_hash", "md5":
		return NormalizeFileHash(ioc)
	}
	return NormalizeFileHash(ioc)
}

// ParseThreatFoxCSV parses export CSV (ioc_value + ioc_type columns).
func ParseThreatFoxCSV(body []byte) (ThreatFoxParsed, error) {
	all, err := readThreatFoxCSVRecords(body)
	if err != nil {
		return ThreatFoxParsed{}, err
	}
	if len(all) < 2 {
		return ThreatFoxParsed{}, fmt.Errorf("threatfox csv: no data rows")
	}
	valIdx, typeIdx := -1, -1
	for i, h := range all[0] {
		h = strings.ToLower(strings.TrimSpace(strings.Trim(h, `"`)))
		switch h {
		case "ioc_value":
			valIdx = i
		case "ioc_type":
			typeIdx = i
		}
	}
	if valIdx < 0 {
		return ThreatFoxParsed{}, fmt.Errorf("threatfox csv: missing ioc_value column")
	}
	var merged ThreatFoxParsed
	for _, row := range all[1:] {
		if valIdx >= len(row) {
			continue
		}
		val := strings.Trim(strings.TrimSpace(row[valIdx]), `"`)
		typ := ""
		if typeIdx >= 0 && typeIdx < len(row) {
			typ = strings.Trim(strings.TrimSpace(row[typeIdx]), `"`)
		}
		mergeThreatFoxParsed(&merged, ParseThreatFoxIOCRow(val, typ))
	}
	out := ThreatFoxParsed{
		IPs:    ValidIPCIDR(UniqueIndicators(rowsToParsed(merged.IPs))),
		Hashes: UniqueFileHashes(merged.Hashes),
	}
	if out.Total() == 0 {
		return out, fmt.Errorf("threatfox csv: no IP/CIDR or file hash indicators")
	}
	return out, nil
}

// ParseThreatFoxAPI parses get_iocs JSON.
func ParseThreatFoxAPI(body []byte) (ThreatFoxParsed, error) {
	var env threatFoxAPIEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		return ThreatFoxParsed{}, err
	}
	if env.QueryStatus != "" && env.QueryStatus != "ok" {
		return ThreatFoxParsed{}, fmt.Errorf("threatfox api: query_status=%s", env.QueryStatus)
	}
	var merged ThreatFoxParsed
	for _, e := range env.Data {
		mergeThreatFoxParsed(&merged, ParseThreatFoxIOCRow(e.IOC, e.IOCType))
	}
	out := ThreatFoxParsed{
		IPs:    ValidIPCIDR(UniqueIndicators(rowsToParsed(merged.IPs))),
		Hashes: UniqueFileHashes(merged.Hashes),
	}
	if out.Total() == 0 {
		return out, fmt.Errorf("threatfox api: no IP/CIDR or file hash indicators")
	}
	return out, nil
}

func trimBOMBytes(b []byte) []byte {
	if len(b) >= 3 && b[0] == 0xef && b[1] == 0xbb && b[2] == 0xbf {
		return b[3:]
	}
	return b
}
