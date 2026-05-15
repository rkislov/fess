package threatfeed

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"strings"
)

// ParsedRow is one indicator optionally tagged with a logical source name (vendor / feed family).
type ParsedRow struct {
	Indicator string
	Source    string
}

var errNoIndicators = errors.New("threatfeed: no indicators parsed")

// ParseFeedBody parses remote feed bytes into rows (before allowlist filtering).
func ParseFeedBody(body []byte, format, csvIndicatorCol, csvSourceCol string) ([]ParsedRow, error) {
	body = bytes.TrimPrefix(body, []byte{0xef, 0xbb, 0xbf})
	format = strings.ToLower(strings.TrimSpace(format))
	if format == "" || format == "auto" {
		format = sniffFormat(body)
	}
	switch format {
	case "plain", "txt", "iplist":
		return parsePlain(body)
	case "ndjson":
		return parseNDJSON(body)
	case "csv":
		return ParseCSV(body, csvIndicatorCol, csvSourceCol)
	default:
		return nil, errors.New("threatfeed: unknown format")
	}
}

func sniffFormat(body []byte) string {
	s := strings.TrimSpace(string(body))
	if s == "" {
		return "plain"
	}
	firstNL := strings.IndexByte(s, '\n')
	firstLine := strings.TrimSpace(s)
	if firstNL >= 0 {
		firstLine = strings.TrimSpace(s[:firstNL])
	}
	fl := strings.ToLower(firstLine)
	if strings.HasPrefix(strings.TrimSpace(firstLine), "{") {
		return "ndjson"
	}
	if strings.Contains(fl, "indicator") || strings.Contains(fl, "ioc") || strings.Contains(fl, "\"ip\"") ||
		(strings.Contains(firstLine, ",") && (strings.Contains(fl, "source") || strings.Contains(fl, "feed") || strings.Contains(fl, "provider"))) {
		return "csv"
	}
	if strings.Count(firstLine, ",") >= 1 {
		return "csv"
	}
	return "plain"
}

func parsePlain(body []byte) ([]ParsedRow, error) {
	var out []ParsedRow
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Strip inline comments common in firewall lists.
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		out = append(out, ParsedRow{Indicator: line, Source: ""})
	}
	return out, nil
}

func parseNDJSON(body []byte) ([]ParsedRow, error) {
	var out []ParsedRow
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var obj map[string]json.RawMessage
		if err := json.Unmarshal([]byte(line), &obj); err != nil {
			continue
		}
		ind := firstString(obj, []string{"indicator", "ioc", "ip", "value", "addr", "cidr"})
		if ind == "" {
			continue
		}
		src := firstString(obj, []string{"source", "sources", "feed", "provider", "vendor"})
		out = append(out, ParsedRow{Indicator: strings.TrimSpace(ind), Source: strings.TrimSpace(src)})
	}
	return out, nil
}

func firstString(obj map[string]json.RawMessage, keys []string) string {
	lk := make(map[string]json.RawMessage, len(obj))
	for k, v := range obj {
		lk[strings.ToLower(strings.TrimSpace(k))] = v
	}
	for _, want := range keys {
		if raw, ok := lk[strings.ToLower(want)]; ok {
			var s string
			if err := json.Unmarshal(raw, &s); err == nil {
				return s
			}
		}
	}
	return ""
}

// ParseCSV parses with header row; columns chosen by names or positional defaults (0=indicator,1=source).
func ParseCSV(body []byte, indicatorCol, sourceCol string) ([]ParsedRow, error) {
	r := csv.NewReader(strings.NewReader(string(body)))
	r.TrimLeadingSpace = true
	all, err := r.ReadAll()
	if err != nil {
		return nil, err
	}
	if len(all) < 1 {
		return nil, errNoIndicators
	}
	header := all[0]
	indIdx, srcIdx := -1, -1
	indLower := strings.ToLower(strings.TrimSpace(indicatorCol))
	srcLower := strings.ToLower(strings.TrimSpace(sourceCol))
	for i, h := range header {
		h = strings.ToLower(strings.TrimSpace(h))
		if indLower != "" && h == indLower {
			indIdx = i
		}
		if srcLower != "" && h == srcLower {
			srcIdx = i
		}
		if indicatorCol == "" {
			switch h {
			case "indicator", "ioc", "ip", "ipv4", "ipv6", "cidr", "address", "value":
				if indIdx < 0 {
					indIdx = i
				}
			}
		}
		if sourceCol == "" {
			switch h {
			case "source", "sources", "feed", "provider", "vendor":
				if srcIdx < 0 {
					srcIdx = i
				}
			}
		}
	}
	if indIdx < 0 {
		if len(header) > 0 {
			indIdx = 0
		}
		if srcIdx < 0 && len(header) > 1 {
			srcIdx = 1
		}
	}
	if indIdx < 0 {
		return nil, errNoIndicators
	}
	var out []ParsedRow
	for _, row := range all[1:] {
		if indIdx >= len(row) {
			continue
		}
		ind := strings.TrimSpace(row[indIdx])
		if ind == "" {
			continue
		}
		src := ""
		if srcIdx >= 0 && srcIdx < len(row) {
			src = strings.TrimSpace(row[srcIdx])
		}
		out = append(out, ParsedRow{Indicator: ind, Source: src})
	}
	return out, nil
}

// FilterBySources keeps rows whose Source is in allow (case-insensitive), or rows with unknown source
// when allow is empty. When allow is non-empty, plain rows without a source tag are skipped.
func FilterBySources(rows []ParsedRow, allow map[string]struct{}) []ParsedRow {
	if allow == nil || len(allow) == 0 {
		return rows
	}
	var out []ParsedRow
	for _, row := range rows {
		tag := strings.ToLower(strings.TrimSpace(row.Source))
		if _, ok := allow[tag]; ok {
			out = append(out, row)
			continue
		}
	}
	return out
}

// UniqueIndicators returns de-duplicated indicator strings (trimmed).
func UniqueIndicators(rows []ParsedRow) []string {
	seen := make(map[string]struct{})
	var list []string
	for _, row := range rows {
		val := strings.TrimSpace(row.Indicator)
		if val == "" {
			continue
		}
		key := strings.ToLower(val)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		list = append(list, val)
	}
	return list
}
