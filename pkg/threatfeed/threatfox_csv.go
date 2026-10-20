package threatfeed

import (
	"encoding/csv"
	"fmt"
	"strings"
)

// filterThreatFoxCSVBody drops ThreatFox comment banners and keeps the header row
// (often embedded as # "first_seen_utc","ioc_value",...) plus data lines.
func filterThreatFoxCSVBody(body []byte) string {
	var out strings.Builder
	for _, line := range strings.Split(string(trimBOMBytes(body)), "\n") {
		line = strings.TrimRight(line, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, "#") {
			rest := strings.TrimSpace(strings.TrimPrefix(trimmed, "#"))
			if rest == "" {
				continue
			}
			if strings.Contains(strings.ToLower(rest), "ioc_value") {
				out.WriteString(rest)
				out.WriteByte('\n')
			}
			continue
		}
		out.WriteString(line)
		out.WriteByte('\n')
	}
	return out.String()
}

func readThreatFoxCSVRecords(body []byte) ([][]string, error) {
	filtered := filterThreatFoxCSVBody(body)
	if strings.TrimSpace(filtered) == "" {
		return nil, fmt.Errorf("threatfox csv: no CSV content after skipping comments")
	}
	r := csv.NewReader(strings.NewReader(filtered))
	r.LazyQuotes = true
	r.TrimLeadingSpace = true
	r.FieldsPerRecord = -1
	return r.ReadAll()
}
