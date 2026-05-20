package main

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

const logSearchMaxLen = 200

// queryBuilder assembles parameterized WHERE fragments (AND-joined).
type queryBuilder struct {
	parts []string
	args  []any
}

func newQueryBuilder() *queryBuilder {
	return &queryBuilder{}
}

func (b *queryBuilder) add(cond string, args ...any) {
	b.parts = append(b.parts, cond)
	b.args = append(b.args, args...)
}

func (b *queryBuilder) whereSQL() string {
	if len(b.parts) == 0 {
		return ""
	}
	return "WHERE " + strings.Join(b.parts, " AND ")
}

func (b *queryBuilder) argsSlice() []any {
	return b.args
}

func parseLogSearch(r *http.Request) string {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	if q == "" {
		q = strings.TrimSpace(r.URL.Query().Get("search"))
	}
	if len(q) > logSearchMaxLen {
		q = q[:logSearchMaxLen]
	}
	return q
}

func ilikePattern(q string) string {
	q = strings.TrimSpace(q)
	if q == "" {
		return ""
	}
	var b strings.Builder
	b.WriteByte('%')
	for _, r := range q {
		switch r {
		case '%', '_', '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('%')
	return b.String()
}

// parseOptionalHours: hours=0 or empty with allowAll → no time filter; else created_at >= now-hours.
func parseOptionalHours(raw string, defaultHours int, allowAll bool) (since *time.Time, useSince bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		if defaultHours <= 0 {
			if allowAll {
				return nil, false
			}
			defaultHours = 168
		}
		if defaultHours <= 0 {
			return nil, false
		}
		t := time.Now().UTC().Add(-time.Duration(defaultHours) * time.Hour)
		return &t, true
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		t := time.Now().UTC().Add(-time.Duration(defaultHours) * time.Hour)
		return &t, defaultHours > 0
	}
	if n <= 0 {
		if allowAll {
			return nil, false
		}
		t := time.Now().UTC().Add(-time.Duration(defaultHours) * time.Hour)
		return &t, defaultHours > 0
	}
	if n > 8760 {
		n = 8760
	}
	t := time.Now().UTC().Add(-time.Duration(n) * time.Hour)
	return &t, true
}

func (b *queryBuilder) addSince(since *time.Time, useSince bool) {
	if useSince && since != nil {
		b.add(fmt.Sprintf("created_at >= $%d", len(b.args)+1), *since)
	}
}

func (b *queryBuilder) addILIKEAny(search string, exprs ...string) {
	pattern := ilikePattern(search)
	if pattern == "" || len(exprs) == 0 {
		return
	}
	var ors []string
	for _, ex := range exprs {
		ors = append(ors, fmt.Sprintf("%s ILIKE $%d", ex, len(b.args)+1))
	}
	b.add("("+strings.Join(ors, " OR ")+")", pattern)
}

func (b *queryBuilder) addFilterEq(column, value string) {
	value = strings.TrimSpace(value)
	if value == "" {
		return
	}
	b.add(fmt.Sprintf("%s = $%d", column, len(b.args)+1), value)
}

func (b *queryBuilder) addFilterILIKE(column, value string) {
	value = strings.TrimSpace(value)
	if value == "" {
		return
	}
	pattern := ilikePattern(value)
	if pattern == "" {
		return
	}
	b.add(fmt.Sprintf("COALESCE(%s,'') ILIKE $%d", column, len(b.args)+1), pattern)
}

func queryParam(r *http.Request, key string) string {
	return strings.TrimSpace(r.URL.Query().Get(key))
}

func validateWafLogFilters(r *http.Request) error {
	action := queryParam(r, "action")
	if action != "" && !logActionParamOK(action) {
		return errors.New("invalid action filter (use letters, digits, underscore)")
	}
	if rid := queryParam(r, "rule_id"); rid != "" {
		if _, err := uuid.Parse(rid); err != nil {
			return errors.New("invalid rule_id")
		}
	}
	if pid := queryParam(r, "policy_id"); pid != "" {
		if _, err := uuid.Parse(pid); err != nil {
			return errors.New("invalid policy_id")
		}
	}
	return nil
}

func buildWafLogsQuery(r *http.Request, defaultHours int) *queryBuilder {
	q := r.URL.Query()
	b := newQueryBuilder()
	since, useSince := parseOptionalHours(q.Get("hours"), defaultHours, true)
	b.addSince(since, useSince)

	b.addFilterEq("action", queryParam(r, "action"))
	if rid := queryParam(r, "rule_id"); rid != "" {
		b.add("rule_id::text = $"+strconv.Itoa(len(b.args)+1), rid)
	}
	if pid := queryParam(r, "policy_id"); pid != "" {
		b.add("policy_id::text = $"+strconv.Itoa(len(b.args)+1), pid)
	}
	b.addFilterILIKE("source_ip", queryParam(r, "source_ip"))
	b.addFilterEq("method", queryParam(r, "method"))
	b.addFilterILIKE("host", queryParam(r, "host"))
	b.addFilterILIKE("path", queryParam(r, "path"))
	b.addFilterILIKE("request_id", queryParam(r, "request_id"))

	search := parseLogSearch(r)
	b.addILIKEAny(search,
		"id::text",
		"request_id",
		"policy_id::text",
		"rule_id::text",
		"action",
		"source_ip",
		"method",
		"path",
		"host",
		"ai_analysis",
		"details::text",
	)
	return b
}

func buildProxyAccessLogsQuery(r *http.Request) *queryBuilder {
	b := newQueryBuilder()
	since, useSince := parseOptionalHours(r.URL.Query().Get("hours"), 168, true)
	b.addSince(since, useSince)

	b.addFilterEq("outcome", queryParam(r, "outcome"))
	b.addFilterEq("method", queryParam(r, "method"))
	b.addFilterILIKE("host", queryParam(r, "host"))
	b.addFilterILIKE("path", queryParam(r, "path"))
	b.addFilterILIKE("client_ip", queryParam(r, "client_ip"))
	b.addFilterILIKE("tcp_peer", queryParam(r, "tcp_peer"))
	b.addFilterILIKE("backend_name", queryParam(r, "backend_name"))
	b.addFilterEq("protocol", queryParam(r, "protocol"))
	b.addFilterEq("country_code", queryParam(r, "country_code"))
	b.addFilterILIKE("user_agent", queryParam(r, "user_agent"))

	search := parseLogSearch(r)
	b.addILIKEAny(search,
		"id::text",
		"host",
		"method",
		"path",
		"client_ip",
		"tcp_peer",
		"backend_name",
		"upstream_base",
		"outcome",
		"protocol",
		"country_code",
		"user_agent",
	)
	return b
}

func buildMalwareScanLogsQuery(r *http.Request, resultFilter string) *queryBuilder {
	b := newQueryBuilder()
	since, useSince := parseOptionalHours(r.URL.Query().Get("hours"), 168, true)
	b.addSince(since, useSince)

	if resultFilter != "" {
		b.addFilterEq("scan_result", resultFilter)
	}
	b.addFilterEq("scan_source", queryParam(r, "source"))
	b.addFilterEq("method", queryParam(r, "method"))
	b.addFilterILIKE("host", queryParam(r, "host"))
	b.addFilterILIKE("path", queryParam(r, "path"))
	b.addFilterILIKE("source_ip", queryParam(r, "source_ip"))
	b.addFilterILIKE("request_id", queryParam(r, "request_id"))
	b.addFilterILIKE("content_type", queryParam(r, "content_type"))

	search := parseLogSearch(r)
	b.addILIKEAny(search,
		"id::text",
		"request_id",
		"host",
		"method",
		"path",
		"content_type",
		"body_bytes::text",
		"scan_result",
		"scan_source",
		"detail",
		"source_ip",
	)
	return b
}
