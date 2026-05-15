package policy

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"
)

type rawPolicy struct {
	ID       string
	Name     string
	Mode     string
	Priority int
}

type rawRule struct {
	ID            string
	Name          string
	Action        string
	Priority      int
	ConditionJSON []byte
	TransformJSON []byte
}

func LoadActiveSnapshot(ctx context.Context, db *sql.DB) (Snapshot, error) {
	const qPolicies = `
SELECT id::text, name, mode, priority
FROM policies
WHERE enabled = TRUE
ORDER BY priority ASC, created_at ASC`

	rows, err := db.QueryContext(ctx, qPolicies)
	if err != nil {
		return Snapshot{}, fmt.Errorf("query policies: %w", err)
	}
	defer rows.Close()

	out := Snapshot{Version: 1}
	for rows.Next() {
		var rp rawPolicy
		if err := rows.Scan(&rp.ID, &rp.Name, &rp.Mode, &rp.Priority); err != nil {
			return Snapshot{}, fmt.Errorf("scan policy: %w", err)
		}
		cp, err := loadCompiledPolicy(ctx, db, rp)
		if err != nil {
			return Snapshot{}, err
		}
		out.Policies = append(out.Policies, cp)
	}
	if err := rows.Err(); err != nil {
		return Snapshot{}, fmt.Errorf("iterate policies: %w", err)
	}

	sort.Slice(out.Policies, func(i, j int) bool { return out.Policies[i].Priority < out.Policies[j].Priority })
	return out, nil
}

func loadCompiledPolicy(ctx context.Context, db *sql.DB, rp rawPolicy) (CompiledPolicy, error) {
	const qRules = `
SELECT id::text, name, action, priority, condition_json, COALESCE(transform_json, '{}'::jsonb)
FROM rules
WHERE policy_id = $1::uuid AND enabled = TRUE
ORDER BY priority ASC, created_at ASC`

	rows, err := db.QueryContext(ctx, qRules, rp.ID)
	if err != nil {
		return CompiledPolicy{}, fmt.Errorf("query rules for %s: %w", rp.ID, err)
	}
	defer rows.Close()

	cp := CompiledPolicy{
		ID:       rp.ID,
		Name:     rp.Name,
		Mode:     rp.Mode,
		Priority: rp.Priority,
	}

	for rows.Next() {
		var rr rawRule
		if err := rows.Scan(&rr.ID, &rr.Name, &rr.Action, &rr.Priority, &rr.ConditionJSON, &rr.TransformJSON); err != nil {
			return CompiledPolicy{}, fmt.Errorf("scan rule: %w", err)
		}

		cr, err := compileRule(rr)
		if err != nil {
			return CompiledPolicy{}, fmt.Errorf("compile rule %s: %w", rr.ID, err)
		}
		cp.Rules = append(cp.Rules, cr)
	}
	if err := rows.Err(); err != nil {
		return CompiledPolicy{}, fmt.Errorf("iterate rules: %w", err)
	}
	return cp, nil
}

type ruleCondition struct {
	Method             string            `json:"method"`
	PathExact          string            `json:"path_exact"`
	PathPrefix         string            `json:"path_prefix"`
	PathContains       string            `json:"path_contains"`
	PathRegex          string            `json:"path_regex"`
	BodyContains       string            `json:"body_contains"`
	RequestURIContains string            `json:"request_uri_contains"`
	QueryEquals        map[string]string `json:"query_equals"`
	HeaderContains     map[string]string `json:"header_contains"`
	ClientIPIn         []string          `json:"client_ip_in"`
	ClientIPNotIn      []string          `json:"client_ip_not_in"`
}

type ruleTransform struct {
	RedirectURL string `json:"redirect_url"`
	ReplaceFrom string `json:"replace_from"`
	ReplaceTo   string `json:"replace_to"`
}

func compileRule(rr rawRule) (CompiledRule, error) {
	var cond ruleCondition
	if len(rr.ConditionJSON) > 0 {
		if err := json.Unmarshal(rr.ConditionJSON, &cond); err != nil {
			return CompiledRule{}, fmt.Errorf("decode condition_json: %w", err)
		}
	}
	var tr ruleTransform
	if len(rr.TransformJSON) > 0 {
		if err := json.Unmarshal(rr.TransformJSON, &tr); err != nil {
			return CompiledRule{}, fmt.Errorf("decode transform_json: %w", err)
		}
	}

	cr := CompiledRule{
		ID:                 rr.ID,
		Name:               rr.Name,
		Action:             rr.Action,
		Priority:           rr.Priority,
		PathExact:          cond.PathExact,
		PathPrefix:         strings.TrimSpace(cond.PathPrefix),
		PathContains:       cond.PathContains,
		PathRegexRaw:       cond.PathRegex,
		Method:             cond.Method,
		BodyContains:       cond.BodyContains,
		RequestURIContains: cond.RequestURIContains,
		QueryEquals:        cond.QueryEquals,
		HeaderContain:      cond.HeaderContains,
		RedirectURL:        tr.RedirectURL,
		ReplaceFrom:        tr.ReplaceFrom,
		ReplaceTo:          tr.ReplaceTo,
	}

	ipIn, err := parsePrefixList(cond.ClientIPIn)
	if err != nil {
		return CompiledRule{}, fmt.Errorf("client_ip_in: %w", err)
	}
	cr.ClientIPIn = ipIn
	ipNotIn, err := parsePrefixList(cond.ClientIPNotIn)
	if err != nil {
		return CompiledRule{}, fmt.Errorf("client_ip_not_in: %w", err)
	}
	cr.ClientIPNotIn = ipNotIn

	if cond.PathRegex != "" {
		re, err := regexp.Compile(cond.PathRegex)
		if err != nil {
			return CompiledRule{}, fmt.Errorf("invalid path_regex: %w", err)
		}
		cr.PathRegex = re
	}
	return cr, nil
}

func parsePrefixList(list []string) ([]netip.Prefix, error) {
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
