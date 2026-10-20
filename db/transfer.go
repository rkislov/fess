package db

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"math/big"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"
)

type TransferReport struct {
	Tables int
	Rows   int64
}

// TransferToPostgres copies a consistent SQLite snapshot into a fresh PostgreSQL
// schema. All destination writes and verification are in one transaction. Existing
// application data is never overwritten. No credentials are included in errors.
func TransferToPostgres(ctx context.Context, src, dst *sql.DB) (TransferReport, error) {
	var report TransferReport
	if !IsSQLite(src) || IsSQLite(dst) {
		return report, fmt.Errorf("migration requires SQLite source and PostgreSQL destination")
	}
	tables, err := transferTables(ctx, src)
	if err != nil {
		return report, err
	}
	source, err := src.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return report, err
	}
	defer source.Rollback()
	target, err := dst.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return report, err
	}
	defer target.Rollback()
	// Prevent concurrent FESS/database writers for the entire transfer.
	names := make([]string, len(tables))
	for i, t := range tables {
		names[i] = quoteIdent(t)
	}
	if _, err = target.ExecContext(ctx, "LOCK TABLE "+strings.Join(names, ",")+" IN ACCESS EXCLUSIVE MODE"); err != nil {
		return report, err
	}
	// A freshly migrated database contains only singleton defaults. Anything else
	// indicates a live destination and is rejected before any row is removed.
	for _, t := range tables {
		if strings.HasSuffix(t, "_settings") || strings.HasSuffix(t, "_sync_state") || t == "siem_export_cursors" {
			continue
		}
		var n int64
		if err = target.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+quoteIdent(t)).Scan(&n); err != nil {
			return report, err
		}
		if n != 0 {
			return report, fmt.Errorf("destination table %s contains data; use a fresh database", t)
		}
	}
	for i := len(tables) - 1; i >= 0; i-- {
		if _, err = target.ExecContext(ctx, "DELETE FROM "+quoteIdent(tables[i])); err != nil {
			return report, err
		}
	}
	for _, t := range tables {
		columns, types, err := postgresColumns(ctx, target, t)
		if err != nil {
			return report, err
		}
		sourceCols, e := source.QueryContext(ctx, `SELECT name FROM pragma_table_info($1)`, t)
		if e != nil {
			return report, e
		}
		sourceNames := map[string]bool{}
		for sourceCols.Next() {
			var name string
			if e = sourceCols.Scan(&name); e != nil {
				sourceCols.Close()
				return report, e
			}
			sourceNames[name] = true
		}
		e = sourceCols.Err()
		sourceCols.Close()
		if e != nil {
			return report, e
		}
		if len(sourceNames) != len(columns) {
			return report, fmt.Errorf("schema mismatch for %s; source and target column counts differ", t)
		}
		for _, name := range columns {
			if !sourceNames[name] {
				return report, fmt.Errorf("schema mismatch for %s.%s", t, name)
			}
		}
		quoted := make([]string, len(columns))
		params := make([]string, len(columns))
		for i, c := range columns {
			quoted[i] = quoteIdent(c)
			params[i] = fmt.Sprintf("$%d", i+1)
		}
		colSQL := strings.Join(quoted, ",")
		rows, err := source.QueryContext(ctx, "SELECT "+colSQL+" FROM "+quoteIdent(t))
		if err != nil {
			return report, err
		}
		insert, err := target.PrepareContext(ctx, "INSERT INTO "+quoteIdent(t)+" ("+colSQL+") VALUES ("+strings.Join(params, ",")+") RETURNING "+colSQL)
		if err != nil {
			rows.Close()
			return report, err
		}
		var count int64
		for rows.Next() {
			values := make([]any, len(columns))
			ptr := make([]any, len(columns))
			for i := range values {
				ptr[i] = &values[i]
			}
			if err = rows.Scan(ptr...); err != nil {
				break
			}
			for i := range values {
				values[i], err = normalizeCell(values[i], types[i])
				if err != nil {
					break
				}
			}
			if err != nil {
				break
			}
			actual := make([]any, len(columns))
			for i := range ptr {
				ptr[i] = &actual[i]
			}
			if err = insert.QueryRowContext(ctx, values...).Scan(ptr...); err != nil {
				break
			}
			for i := range values {
				got, e := normalizeCell(actual[i], types[i])
				if e != nil {
					err = e
					break
				}
				if !cellsEqual(values[i], got, types[i]) {
					err = fmt.Errorf("verification failed: %s.%s row %d", t, columns[i], count+1)
					break
				}
			}
			if err != nil {
				break
			}
			count++
		}
		if err == nil {
			err = rows.Err()
		}
		rows.Close()
		insert.Close()
		if err != nil {
			return report, fmt.Errorf("transfer %s: %w", t, err)
		}
		var destCount int64
		if err = target.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+quoteIdent(t)).Scan(&destCount); err != nil {
			return report, err
		}
		if destCount != count {
			return report, fmt.Errorf("count verification failed: %s", t)
		}
		// Preserve IDs while advancing sequence-backed log IDs beyond the copied max.
		for _, col := range columns {
			var sequence sql.NullString
			if err = target.QueryRowContext(ctx, `SELECT pg_get_serial_sequence($1,$2)`, t, col).Scan(&sequence); err != nil {
				return report, err
			}
			if sequence.Valid {
				var max int64
				if err = target.QueryRowContext(ctx, "SELECT COALESCE(MAX("+quoteIdent(col)+"),0) FROM "+quoteIdent(t)).Scan(&max); err != nil {
					return report, err
				}
				if _, err = target.ExecContext(ctx, `SELECT setval($1::regclass,$2,$3)`, sequence.String, maxInt64(1, max), max > 0); err != nil {
					return report, err
				}
			}
		}
		report.Tables++
		report.Rows += count
	}
	if err = target.Commit(); err != nil {
		return TransferReport{}, err
	}
	return report, nil
}
func maxInt64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}
func quoteIdent(s string) string { return `"` + strings.ReplaceAll(s, `"`, `""`) + `"` }
func postgresColumns(ctx context.Context, tx *sql.Tx, table string) ([]string, []string, error) {
	rows, err := tx.QueryContext(ctx, `SELECT column_name,data_type FROM information_schema.columns WHERE table_schema=current_schema() AND table_name=$1 ORDER BY ordinal_position`, table)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	var names, types []string
	for rows.Next() {
		var n, t string
		if err = rows.Scan(&n, &t); err != nil {
			return nil, nil, err
		}
		names = append(names, n)
		types = append(types, t)
	}
	if len(names) == 0 {
		return nil, nil, fmt.Errorf("missing target table %s", table)
	}
	return names, types, rows.Err()
}
func transferTables(ctx context.Context, d *sql.DB) ([]string, error) {
	rows, err := d.QueryContext(ctx, `SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name<>'fence_schema_migrations' ORDER BY name`)
	if err != nil {
		return nil, err
	}
	var names []string
	for rows.Next() {
		var n string
		if err = rows.Scan(&n); err != nil {
			rows.Close()
			return nil, err
		}
		names = append(names, n)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	deps := map[string][]string{}
	for _, n := range names {
		rs, e := d.QueryContext(ctx, "PRAGMA foreign_key_list("+quoteIdent(n)+")")
		if e != nil {
			return nil, e
		}
		for rs.Next() {
			var id, seq int
			var table, from, to, update, del, match string
			if e = rs.Scan(&id, &seq, &table, &from, &to, &update, &del, &match); e != nil {
				rs.Close()
				return nil, e
			}
			deps[n] = append(deps[n], table)
		}
		e = rs.Err()
		rs.Close()
		if e != nil {
			return nil, e
		}
	}
	seen := map[string]int{}
	var out []string
	var visit func(string) error
	visit = func(n string) error {
		if seen[n] == 2 {
			return nil
		}
		if seen[n] == 1 {
			return fmt.Errorf("cyclic table dependency: %s", n)
		}
		seen[n] = 1
		sort.Strings(deps[n])
		for _, dep := range deps[n] {
			if err := visit(dep); err != nil {
				return err
			}
		}
		seen[n] = 2
		out = append(out, n)
		return nil
	}
	for _, n := range names {
		if err := visit(n); err != nil {
			return nil, err
		}
	}
	return out, nil
}
func normalizeCell(v any, typ string) (any, error) {
	if v == nil {
		return nil, nil
	}
	if b, ok := v.([]byte); ok {
		v = string(b)
	}
	switch typ {
	case "json", "jsonb":
		var obj any
		decoder := json.NewDecoder(bytes.NewBufferString(fmt.Sprint(v)))
		decoder.UseNumber()
		if err := decoder.Decode(&obj); err != nil {
			return nil, err
		}
		b, err := json.Marshal(obj)
		return string(b), err
	case "boolean":
		switch x := v.(type) {
		case bool:
			return x, nil
		case int64:
			return x != 0, nil
		default:
			b, e := strconv.ParseBool(fmt.Sprint(v))
			return b, e
		}
	case "timestamp with time zone", "timestamp without time zone", "date":
		var t time.Time
		var err error
		if x, ok := v.(time.Time); ok {
			t = x
		} else {
			t, err = parseSQLiteTime(fmt.Sprint(v))
			if err != nil {
				return nil, err
			}
		}
		if typ == "date" {
			return t.UTC().Format("2006-01-02"), nil
		}
		return t.UTC().Truncate(time.Microsecond), nil
	case "integer", "bigint", "smallint":
		n, err := strconv.ParseInt(fmt.Sprint(v), 10, 64)
		return n, err
	}
	return v, nil
}

func cellsEqual(a, b any, typ string) bool {
	if reflect.DeepEqual(a, b) {
		return true
	}
	if (typ != "json" && typ != "jsonb") || a == nil || b == nil {
		return false
	}
	decode := func(v any) any {
		var obj any
		d := json.NewDecoder(strings.NewReader(fmt.Sprint(v)))
		d.UseNumber()
		if d.Decode(&obj) != nil {
			return nil
		}
		return canonicalNumbers(obj)
	}
	return reflect.DeepEqual(decode(a), decode(b))
}
func canonicalNumbers(v any) any {
	switch x := v.(type) {
	case json.Number:
		r := new(big.Rat)
		if _, ok := r.SetString(string(x)); ok {
			return struct{ Number string }{r.RatString()}
		}
		return x
	case map[string]any:
		for k, v := range x {
			x[k] = canonicalNumbers(v)
		}
		return x
	case []any:
		for i, v := range x {
			x[i] = canonicalNumbers(v)
		}
		return x
	}
	return v
}
