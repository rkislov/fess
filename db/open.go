package db

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"regexp"
	"strings"
	"time"

	_ "github.com/lib/pq"
	"modernc.org/sqlite"
)

const timeLayout = "2006-01-02 15:04:05.000000000"

func init() { sql.Register("fess-sqlite", &sqliteDriver{}) }

// Open opens the selected backend. SQLite is local, uses WAL, foreign keys and a
// busy timeout. Immediate transactions serialize writers; WAL allows concurrent readers.
func Open(ctx context.Context, backend, dsn string) (*sql.DB, error) {
	name := backend
	if backend == "sqlite" {
		name = "fess-sqlite"
		if dsn == "" {
			return nil, fmt.Errorf("SQLite path is required")
		}
		sep := "?"
		if strings.Contains(dsn, "?") {
			sep = "&"
		}
		dsn += sep + "_pragma=foreign_keys(1)&_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)&_txlock=immediate"
	}
	if backend != "sqlite" && backend != "postgres" {
		return nil, fmt.Errorf("unsupported database %q", backend)
	}
	d, err := sql.Open(name, dsn)
	if err != nil {
		return nil, err
	}
	if backend == "sqlite" {
		d.SetMaxOpenConns(8)
	} else {
		d.SetMaxOpenConns(16)
		d.SetMaxIdleConns(8)
	}
	if err = d.PingContext(ctx); err != nil {
		d.Close()
		return nil, err
	}
	return d, nil
}
func IsSQLite(d *sql.DB) bool { _, ok := d.Driver().(*sqliteDriver); return ok }

type sqliteDriver struct{}

func (*sqliteDriver) Open(name string) (driver.Conn, error) {
	c, err := (&sqlite.Driver{}).Open(name)
	if err != nil {
		return nil, err
	}
	return &sqliteConn{Conn: c}, nil
}

type sqliteConn struct{ driver.Conn }

func (c *sqliteConn) Prepare(q string) (driver.Stmt, error) {
	s, err := c.Conn.Prepare(sqliteQuery(q))
	if err != nil {
		return nil, err
	}
	return &sqliteStmt{Stmt: s}, nil
}
func (c *sqliteConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	return c.Conn.(driver.ConnBeginTx).BeginTx(ctx, opts)
}
func (c *sqliteConn) ExecContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Result, error) {
	normalizeArgs(args)
	return c.Conn.(driver.ExecerContext).ExecContext(ctx, sqliteQuery(q), args)
}
func (c *sqliteConn) QueryContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	normalizeArgs(args)
	r, err := c.Conn.(driver.QueryerContext).QueryContext(ctx, sqliteQuery(q), args)
	if err != nil {
		return nil, err
	}
	return &sqliteRows{Rows: r}, nil
}
func (c *sqliteConn) CheckNamedValue(v *driver.NamedValue) error {
	if t, ok := v.Value.(time.Time); ok {
		v.Value = t.UTC().Format(timeLayout)
		return nil
	}
	return driver.ErrSkip
}
func normalizeArgs(args []driver.NamedValue) {
	for i := range args {
		if t, ok := args[i].Value.(time.Time); ok {
			args[i].Value = t.UTC().Format(timeLayout)
		}
	}
}

type sqliteStmt struct{ driver.Stmt }

func (s *sqliteStmt) Query(args []driver.Value) (driver.Rows, error) {
	r, err := s.Stmt.Query(args)
	if err != nil {
		return nil, err
	}
	return &sqliteRows{Rows: r}, nil
}

type sqliteRows struct{ driver.Rows }

func (r *sqliteRows) Next(dest []driver.Value) error {
	if err := r.Rows.Next(dest); err != nil {
		return err
	}
	for i, name := range r.Columns() {
		if dest[i] == nil {
			continue
		}
		if strings.HasSuffix(name, "_at") || name == "b" || name == "not_before" || name == "not_after" || name == "auto_sync_day" || name == "last_at" {
			if s, ok := dest[i].(string); ok {
				if t, err := parseSQLiteTime(s); err == nil {
					dest[i] = t
				}
			}
		}
		if s, ok := dest[i].(string); ok {
			dest[i] = []byte(s)
		}
	}
	return nil
}
func parseSQLiteTime(s string) (time.Time, error) {
	for _, layout := range []string{timeLayout, "2006-01-02 15:04:05.999999999", time.RFC3339Nano, "2006-01-02 15:04:05.999999999 -0700 MST", "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("invalid SQLite time %q", s)
}

var casts = regexp.MustCompile(`(?i)::(?:uuid|text|jsonb|json|bigint|integer|int|interval)\b`)
var placeholders = regexp.MustCompile(`\$(\d+)`)
var oneHour = regexp.MustCompile(`(?i)NOW\(\)\s*-\s*INTERVAL\s+'1 hour'`)
var secondsInterval = regexp.MustCompile(`(?i)NOW\(\)\s*\+\s*\(\$(\d+)\s*\*\s*INTERVAL\s+'1 second'\)`)
var daysInterval = regexp.MustCompile(`(?i)NOW\(\)\s*\+\s*\(\$(\d+)\s*\|\|\s*' days'\)::interval`)

// sqliteQuery adapts the bounded SQL dialect used by FESS. Values are always
// parameters; quoted SQL literals are preserved by the lexical pass below.
func sqliteQuery(q string) string {
	q = oneHour.ReplaceAllString(q, "datetime('now','-1 hour')")
	q = secondsInterval.ReplaceAllString(q, "datetime('now', '+' || $$${1} || ' seconds')")
	q = daysInterval.ReplaceAllString(q, "datetime('now', '+' || $$${1} || ' days')")
	// These functions/expressions are only used by the reporting and GeoIP APIs.
	q = strings.ReplaceAll(q, "TIMESTAMPTZ '2000-01-01'", "'2000-01-01'")
	q = strings.ReplaceAll(q, "date_bin($2::interval, created_at, '2000-01-01')", "datetime((unixepoch(created_at) / (CAST($2 AS INTEGER) * CASE WHEN $2 LIKE '%hour%' THEN 3600 ELSE 60 END)) * (CAST($2 AS INTEGER) * CASE WHEN $2 LIKE '%hour%' THEN 3600 ELSE 60 END), 'unixepoch')")
	q = geoIPUpdate.ReplaceAllString(q, "json_set(config, '$.geoip.mmdb_last_installed_at', $$${1})")
	var b strings.Builder
	for i := 0; i < len(q); {
		if q[i] == '\'' || q[i] == '"' {
			quote := q[i]
			j := i + 1
			for j < len(q) {
				if q[j] == quote {
					j++
					if j < len(q) && q[j] == quote {
						j++
						continue
					}
					break
				}
				j++
			}
			b.WriteString(q[i:j])
			i = j
			continue
		}
		j := i
		for j < len(q) && q[j] != '\'' && q[j] != '"' {
			j++
		}
		part := casts.ReplaceAllString(q[i:j], "")
		part = placeholders.ReplaceAllString(part, "?${1}")
		part = strings.NewReplacer("NOW()", "(strftime('%Y-%m-%d %H:%M:%f','now'))", "ILIKE", "LIKE", "json_agg(", "json_group_array(", "json_build_object(", "json_object(", "LEFT(", "substr(").Replace(part)
		// LEFT has a different argument signature; see the explicit conversion below.
		b.WriteString(part)
		i = j
	}
	out := b.String()
	// FESS only uses LEFT(COALESCE(expr, default), length).
	out = leftExpr.ReplaceAllString(out, "substr($1,1,$2)")
	return out
}

var leftExpr = regexp.MustCompile(`substr\((COALESCE\([^)]*\)),\s*(\d+)\)`)
var _ driver.Rows = (*sqliteRows)(nil)

var geoIPUpdate = regexp.MustCompile(`(?i)jsonb_set\(\s*config\s*,\s*'{geoip,mmdb_last_installed_at}'\s*,\s*to_jsonb\(\$([0-9]+)::text\)\s*,\s*true\s*\)`)
