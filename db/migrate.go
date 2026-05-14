package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const advisoryLockKey int64 = 872364651 // arbitrary stable ID for Fence migrate

var migrationFileRe = regexp.MustCompile(`^(\d{3})_(.+)\.sql$`)

type migration struct {
	version int
	name    string
	file    string
}

// ApplyMigrations runs SQL files named NNN_description.sql (e.g. 009_foo.sql) in order.
// Skips schema.sql, seeds.sql, and any file not matching the pattern.
// Uses table fence_schema_migrations and a session advisory lock so concurrent policy-api
// instances do not race.
func ApplyMigrations(ctx context.Context, db *sql.DB) error {
	if _, err := db.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS fence_schema_migrations (
  version INT PRIMARY KEY,
  name TEXT NOT NULL,
  applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);`); err != nil {
		return fmt.Errorf("create migrations table: %w", err)
	}

	if _, err := db.ExecContext(ctx, `SELECT pg_advisory_lock($1)`, advisoryLockKey); err != nil {
		return fmt.Errorf("advisory lock: %w", err)
	}
	defer func() {
		if _, err := db.ExecContext(context.Background(), `SELECT pg_advisory_unlock($1)`, advisoryLockKey); err != nil {
			log.Printf("db migrate: pg_advisory_unlock: %v", err)
		}
	}()

	list, err := listMigrations()
	if err != nil {
		return err
	}

	for _, m := range list {
		var dummy int
		err := db.QueryRowContext(ctx, `SELECT 1 FROM fence_schema_migrations WHERE version = $1`, m.version).Scan(&dummy)
		if err == nil {
			continue
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("check migration %d: %w", m.version, err)
		}

		body, err := fs.ReadFile(sqlFiles, m.file)
		if err != nil {
			return fmt.Errorf("read migration %s: %w", m.file, err)
		}

		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("begin tx %d: %w", m.version, err)
		}
		if _, err := tx.ExecContext(ctx, string(body)); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("apply migration %d (%s): %w", m.version, m.file, err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO fence_schema_migrations (version, name) VALUES ($1, $2)`, m.version, m.name); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("record migration %d: %w", m.version, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit migration %d: %w", m.version, err)
		}
		log.Printf("db migrate: applied %03d %s", m.version, m.file)
	}
	return nil
}

func listMigrations() ([]migration, error) {
	entries, err := fs.ReadDir(sqlFiles, ".")
	if err != nil {
		return nil, fmt.Errorf("read embedded db: %w", err)
	}
	var out []migration
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		sub := migrationFileRe.FindStringSubmatch(e.Name())
		if len(sub) != 3 {
			continue
		}
		v, err := strconv.Atoi(sub[1])
		if err != nil || v <= 0 {
			continue
		}
		out = append(out, migration{version: v, name: sub[2], file: e.Name()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].version < out[j].version })
	return out, nil
}
