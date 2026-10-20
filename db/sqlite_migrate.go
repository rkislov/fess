package db

import (
	"context"
	"database/sql"
	"fmt"
	"io/fs"
	"sort"
)

func applySQLiteMigrations(ctx context.Context, d *sql.DB) error {
	if _, err := d.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS fence_schema_migrations (version TEXT PRIMARY KEY, name TEXT NOT NULL, applied_at TIMESTAMP NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')))`); err != nil {
		return err
	}
	files, err := fs.Glob(sqlFiles, "sqlite/*.sql")
	if err != nil {
		return err
	}
	sort.Strings(files)
	for _, file := range files {
		tx, err := d.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		var n int
		err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM fence_schema_migrations WHERE version=$1`, file).Scan(&n)
		if err != nil {
			tx.Rollback()
			return err
		}
		if n > 0 {
			tx.Rollback()
			continue
		}
		body, err := sqlFiles.ReadFile(file)
		if err == nil {
			_, err = tx.ExecContext(ctx, string(body))
		}
		if err == nil {
			_, err = tx.ExecContext(ctx, `INSERT INTO fence_schema_migrations(version,name) VALUES($1,$1)`, file)
		}
		if err != nil {
			tx.Rollback()
			return fmt.Errorf("SQLite migration %s: %w", file, err)
		}
		if err = tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}
