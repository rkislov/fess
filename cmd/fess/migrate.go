package main

import (
	"context"
	fencedb "fence/db"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

func migrateCommand(args []string) error {
	flags := flag.NewFlagSet("fess migrate", flag.ContinueOnError)
	data := flags.String("data-dir", env("FESS_DATA_DIR", "./data"), "stopped FESS data directory")
	source := flags.String("source", "", "SQLite source file (default: data-dir/fess.db)")
	target := flags.String("target", env("FESS_MIGRATE_TARGET", ""), "fresh PostgreSQL DSN; prefer FESS_MIGRATE_TARGET to keep credentials out of process args")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *target == "" {
		return fmt.Errorf("set FESS_MIGRATE_TARGET to a fresh PostgreSQL database")
	}
	if *source == "" {
		*source = filepath.Join(*data, "fess.db")
	}
	if _, err := os.Stat(*source); err != nil {
		return err
	}
	unlock, err := lockData(*data)
	if err != nil {
		return err
	}
	defer unlock()
	unlockDB, err := lockFile(*source + ".lock")
	if err != nil {
		return err
	}
	defer unlockDB()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Hour)
	defer cancel()
	src, err := fencedb.Open(ctx, "sqlite", *source)
	if err != nil {
		return fmt.Errorf("open source: %w", err)
	}
	defer src.Close()
	if err = fencedb.ApplyMigrations(ctx, src); err != nil {
		return err
	}
	dst, err := fencedb.Open(ctx, "postgres", *target)
	if err != nil {
		return fmt.Errorf("open destination: %w", err)
	}
	defer dst.Close()
	var tables int
	if err = dst.QueryRowContext(ctx, `SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=current_schema() AND table_type='BASE TABLE'`).Scan(&tables); err != nil {
		return err
	}
	if tables != 0 {
		return fmt.Errorf("destination schema must be empty; create a fresh database or schema")
	}
	if err = fencedb.ApplyMigrations(ctx, dst); err != nil {
		return err
	}
	report, err := fencedb.TransferToPostgres(ctx, src, dst)
	if err != nil {
		return err
	}
	fmt.Printf("Verified migration: %d tables, %d rows. SQLite source preserved. Set FESS_DB=postgres and FESS_DATABASE_URL, then restart FESS.\n", report.Tables, report.Rows)
	return nil
}
