package db

import "embed"

// All .sql in this directory (schema, seeds, numbered migrations).
//
//go:embed *.sql
var sqlFiles embed.FS
