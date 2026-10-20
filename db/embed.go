package db

import "embed"

// All .sql in this directory (schema, seeds, numbered migrations).
//
//go:embed *.sql sqlite/*.sql
var sqlFiles embed.FS
