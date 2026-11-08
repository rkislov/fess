//go:build !fess_alt_sqlite && !(linux && (mips || mipsle || mips64 || mips64le || ppc64))

package db

import (
	"database/sql/driver"
	"modernc.org/sqlite"
)

func openSQLiteConn(name string) (driver.Conn, error) { return (&sqlite.Driver{}).Open(name) }
