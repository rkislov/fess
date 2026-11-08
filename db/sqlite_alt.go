//go:build fess_alt_sqlite || (linux && (mips || mipsle || mips64 || mips64le || ppc64))

package db

import (
	"database/sql/driver"
	sqlite "github.com/ncruces/go-sqlite3/driver"
	"strings"
)

func openSQLiteConn(name string) (driver.Conn, error) {
	if !strings.HasPrefix(name, "file:") {
		name = "file:" + name
	}
	return (&sqlite.SQLite{}).Open(name)
}
