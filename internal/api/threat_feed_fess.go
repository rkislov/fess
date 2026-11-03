package api

import (
	"context"
	"database/sql"
	"fence/pkg/threatfeed"
)

func syncFessFeed(ctx context.Context, db *sql.DB, cfg threatfeed.Config) error {
	return syncFessBundle(ctx, db, cfg)
}
