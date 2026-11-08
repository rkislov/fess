// Alerts are evaluated by FESS, independently of dashboard requests.
package xdphistory

import (
	"context"
	"database/sql"
	"log"
	"math"
	"strings"
	"time"
)

var reasons = [...]string{"cidr_drop", "rate_drop", "global_budget_drop", "icmp_ping_drop", "malformed_drop", "temporary_block_drop", "fragment_drop"}

type Alert struct {
	Kind    string  `json:"kind"`
	Opened  int64   `json:"opened_ms"`
	Closed  *int64  `json:"closed_ms"`
	Reason  string  `json:"reason"`
	Percent float64 `json:"drop_percent"`
}

func RecentAlerts(ctx context.Context, db *sql.DB) ([]Alert, error) {
	rows, err := db.QueryContext(ctx, `SELECT kind,opened_ms,closed_ms,reason,drop_percent FROM xdp_alerts ORDER BY CASE WHEN closed_ms IS NULL THEN 0 ELSE 1 END, opened_ms DESC LIMIT 20`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Alert{}
	for rows.Next() {
		var a Alert
		if err = rows.Scan(&a.Kind, &a.Opened, &a.Closed, &a.Reason, &a.Percent); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
func transition(ctx context.Context, db *sql.DB, kind string, active bool, now int64, reason string, percent float64) error {
	var result sql.Result
	var err error
	if active {
		result, err = db.ExecContext(ctx, `INSERT INTO xdp_alerts(kind,opened_ms,reason,drop_percent) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING`, kind, now, reason, percent)
	} else {
		result, err = db.ExecContext(ctx, `UPDATE xdp_alerts SET closed_ms=$1 WHERE kind=$2 AND closed_ms IS NULL`, now, kind)
	}
	if err != nil {
		return err
	}
	if n, _ := result.RowsAffected(); n > 0 {
		log.Printf("XDP alert kind=%s active=%t reason=%s drop_percent=%.2f", kind, active, reason, percent)
	}
	return nil
}

type alertWindow struct {
	seconds, seen float64
	drops         [len(reasons)]float64
}

func (w alertWindow) high() bool {
	var dropped float64
	for _, d := range w.drops {
		dropped += d
	}
	return w.seen > 0 && dropped >= 10 && dropped*100 >= w.seen
}

// EvaluateAlerts opens on three successive measured 30-second windows, and
// recovers on three quiet ones. Missing coverage cannot establish either state.
func EvaluateAlerts(ctx context.Context, db *sql.DB, now time.Time) error {
	var last sql.NullInt64
	if err := db.QueryRowContext(ctx, `SELECT MAX(sampled_ms) FROM xdp_samples`).Scan(&last); err != nil || !last.Valid {
		return err
	}
	age := now.UnixMilli() - last.Int64
	if age >= 60000 {
		return transition(ctx, db, "collection_gap", true, now.UnixMilli(), "", 0)
	}
	if age > 30000 || age < 0 {
		return nil
	}
	if err := transition(ctx, db, "collection_gap", false, now.UnixMilli(), "", 0); err != nil {
		return err
	}
	start := last.Int64 - 90000
	rows, err := db.QueryContext(ctx, `SELECT sampled_ms,interval_seconds,seen,`+strings.Join(reasons[:], ",")+` FROM xdp_samples WHERE sampled_ms>$1 AND sampled_ms<=$2`, start, last.Int64)
	if err != nil {
		return err
	}
	var windows [3]alertWindow
	for rows.Next() {
		var at int64
		var secs, seen float64
		var rates [len(reasons)]float64
		dest := []any{&at, &secs, &seen}
		for i := range rates {
			dest = append(dest, &rates[i])
		}
		if err = rows.Scan(dest...); err != nil {
			rows.Close()
			return err
		}
		end := float64(at-start) / 1000
		for i := range windows {
			// Clip the measurement to this window rather than attributing its entire
			// interval to the bucket containing its end timestamp.
			n := math.Min(end, float64(i+1)*30) - math.Max(end-secs, float64(i)*30)
			if n <= 0 {
				continue
			}
			w := &windows[i]
			w.seconds += n
			w.seen += seen * n
			for j, r := range rates {
				w.drops[j] += r * n
			}
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	high := 0
	var totals alertWindow
	for _, w := range windows {
		if w.seconds < 24 {
			return nil
		}
		if w.high() {
			high++
		}
		totals.seen += w.seen
		for i, d := range w.drops {
			totals.drops[i] += d
		}
	}
	if high == 0 {
		return transition(ctx, db, "drop_share", false, now.UnixMilli(), "", 0)
	}
	if high != 3 {
		return nil
	}
	var dropped float64
	top := 0
	for i, d := range totals.drops {
		dropped += d
		if d > totals.drops[top] {
			top = i
		}
	}
	return transition(ctx, db, "drop_share", true, now.UnixMilli(), reasons[top], 100*dropped/totals.seen)
}
