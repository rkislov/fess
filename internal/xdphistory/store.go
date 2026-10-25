// Package xdphistory stores XDP measurements in the application's durable DB.
package xdphistory

import (
	"context"
	"database/sql"
	"fmt"
	"math"
	"strings"
	"time"

	"fence/internal/xdpguard"
)

const Retention = 8 * 24 * time.Hour

// Schema columns are fixed independently of future kernel counter additions.
var metrics = []string{"seen", "passed", "cidr_drop", "rate_drop", "fragment_drop", "malformed_pass", "global_budget_drop", "icmp_ping_drop", "malformed_drop", "temporary_block_drop", "frame_bytes", "protected_packets", "protected_bytes", "protected_syn", "icmp_echo"}

type Point struct {
	At              int64              `json:"at"`
	FirstAt         int64              `json:"first_at"`
	Source          string             `json:"source"`
	Interface       string             `json:"interface"`
	CoverageSeconds float64            `json:"coverage_seconds"`
	Rates           map[string]float64 `json:"rates"`
}

type History struct {
	Period      string    `json:"period"`
	From        time.Time `json:"from"`
	To          time.Time `json:"to"`
	StepSeconds int64     `json:"step_seconds"`
	Points      []Point   `json:"points"`
}

func Period(period string) (window, step time.Duration, ok bool) {
	switch period {
	case "hour":
		return time.Hour, 10 * time.Second, true
	case "day":
		return 24 * time.Hour, 2 * time.Minute, true
	case "week":
		return 7 * 24 * time.Hour, 10 * time.Minute, true
	}
	return 0, 0, false
}

// Save ignores initial, stale and invalid samples. The primary key also prevents
// double-counting after a collector restart or when several FESS processes poll.
func Save(ctx context.Context, db *sql.DB, s *xdpguard.Statistics, now time.Time) error {
	if s == nil || s.Stale || s.PID <= 0 || s.ProgramID == 0 || s.Interface == "" || s.StartedAt.IsZero() || s.SampledAt.IsZero() || s.SampledAt.Before(s.StartedAt) || now.Sub(s.SampledAt) > 30*time.Second || s.SampledAt.After(now.Add(5*time.Second)) || s.IntervalSeconds <= 0 || s.IntervalSeconds > 30 || math.IsNaN(s.IntervalSeconds) {
		return nil
	}
	source := fmt.Sprintf("%s/%s/%d/%d", s.Interface, s.StartedAt.UTC().Format(time.RFC3339Nano), s.PID, s.ProgramID)
	args := []any{s.SampledAt.UnixMilli(), source, s.Interface, s.IntervalSeconds}
	for _, key := range metrics {
		value, ok := s.Rates[key]
		if !ok || value < 0 || math.IsInf(value, 0) || math.IsNaN(value) {
			return nil
		}
		args = append(args, value)
	}
	params := make([]string, len(args))
	for i := range params {
		params[i] = fmt.Sprintf("$%d", i+1)
	}
	_, err := db.ExecContext(ctx, `INSERT INTO xdp_samples (sampled_ms,run_id,interface,interval_seconds,`+strings.Join(metrics, ",")+`) VALUES (`+strings.Join(params, ",")+`) ON CONFLICT (sampled_ms,run_id) DO NOTHING`, args...)
	return err
}

func Prune(ctx context.Context, db *sql.DB, now time.Time) error {
	_, err := db.ExecContext(ctx, `DELETE FROM xdp_samples WHERE sampled_ms < $1`, now.Add(-Retention).UnixMilli())
	return err
}

// Query aggregates in SQL so a week does not transfer all raw samples to the
// WAF process. Rates are weighted by actual measured time, never by sample count.
func Query(ctx context.Context, db *sql.DB, period string, now time.Time) (History, error) {
	window, step, ok := Period(period)
	if !ok {
		return History{}, fmt.Errorf("invalid XDP history period")
	}
	h := History{Period: period, From: now.Add(-window).UTC(), To: now.UTC(), StepSeconds: int64(step.Seconds()), Points: []Point{}}
	fields := []string{"MAX(sampled_ms)", "MIN(sampled_ms)", "run_id", "interface", "SUM(interval_seconds)"}
	for _, key := range metrics {
		fields = append(fields, "SUM("+key+" * interval_seconds) / SUM(interval_seconds)")
	}
	rows, err := db.QueryContext(ctx, `SELECT `+strings.Join(fields, ",")+` FROM xdp_samples WHERE sampled_ms >= $1 AND sampled_ms <= $2 GROUP BY (sampled_ms / $3),run_id,interface ORDER BY MIN(sampled_ms)`, h.From.UnixMilli(), h.To.UnixMilli(), step.Milliseconds())
	if err != nil {
		return h, err
	}
	defer rows.Close()
	for rows.Next() {
		p := Point{Rates: map[string]float64{}}
		values := make([]float64, len(metrics))
		dest := []any{&p.At, &p.FirstAt, &p.Source, &p.Interface, &p.CoverageSeconds}
		for i := range values {
			dest = append(dest, &values[i])
		}
		if err = rows.Scan(dest...); err != nil {
			return h, err
		}
		for i, key := range metrics {
			p.Rates[key] = values[i]
		}
		h.Points = append(h.Points, p)
	}
	return h, rows.Err()
}
