package integration

import (
	"context"
	"testing"
	"time"

	"fence/internal/xdpguard"
	"fence/internal/xdphistory"
)

func TestXDPHistoryBackends(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			db := openBackend(t, backend)
			ctx := context.Background()
			now := time.Date(2026, 10, 23, 10, 0, 0, 0, time.UTC)
			sample := func(at time.Time, duration, rate float64, pid int) *xdpguard.Statistics {
				rates := map[string]float64{}
				for _, key := range xdpguard.CounterNames {
					rates[key] = rate
				}
				return &xdpguard.Statistics{PID: pid, ProgramID: 42, Interface: "ens3", StartedAt: at.Add(-time.Hour), SampledAt: at, IntervalSeconds: duration, Rates: rates}
			}
			a := sample(now.Add(-50*time.Second), 10, 100, 1)
			b := sample(now.Add(-30*time.Second), 20, 300, 1)
			b.StartedAt = a.StartedAt
			for _, s := range []*xdpguard.Statistics{a, b, a} {
				if err := xdphistory.Save(ctx, db, s, s.SampledAt); err != nil {
					t.Fatal(err)
				}
			}
			history, err := xdphistory.Query(ctx, db, "day", now)
			if err != nil || len(history.Points) != 1 {
				t.Fatalf("aggregation: %+v %v", history, err)
			}
			p := history.Points[0]
			if p.CoverageSeconds != 30 || p.Rates["seen"] != 7000.0/30 {
				t.Fatalf("duplicate or unweighted average: %+v", p)
			}
			// A new process is a separate segment, not a counter-reset spike.
			restarted := sample(now.Add(-10*time.Second), 10, 5, 2)
			if err = xdphistory.Save(ctx, db, restarted, now); err != nil {
				t.Fatal(err)
			}
			history, err = xdphistory.Query(ctx, db, "day", now)
			if err != nil || len(history.Points) != 2 || history.Points[1].Rates["seen"] != 5 {
				t.Fatalf("restart: %+v %v", history, err)
			}
			for _, period := range []string{"hour", "day", "week"} {
				h, err := xdphistory.Query(ctx, db, period, now)
				if err != nil || len(h.Points) == 0 || h.Period != period {
					t.Fatalf("%s: %+v %v", period, h, err)
				}
			}
			// Initial/stale/future snapshots are missing data, not zero traffic.
			for _, invalid := range []*xdpguard.Statistics{nil, sample(now, 0, 0, 3), sample(now.Add(time.Minute), 10, 0, 3), sample(now.Add(-time.Minute), 10, 0, 3)} {
				if err = xdphistory.Save(ctx, db, invalid, now); err != nil {
					t.Fatal(err)
				}
			}
			var count int
			if err = db.QueryRow(`SELECT COUNT(*) FROM xdp_samples`).Scan(&count); err != nil || count != 3 {
				t.Fatalf("invalid sample saved: %d %v", count, err)
			}
			for _, age := range []time.Duration{2 * time.Hour, 30 * time.Hour, 180 * time.Hour} {
				s := sample(now.Add(-age), 10, 77, 3)
				if err = xdphistory.Save(ctx, db, s, s.SampledAt); err != nil {
					t.Fatal(err)
				}
			}
			for period, want := range map[string]int{"hour": 3, "day": 3, "week": 4} {
				h, err := xdphistory.Query(ctx, db, period, now)
				if err != nil || len(h.Points) != want {
					t.Fatalf("%s window: %d points, want %d: %v", period, len(h.Points), want, err)
				}
			}
			old := sample(now.Add(-9*24*time.Hour), 10, 1000, 1)
			if err = xdphistory.Save(ctx, db, old, old.SampledAt); err != nil {
				t.Fatal(err)
			}
			if err = xdphistory.Prune(ctx, db, now); err != nil {
				t.Fatal(err)
			}
			if err = db.QueryRow(`SELECT COUNT(*) FROM xdp_samples`).Scan(&count); err != nil || count != 6 {
				t.Fatalf("retention: %d %v", count, err)
			}
		})
	}
}
