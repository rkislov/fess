package integration

import (
	"context"
	"fence/internal/xdpguard"
	"fence/internal/xdphistory"
	"testing"
	"time"
)

func TestXDPAlertLifecycle(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			db := openBackend(t, backend)
			ctx := context.Background()
			base := time.Date(2031, 2, 1, 12, 0, 0, 0, time.UTC)
			tick := func(s int) {
				if err := xdphistory.EvaluateAlerts(ctx, db, base.Add(time.Duration(s)*time.Second)); err != nil {
					t.Fatal(err)
				}
			}
			state := func(active, all int) []xdphistory.Alert {
				t.Helper()
				items, err := xdphistory.RecentAlerts(ctx, db)
				if err != nil {
					t.Fatal(err)
				}
				n := 0
				for _, a := range items {
					if a.Closed == nil {
						n++
					}
				}
				if n != active || len(items) != all {
					t.Fatalf("alerts: %+v, want %d active, %d total", items, active, all)
				}
				return items
			}
			sample := func(s int, drops float64, legacy bool) {
				rates := map[string]float64{}
				for _, name := range xdpguard.CounterNames {
					rates[name] = 0
				}
				rates["seen"] = 100
				rates["passed"] = 100 - drops
				rates["temporary_block_drop"] = drops
				rates["trial_icmp_hit"] = 40
				if legacy {
					delete(rates, "trial_icmp_hit")
					delete(rates, "trial_budget_hit")
				}
				at := base.Add(time.Duration(s) * time.Second)
				if err := xdphistory.Save(ctx, db, &xdpguard.Statistics{PID: 1, ProgramID: 1, Interface: "eth0", StartedAt: base, SampledAt: at, IntervalSeconds: 10, Rates: rates}, at); err != nil {
					t.Fatal(err)
				}
			}
			tick(0)
			state(0, 0)
			for s := 10; s <= 90; s += 10 {
				sample(s, 0, s == 10)
			}
			tick(90)
			state(0, 0) // Trial hits alone cannot alert.
			for s := 100; s <= 160; s += 10 {
				sample(s, 2, false)
			}
			tick(160)
			state(0, 0)
			for s := 170; s <= 180; s += 10 {
				sample(s, 2, false)
			}
			tick(180)
			tick(185)
			a := state(1, 1)[0]
			if a.Reason != "temporary_block_drop" || a.Percent != 2 {
				t.Fatal(a)
			}
			tick(240)
			tick(250)
			state(2, 2) // Do not treat missing data as recovery.
			sample(260, 0, false)
			tick(260)
			state(1, 2) // Only gap resolves on the first fresh sample.
			for s := 270; s <= 340; s += 10 {
				sample(s, 0, false)
			}
			tick(340)
			state(0, 2)
			h, err := xdphistory.Query(ctx, db, "hour", base.Add(340*time.Second))
			if err != nil || len(h.Points) == 0 {
				t.Fatalf("history %v", err)
			}
			if h.Points[0].Rates["trial_icmp_hit"] != 0 || h.Points[1].Rates["trial_icmp_hit"] != 40 {
				t.Fatal("mixed-version history lost trial measurements")
			}
			if err := xdphistory.Prune(ctx, db, base.Add(9*24*time.Hour)); err != nil {
				t.Fatal(err)
			}
			state(0, 0)
		})
	}
}
