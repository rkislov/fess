package xdpguard

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestStatisticsSamplingAndReset(t *testing.T) {
	now := time.Now()
	first := SampleStatistics(nil, Statistics{PID: 10, ProgramID: 1, StartedAt: now, SampledAt: now, Counters: map[string]uint64{"seen": 100, "frame_bytes": 1000}})
	if first.IntervalSeconds != 0 || len(first.Rates) != 0 {
		t.Fatal("first sample invented a rate")
	}
	next := SampleStatistics(&first, Statistics{PID: 10, ProgramID: 1, StartedAt: now, SampledAt: now.Add(10 * time.Second), Counters: map[string]uint64{"seen": 130, "frame_bytes": 3000}})
	if next.Rates["seen"] != 3 || next.Rates["frame_bytes"] != 200 || next.IntervalSeconds != 10 {
		t.Fatalf("wrong rates: %+v", next)
	}
	reset := SampleStatistics(&next, Statistics{PID: 11, ProgramID: 2, SampledAt: now.Add(20 * time.Second), Counters: map[string]uint64{"seen": 2}})
	if len(reset.Rates) != 0 {
		t.Fatal("restart created bogus rates")
	}
	decreased := SampleStatistics(&next, Statistics{PID: 10, ProgramID: 1, SampledAt: now.Add(20 * time.Second), Counters: map[string]uint64{"seen": 1}})
	if _, ok := decreased.Rates["seen"]; ok {
		t.Fatal("counter reset underflowed")
	}
}

func TestStatisticsPublicationAndFreshness(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	s := Statistics{PID: 42, ProgramID: 7, Interface: "ens3", StartedAt: now.Add(-time.Minute), SampledAt: now, IntervalSeconds: 10, Counters: map[string]uint64{"seen": 50}, Rates: map[string]float64{"seen": 5}}
	if err := PublishStatistics(dir, s); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(StatisticsPath(dir, 42))
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0640 {
		t.Fatal("statistics must not be world readable")
	}
	got, err := ReadStatistics(dir, 42, "ens3", now)
	if err != nil || got.Stale || got.Rates["seen"] != 5 {
		t.Fatalf("fresh sample: %+v %v", got, err)
	}
	got, err = ReadStatistics(dir, 42, "ens3", now.Add(31*time.Second))
	if err != nil || !got.Stale || len(got.Rates) != 0 {
		t.Fatalf("stale rates were presented as live: %+v %v", got, err)
	}
	if _, err := ReadStatistics(dir, 43, "ens3", now); err == nil {
		t.Fatal("accepted another process")
	}
	if _, err := ReadStatistics(dir, 42, "eth0", now); err == nil {
		t.Fatal("accepted another interface")
	}
	if err := os.WriteFile(StatisticsPath(dir, 42), []byte(`{"pid":1,"interface":"ens3"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadStatistics(dir, 42, "ens3", now); err == nil {
		t.Fatal("accepted mismatched contents")
	}
	if matches, err := filepath.Glob(filepath.Join(dir, ".stats-*.json")); err != nil || len(matches) != 0 {
		t.Fatal("temporary file leaked")
	}
}
