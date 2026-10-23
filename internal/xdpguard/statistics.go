package xdpguard

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

const StatisticsDirectory = "/run/fess-xdp"

// Statistics is a snapshot of kernel counters for one running XDP process.
// Rates use differences between samples, never totals divided by wall time.
type Statistics struct {
	PID             int                `json:"pid"`
	ProgramID       uint32             `json:"program_id"`
	Interface       string             `json:"interface"`
	StartedAt       time.Time          `json:"started_at"`
	SampledAt       time.Time          `json:"sampled_at"`
	IntervalSeconds float64            `json:"interval_seconds"`
	Counters        map[string]uint64  `json:"counters"`
	Rates           map[string]float64 `json:"rates"`
	Stale           bool               `json:"stale"`
}

func StatisticsPath(dir string, pid int) string {
	return filepath.Join(dir, "stats-"+strconv.Itoa(pid)+".json")
}

func SampleStatistics(previous *Statistics, current Statistics) Statistics {
	current.Rates = map[string]float64{}
	if previous != nil && previous.PID == current.PID && previous.ProgramID == current.ProgramID {
		elapsed := current.SampledAt.Sub(previous.SampledAt).Seconds()
		if elapsed > 0 {
			current.IntervalSeconds = elapsed
			for key, value := range current.Counters {
				if old, ok := previous.Counters[key]; ok && value >= old {
					current.Rates[key] = float64(value-old) / elapsed
				}
			}
		}
	}
	return current
}

// PublishStatistics uses rename so readers cannot observe a partial JSON write.
// The runtime directory is supplied by systemd; CLI invocations do not create it.
func PublishStatistics(dir string, s Statistics) error {
	data, err := json.Marshal(s)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".stats-*.json")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(0640); err == nil {
		_, err = f.Write(data)
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(f.Name(), StatisticsPath(dir, s.PID))
}

func ReadStatistics(dir string, pid int, iface string, now time.Time) (*Statistics, error) {
	if pid <= 0 {
		return nil, fmt.Errorf("XDP process is not running")
	}
	f, err := os.Open(StatisticsPath(dir, pid))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var s Statistics
	d := json.NewDecoder(io.LimitReader(f, 128<<10))
	if err = d.Decode(&s); err != nil {
		return nil, err
	}
	if s.PID != pid || s.Interface != iface {
		return nil, fmt.Errorf("statistics belong to a different XDP process or interface")
	}
	if s.SampledAt.IsZero() || s.StartedAt.IsZero() || s.Counters == nil {
		return nil, fmt.Errorf("incomplete XDP statistics")
	}
	s.Stale = now.Sub(s.SampledAt) > 30*time.Second || s.SampledAt.After(now.Add(5*time.Second))
	if s.Stale {
		s.Rates = map[string]float64{}
	}
	return &s, nil
}
