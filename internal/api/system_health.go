package api

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

type hostCPUSample struct {
	idle  uint64
	total uint64
}

var (
	hostCPUMu   sync.Mutex
	hostCPULast hostCPUSample
)

type systemHealthResponse struct {
	CollectedAt time.Time     `json:"collected_at"`
	Product     string        `json:"product"`
	Host        hostHealth    `json:"host"`
	Process     processHealth `json:"process"`
}

type hostHealth struct {
	Hostname      string   `json:"hostname"`
	OS            string   `json:"os"`
	Arch          string   `json:"arch"`
	UptimeSec     uint64   `json:"uptime_sec"`
	Load1         float64  `json:"load1"`
	Load5         float64  `json:"load5"`
	Load15        float64  `json:"load15"`
	CPUPercent    *float64 `json:"cpu_percent"`
	CPUCores      int      `json:"cpu_cores"`
	MemoryTotalB  uint64   `json:"memory_total_bytes"`
	MemoryUsedB   uint64   `json:"memory_used_bytes"`
	MemoryAvailB  uint64   `json:"memory_available_bytes"`
	MemoryPercent float64  `json:"memory_percent"`
}

type processHealth struct {
	GoRoutines int    `json:"goroutines"`
	AllocBytes uint64 `json:"alloc_bytes"`
	SysBytes   uint64 `json:"sys_bytes"`
}

func systemHealthHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, collectSystemHealth(r.Context()))
}

func collectSystemHealth(ctx context.Context) systemHealthResponse {
	host, cpuPct := collectHostHealth()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	out := systemHealthResponse{
		CollectedAt: time.Now().UTC(),
		Product:     "FESS",
		Host:        host,
		Process: processHealth{
			GoRoutines: runtime.NumGoroutine(),
			AllocBytes: ms.Alloc,
			SysBytes:   ms.Sys,
		},
	}
	out.Host.CPUPercent = cpuPct
	return out
}

func collectHostHealth() (hostHealth, *float64) {
	hn, _ := os.Hostname()
	h := hostHealth{
		Hostname: hn,
		OS:       runtime.GOOS,
		Arch:     runtime.GOARCH,
		CPUCores: runtime.NumCPU(),
	}
	if u, err := readUptimeSec(); err == nil {
		h.UptimeSec = u
	}
	h.Load1, h.Load5, h.Load15 = readLoadAvg()
	total, avail := readMemInfo()
	h.MemoryTotalB = total
	h.MemoryAvailB = avail
	if total > avail {
		h.MemoryUsedB = total - avail
	}
	if total > 0 {
		h.MemoryPercent = float64(h.MemoryUsedB) / float64(total) * 100
	}
	return h, hostCPUPercent()
}

func readUptimeSec() (uint64, error) {
	b, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0, err
	}
	fields := strings.Fields(string(b))
	if len(fields) == 0 {
		return 0, io.EOF
	}
	f, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0, err
	}
	return uint64(f), nil
}

func readLoadAvg() (float64, float64, float64) {
	b, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return 0, 0, 0
	}
	fields := strings.Fields(string(b))
	if len(fields) < 3 {
		return 0, 0, 0
	}
	a, _ := strconv.ParseFloat(fields[0], 64)
	c, _ := strconv.ParseFloat(fields[1], 64)
	d, _ := strconv.ParseFloat(fields[2], 64)
	return a, c, d
}

func readMemInfo() (total, available uint64) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, 0
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "MemTotal:"):
			total = parseMemKB(line) * 1024
		case strings.HasPrefix(line, "MemAvailable:"):
			available = parseMemKB(line) * 1024
		}
	}
	return total, available
}

func parseMemKB(line string) uint64 {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return 0
	}
	n, _ := strconv.ParseUint(fields[1], 10, 64)
	return n
}

func hostCPUPercent() *float64 {
	idle, total, err := readProcStatCPU()
	if err != nil {
		return nil
	}
	hostCPUMu.Lock()
	defer hostCPUMu.Unlock()
	prev := hostCPULast
	hostCPULast = hostCPUSample{idle: idle, total: total}
	if prev.total == 0 || total <= prev.total {
		return nil
	}
	idleDelta := idle - prev.idle
	totalDelta := total - prev.total
	if totalDelta == 0 {
		return nil
	}
	pct := (1 - float64(idleDelta)/float64(totalDelta)) * 100
	if pct < 0 {
		pct = 0
	}
	if pct > 100 {
		pct = 100
	}
	return &pct
}

func readProcStatCPU() (idle, total uint64, err error) {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	if !sc.Scan() {
		return 0, 0, io.EOF
	}
	fields := strings.Fields(sc.Text())
	if len(fields) < 5 || fields[0] != "cpu" {
		return 0, 0, fmt.Errorf("unexpected /proc/stat")
	}
	var vals []uint64
	for _, s := range fields[1:] {
		n, e := strconv.ParseUint(s, 10, 64)
		if e != nil {
			continue
		}
		vals = append(vals, n)
		total += n
	}
	if len(vals) > 3 {
		idle = vals[3]
	}
	if len(vals) > 4 {
		idle += vals[4] // iowait
	}
	return idle, total, nil
}
