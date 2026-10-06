package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
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
	CollectedAt    time.Time           `json:"collected_at"`
	Product        string              `json:"product"`
	Host           hostHealth          `json:"host"`
	Docker         dockerHealth        `json:"docker"`
	Process        processHealth       `json:"process"`
}

type hostHealth struct {
	Hostname      string    `json:"hostname"`
	OS            string    `json:"os"`
	Arch          string    `json:"arch"`
	UptimeSec     uint64    `json:"uptime_sec"`
	Load1         float64   `json:"load1"`
	Load5         float64   `json:"load5"`
	Load15        float64   `json:"load15"`
	CPUPercent    *float64  `json:"cpu_percent"`
	CPUCores      int       `json:"cpu_cores"`
	MemoryTotalB  uint64    `json:"memory_total_bytes"`
	MemoryUsedB   uint64    `json:"memory_used_bytes"`
	MemoryAvailB  uint64    `json:"memory_available_bytes"`
	MemoryPercent float64   `json:"memory_percent"`
}

type processHealth struct {
	GoRoutines int    `json:"goroutines"`
	AllocBytes uint64 `json:"alloc_bytes"`
	SysBytes   uint64 `json:"sys_bytes"`
}

type dockerHealth struct {
	Available  bool              `json:"available"`
	Error      string            `json:"error,omitempty"`
	Socket     string            `json:"socket,omitempty"`
	Project    string            `json:"project,omitempty"`
	Containers []containerHealth `json:"containers"`
}

type containerHealth struct {
	ID            string   `json:"id"`
	Name          string   `json:"name"`
	Service       string   `json:"service"`
	Image         string   `json:"image"`
	State         string   `json:"state"`
	Status        string   `json:"status"`
	Health        string   `json:"health"`
	Running       bool     `json:"running"`
	CPUPercent    *float64 `json:"cpu_percent"`
	MemoryUsageB  uint64   `json:"memory_usage_bytes"`
	MemoryLimitB  uint64   `json:"memory_limit_bytes"`
	MemoryPercent *float64 `json:"memory_percent"`
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
		Docker: collectDockerHealth(ctx),
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

func dockerSockPath() string {
	if v := strings.TrimSpace(os.Getenv("FENCE_DOCKER_SOCK")); v != "" {
		return v
	}
	if v := strings.TrimSpace(os.Getenv("DOCKER_HOST")); strings.HasPrefix(v, "unix://") {
		return strings.TrimPrefix(v, "unix://")
	}
	return "/var/run/docker.sock"
}

func collectDockerHealth(ctx context.Context) dockerHealth {
	sock := dockerSockPath()
	out := dockerHealth{Socket: sock, Containers: []containerHealth{}}
	if _, err := os.Stat(sock); err != nil {
		out.Error = "сокет Docker недоступен (подключите /var/run/docker.sock к policy-api)"
		return out
	}
	cli := dockerHTTPClient(sock)
	project := strings.TrimSpace(os.Getenv("FENCE_DOCKER_PROJECT"))
	if project == "" {
		project = detectComposeProject(ctx, cli)
	}
	out.Project = project

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost/containers/json?all=true", nil)
	if err != nil {
		out.Error = err.Error()
		return out
	}
	resp, err := cli.Do(req)
	if err != nil {
		out.Error = err.Error()
		return out
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		out.Error = fmt.Sprintf("docker API %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
		return out
	}
	var list []dockerContainerJSON
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		out.Error = err.Error()
		return out
	}
	out.Available = true
	for _, c := range list {
		svc := c.Labels["com.docker.compose.service"]
		proj := c.Labels["com.docker.compose.project"]
		if project != "" && proj != "" && proj != project {
			continue
		}
		if project == "" && svc == "" && !looksLikeFESSContainer(c) {
			continue
		}
		item := containerHealth{
			ID:      shortID(c.ID),
			Name:    trimContainerName(c.Names),
			Service: svc,
			Image:   c.Image,
			State:   c.State,
			Status:  c.Status,
			Running: strings.EqualFold(c.State, "running"),
		}
		if h := strings.TrimSpace(c.State); c.Status != "" {
			if strings.Contains(strings.ToLower(c.Status), "unhealthy") {
				item.Health = "unhealthy"
			} else if strings.Contains(strings.ToLower(c.Status), "healthy") {
				item.Health = "healthy"
			} else if item.Running {
				item.Health = "running"
			} else {
				item.Health = h
			}
		}
		fillContainerStats(ctx, cli, c.ID, &item)
		out.Containers = append(out.Containers, item)
	}
	return out
}

func looksLikeFESSContainer(c dockerContainerJSON) bool {
	name := strings.ToLower(trimContainerName(c.Names) + " " + c.Image)
	keys := []string{"policy-api", "waf-gateway", "clamav", "postgres", "redis", "fence", "fess"}
	for _, k := range keys {
		if strings.Contains(name, k) {
			return true
		}
	}
	return false
}

func detectComposeProject(ctx context.Context, cli *http.Client) string {
	hn, _ := os.Hostname()
	if hn == "" {
		return strings.TrimSpace(os.Getenv("COMPOSE_PROJECT_NAME"))
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost/containers/"+hn+"/json", nil)
	if err != nil {
		return ""
	}
	resp, err := cli.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	var inspect struct {
		Config struct {
			Labels map[string]string `json:"Labels"`
		} `json:"Config"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&inspect); err != nil {
		return ""
	}
	return inspect.Config.Labels["com.docker.compose.project"]
}

type dockerContainerJSON struct {
	ID     string            `json:"Id"`
	Names  []string          `json:"Names"`
	Image  string            `json:"Image"`
	State  string            `json:"State"`
	Status string            `json:"Status"`
	Labels map[string]string `json:"Labels"`
}

type dockerStatsJSON struct {
	CPUStats struct {
		CPUUsage struct {
			TotalUsage  uint64   `json:"total_usage"`
			PercpuUsage []uint64 `json:"percpu_usage"`
		} `json:"cpu_usage"`
		SystemCPUUsage uint64 `json:"system_cpu_usage"`
		OnlineCPUs     uint32 `json:"online_cpus"`
	} `json:"cpu_stats"`
	PreCPUStats struct {
		CPUUsage struct {
			TotalUsage uint64 `json:"total_usage"`
		} `json:"cpu_usage"`
		SystemCPUUsage uint64 `json:"system_cpu_usage"`
	} `json:"precpu_stats"`
	MemoryStats struct {
		Usage    uint64            `json:"usage"`
		Limit    uint64            `json:"limit"`
		Stats    map[string]uint64 `json:"stats"`
	} `json:"memory_stats"`
}

func fillContainerStats(ctx context.Context, cli *http.Client, id string, item *containerHealth) {
	if id == "" || !item.Running {
		return
	}
	sctx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
	defer cancel()
	req, err := http.NewRequestWithContext(sctx, http.MethodGet, "http://localhost/containers/"+id+"/stats?stream=false", nil)
	if err != nil {
		return
	}
	resp, err := cli.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return
	}
	var st dockerStatsJSON
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		return
	}
	if pct, ok := dockerCPUPercent(st); ok {
		item.CPUPercent = &pct
	}
	cache := st.MemoryStats.Stats["cache"]
	used := st.MemoryStats.Usage
	if used > cache {
		used -= cache
	}
	item.MemoryUsageB = used
	item.MemoryLimitB = st.MemoryStats.Limit
	if st.MemoryStats.Limit > 0 {
		p := float64(used) / float64(st.MemoryStats.Limit) * 100
		item.MemoryPercent = &p
	}
}

func dockerCPUPercent(st dockerStatsJSON) (float64, bool) {
	cpuDelta := float64(st.CPUStats.CPUUsage.TotalUsage) - float64(st.PreCPUStats.CPUUsage.TotalUsage)
	sysDelta := float64(st.CPUStats.SystemCPUUsage) - float64(st.PreCPUStats.SystemCPUUsage)
	if cpuDelta < 0 || sysDelta <= 0 {
		return 0, false
	}
	ncpu := float64(st.CPUStats.OnlineCPUs)
	if ncpu == 0 {
		ncpu = float64(len(st.CPUStats.CPUUsage.PercpuUsage))
	}
	if ncpu == 0 {
		ncpu = float64(runtime.NumCPU())
	}
	return (cpuDelta / sysDelta) * ncpu * 100.0, true
}

func dockerHTTPClient(sock string) *http.Client {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 2 * time.Second}
			return d.DialContext(ctx, "unix", sock)
		},
	}
	return &http.Client{Transport: tr, Timeout: 6 * time.Second}
}

func trimContainerName(names []string) string {
	if len(names) == 0 {
		return ""
	}
	n := names[0]
	return strings.TrimPrefix(n, "/")
}

func shortID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}
