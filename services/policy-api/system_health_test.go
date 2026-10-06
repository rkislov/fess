package main

import "testing"

func TestDockerCPUPercent(t *testing.T) {
	var st dockerStatsJSON
	st.CPUStats.CPUUsage.TotalUsage = 200
	st.PreCPUStats.CPUUsage.TotalUsage = 100
	st.CPUStats.SystemCPUUsage = 400
	st.PreCPUStats.SystemCPUUsage = 200
	st.CPUStats.OnlineCPUs = 2
	pct, ok := dockerCPUPercent(st)
	if !ok {
		t.Fatal("expected ok")
	}
	if pct != 100 {
		t.Fatalf("got %v want 100", pct)
	}
}
