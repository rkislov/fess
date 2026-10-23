package xdpcontrol

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"fence/internal/xdpguard"
)

func testConfig(t *testing.T) xdpguard.Config {
	t.Helper()
	list, err := net.Interfaces()
	if err != nil || len(list) == 0 {
		t.Fatal("no test interface")
	}
	c := xdpguard.Config{Interface: list[0].Name}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	return c
}
func request(c *Controller, method, path string, body any) *httptest.ResponseRecorder {
	raw, _ := json.Marshal(body)
	r := httptest.NewRequest(method, path, bytes.NewReader(raw))
	w := httptest.NewRecorder()
	c.ServeHTTP(w, r)
	return w
}

func TestControllerSettingsLifecycle(t *testing.T) {
	c := New(filepath.Join(t.TempDir(), "xdp.json"))
	active := false
	foreign := false
	started := false
	c.command = func(_ context.Context, name string, args ...string) ([]byte, error) {
		if name == "systemctl" {
			if len(args) < 2 || args[1] != unit {
				t.Fatalf("unexpected unit: %v", args)
			}
			switch args[0] {
			case "show":
				if active {
					return []byte("LoadState=loaded\nActiveState=active\nSubState=running\nResult=success\n"), nil
				}
				return []byte("LoadState=loaded\nActiveState=inactive\nSubState=dead\nResult=success\n"), nil
			case "start":
				active = true
				started = true
				return nil, nil
			case "stop":
				active = false
				return nil, nil
			}
		}
		if name == "ip" {
			if active || foreign {
				return []byte(`[{"xdp":{"attached":"generic","prog":{"id":42,"name":"fess_filter"}}}]`), nil
			}
			return []byte(`[{}]`), nil
		}
		return nil, fmt.Errorf("unexpected command %s %v", name, args)
	}
	if w := request(c, "GET", "/config", nil); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	if w := request(c, "POST", "/start", nil); w.Code != 400 {
		t.Fatal("started without saved config")
	}
	cfg := testConfig(t)
	if w := request(c, "PUT", "/config", map[string]any{"config": cfg}); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	info, _ := os.Stat(c.path)
	if info.Mode().Perm() != 0600 {
		t.Fatal("config must be root-owned/private")
	}
	foreign = true
	if w := request(c, "POST", "/start", nil); w.Code != 409 || started {
		t.Fatal("replaced foreign XDP program")
	}
	foreign = false
	if w := request(c, "POST", "/start", nil); w.Code != 200 || !active {
		t.Fatal(w.Body.String())
	}
	if w := request(c, "PUT", "/config", map[string]any{"config": cfg}); w.Code != 409 {
		t.Fatal("changed config while attached")
	}
	if w := request(c, "GET", "/status", nil); w.Code != 200 || !strings.Contains(w.Body.String(), `"id":42`) {
		t.Fatal(w.Body.String())
	}
	if w := request(c, "POST", "/stop", nil); w.Code != 200 || active {
		t.Fatal(w.Body.String())
	}
	if w := request(c, "GET", "/interfaces", nil); w.Code != 200 || !strings.Contains(w.Body.String(), cfg.Interface) {
		t.Fatal(w.Body.String())
	}
	if w := request(c, "POST", "/restart-anything", nil); w.Code != 404 {
		t.Fatal("unknown command accepted")
	}
	cfg.Interface = "fess-nonexistent-interface"
	if w := request(c, "PUT", "/config", map[string]any{"config": cfg}); w.Code != 400 {
		t.Fatal("missing interface accepted")
	}
}

func TestControllerReportsAttachFailure(t *testing.T) {
	c := New(filepath.Join(t.TempDir(), "xdp.json"))
	if err := c.save(testConfig(t)); err != nil {
		t.Fatal(err)
	}
	started := false
	c.command = func(_ context.Context, name string, args ...string) ([]byte, error) {
		if name == "ip" {
			return []byte(`[{}]`), nil
		}
		if args[0] == "start" {
			started = true
			return nil, nil
		}
		if started {
			return []byte("ActiveState=activating\nSubState=auto-restart\nResult=exit-code\n"), nil
		}
		return []byte("ActiveState=inactive\nSubState=dead\n"), nil
	}
	w := request(c, "POST", "/start", nil)
	if w.Code != 503 || !strings.Contains(w.Body.String(), "failed to attach") {
		t.Fatal(w.Body.String())
	}
}

func TestControllerRejectsArbitrarySocketAndInvalidJSON(t *testing.T) {
	c := New(filepath.Join(t.TempDir(), "xdp.json"))
	cfg := testConfig(t)
	cfg.TemporaryBlocks = xdpguard.TemporaryBlockConfig{Enabled: true, SocketPath: "/tmp/other.sock", SocketGroup: "fess", TTLSeconds: 60}
	if w := request(c, "PUT", "/config", map[string]any{"config": cfg}); w.Code != 400 {
		t.Fatal("arbitrary socket accepted")
	}
	w := httptest.NewRecorder()
	c.ServeHTTP(w, httptest.NewRequest("PUT", "/config", strings.NewReader(`{"config":{},"unexpected":true}`)))
	if w.Code != 400 {
		t.Fatal("unknown fields accepted")
	}
}

func TestControllerReadsOnlyCurrentProcessStatistics(t *testing.T) {
	c := New(filepath.Join(t.TempDir(), "xdp.json"))
	c.statisticsDir = t.TempDir()
	cfg := testConfig(t)
	if err := c.save(cfg); err != nil {
		t.Fatal(err)
	}
	c.command = func(_ context.Context, name string, args ...string) ([]byte, error) {
		if name == "ip" {
			return []byte(`[{}]`), nil
		}
		return []byte("ActiveState=active\nMainPID=42\n"), nil
	}
	now := time.Now()
	if err := xdpguard.PublishStatistics(c.statisticsDir, xdpguard.Statistics{PID: 42, Interface: cfg.Interface, StartedAt: now, SampledAt: now, Counters: map[string]uint64{"seen": 123}}); err != nil {
		t.Fatal(err)
	}
	w := request(c, "GET", "/status", nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"seen":123`) {
		t.Fatal(w.Body.String())
	}
	c.command = func(_ context.Context, name string, args ...string) ([]byte, error) {
		if name == "ip" {
			return []byte(`[{}]`), nil
		}
		return []byte("ActiveState=active\nMainPID=43\n"), nil
	}
	w = request(c, "GET", "/status", nil)
	if strings.Contains(w.Body.String(), `"seen":123`) {
		t.Fatal("previous process statistics leaked into new process")
	}
}
