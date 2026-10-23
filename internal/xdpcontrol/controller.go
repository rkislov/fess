// Package xdpcontrol exposes a local, narrowly scoped controller for fess-xdp.service.
// The HTTP WAF uses its Unix socket and needs no BPF or systemd privileges.
package xdpcontrol

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"fence/internal/xdpguard"
)

const DefaultSocket = "/run/fess-xdp-control/control.sock"
const unit = "fess-xdp.service"

type commandFunc func(context.Context, string, ...string) ([]byte, error)
type Controller struct {
	path          string
	statisticsDir string
	command       commandFunc
	mu            sync.Mutex
}

func command(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}
func New(path string) *Controller {
	return &Controller{path: path, statisticsDir: xdpguard.StatisticsDirectory, command: command}
}

func respond(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(value)
}
func decode(w http.ResponseWriter, r *http.Request, value any) error {
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<20))
	d.DisallowUnknownFields()
	if err := d.Decode(value); err != nil {
		return err
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return fmt.Errorf("expected one JSON object")
	}
	return nil
}

func (c *Controller) config() (xdpguard.Config, error) {
	cfg, err := xdpguard.ReadConfig(c.path)
	if errors.Is(err, os.ErrNotExist) {
		// An interface must be chosen explicitly before saving or starting.
		cfg = xdpguard.Config{Mode: "native", Ports: []xdpguard.Port{{Protocol: "tcp", Port: 80}, {Protocol: "tcp", Port: 443}}, AllowCIDRs: []string{}, BlockCIDRs: []string{}}
		cfg.TemporaryBlocks = xdpguard.TemporaryBlockConfig{SocketPath: "/run/fess-xdp/blocks.sock", SocketGroup: "fess", TTLSeconds: 60, MinEvents: 3, WindowSeconds: 30}
		return cfg, nil
	}
	return cfg, err
}
func (c *Controller) save(cfg xdpguard.Config) error {
	raw, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(c.path), ".xdp-*.json")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(append(raw, '\n')); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(f.Name(), c.path)
}

func (c *Controller) service(ctx context.Context) (map[string]string, error) {
	out, err := c.command(ctx, "systemctl", "show", unit, "--property=LoadState,ActiveState,SubState,Result,MainPID")
	if err != nil {
		return nil, fmt.Errorf("systemctl show: %s: %w", strings.TrimSpace(string(out)), err)
	}
	state := map[string]string{}
	for _, line := range strings.Split(string(out), "\n") {
		k, v, ok := strings.Cut(line, "=")
		if ok {
			state[k] = v
		}
	}
	return state, nil
}

// readAttachment reports what the kernel actually has attached, including a
// foreign program. Service activity alone is not evidence of XDP attachment.
func (c *Controller) readAttachment(ctx context.Context, iface string) (any, error) {
	out, err := c.command(ctx, "ip", "-j", "link", "show", "dev", iface)
	if err != nil {
		return nil, fmt.Errorf("read interface XDP state: %s: %w", strings.TrimSpace(string(out)), err)
	}
	var links []struct {
		XDP json.RawMessage `json:"xdp"`
	}
	if err = json.Unmarshal(out, &links); err != nil {
		return nil, err
	}
	if len(links) == 0 || len(links[0].XDP) == 0 || bytes.Equal(links[0].XDP, []byte("null")) {
		return nil, nil
	}
	var value map[string]any
	if err = json.Unmarshal(links[0].XDP, &value); err != nil {
		return nil, err
	}
	return value, nil
}

func (c *Controller) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	c.mu.Lock()
	defer c.mu.Unlock()
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	fail := func(status int, err error) { respond(w, status, map[string]string{"error": err.Error()}) }
	switch {
	case r.URL.Path == "/config" && r.Method == http.MethodGet:
		cfg, err := c.config()
		if err != nil {
			fail(500, err)
			return
		}
		respond(w, 200, map[string]any{"config": cfg})
	case r.URL.Path == "/config" && r.Method == http.MethodPut:
		var body struct {
			Config xdpguard.Config `json:"config"`
		}
		if err := decode(w, r, &body); err != nil {
			fail(400, err)
			return
		}
		if err := body.Config.Validate(); err != nil {
			fail(400, err)
			return
		}
		if _, err := net.InterfaceByName(body.Config.Interface); err != nil {
			fail(400, err)
			return
		}
		// Socket ownership is managed by the optional package, not by web input.
		if body.Config.TemporaryBlocks.Enabled && (body.Config.TemporaryBlocks.SocketPath != "/run/fess-xdp/blocks.sock" || body.Config.TemporaryBlocks.SocketGroup != "fess") {
			fail(400, fmt.Errorf("panel-managed bans require /run/fess-xdp/blocks.sock and group fess"))
			return
		}
		state, err := c.service(ctx)
		if err != nil {
			fail(503, err)
			return
		}
		if state["ActiveState"] != "inactive" && state["ActiveState"] != "failed" {
			fail(409, fmt.Errorf("stop and detach XDP before changing configuration"))
			return
		}
		if err := c.save(body.Config); err != nil {
			fail(500, err)
			return
		}
		respond(w, 200, map[string]any{"config": body.Config})
	case r.URL.Path == "/interfaces" && r.Method == http.MethodGet:
		list, err := net.Interfaces()
		if err != nil {
			fail(500, err)
			return
		}
		items := []map[string]any{}
		for _, iface := range list {
			addrs, _ := iface.Addrs()
			addresses := []string{}
			for _, a := range addrs {
				addresses = append(addresses, a.String())
			}
			items = append(items, map[string]any{"name": iface.Name, "index": iface.Index, "up": iface.Flags&net.FlagUp != 0, "loopback": iface.Flags&net.FlagLoopback != 0, "mtu": iface.MTU, "addresses": addresses})
		}
		respond(w, 200, map[string]any{"items": items})
	case r.URL.Path == "/status" && r.Method == http.MethodGet:
		state, err := c.service(ctx)
		if err != nil {
			fail(503, err)
			return
		}
		cfg, configErr := c.config()
		result := map[string]any{"service": state, "interface": cfg.Interface, "mode": cfg.Mode, "attachment": nil, "config_error": ""}
		if configErr != nil {
			result["config_error"] = configErr.Error()
		}
		if cfg.Interface != "" {
			attachment, err := c.readAttachment(ctx, cfg.Interface)
			if err != nil {
				result["attachment_error"] = err.Error()
			} else {
				result["attachment"] = attachment
			}
		}
		result["statistics"] = nil
		if state["ActiveState"] == "active" {
			pid, _ := strconv.Atoi(state["MainPID"])
			statistics, err := xdpguard.ReadStatistics(c.statisticsDir, pid, cfg.Interface, time.Now())
			if err != nil {
				result["statistics_error"] = "Statistics unavailable: " + err.Error()
			} else {
				result["statistics"] = statistics
			}
		}
		respond(w, 200, result)
	case (r.URL.Path == "/start" || r.URL.Path == "/stop") && r.Method == http.MethodPost:
		action := "stop"
		if r.URL.Path == "/start" {
			action = "start"
			cfg, err := xdpguard.ReadConfig(c.path)
			if err != nil {
				fail(400, err)
				return
			}
			if _, err := net.InterfaceByName(cfg.Interface); err != nil {
				fail(400, err)
				return
			}
		}
		if action == "start" {
			before, err := c.service(ctx)
			if err != nil {
				fail(503, err)
				return
			}
			cfg, _ := xdpguard.ReadConfig(c.path)
			existing, err := c.readAttachment(ctx, cfg.Interface)
			if err != nil {
				fail(400, err)
				return
			}
			if before["ActiveState"] != "active" && attached(existing) {
				fail(409, fmt.Errorf("interface already has an XDP program; existing filters are never replaced"))
				return
			}
		}
		out, err := c.command(ctx, "systemctl", action, unit)
		if err != nil {
			fail(503, fmt.Errorf("systemctl %s: %s: %w", action, strings.TrimSpace(string(out)), err))
			return
		}
		state, err := c.service(ctx)
		if err != nil {
			fail(503, err)
			return
		}
		// Type=simple becomes active before BPF attach completes. Poll actual kernel
		// attachment and service failure so the UI never reports a successful start early.
		if action == "start" {
			cfg, _ := xdpguard.ReadConfig(c.path)
			for {
				attachment, attachErr := c.readAttachment(ctx, cfg.Interface)
				if state["ActiveState"] == "active" && attachErr == nil && attached(attachment) {
					respond(w, 200, map[string]any{"service": state, "attachment": attachment})
					return
				}
				if state["ActiveState"] == "failed" || state["ActiveState"] == "activating" && state["SubState"] == "auto-restart" {
					fail(503, fmt.Errorf("XDP failed to attach: service result %s; check journalctl -u fess-xdp", state["Result"]))
					return
				}
				select {
				case <-ctx.Done():
					fail(503, fmt.Errorf("XDP attachment not confirmed: %w", ctx.Err()))
					return
				case <-time.After(100 * time.Millisecond):
				}
				state, err = c.service(ctx)
				if err != nil {
					fail(503, err)
					return
				}
			}
		}
		respond(w, 200, map[string]any{"service": state})
	default:
		respond(w, http.StatusNotFound, map[string]string{"error": "unknown XDP controller operation"})
	}
}

func attached(value any) bool {
	m, ok := value.(map[string]any)
	if !ok {
		return false
	}
	// iproute2 normally exposes prog.id and attached=drv/generic; older versions
	// may expose prog_id directly.
	if p, ok := m["prog"].(map[string]any); ok {
		if id, ok := p["id"].(float64); ok && id > 0 {
			return true
		}
	}
	if id, ok := m["prog_id"].(float64); ok && id > 0 {
		return true
	}
	return false
}

func Serve(ctx context.Context, path, socket string) error {
	// The systemd service runs root:fess inside its own non-writable runtime dir.
	conn, err := net.Listen("unix", socket)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err = os.Chmod(socket, 0660); err != nil {
		return err
	}
	server := &http.Server{Handler: New(path), ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 20 * time.Second, IdleTimeout: 30 * time.Second}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		server.Shutdown(shutdown)
	}()
	err = server.Serve(conn)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
