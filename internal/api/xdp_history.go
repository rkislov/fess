package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"fence/internal/xdpguard"
	"fence/internal/xdphistory"
	"fence/pkg/auth"
)

func xdpControllerClient(timeout time.Duration) *http.Client {
	socket := strings.TrimSpace(os.Getenv("FESS_XDP_CONTROL_SOCKET"))
	if socket == "" {
		socket = "/run/fess-xdp-control/control.sock"
	}
	return &http.Client{Timeout: timeout, Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "unix", socket)
	}}}
}

func collectXDPHistory(ctx context.Context, db *sql.DB, client *http.Client, now time.Time) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://xdp-controller/status", nil)
	if err != nil {
		return err
	}
	response, err := client.Do(req)
	if err != nil {
		// XDP is optional; connection failures create a gap, never zero samples.
		return nil
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil
	}
	var status struct {
		Service    map[string]string    `json:"service"`
		Statistics *xdpguard.Statistics `json:"statistics"`
	}
	if err = json.NewDecoder(io.LimitReader(response.Body, 128<<10)).Decode(&status); err != nil {
		return fmt.Errorf("decode XDP snapshot: %w", err)
	}
	if status.Service["ActiveState"] != "active" {
		return nil
	}
	return xdphistory.Save(ctx, db, status.Statistics, now)
}

func runXDPHistoryCollector(ctx context.Context, db *sql.DB) {
	client := xdpControllerClient(4 * time.Second)
	defer client.CloseIdleConnections()
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	var lastPrune, lastLog, lastAlert time.Time
	for {
		now := time.Now()
		work, cancel := context.WithTimeout(ctx, 4*time.Second)
		err := collectXDPHistory(work, db, client, now)
		cancel()
		if now.Sub(lastAlert) >= 15*time.Second {
			// Give monitoring its own deadline even if the controller times out.
			aw, done := context.WithTimeout(ctx, 3*time.Second)
			if ae := xdphistory.EvaluateAlerts(aw, db, now); ae != nil {
				err = ae
			}
			done()
			lastAlert = now
		}
		if now.Sub(lastPrune) >= time.Hour {
			pw, done := context.WithTimeout(ctx, 4*time.Second)
			pruneErr := xdphistory.Prune(pw, db, now)
			done()
			if pruneErr != nil {
				err = pruneErr
			} else {
				lastPrune = now
			}
		}
		if err != nil && ctx.Err() == nil && now.Sub(lastLog) >= time.Minute {
			log.Printf("XDP history: %v", err)
			lastLog = now
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func xdpHistoryHandler(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	claims, ok := auth.ClaimsFromContext(r.Context())
	if !ok || !auth.CanAdmin(claims.Role) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "admin required"})
		return
	}
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	period := r.URL.Query().Get("period")
	if period == "" {
		period = "hour"
	}
	if _, _, ok := xdphistory.Period(period); !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "period must be hour, day or week"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	history, err := xdphistory.Query(ctx, db, period, time.Now())
	if err != nil {
		log.Printf("query XDP history: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "XDP history unavailable"})
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, history)
}

func xdpAlertsHandler(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	claims, ok := auth.ClaimsFromContext(r.Context())
	if !ok || !auth.CanAdmin(claims.Role) {
		writeJSON(w, 403, map[string]string{"error": "admin required"})
		return
	}
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	alerts, err := xdphistory.RecentAlerts(ctx, db)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "XDP alerts unavailable"})
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{"items": alerts})
}
