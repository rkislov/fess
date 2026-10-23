package api

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"fence/pkg/auth"
)

func xdpSettingsHandler(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.ClaimsFromContext(r.Context())
	if !ok || !auth.CanAdmin(claims.Role) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "admin required"})
		return
	}
	suffix := strings.TrimPrefix(r.URL.Path, "/api/v1/settings/xdp")
	endpoint := ""
	switch suffix {
	case "":
		if r.Method == http.MethodGet || r.Method == http.MethodPut {
			endpoint = "/config"
		}
	case "/status", "/interfaces":
		if r.Method == http.MethodGet {
			endpoint = suffix
		}
	case "/start", "/stop":
		if r.Method == http.MethodPost {
			endpoint = suffix
		}
	}
	if endpoint == "" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	socket := strings.TrimSpace(os.Getenv("FESS_XDP_CONTROL_SOCKET"))
	if socket == "" {
		socket = "/run/fess-xdp-control/control.sock"
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "unix", socket)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 20 * time.Second}
	req, err := http.NewRequestWithContext(r.Context(), r.Method, "http://xdp-controller"+endpoint, http.MaxBytesReader(w, r.Body, 4<<20))
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	req.Header.Set("Content-Type", "application/json")
	response, err := client.Do(req)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "XDP controller unavailable: install fess-xdp and start fess-xdp-control.service"})
		return
	}
	defer response.Body.Close()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(response.StatusCode)
	io.Copy(w, io.LimitReader(response.Body, 4<<20))
}
