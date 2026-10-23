package api

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"fence/pkg/auth"
)

func TestXDPRequiresAdmin(t *testing.T) {
	for _, role := range []string{"", auth.RoleViewer, auth.RoleOperator} {
		r := httptest.NewRequest("POST", "/api/v1/settings/xdp/start", nil)
		r = r.WithContext(auth.WithClaims(r.Context(), auth.Claims{Role: role}))
		w := httptest.NewRecorder()
		xdpSettingsHandler(w, r)
		if w.Code != http.StatusForbidden {
			t.Fatalf("role %s: %d", role, w.Code)
		}
	}
}

func TestXDPProxyUsesLocalControllerWhitelist(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "fess-xdp-api-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, "c.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/status" || r.Method != "GET" {
			t.Errorf("unexpected controller request %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"service":{"ActiveState":"inactive"}}`))
	})}
	go server.Serve(listener)
	defer server.Shutdown(context.Background())
	t.Setenv("FESS_XDP_CONTROL_SOCKET", path)
	for _, tc := range []struct {
		path, method string
		want         int
	}{{"/status", "GET", 200}, {"/start", "GET", 405}, {"/anything", "POST", 405}} {
		r := httptest.NewRequest(tc.method, "/api/v1/settings/xdp"+tc.path, nil)
		r = r.WithContext(auth.WithClaims(r.Context(), auth.Claims{Role: auth.RoleAdmin}))
		w := httptest.NewRecorder()
		xdpSettingsHandler(w, r)
		if w.Code != tc.want {
			t.Fatalf("%s: %d: %s", tc.path, w.Code, w.Body.String())
		}
	}
}
