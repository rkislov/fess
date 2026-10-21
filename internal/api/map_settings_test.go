package api

import (
	"context"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	fencedb "fence/db"
	"fence/pkg/auth"
)

func TestMapSettingsPermissionsAndPersistence(t *testing.T) {
	d, err := fencedb.Open(context.Background(), "sqlite", filepath.Join(t.TempDir(), "fess.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if err = fencedb.ApplyMigrations(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		role, body string
		want       int
	}{
		{"viewer", `{"provider":"carto","api_key":"test"}`, 403},
		{"operator", `{"provider":"carto","api_key":"test"}`, 403},
		{"admin", `{"provider":"evil","api_key":"test"}`, 400},
		{"admin", `{"provider":"yandex","api_key":"test<&"}`, 200},
	} {
		req := httptest.NewRequest("PUT", "/", strings.NewReader(tc.body))
		req = req.WithContext(auth.WithClaims(req.Context(), auth.Claims{Role: tc.role, Username: "tester"}))
		w := httptest.NewRecorder()
		mapSettingsHandler(w, req, d)
		if w.Code != tc.want {
			t.Fatalf("%s: %d %s", tc.role, w.Code, w.Body.String())
		}
	}
	w := httptest.NewRecorder()
	mapSettingsHandler(w, httptest.NewRequest("GET", "/", nil), d)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"provider":"yandex"`) {
		t.Fatal(w.Code, w.Body.String())
	}
}
