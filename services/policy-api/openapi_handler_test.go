package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestOpenAPISpecHandler(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/openapi.yaml", nil)
	rec := httptest.NewRecorder()
	openAPISpecHandler(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.HasPrefix(body, "openapi: 3.0.3") {
		t.Fatalf("unexpected spec prefix: %q", body[:min(80, len(body))])
	}
	if !strings.Contains(body, "/api/v1/certificates") {
		t.Fatal("spec missing certificates path")
	}
	if !strings.Contains(body, "/api/v1/dashboard/containers/update-all") {
		t.Fatal("spec missing container update path")
	}
	if !strings.Contains(body, `version: "1.2.0"`) {
		t.Fatal("spec version should be 1.2.0")
	}
	if !strings.Contains(rec.Header().Get("Content-Type"), "yaml") {
		t.Fatalf("content-type %q", rec.Header().Get("Content-Type"))
	}
}
