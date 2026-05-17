package main

import (
	"net/http"
	"testing"
)

func TestIsStaticAssetRequest(t *testing.T) {
	t.Parallel()
	req, _ := http.NewRequest(http.MethodGet, "https://ds.example/2024/web-apps/spell.js", nil)
	if !isStaticAssetRequest(req) {
		t.Fatal("expected spell.js GET to be static")
	}
	req2, _ := http.NewRequest(http.MethodPost, "https://ds.example/spell.js", nil)
	if isStaticAssetRequest(req2) {
		t.Fatal("POST should not be static fast path")
	}
	req3, _ := http.NewRequest(http.MethodGet, "https://ds.example/coauthoring", nil)
	if isStaticAssetRequest(req3) {
		t.Fatal("path without extension should not match")
	}
}
