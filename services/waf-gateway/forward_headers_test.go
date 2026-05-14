package main

import (
	"net/http"
	"net/url"
	"testing"

	"fence/pkg/clientip"
)

func TestApplyUpstream_untrustedOverwritesSpoofedXFF(t *testing.T) {
	r := clientip.ParseTrustedProxies("")
	req := newTestReq("198.51.100.5:4000", "1.2.3.4", "")
	applyUpstreamClientHeaders(req, r)
	if got := req.Header.Get("X-Forwarded-For"); got != "198.51.100.5" {
		t.Fatalf("X-Forwarded-For: got %q want 198.51.100.5", got)
	}
	if got := req.Header.Get("X-Real-IP"); got != "198.51.100.5" {
		t.Fatalf("X-Real-IP: got %q", got)
	}
}

func TestApplyUpstream_trustedPreservesNonEmptyXFF(t *testing.T) {
	r := clientip.ParseTrustedProxies("192.0.2.1/32")
	chain := "203.0.113.9, 192.0.2.1"
	req := newTestReq("192.0.2.1:443", chain, "")
	applyUpstreamClientHeaders(req, r)
	if got := req.Header.Get("X-Forwarded-For"); got != chain {
		t.Fatalf("X-Forwarded-For: got %q want %q", got, chain)
	}
	if got := req.Header.Get("X-Real-IP"); got != "203.0.113.9" {
		t.Fatalf("X-Real-IP: got %q want 203.0.113.9", got)
	}
}

func TestApplyUpstream_trustedFillsEmptyXFF(t *testing.T) {
	r := clientip.ParseTrustedProxies("192.0.2.1/32")
	req := newTestReq("192.0.2.1:443", "", "")
	applyUpstreamClientHeaders(req, r)
	if got := req.Header.Get("X-Forwarded-For"); got != "192.0.2.1" {
		t.Fatalf("X-Forwarded-For: got %q want 192.0.2.1", got)
	}
}

func newTestReq(remoteAddr, xff, xfp string) *http.Request {
	req := &http.Request{
		Method:     "GET",
		RemoteAddr: remoteAddr,
		Header:     make(http.Header),
		URL:        &url.URL{Scheme: "http", Host: "app.internal", Path: "/"},
		Host:       "app.internal",
	}
	if xff != "" {
		req.Header.Set("X-Forwarded-For", xff)
	}
	if xfp != "" {
		req.Header.Set("X-Forwarded-Proto", xfp)
	}
	return req
}
