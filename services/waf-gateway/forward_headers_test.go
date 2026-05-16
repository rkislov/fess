package main

import (
	"net/http"
	"net/url"
	"testing"

	"fence/pkg/clientip"
	"fence/pkg/routing"
)

func TestApplyUpstream_untrustedOverwritesSpoofedXFF(t *testing.T) {
	r := clientip.ParseTrustedProxies("")
	req := newTestReq("198.51.100.5:4000", "1.2.3.4", "")
	applyUpstreamClientHeaders(req, r, req.Host, "http")
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
	applyUpstreamClientHeaders(req, r, req.Host, "http")
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
	applyUpstreamClientHeaders(req, r, req.Host, "http")
	if got := req.Header.Get("X-Forwarded-For"); got != "192.0.2.1" {
		t.Fatalf("X-Forwarded-For: got %q want 192.0.2.1", got)
	}
}

func TestApplyUpstream_setsForwardedHostProtoAndPort(t *testing.T) {
	r := clientip.ParseTrustedProxies("")
	req := newTestReq("198.51.100.5:4000", "", "")
	applyUpstreamClientHeaders(req, r, "public.example.com:8443", "https")
	if got := req.Header.Get("X-Forwarded-Host"); got != "public.example.com:8443" {
		t.Fatalf("X-Forwarded-Host: got %q want public.example.com:8443", got)
	}
	if got := req.Header.Get("X-Original-Host"); got != "public.example.com:8443" {
		t.Fatalf("X-Original-Host: got %q want public.example.com:8443", got)
	}
	if got := req.Header.Get("X-Forwarded-Proto"); got != "https" {
		t.Fatalf("X-Forwarded-Proto: got %q want https", got)
	}
	if got := req.Header.Get("X-Forwarded-Ssl"); got != "on" {
		t.Fatalf("X-Forwarded-Ssl: got %q want on", got)
	}
	if got := req.Header.Get("HTTPS"); got != "on" {
		t.Fatalf("HTTPS: got %q want on", got)
	}
	if got := req.Header.Get("X-Url-Scheme"); got != "https" {
		t.Fatalf("X-Url-Scheme: got %q want https", got)
	}
	if got := req.Header.Get("X-Forwarded-Server"); got != "public.example.com" {
		t.Fatalf("X-Forwarded-Server: got %q want public.example.com", got)
	}
	if got := req.Header.Get("X-Forwarded-Port"); got != "8443" {
		t.Fatalf("X-Forwarded-Port: got %q want 8443", got)
	}
}

func TestDynamicReverseProxyPreservesPublicHost(t *testing.T) {
	target, _ := url.Parse("http://backend.internal:8080")
	store := routing.NewStore(target)
	proxy := newDynamicReverseProxy(target, store, clientip.ParseTrustedProxies(""))
	req := newTestReq("198.51.100.5:4000", "", "")
	req.Host = "public.example.com"
	req.Header.Set("Origin", "https://public.example.com")

	proxy.Director(req)

	if req.URL.Host != "backend.internal:8080" {
		t.Fatalf("URL.Host = %q, want backend.internal:8080", req.URL.Host)
	}
	if req.Host != "public.example.com" {
		t.Fatalf("Host header = %q, want public.example.com", req.Host)
	}
	if got := req.Header.Get("X-Forwarded-Host"); got != "public.example.com" {
		t.Fatalf("X-Forwarded-Host = %q, want public.example.com", got)
	}
	if got := req.Header.Get("Origin"); got != "https://public.example.com" {
		t.Fatalf("Origin = %q, want preserved", got)
	}
}

func TestDynamicReverseProxyUsesTrustedForwardedHost(t *testing.T) {
	target, _ := url.Parse("http://backend.internal:8080")
	store := routing.NewStore(target)
	proxy := newDynamicReverseProxy(target, store, clientip.ParseTrustedProxies("198.51.100.5/32"))
	req := newTestReq("198.51.100.5:4000", "", "")
	req.Host = "10.78.3.61:80"
	req.Header.Set("X-Forwarded-Host", "cifro.tech")
	req.Header.Set("Origin", "https://cifro.tech")

	proxy.Director(req)

	if req.URL.Host != "backend.internal:8080" {
		t.Fatalf("URL.Host = %q, want backend.internal:8080", req.URL.Host)
	}
	if req.Host != "cifro.tech" {
		t.Fatalf("Host header = %q, want cifro.tech", req.Host)
	}
	if got := req.Header.Get("X-Forwarded-Host"); got != "cifro.tech" {
		t.Fatalf("X-Forwarded-Host = %q, want cifro.tech", got)
	}
	if got := req.Header.Get("Origin"); got != "https://cifro.tech" {
		t.Fatalf("Origin = %q, want preserved", got)
	}
}

func TestPublicHostHeaderIgnoresUntrustedForwardedHost(t *testing.T) {
	req := newTestReq("203.0.113.9:4000", "", "")
	req.Host = "10.78.3.61:80"
	req.Header.Set("X-Forwarded-Host", "cifro.tech")
	if got := publicHostHeader(req, clientip.ParseTrustedProxies("198.51.100.5/32")); got != "10.78.3.61:80" {
		t.Fatalf("got %q want direct host", got)
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
