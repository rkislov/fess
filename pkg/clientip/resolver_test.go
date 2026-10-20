package clientip

import (
	"net/http"
	"testing"
)

func TestParseTrustedProxies_empty(t *testing.T) {
	r := ParseTrustedProxies("")
	if r.TrustsForwardedHeaders() {
		t.Fatal("empty list should not trust forwarded headers")
	}
	req := mustReq("192.0.2.10:5555", "X-Forwarded-For", "198.51.100.1")
	if got := r.ClientHost(req); got != "192.0.2.10" {
		t.Fatalf("no trust: got %q want 192.0.2.10", got)
	}
}

func TestTrustsForwardedHeaders_nonEmpty(t *testing.T) {
	r := ParseTrustedProxies("10.0.0.0/8")
	if !r.TrustsForwardedHeaders() {
		t.Fatal("expected trust with CIDR configured")
	}
}

func TestClientHost_trustedXFF(t *testing.T) {
	r := ParseTrustedProxies("192.0.2.1/32")
	// LB at 192.0.2.1, client 198.51.100.7
	req := mustReq("192.0.2.1:443", "X-Forwarded-For", "198.51.100.7, 192.0.2.1")
	if got := r.ClientHost(req); got != "198.51.100.7" {
		t.Fatalf("got %q want 198.51.100.7", got)
	}
}

func TestClientHost_untrustedPeerIgnoresXFF(t *testing.T) {
	r := ParseTrustedProxies("192.0.2.1/32")
	req := mustReq("198.51.100.99:443", "X-Forwarded-For", "1.2.3.4")
	if got := r.ClientHost(req); got != "198.51.100.99" {
		t.Fatalf("got %q want 198.51.100.99 (ignore spoofed XFF)", got)
	}
	if r.TrustsRequest(req) {
		t.Fatal("untrusted peer must not be trusted")
	}
}

func TestClientHost_xRealIP(t *testing.T) {
	r := ParseTrustedProxies("10.0.0.0/8")
	req := mustReq("10.1.2.3:80", "X-Real-IP", "203.0.113.44")
	if !r.TrustsRequest(req) {
		t.Fatal("trusted peer should be trusted")
	}
	if got := r.ClientHost(req); got != "203.0.113.44" {
		t.Fatalf("got %q want 203.0.113.44", got)
	}
}

func mustReq(remoteAddr, hdr, val string) *http.Request {
	req := &http.Request{
		RemoteAddr: remoteAddr,
		Header:     make(http.Header),
	}
	if hdr != "" && val != "" {
		req.Header.Set(hdr, val)
	}
	return req
}
