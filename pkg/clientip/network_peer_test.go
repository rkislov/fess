package clientip

import (
	"context"
	"crypto/tls"
	"net"
	"net/http/httptest"
	"testing"

	"github.com/pires/go-proxyproto"
)

type peerConn struct{ net.Conn }

func (c peerConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}
}

func TestCaptureNetworkPeerBeforeTLSAndProxyHeaders(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	// No PROXY/TLS data is sent: capturing the raw peer must never read headers.
	wrapped := tls.Server(proxyproto.NewConn(peerConn{a}), &tls.Config{MinVersion: tls.VersionTLS12})
	ctx := CaptureNetworkPeer(context.Background(), wrapped)
	req := httptest.NewRequest("GET", "https://example.test/", nil).WithContext(ctx)
	req.RemoteAddr = "198.51.100.8:443"
	if peer, ok := NetworkPeer(req); !ok || peer != "127.0.0.1:12345" {
		t.Fatalf("lost transport peer: %q %v", peer, ok)
	}
}
