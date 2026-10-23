package xdpnotify

import (
	"context"
	"net"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"fence/pkg/clientip"
)

func TestBlockOnlyDirectPeers(t *testing.T) {
	for _, tc := range []struct{ name, peer, proxies, xff, want string }{
		{"direct", "198.51.100.2:1234", "", "", "198.51.100.2"},
		{"forged-header", "198.51.100.2:1234", "", "203.0.113.1", "198.51.100.2"},
		{"trusted-proxy", "192.0.2.1:1234", "192.0.2.0/24", "198.51.100.2", ""},
		{"proxy-without-header", "192.0.2.1:1234", "192.0.2.0/24", "", ""},
		{"ipv6", "[2001:db8::2]:1234", "", "", "2001:db8::2"},
		{"mapped", "[::ffff:198.51.100.2]:1234", "", "", "198.51.100.2"},
		{"invalid", "unknown", "", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &Client{ctx: context.Background(), queue: make(chan string, 1)}
			r := httptest.NewRequest("GET", "http://example.com/", nil)
			r.RemoteAddr = tc.peer
			r.Header.Set("X-Forwarded-For", tc.xff)
			c.Block(r, clientip.ParseTrustedProxies(tc.proxies))
			got := ""
			select {
			case got = <-c.queue:
			default:
			}
			if got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}
}

func TestBoundedDeliveryAndCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := &Client{ctx: ctx, queue: make(chan string, 1)}
	r := httptest.NewRequest("GET", "http://example.com/", nil)
	r.RemoteAddr = "198.51.100.2:1234"
	resolver := clientip.ParseTrustedProxies("")
	c.Block(r, resolver)
	c.Block(r, resolver)
	if c.dropped.Load() != 1 {
		t.Fatal("full queue must drop without blocking")
	}
	cancel()
	c.Block(r, resolver)
	if c.dropped.Load() != 1 {
		t.Fatal("cancelled client accepted work")
	}
	var disabled *Client
	disabled.Block(r, resolver)
	if New(ctx, "") != nil || New(ctx, "relative.sock") != nil {
		t.Fatal("disabled/invalid client")
	}
}

func TestUnixDatagramDelivery(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "b.sock")
	conn, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: socket, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := New(ctx, socket)
	r := httptest.NewRequest("GET", "http://example.com/", nil)
	r.RemoteAddr = "198.51.100.2:1234"
	c.Block(r, clientip.ParseTrustedProxies(""))
	conn.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 128)
	n, _, err := conn.ReadFromUnix(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "198.51.100.2" {
		t.Fatalf("message: %q", buf[:n])
	}
}

func TestProxyProtocolSeparatesDirectAndForwardedConnections(t *testing.T) {
	for _, tc := range []struct{ name, remote, network, proxy, want string }{
		{"direct-http-with-proxy-enabled", "198.51.100.2:1234", "198.51.100.2:1234", "127.0.0.1/32", "198.51.100.2"},
		{"forwarded-tls", "198.51.100.2:1234", "127.0.0.1:1234", "127.0.0.1/32", ""},
		{"unverified-transport", "198.51.100.2:1234", "", "127.0.0.1/32", ""},
		{"proxy-header-claims-proxy", "192.0.2.1:1234", "192.0.2.1:1234", "192.0.2.0/24", ""},
		{"loopback-never-banned", "127.0.0.1:1234", "127.0.0.1:1234", "", ""},
		{"mismatched-transport", "198.51.100.2:1234", "203.0.113.4:1234", "127.0.0.1/32", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &Client{ctx: context.Background(), queue: make(chan string, 1), proxyProtocol: clientip.ParseTrustedProxies(tc.proxy)}
			r := httptest.NewRequest("GET", "http://example.com/", nil)
			r.RemoteAddr = tc.remote
			if tc.network != "" {
				r = r.WithContext(clientip.WithNetworkPeer(r.Context(), tc.network))
			}
			c.Block(r, clientip.ParseTrustedProxies(""))
			got := ""
			select {
			case got = <-c.queue:
			default:
			}
			if got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}
}
