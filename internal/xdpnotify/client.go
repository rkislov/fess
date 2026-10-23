// Package xdpnotify sends best-effort ban requests without giving the WAF BPF privileges.
package xdpnotify

import (
	"context"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"fence/pkg/clientip"
)

type Client struct {
	proxyProtocol *clientip.Resolver
	socket        string
	ctx           context.Context
	queue         chan string
	dropped       atomic.Uint64
}

func New(ctx context.Context, socket string) *Client {
	if socket == "" {
		return nil
	}
	if !filepath.IsAbs(socket) || len(socket) > 100 {
		log.Printf("xdp bans disabled: socket must be an absolute path of at most 100 bytes")
		return nil
	}
	c := &Client{ctx: ctx, socket: socket, queue: make(chan string, 256), proxyProtocol: clientip.ParseTrustedProxies(os.Getenv("WAF_TLS_PROXY_PROTOCOL_TRUSTED_CIDRS"))}
	go c.run(socket)
	return c
}

// Block only direct network peers. Header-derived client addresses and trusted
// proxy addresses must never turn into packet-level bans on the proxy.
func (c *Client) Block(r *http.Request, resolver *clientip.Resolver) {
	if c == nil || r == nil || resolver.TrustsRequest(r) || c.ctx.Err() != nil {
		return
	}
	if c.socket != "" {
		if st, err := os.Stat(c.socket); err != nil || st.Mode()&os.ModeSocket == 0 {
			return
		}
	}
	networkPeer, known := clientip.NetworkPeer(r)
	if !known {
		// Embedders that enable PROXY protocol must preserve the real socket peer.
		if c.proxyProtocol.TrustsForwardedHeaders() {
			return
		}
		networkPeer = r.RemoteAddr
	}
	peerRequest := *r
	peerRequest.RemoteAddr = networkPeer
	if resolver.TrustsRequest(&peerRequest) || c.proxyProtocol.TrustsRequest(&peerRequest) {
		return
	}
	peer, err := netip.ParseAddr(clientip.PeerHost(&peerRequest))
	if err != nil || peer.Zone() != "" || peer.IsUnspecified() || peer.IsMulticast() || peer.IsLoopback() {
		return
	}
	client, err := netip.ParseAddr(resolver.ClientHost(r))
	if err != nil || peer.Unmap() != client.Unmap() {
		return
	}
	select {
	case c.queue <- peer.Unmap().String():
	default:
		c.dropped.Add(1)
	}
}

func (c *Client) run(socket string) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	var failed uint64
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			if dropped := c.dropped.Swap(0); dropped != 0 || failed != 0 {
				log.Printf("xdp ban delivery: failed=%d queue_dropped=%d (WAF decisions remain enforced)", failed, dropped)
				failed = 0
			}
		case ip := <-c.queue:
			conn, err := net.DialTimeout("unixgram", socket, 50*time.Millisecond)
			if err == nil {
				err = conn.SetWriteDeadline(time.Now().Add(50 * time.Millisecond))
				if err == nil {
					_, err = conn.Write([]byte(ip))
				}
				conn.Close()
			}
			if err != nil {
				failed++
			}
		}
	}
}
