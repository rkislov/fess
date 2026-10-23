package clientip

import (
	"context"
	"net"
	"net/http"
)

type networkPeerKey struct{}

// CaptureNetworkPeer runs in http.Server.ConnContext, before TLS/PROXY header
// processing can replace RemoteAddr. Only the real socket peer can be banned.
func CaptureNetworkPeer(ctx context.Context, conn net.Conn) context.Context {
	for i := 0; i < 8; i++ {
		switch c := conn.(type) {
		case interface{ NetConn() net.Conn }:
			conn = c.NetConn()
		case interface{ Raw() net.Conn }:
			conn = c.Raw()
		default:
			return WithNetworkPeer(ctx, conn.RemoteAddr().String())
		}
	}
	return ctx // Unknown wrapper depth: do not assert that a peer is verified.
}
func WithNetworkPeer(ctx context.Context, peer string) context.Context {
	return context.WithValue(ctx, networkPeerKey{}, peer)
}
func NetworkPeer(r *http.Request) (string, bool) {
	peer, ok := r.Context().Value(networkPeerKey{}).(string)
	return peer, ok && peer != ""
}
