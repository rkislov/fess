package main

import (
	"context"
	"crypto/tls"
	"database/sql"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"

	"fence/pkg/clientip"
	"fence/pkg/routing"
	"fence/pkg/tlssites"
	"github.com/redis/go-redis/v9"
)

func reloadRoutingTable(db *sql.DB, defaultUpstream *url.URL, store *routing.Store) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	snap, err := routing.LoadSnapshot(ctx, db, defaultUpstream)
	if err != nil {
		log.Printf("routing reload failed: %v", err)
		return
	}
	store.Swap(snap)
	log.Printf("routing table loaded sites=%d default=%s", len(snap.Sites), snap.Default.String())
}

func reloadTLSTable(db *sql.DB, tlsStore *tlssites.Store) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	snap, err := tlssites.LoadSnapshot(ctx, db)
	if err != nil {
		log.Printf("tls snapshot reload failed: %v", err)
		return
	}
	tlsStore.Swap(snap)
	log.Printf("tls site certificates loaded count=%d", len(snap.Entries))
}

func subscribeRoutingUpdates(db *sql.DB, rdb *redis.Client, defaultUpstream *url.URL, store *routing.Store, tlsStore *tlssites.Store) {
	ctx := context.Background()
	sub := rdb.Subscribe(ctx, "routing_updated")
	defer sub.Close()
	for msg := range sub.Channel() {
		log.Printf("routing update event: %s", msg.Payload)
		reloadRoutingTable(db, defaultUpstream, store)
		reloadTLSTable(db, tlsStore)
	}
}

var (
	backendHTTPTransports     http.RoundTripper
	initBackendHTTPTransports sync.Once
)

func backendProxyTransport() http.RoundTripper {
	initBackendHTTPTransports.Do(func() {
		base, ok := http.DefaultTransport.(*http.Transport)
		if !ok {
			base = &http.Transport{
				Proxy: http.ProxyFromEnvironment,
				DialContext: (&net.Dialer{
					Timeout:   30 * time.Second,
					KeepAlive: 30 * time.Second,
				}).DialContext,
				ForceAttemptHTTP2:     true,
				MaxIdleConns:          100,
				IdleConnTimeout:       90 * time.Second,
				TLSHandshakeTimeout:   10 * time.Second,
				ExpectContinueTimeout: 1 * time.Second,
			}
		}
		secure := base.Clone()
		insecure := base.Clone()
		if insecure.TLSClientConfig == nil {
			insecure.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		} else {
			insecure.TLSClientConfig = insecure.TLSClientConfig.Clone()
		}
		insecure.TLSClientConfig.InsecureSkipVerify = true
		backendHTTPTransports = &backendTLSPickTransport{secure: secure, insecure: insecure}
	})
	return backendHTTPTransports
}

type backendTLSPickTransport struct {
	secure   http.RoundTripper
	insecure http.RoundTripper
}

func (t *backendTLSPickTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if routing.TLSSkipVerifyFromContext(req.Context()) {
		return t.insecure.RoundTrip(req)
	}
	return t.secure.RoundTrip(req)
}

func newDynamicReverseProxy(defaultUpstream *url.URL, store *routing.Store, ipRes *clientip.Resolver) *httputil.ReverseProxy {
	return &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			host := req.Host
			if host == "" {
				host = req.URL.Host
			}
			mr := store.Current().Match(host)
			target := mr.Backend
			if target == nil {
				target = defaultUpstream
			}
			skip := mr.TLSSkipVerify && target != nil && target.Scheme == "https"
			*req = *req.WithContext(routing.WithTLSSkipVerify(req.Context(), skip))
			req.URL.Scheme = target.Scheme
			req.URL.Host = target.Host
			req.Host = target.Host
			req.URL.User = target.User

			if ipRes != nil && strings.TrimSpace(req.Header.Get("X-Forwarded-For")) == "" {
				ch := ipRes.ClientHost(req)
				peer := clientip.PeerHost(req)
				if ch != "" && peer != "" && ch != peer {
					req.Header.Set("X-Forwarded-For", ch)
				}
			}
		},
		Transport: backendProxyTransport(),
	}
}
