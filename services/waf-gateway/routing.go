package main

import (
	"context"
	"database/sql"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

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

func newDynamicReverseProxy(defaultUpstream *url.URL, store *routing.Store) *httputil.ReverseProxy {
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
			req.URL.Scheme = target.Scheme
			req.URL.Host = target.Host
			req.Host = target.Host
			req.URL.User = target.User
		},
	}
}
