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
	def := "(splash)"
	if snap.Default != nil {
		def = snap.Default.String()
	}
	store.Swap(snap)
	log.Printf("routing table loaded sites=%d default=%s", len(snap.Sites), def)
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
		secureWS := base.Clone()
		insecureWS := base.Clone()
		secureWS.ForceAttemptHTTP2 = false
		secureWS.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
		insecureWS.ForceAttemptHTTP2 = false
		insecureWS.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
		if insecure.TLSClientConfig == nil {
			insecure.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		} else {
			insecure.TLSClientConfig = insecure.TLSClientConfig.Clone()
		}
		insecure.TLSClientConfig.InsecureSkipVerify = true
		if insecureWS.TLSClientConfig == nil {
			insecureWS.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		} else {
			insecureWS.TLSClientConfig = insecureWS.TLSClientConfig.Clone()
		}
		insecureWS.TLSClientConfig.InsecureSkipVerify = true
		backendHTTPTransports = &backendTLSPickTransport{
			base:       base,
			secure:     secure,
			insecure:   insecure,
			secureWS:   secureWS,
			insecureWS: insecureWS,
		}
	})
	return backendHTTPTransports
}

type backendTLSPickTransport struct {
	base       *http.Transport
	secure     http.RoundTripper
	insecure   http.RoundTripper
	secureWS   http.RoundTripper
	insecureWS http.RoundTripper
	custom     sync.Map // transportCacheKey -> http.RoundTripper
}

type transportCacheKey struct {
	insecure    bool
	websocket   bool
	idleSeconds int
}

func (t *backendTLSPickTransport) transportFor(req *http.Request) http.RoundTripper {
	insecure := routing.TLSSkipVerifyFromContext(req.Context())
	ws := isWebSocketUpgrade(req)
	idleSec := 0
	if bt, ok := routing.BackendTimeoutsFromContext(req.Context()); ok && bt.IdleTimeout > 0 {
		idleSec = int(bt.IdleTimeout / time.Second)
	}
	if idleSec == 0 {
		if ws {
			if insecure {
				return t.insecureWS
			}
			return t.secureWS
		}
		if insecure {
			return t.insecure
		}
		return t.secure
	}
	key := transportCacheKey{insecure: insecure, websocket: ws, idleSeconds: idleSec}
	if v, ok := t.custom.Load(key); ok {
		return v.(http.RoundTripper)
	}
	rt := t.cloneWithIdleTimeout(insecure, ws, time.Duration(idleSec)*time.Second)
	actual, _ := t.custom.LoadOrStore(key, rt)
	return actual.(http.RoundTripper)
}

func (t *backendTLSPickTransport) cloneWithIdleTimeout(insecure, ws bool, idle time.Duration) http.RoundTripper {
	tr := t.base.Clone()
	tr.IdleConnTimeout = idle
	if ws {
		tr.ForceAttemptHTTP2 = false
		tr.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
	}
	if insecure {
		if tr.TLSClientConfig == nil {
			tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		} else {
			tr.TLSClientConfig = tr.TLSClientConfig.Clone()
		}
		tr.TLSClientConfig.InsecureSkipVerify = true
	}
	return tr
}

func (t *backendTLSPickTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	rt := t.transportFor(req)
	if bt, ok := routing.BackendTimeoutsFromContext(req.Context()); ok && bt.Timeout > 0 {
		ctx, cancel := context.WithTimeout(req.Context(), bt.Timeout)
		defer cancel()
		req = req.WithContext(ctx)
	}
	return rt.RoundTrip(req)
}

func newDynamicReverseProxy(defaultUpstream *url.URL, store *routing.Store, ipRes *clientip.Resolver) *httputil.ReverseProxy {
	return &httputil.ReverseProxy{
		FlushInterval: 100 * time.Millisecond,
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			log.Printf("upstream error: %v", err)
			writeFESSError(w, http.StatusBadGateway, pageError, "Бэкенд недоступен", "FESS не смог связаться с upstream. Проверьте сайт и бэкенд в панели.")
		},
		Director: func(req *http.Request) {
			originalHost := publicHostHeader(req, ipRes)
			originalScheme := requestScheme(req)
			mr := store.Current().Match(originalHost, req.URL.Path)
			target := mr.Backend
			if target == nil {
				target = defaultUpstream
			}
			if target == nil {
				target = &url.URL{Scheme: "http", Host: "127.0.0.1:9"}
			}
			skip := mr.TLSSkipVerify && target != nil && target.Scheme == "https"
			ctx := routing.WithTLSSkipVerify(req.Context(), skip)
			if mr.TimeoutSec > 0 || mr.IdleTimeoutSec > 0 {
				ctx = routing.WithBackendTimeouts(ctx, routing.TimeoutsFromSeconds(mr.TimeoutSec, mr.IdleTimeoutSec))
			}
			*req = *req.WithContext(ctx)
			req.URL.Scheme = target.Scheme
			req.URL.Host = target.Host
			// Preserve the public Host header. Many backends build CORS, redirects and absolute URLs
			// from Host/X-Forwarded-Host; replacing it with the container/upstream host breaks them.
			req.Host = originalHost
			req.URL.User = target.User
			if mr.MatchedPathPrefix != "" {
				req.URL.Path = routing.StripPathPrefix(req.URL.Path, mr.MatchedPathPrefix)
				req.URL.RawPath = ""
			}

			applyUpstreamClientHeaders(req, ipRes, originalHost, originalScheme)
		},
		Transport: backendProxyTransport(),
	}
}
