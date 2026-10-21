package gateway

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"fence/internal/logbatch"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"fence/pkg/clientip"
	"fence/pkg/engine"
	"fence/pkg/malware"
	"fence/pkg/policy"
	"fence/pkg/prommetrics"
	"fence/pkg/routing"
	"fence/pkg/tlssites"

	"fence/internal/runtimebus"
)

func New(ctx context.Context, db *sql.DB, state *runtimebus.Client) (http.Handler, *tls.Config, error) {
	target := strings.TrimSpace(getenv("UPSTREAM_URL", ""))
	failMode := getenv("WAF_FAIL_MODE", "open")

	var upstream *url.URL
	if target != "" && !strings.EqualFold(target, "splash") && !strings.EqualFold(target, "fess") {
		u, err := url.Parse(target)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid UPSTREAM_URL: %w", err)
		}
		upstream = u
	}
	if _, err := logbatch.Start(db); err != nil {
		return nil, nil, err
	}
	initGeoPath := getenv("GEOIP_MMDB_PATH", "")
	initASNPath := getenv("GEOIP_ASN_MMDB_PATH", "")
	reloadGeoIP(initGeoPath)
	reloadGeoASN(initASNPath)

	ipRes := clientip.ParseTrustedProxies(getenv("WAF_TRUSTED_PROXIES", ""))
	if !ipRes.TrustsForwardedHeaders() {
		log.Printf("waf-gateway: WAF_TRUSTED_PROXIES is unset — logs/WAF use TCP peer as client IP; behind Nginx/LB set CIDR(s) of the hop that connects to this gateway (see README: Nginx before waf-gateway)")
	}

	store := policy.NewStore()
	mwStore := newMalwareStore()
	evaluator := engine.NewEvaluator()

	routeStore := routing.NewStore(upstream)
	tlsStore := &tlssites.Store{}
	tfStore := newThreatFeedStore()
	botStore := newBotProtectionStore()
	rlStore := newRateLimitStore()
	bypassStore := newIPBypassStore()
	proxy := newDynamicReverseProxy(upstream, routeStore, ipRes)
	reloadPolicySnapshot(db, store)
	reloadMalwareConfig(db, mwStore)
	reloadThreatFeed(db, tfStore)
	reloadBotProtection(db, botStore)
	reloadRateLimitSettings(db, rlStore)
	reloadIPBypass(db, bypassStore)
	reloadRoutingTable(db, upstream, routeStore)
	reloadTLSTable(db, tlsStore)
	subscribePolicyUpdates(db, state, store)
	subscribeMalwareUpdates(db, state, mwStore)
	subscribeThreatFeedUpdates(db, state, tfStore)
	subscribeBotProtectionUpdates(db, state, botStore)
	subscribeRateLimitUpdates(db, state, rlStore)
	subscribeIPBypassUpdates(db, state, bypassStore)
	subscribeGeoIPUpdates(state, initGeoPath)
	subscribeGeoASNUpdates(state, initASNPath)
	subscribeRoutingUpdates(db, state, upstream, routeStore, tlsStore)

	redirects := map[string]string{}
	var knownTLS func(string) bool
	if strings.EqualFold(os.Getenv("WAF_HTTP_REDIRECT_HTTPS"), "true") {
		knownTLS = func(host string) bool {
			_, err := tlsStore.GetCertificate(&tls.ClientHelloInfo{ServerName: host})
			return err == nil
		}
	}
	for _, mapping := range strings.Split(os.Getenv("WAF_HTTP_CANONICAL_HOSTS"), ",") {
		parts := strings.SplitN(strings.TrimSpace(mapping), "=", 2)
		if len(parts) == 2 && parts[0] != "" && parts[1] != "" && !strings.ContainsAny(parts[0]+parts[1], "/\\?#@ \r\n") {
			redirects[parts[0]] = parts[1]
		}
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if serveACMEHTTP01(w, r, db) {
			return
		}
		if httpsRedirect(w, r, redirects, knownTLS) {
			return
		}
		if serveBrandAsset(w, r) {
			return
		}
		mr := routeStore.Current().Match(publicHostHeader(r, ipRes), r.URL.Path)
		if !enforceBackendIPAllow(w, r, mr, db, ipRes) {
			return
		}
		clientHost := ipRes.ClientHost(r)
		if strings.TrimSpace(clientHost) == "" {
			clientHost = clientip.PeerHost(r)
		}
		ipBypassed := clientIPBypassed(bypassStore, clientHost)

		var gateTF threatFeedGateResult
		var gateBot botProtectionGateResult
		if !ipBypassed {
			gateRL := applyRateLimitGate(w, r, db, mr, ipRes, rlStore.Global(), state)
			if gateRL.Responded {
				return
			}
			gateTF = applyThreatFeedGate(w, r, db, mr, ipRes, tfStore)
			if gateTF.Responded {
				return
			}
			gateBot = applyBotProtectionGate(w, r, db, mr, ipRes, botStore, state)
			if gateBot.Responded {
				return
			}
		}

		if isStaticAssetRequest(r) {
			if maybeServeSplash(w, r, mr, db, ipRes) {
				return
			}
			serveStaticFastPath(w, r, mr, db, proxy, ipRes, gateTF.ProxyOutcomeHint)
			return
		}

		if isWebSocketUpgrade(r) {
			serveWebSocketUpgrade(w, r, mr, db, store, evaluator, proxy, failMode, gateTF, ipRes, bypassStore)
			return
		}

		mcfg := mwStore.Current()
		maxRead := mcfg.BodyScan.MaxBytes
		if maxRead <= 0 {
			maxRead = 32 << 20
		}
		body, err := readRequestBody(r, maxRead)
		if err != nil {
			if strings.Contains(err.Error(), "exceeds max_bytes") {
				writeFESSError(w, http.StatusRequestEntityTooLarge, pageError, "Слишком большой запрос", "Тело запроса превысило лимит сканирования FESS.")
				return
			}
			writeFESSError(w, http.StatusBadRequest, pageError, "Некорректный запрос", "FESS не смог прочитать тело запроса.")
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))

		if len(body) > 0 {
			tfSnap := tfStore.Current()
			if hash, matched, shouldBlock := tfSnap.MatchFileHash(body); matched {
				v := malware.Verdict{
					Clean:  false,
					Source: "threatfox_hash",
					Detail: "ThreatFox file hash IOC: " + hash,
				}
				writeMalwareScanLog(r.Context(), db, r, v, int64(len(body)), ipRes)
				if shouldBlock {
					writeThreatFeedLog(r.Context(), db, r, true, ipRes)
					writeProxyAccessLog(r.Context(), db, r, mr, "threat_feed_block", ipRes)
					writeFESSError(w, http.StatusForbidden, pageBlocked, "Заблокировано", "Хэш файла совпал с индикатором ThreatFox.")
					return
				}
				writeThreatFeedLog(r.Context(), db, r, false, ipRes)
			}
		}

		if mcfg.ShouldScanHTTPRequest(r.Method, r.Header.Get("Content-Type"), int64(len(body))) {
			v := malware.Scan(r.Context(), mcfg, r.Method, r.URL.RequestURI(), hostHeader(r), r.Header.Get("Content-Type"), body)
			writeMalwareScanLog(r.Context(), db, r, v, int64(len(body)), ipRes)
			if !v.Clean {
				writeMalwareLog(r.Context(), db, r, v, ipRes)
				writeProxyAccessLog(r.Context(), db, r, mr, "malware_block", ipRes)
				writeFESSError(w, http.StatusForbidden, pageBlocked, "Вредоносный файл", "Антивирус FESS остановил этот запрос.")
				return
			}
		}

		snapshot := store.Current()
		var decision engine.Decision
		if ipBypassed {
			decision = engine.Decision{Action: "allow", Reason: "ip bypass allowlist"}
		} else {
			decision = evaluator.EvaluateBody(r, snapshot, mr.PolicyID, clientHost, body)
		}
		effectiveAction := decision.Action
		if decision.PolicyMode == "log" && (decision.Action == "block" || decision.Action == "redirect" || decision.Action == "replace") {
			effectiveAction = "log"
		}
		writeWAFLog(r.Context(), db, r, decision, effectiveAction, ipRes)

		accessOutcome := "proxied"
		switch effectiveAction {
		case "block":
			accessOutcome = "waf_block"
		case "redirect":
			accessOutcome = "redirect"
		}
		if accessOutcome == "proxied" {
			if gateBot.ProxyOutcomeHint != "" {
				accessOutcome = gateBot.ProxyOutcomeHint
			} else if gateTF.ProxyOutcomeHint != "" {
				accessOutcome = gateTF.ProxyOutcomeHint
			}
		}
		writeProxyAccessLog(r.Context(), db, r, mr, accessOutcome, ipRes)

		switch effectiveAction {
		case "block":
			writeFESSError(w, http.StatusForbidden, pageBlocked, "Заблокировано политикой", "Правило WAF отклонило этот запрос.")
			return
		case "redirect":
			target := decision.RedirectURL
			if target == "" {
				target = "/"
			}
			http.Redirect(w, r, target, http.StatusFound)
			return
		case "replace":
			if maybeServeSplash(w, r, mr, db, ipRes) {
				return
			}
			proxy.ServeHTTP(w, r)
			return
		default:
			if decision.Action == "deny_on_error" && strings.EqualFold(failMode, "close") {
				writeFESSError(w, http.StatusServiceUnavailable, pageError, "Временно недоступно", "FESS не смог применить политику (fail-closed).")
				return
			}
			if maybeServeSplash(w, r, mr, db, ipRes) {
				return
			}
			proxy.ServeHTTP(w, r)
		}
	})

	wrapped := prommetrics.Middleware("waf-gateway", handler)
	tlsCfg := &tls.Config{
		MinVersion:     tls.VersionTLS12,
		GetCertificate: tlsStore.GetCertificate,
		NextProtos:     []string{"h2", "http/1.1"},
	}

	return loggingMiddleware(wrapped, ipRes), tlsCfg, nil
}

func Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	err := logbatch.CloseAll(ctx)
	closeGeoIP()
	asnMu.Lock()
	defer asnMu.Unlock()
	if asnReader != nil {
		asnReader.Close()
		asnReader = nil
	}
	return err
}

func reloadPolicySnapshot(db *sql.DB, store *policy.Store) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	next, err := policy.LoadActiveSnapshot(ctx, db)
	if err != nil {
		log.Printf("policy reload failed: %v", err)
		return
	}
	next.Version = store.Current().Version + 1
	store.Swap(next)
	log.Printf("policy snapshot loaded version=%d policies=%d", next.Version, len(next.Policies))
}

func subscribePolicyUpdates(db *sql.DB, state *runtimebus.Client, store *policy.Store) {
	ctx := context.Background()
	sub := state.Subscribe(ctx, "policy_updates")
	go func() {
		defer sub.Close()

		for msg := range sub.Channel() {
			log.Printf("received policy update event: %s", msg.Payload)
			reloadPolicySnapshot(db, store)
		}
	}()
}

func writeWAFLog(ctx context.Context, db *sql.DB, r *http.Request, decision engine.Decision, effectiveAction string, ipRes *clientip.Resolver) {
	if decision.RuleID == "" {
		return
	}
	requestID := r.Header.Get("X-Request-Id")
	if requestID == "" {
		requestID = fmt.Sprintf("req-%d", time.Now().UnixNano())
	}

	details, _ := json.Marshal(map[string]any{
		"reason":         decision.Reason,
		"policy_mode":    decision.PolicyMode,
		"effective":      effectiveAction,
		"originalAction": decision.Action,
	})
	h := publicHostHeader(r, ipRes)
	srcIP := ipRes.ClientHost(r)
	if srcIP == "" {
		srcIP = r.RemoteAddr
	}
	err := logbatch.Exec(ctx, db, `
INSERT INTO waf_logs(request_id, policy_id, rule_id, action, source_ip, method, path, host, details)
VALUES ($1, $2::uuid, $3::uuid, $4, $5, $6, $7, $8, $9::jsonb)`,
		requestID, decision.PolicyID, decision.RuleID, effectiveAction, srcIP, r.Method, r.URL.Path, h, string(details))
	if err != nil {
		log.Printf("failed to write waf log: %v", err)
	}
	prommetrics.RecordGatewayWAF(effectiveAction)
}

func loggingMiddleware(next http.Handler, ipRes *clientip.Resolver) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		lw := &loggingResponseWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(lw, r)
		client := ipRes.ClientHost(r)
		if client == "" {
			client = r.RemoteAddr
		}
		log.Printf(
			"method=%s path=%s status=%d bytes=%d upgrade=%q client=%s remote=%s latency=%s",
			r.Method,
			r.URL.Path,
			lw.status,
			lw.bytes,
			r.Header.Get("Upgrade"),
			client,
			r.RemoteAddr,
			time.Since(start),
		)
	})
}

type loggingResponseWriter struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (w *loggingResponseWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *loggingResponseWriter) Write(p []byte) (int, error) {
	n, err := w.ResponseWriter.Write(p)
	w.bytes += n
	return n, err
}

func (w *loggingResponseWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *loggingResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, http.ErrNotSupported
	}
	return h.Hijack()
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
