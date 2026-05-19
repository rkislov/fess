package prommetrics

import (
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (w *statusRecorder) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

// Middleware records request counts and latency for Prometheus.
func Middleware(service string, next http.Handler) http.Handler {
	initRegistry()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/metrics" {
			next.ServeHTTP(w, r)
			return
		}
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		path := normalizePath(r.URL.Path)
		status := strconv.Itoa(rec.status)
		HTTPRequestsTotal.WithLabelValues(service, r.Method, path, status).Inc()
		HTTPRequestDuration.WithLabelValues(service, r.Method, path).Observe(time.Since(start).Seconds())
	})
}

func normalizePath(p string) string {
	if p == "" {
		return "/"
	}
	parts := strings.Split(p, "/")
	for i, part := range parts {
		if part == "" {
			continue
		}
		if _, err := uuid.Parse(part); err == nil {
			parts[i] = ":id"
			continue
		}
		if len(part) > 36 && strings.Count(part, "-") >= 4 {
			parts[i] = ":id"
		}
	}
	out := strings.Join(parts, "/")
	if !strings.HasPrefix(out, "/") {
		out = "/" + out
	}
	return out
}

// ListenAndServe starts a dedicated HTTP server for /metrics and /healthz.
func ListenAndServe(addr string) {
	if strings.TrimSpace(addr) == "" {
		return
	}
	mux := http.NewServeMux()
	mux.Handle("/metrics", Handler())
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	go func() {
		log.Printf("prometheus metrics listening on %s (/metrics, /healthz)", addr)
		if err := http.ListenAndServe(addr, mux); err != nil && err != http.ErrServerClosed {
			log.Printf("prometheus metrics server error: %v", err)
		}
	}()
}
