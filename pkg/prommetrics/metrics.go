package prommetrics

import (
	"net/http"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const namespace = "fence"

var (
	once     sync.Once
	registry *prometheus.Registry

	HTTPRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "http_requests_total",
			Help:      "HTTP requests processed.",
		},
		[]string{"service", "method", "path", "status"},
	)
	HTTPRequestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "http_request_duration_seconds",
			Help:      "HTTP request latency in seconds.",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"service", "method", "path"},
	)

	GatewayConnectionsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "gateway_connections_total",
			Help:      "Proxy connections handled by waf-gateway (by outcome).",
		},
		[]string{"outcome"},
	)
	GatewayWAFDecisionsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "gateway_waf_decisions_total",
			Help:      "WAF rule evaluations with a matching rule.",
		},
		[]string{"action"},
	)
	GatewayMalwareScansTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "gateway_malware_scans_total",
			Help:      "Malware scan attempts on request bodies.",
		},
		[]string{"result", "source"},
	)

	DBRowsTotal = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "db_rows_total",
			Help:      "Approximate row counts in PostgreSQL tables.",
		},
		[]string{"table"},
	)
	DBEventsLastHour = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "db_events_last_hour",
			Help:      "Event counts in the last hour from database.",
		},
		[]string{"stream"},
	)
)

func Registry() *prometheus.Registry {
	initRegistry()
	return registry
}

func initRegistry() {
	once.Do(func() {
		registry = prometheus.NewRegistry()
		registry.MustRegister(collectors.NewGoCollector())
		registry.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
		registry.MustRegister(
			HTTPRequestsTotal,
			HTTPRequestDuration,
			GatewayConnectionsTotal,
			GatewayWAFDecisionsTotal,
			GatewayMalwareScansTotal,
			DBRowsTotal,
			DBEventsLastHour,
		)
	})
}

func Handler() http.Handler {
	initRegistry()
	return promhttp.HandlerFor(registry, promhttp.HandlerOpts{})
}

func RecordGatewayOutcome(outcome string) {
	if outcome == "" {
		outcome = "unknown"
	}
	GatewayConnectionsTotal.WithLabelValues(outcome).Inc()
}

func RecordGatewayWAF(action string) {
	if action == "" {
		action = "unknown"
	}
	GatewayWAFDecisionsTotal.WithLabelValues(action).Inc()
}

func RecordGatewayMalwareScan(clean bool, source string) {
	result := "clean"
	if !clean {
		result = "not_clean"
	}
	if source == "" {
		source = "unknown"
	}
	GatewayMalwareScansTotal.WithLabelValues(result, source).Inc()
}
