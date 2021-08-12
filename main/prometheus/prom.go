package prometheus

import (
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func NewResponseWriter(w http.ResponseWriter) *responseWriter {
	return &responseWriter{w, http.StatusOK}
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

var totalRequests = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "http_requests_total",
		Help: "Number of get requests.",
	},
	[]string{"path"},
)

var responseStatus = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "response_status",
		Help: "Status of HTTP response",
	},
	[]string{"status"},
)

var httpDuration = promauto.NewHistogramVec(
	prometheus.HistogramOpts{
		Name: "http_response_time_seconds",
		Help: "Duration of HTTP requests.",
	},
	[]string{"path"},
)

var IdentityCreationCounter = promauto.NewCounter(
	prometheus.CounterOpts{
		Name: "identity_creation_success",
		Help: "Number of identities which have been successfully created and stored.",
	})

var SignatureCreationCounter = promauto.NewCounter(
	prometheus.CounterOpts{
		Name: "signature_creation_success",
		Help: "Number of successfully created signatures",
	})

var SignatureCreationDuration = promauto.NewHistogram(
	prometheus.HistogramOpts{
		Name:    "signature_creation_duration",
		Help:    "Duration of the creation of a signed object",
		Buckets: []float64{.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5},
	})

var AuthCheckDuration = promauto.NewHistogram(
	prometheus.HistogramOpts{
		Name:    "auth_check_duration",
		Help:    "Duration of the auth token being checked for validity.",
		Buckets: []float64{.001, .0025, .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5},
	})

var AuthCheckWithWaitDuration = promauto.NewHistogram(
	prometheus.HistogramOpts{
		Name:    "auth_check_with_wait_duration",
		Help:    "Duration of the auth token being checked for validity including waiting time for semaphore.",
		Buckets: []float64{.001, .0025, .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5},
	})

func PromMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rw := NewResponseWriter(w)
		startTimer := time.Now()
		next.ServeHTTP(rw, r)

		path := chi.RouteContext(r.Context()).RoutePattern()
		statusCode := rw.statusCode

		httpDuration.WithLabelValues(path).Observe(time.Since(startTimer).Seconds())
		totalRequests.WithLabelValues(path).Inc()
		responseStatus.WithLabelValues(strconv.Itoa(statusCode)).Inc()
	})
}

func InitPromMetrics(router *chi.Mux) {
	router.Use(PromMiddleware)
	router.Method(http.MethodGet, "/metrics", promhttp.Handler())
}
