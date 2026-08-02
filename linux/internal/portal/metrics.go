package portal

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync/atomic"
	"time"
)

type portalMetrics struct {
	started       time.Time
	requests      atomic.Uint64
	active        atomic.Int64
	responses2xx  atomic.Uint64
	responses4xx  atomic.Uint64
	responses5xx  atomic.Uint64
	duration      [6]atomic.Uint64
	readiness     atomic.Int64
	readinessRuns atomic.Uint64
}

var durationBounds = [...]time.Duration{10 * time.Millisecond, 50 * time.Millisecond, 250 * time.Millisecond, time.Second, 5 * time.Second}

func newPortalMetrics(now time.Time) *portalMetrics {
	value := &portalMetrics{started: now.UTC()}
	value.readiness.Store(-1)
	return value
}

func (m *portalMetrics) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		started := time.Now()
		m.requests.Add(1)
		m.active.Add(1)
		defer m.active.Add(-1)
		tracked := &metricsResponseWriter{ResponseWriter: writer, status: http.StatusOK}
		next.ServeHTTP(tracked, request)
		switch {
		case tracked.status >= 500:
			m.responses5xx.Add(1)
		case tracked.status >= 400:
			m.responses4xx.Add(1)
		case tracked.status >= 200 && tracked.status < 300:
			m.responses2xx.Add(1)
		}
		elapsed := time.Since(started)
		bucket := len(durationBounds)
		for index, bound := range durationBounds {
			if elapsed <= bound {
				bucket = index
				break
			}
		}
		m.duration[bucket].Add(1)
	})
}

func (m *portalMetrics) handler(writer http.ResponseWriter, _ *http.Request) {
	writer.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	writer.Header().Set("Cache-Control", "no-store")
	writeMetric(writer, "workagent_portal_uptime_seconds", time.Since(m.started).Seconds())
	writeMetric(writer, "workagent_portal_http_requests_total", m.requests.Load())
	writeMetric(writer, "workagent_portal_http_active_requests", m.active.Load())
	writeMetricLabel(writer, "workagent_portal_http_responses_total", "class", "2xx", m.responses2xx.Load())
	writeMetricLabel(writer, "workagent_portal_http_responses_total", "class", "4xx", m.responses4xx.Load())
	writeMetricLabel(writer, "workagent_portal_http_responses_total", "class", "5xx", m.responses5xx.Load())
	cumulative := uint64(0)
	for index, bound := range durationBounds {
		cumulative += m.duration[index].Load()
		writeMetricLabel(writer, "workagent_portal_http_request_duration_seconds_bucket", "le", strconv.FormatFloat(bound.Seconds(), 'f', -1, 64), cumulative)
	}
	cumulative += m.duration[len(durationBounds)].Load()
	writeMetricLabel(writer, "workagent_portal_http_request_duration_seconds_bucket", "le", "+Inf", cumulative)
	writeMetric(writer, "workagent_portal_readiness", m.readiness.Load())
	writeMetric(writer, "workagent_portal_readiness_checks_total", m.readinessRuns.Load())
}

func writeMetric(writer io.Writer, name string, value any) {
	_, _ = fmt.Fprintf(writer, "%s %v\n", name, value)
}

func writeMetricLabel(writer io.Writer, name, label, value string, metric any) {
	_, _ = fmt.Fprintf(writer, "%s{%s=%q} %v\n", name, label, value, metric)
}

type metricsResponseWriter struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (w *metricsResponseWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *metricsResponseWriter) WriteHeader(status int) {
	if w.wroteHeader {
		return
	}
	w.wroteHeader = true
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *metricsResponseWriter) Write(payload []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(payload)
}

func (w *metricsResponseWriter) Flush() {
	_ = http.NewResponseController(w.ResponseWriter).Flush()
}

func (w *metricsResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return http.NewResponseController(w.ResponseWriter).Hijack()
}

func (w *metricsResponseWriter) Push(target string, options *http.PushOptions) error {
	if pusher, ok := w.ResponseWriter.(http.Pusher); ok {
		return pusher.Push(target, options)
	}
	return http.ErrNotSupported
}

func (w *metricsResponseWriter) ReadFrom(reader io.Reader) (int64, error) {
	if readerFrom, ok := w.ResponseWriter.(io.ReaderFrom); ok {
		return readerFrom.ReadFrom(reader)
	}
	return io.Copy(w.ResponseWriter, reader)
}
