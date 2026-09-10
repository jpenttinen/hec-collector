package main

import (
	"crypto/rand"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

type limits struct {
	maxBodyBytes, maxExpandedBytes                 int64
	maxEvents, maxQueryBytes, maxMetadataBytes     int
	maxStorageBytes, minFreeBytes                  int64
	maxFiles, minFreeInodes                        int
	maxConnections, maxInflight, requestsPerSecond int
}

func defaultLimits() limits {
	return limits{
		maxBodyBytes: 10 << 20, maxExpandedBytes: 10 << 20,
		maxEvents: 10000, maxQueryBytes: 8192, maxMetadataBytes: 1024,
		maxStorageBytes: 10 << 30, minFreeBytes: 256 << 20,
		maxFiles: 100000, minFreeInodes: 1024,
		maxConnections: 32, maxInflight: 8, requestsPerSecond: 100,
	}
}

type rateLimit struct {
	mu                  sync.Mutex
	tokens, rate, burst float64
	last                time.Time
}

func newRateLimit(rate, burst int) *rateLimit {
	return &rateLimit{tokens: float64(burst), rate: float64(rate), burst: float64(burst), last: time.Now()}
}
func (r *rateLimit) allow() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	r.tokens = min(r.burst, r.tokens+now.Sub(r.last).Seconds()*r.rate)
	r.last = now
	if r.tokens < 1 {
		return false
	}
	r.tokens--
	return true
}

type limitedListener struct {
	net.Listener
	slots chan struct{}
	audit *auditLogger
}

func (l *limitedListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		// Refuse before net/http allocates a worker or TLS performs a handshake.
		select {
		case l.slots <- struct{}{}:
			return &limitedConn{Conn: conn, slots: l.slots}, nil
		default:
			peer := conn.RemoteAddr().String()
			conn.Close()
			l.audit.record("connection", 503, peer, "")
		}
	}
}

type limitedConn struct {
	net.Conn
	slots chan struct{}
	once  sync.Once
}

func (c *limitedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { <-c.slots })
	return err
}

type auditResponse struct {
	http.ResponseWriter
	status  int
	written bool
}

func (w *auditResponse) WriteHeader(status int) {
	if !w.written {
		w.status = status
		w.written = true
		w.ResponseWriter.WriteHeader(status)
	}
}
func (w *auditResponse) Write(data []byte) (int, error) {
	if !w.written {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(data)
}
func (w *auditResponse) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func requestID() string                              { return rand.Text() }
func endpointName(path string) string {
	switch strings.TrimSuffix(path, "/") {
	case "/services/collector", "/services/collector/event", "/services/collector/event/1.0":
		return "ingest"
	case "/services/collector/health", "/services/collector/health/1.0":
		return "health"
	case "/services/collector/ready":
		return "ready"
	case "/services/collector/ack":
		return "ack"
	default:
		return "unknown"
	}
}

type auditLogger struct {
	mu         sync.Mutex
	logger     *log.Logger
	rate       *rateLimit
	counts     map[string]uint64
	suppressed uint64
}

func newAuditLogger(w io.Writer) *auditLogger {
	return &auditLogger{logger: log.New(w, "", 0), rate: newRateLimit(10, 20), counts: make(map[string]uint64)}
}
func (a *auditLogger) record(endpoint string, status int, peer, id string) {
	if a == nil {
		return
	}
	// Bound labels even for internal callers; no attacker-controlled map keys.
	switch endpoint {
	case "ingest", "health", "ready", "ack", "unknown", "connection":
	default:
		endpoint = "unknown"
	}
	outcome := "server_error"
	switch {
	case status == 401 || status == 403:
		outcome = "auth_rejected"
	case status == 413:
		outcome = "size_rejected"
	case status == 503:
		outcome = "unavailable"
	case status >= 200 && status < 300:
		outcome = "accepted"
	case status >= 400 && status < 500:
		outcome = "request_rejected"
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.counts[endpoint+":"+outcome]++
	if !a.rate.allow() {
		a.suppressed++
		return
	}
	host, _, err := net.SplitHostPort(peer)
	if err != nil || net.ParseIP(host) == nil {
		host = "unknown"
	}
	a.emit(map[string]any{"time": time.Now().UTC().Format(time.RFC3339Nano), "type": "security", "endpoint": endpoint, "outcome": outcome, "status": status, "peer": host, "request_id": id})
}
func (a *auditLogger) emit(record any) {
	data, err := json.Marshal(record)
	if err == nil {
		a.logger.Print(string(data))
	}
}
func (a *auditLogger) flush() {
	if a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.counts) == 0 {
		return
	}
	a.emit(map[string]any{"time": time.Now().UTC().Format(time.RFC3339Nano), "type": "security_summary", "counts": a.counts, "suppressed": a.suppressed})
	clear(a.counts)
	a.suppressed = 0
}
