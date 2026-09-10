package main

import (
	"bytes"
	"compress/gzip"
	"crypto/subtle"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
)

type collector struct {
	token   string
	limits  limits
	storage *eventStorage
	active  chan struct{}
	rate    *rateLimit
	audit   *auditLogger
}

func newCollector(token string, l limits, storage *eventStorage, audit *auditLogger) *collector {
	return &collector{token: token, limits: l, storage: storage, active: make(chan struct{}, l.maxInflight), rate: newRateLimit(l.requestsPerSecond, l.requestsPerSecond), audit: audit}
}

type response struct {
	Text string `json:"text"`
	Code int    `json:"code"`
}

func reply(w http.ResponseWriter, status, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(response{message, code})
}
func (c *collector) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Record fixed outcomes, never credentials, bodies, or raw URLs.
	observed := &auditResponse{ResponseWriter: w, status: 500}
	w = observed
	id := requestID()
	w.Header().Set("X-Request-ID", id)
	defer func() { c.audit.record(endpointName(r.URL.Path), observed.status, r.RemoteAddr, id) }()
	c.serve(w, r)
}

func unavailable(w http.ResponseWriter) {
	w.Header().Set("Retry-After", "1")
	reply(w, 503, 8, "Service temporarily unavailable")
}

func (c *collector) serve(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimSuffix(r.URL.Path, "/")
	if path == "/services/collector/health" || path == "/services/collector/health/1.0" {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET")
			reply(w, 405, 6, "Method not allowed")
			return
		}
		reply(w, 200, 17, "HEC is healthy")
		return
	}
	if path == "/services/collector/ready" {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET")
			reply(w, 405, 6, "Method not allowed")
			return
		}
		if !c.rate.allow() {
			unavailable(w)
			return
		}
		if err := c.storage.ready(); err != nil {
			unavailable(w)
			return
		}
		reply(w, 200, 17, "HEC is ready")
		return
	}
	switch path {
	case "/services/collector", "/services/collector/event", "/services/collector/event/1.0", "/services/collector/ack":
	default:
		reply(w, 404, 6, "Not found")
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		reply(w, 405, 6, "Method not allowed")
		return
	}
	if !c.rate.allow() {
		unavailable(w)
		return
	}
	if c.token != "" {
		auth := r.Header.Get("Authorization")
		if auth == "" {
			reply(w, 401, 2, "Token is required")
			return
		}
		parts := strings.Fields(auth)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Splunk") {
			reply(w, 401, 3, "Invalid authorization")
			return
		}
		if subtle.ConstantTimeCompare([]byte(parts[1]), []byte(c.token)) != 1 {
			reply(w, 403, 4, "Invalid token")
			return
		}
	}
	if path == "/services/collector/ack" {
		reply(w, 400, 14, "ACK is disabled")
		return
	}
	// Admission is nonblocking: overload must not create an unbounded queue.
	select {
	case c.active <- struct{}{}:
		defer func() { <-c.active }()
	default:
		unavailable(w)
		return
	}
	defaults, err := queryDefaults(r.URL.RawQuery, c.limits)
	if err != nil {
		reply(w, 413, 6, "Query exceeds limits or is invalid")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, c.limits.maxBodyBytes)
	defer r.Body.Close()
	var reader io.Reader = r.Body
	switch strings.ToLower(strings.TrimSpace(r.Header.Get("Content-Encoding"))) {
	case "", "identity":
	case "gzip":
		gz, err := gzip.NewReader(reader)
		if err != nil {
			reply(w, 400, 6, "Invalid data format")
			return
		}
		defer gz.Close()
		reader = gz
	default:
		reply(w, 415, 6, "Unsupported content encoding")
		return
	}
	data, err := io.ReadAll(io.LimitReader(reader, c.limits.maxBodyBytes+1))
	if int64(len(data)) > c.limits.maxBodyBytes {
		reply(w, 413, 6, "Request too large")
		return
	}
	if err != nil {
		if _, ok := err.(*http.MaxBytesError); ok {
			reply(w, 413, 6, "Request too large")
		} else {
			reply(w, 400, 6, "Invalid data format")
		}
		return
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	events := make([]json.RawMessage, 0)
	expanded := int64(3) // Brackets and final newline of the compact array.
	for {
		if err := r.Context().Err(); err != nil {
			return
		}
		var raw json.RawMessage
		err = decoder.Decode(&raw)
		if err == io.EOF {
			break
		}
		if err != nil {
			reply(w, 400, 6, "Invalid data format")
			return
		}
		if len(events) >= c.limits.maxEvents {
			reply(w, 413, 6, "Too many events")
			return
		}
		var event map[string]json.RawMessage
		if json.Unmarshal(raw, &event) != nil || event == nil {
			reply(w, 400, 6, "Invalid data format")
			return
		}
		value, ok := event["event"]
		if !ok {
			reply(w, 400, 12, "Event field is required")
			return
		}
		if string(value) == "null" || string(value) == `""` || string(value) == "{}" {
			reply(w, 400, 13, "Event field cannot be blank")
			return
		}
		if value[0] != '"' && value[0] != '{' {
			reply(w, 400, 6, "Invalid data format")
			return
		}
		for key, value := range defaults {
			if _, ok := event[key]; !ok {
				event[key] = value
			}
		}
		raw, err = json.Marshal(event)
		if err != nil {
			reply(w, 500, 8, "Internal server error")
			return
		}
		cost := int64(len(raw))
		if len(events) != 0 {
			cost++
		}
		if cost > c.limits.maxExpandedBytes-expanded {
			reply(w, 413, 6, "Expanded batch too large")
			return
		}
		expanded += cost
		events = append(events, raw)
	}
	if len(events) == 0 {
		reply(w, 400, 5, "No data")
		return
	}
	if err = c.storage.store(r.Context(), events, expanded); err != nil {
		if storagePressure(err) {
			unavailable(w)
			return
		}
		reply(w, 500, 8, "Internal server error")
		return
	}
	reply(w, 200, 0, "Success")
}

// Parse once and bound query data before multiplying defaults across events.
func queryDefaults(raw string, l limits) (map[string]json.RawMessage, error) {
	if len(raw) > l.maxQueryBytes || (raw != "" && strings.Count(raw, "&")+1 > 32) {
		return nil, errCapacity
	}
	query, err := url.ParseQuery(raw)
	if err != nil {
		return nil, err
	}
	defaults := make(map[string]json.RawMessage)
	for _, key := range []string{"host", "source", "sourcetype", "index", "time"} {
		if query.Has(key) {
			value := query.Get(key)
			if len(value) > l.maxMetadataBytes {
				return nil, errCapacity
			}
			defaults[key], err = json.Marshal(value)
			if err != nil {
				return nil, err
			}
		}
	}
	return defaults, nil
}
