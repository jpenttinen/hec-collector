package main

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestCollector(t *testing.T) {
	for _, tc := range []struct {
		name, body, auth    string
		status, code, files int
	}{
		{"single", `{"event":{"message":"hello"},"time":123.456}`, "Splunk secret", 200, 0, 1},
		{"batch", `{"event":"one"}{"event":"two"}`, "Splunk secret", 200, 0, 1},
		{"missing token", `{"event":"x"}`, "", 401, 2, 0},
		{"bad auth", `{"event":"x"}`, "Bearer secret", 401, 3, 0},
		{"wrong token", `{"event":"x"}`, "Splunk wrong", 403, 4, 0},
		{"empty", "", "Splunk secret", 400, 5, 0},
		{"missing event", `{"host":"x"}`, "Splunk secret", 400, 12, 0},
		{"blank event", `{"event":""}`, "Splunk secret", 400, 13, 0},
		{"null event", `{"event":null}`, "Splunk secret", 400, 13, 0},
		{"array", `[{"event":"x"}]`, "Splunk secret", 400, 6, 0},
		{"invalid suffix", `{"event":"valid"}{`, "Splunk secret", 400, 6, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			c := testCollector(t, dir, "secret", 1024)
			req := httptest.NewRequest("POST", "/services/collector/event", strings.NewReader(tc.body))
			req.Header.Set("Authorization", tc.auth)
			w := httptest.NewRecorder()
			c.ServeHTTP(w, req)
			var result response
			if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			if w.Code != tc.status || result.Code != tc.code {
				t.Fatalf("status=%d response=%+v", w.Code, result)
			}
			files, _ := filepath.Glob(filepath.Join(dir, "events-*.json"))
			if len(files) != tc.files {
				t.Fatalf("files=%d", len(files))
			}
		})
	}
}
func TestTransportsAndPersistence(t *testing.T) {
	for _, secure := range []bool{false, true} {
		t.Run(fmt.Sprint(secure), func(t *testing.T) {
			dir := t.TempDir()
			c := testCollector(t, dir, "", 1024)
			var server *httptest.Server
			if secure {
				server = httptest.NewTLSServer(c)
			} else {
				server = httptest.NewServer(c)
			}
			defer server.Close()
			res, err := server.Client().Post(server.URL+"/services/collector/event/1.0?host=default&source=test", "application/json", strings.NewReader(`{"event":{"n":9007199254740993},"host":"override"}{"event":"second"}`))
			if err != nil {
				t.Fatal(err)
			}
			defer res.Body.Close()
			if res.StatusCode != 200 {
				t.Fatal(res.Status)
			}
			files, _ := filepath.Glob(filepath.Join(dir, "*.json"))
			if len(files) != 1 {
				t.Fatalf("files=%v", files)
			}
			data, err := os.ReadFile(files[0])
			if err != nil {
				t.Fatal(err)
			}
			var events []map[string]json.RawMessage
			if err = json.Unmarshal(data, &events); err != nil {
				t.Fatal(err)
			}
			if len(events) != 2 || string(events[0]["host"]) != `"override"` || string(events[1]["host"]) != `"default"` || !bytes.Contains(events[0]["event"], []byte("9007199254740993")) {
				t.Fatalf("stored: %s", data)
			}
		})
	}
}
func TestGzipAndLimit(t *testing.T) {
	for _, size := range []int{10, 2000} {
		var body bytes.Buffer
		gz := gzip.NewWriter(&body)
		fmt.Fprintf(gz, `{"event":"%s"}`, strings.Repeat("a", size))
		gz.Close()
		c := testCollector(t, t.TempDir(), "", 1024)
		req := httptest.NewRequest("POST", "/services/collector", &body)
		req.Header.Set("Content-Encoding", "gzip")
		w := httptest.NewRecorder()
		c.ServeHTTP(w, req)
		want := 200
		if size > 1024 {
			want = 413
		}
		if w.Code != want {
			t.Fatalf("status %d want %d", w.Code, want)
		}
	}
}
func TestConcurrentRequests(t *testing.T) {
	dir := t.TempDir()
	server := httptest.NewServer(testCollector(t, dir, "", 1024))
	defer server.Close()
	var wg sync.WaitGroup
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := http.Post(server.URL+"/services/collector", "application/json", strings.NewReader(`{"event":"concurrent"}`))
			if err != nil {
				t.Error(err)
				return
			}
			io.Copy(io.Discard, res.Body)
			res.Body.Close()
			if res.StatusCode != 200 {
				t.Error(res.Status)
			}
		}()
	}
	wg.Wait()
	files, _ := filepath.Glob(filepath.Join(dir, "events-*.json"))
	if len(files) != 40 {
		t.Fatalf("files=%d", len(files))
	}
}
func TestStorageFailure(t *testing.T) {
	c := testCollector(t, t.TempDir(), "", 1024)
	c.storage.root.Close()
	w := httptest.NewRecorder()
	c.ServeHTTP(w, httptest.NewRequest("POST", "/services/collector", strings.NewReader(`{"event":"x"}`)))
	if w.Code != 500 {
		t.Fatal(w.Code)
	}
}
func TestRouting(t *testing.T) {
	c := testCollector(t, t.TempDir(), "", 1024)
	for _, tc := range []struct {
		method, path string
		status       int
	}{{"GET", "/services/collector/health", 200}, {"GET", "/services/collector", 405}, {"POST", "/services/collector/ack", 400}, {"POST", "/unknown", 404}} {
		w := httptest.NewRecorder()
		c.ServeHTTP(w, httptest.NewRequest(tc.method, tc.path, nil))
		if w.Code != tc.status {
			t.Fatalf("%s: %d", tc.path, w.Code)
		}
	}
}

func testCollector(t *testing.T, dir, token string, maxBytes int64) *collector {
	t.Helper()
	l := defaultLimits()
	l.maxBodyBytes = maxBytes
	// Existing persistence-concurrency test intentionally admits all 40 requests.
	l.maxInflight = 64
	storage, err := openStorage(dir, l)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { storage.Close() })
	return newCollector(token, l, storage, newAuditLogger(io.Discard))
}
