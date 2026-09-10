package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"math/big"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func ingest(c *collector, body, query, auth string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "/services/collector"+query, strings.NewReader(body))
	if auth != "" {
		r.Header.Set("Authorization", auth)
	}
	w := httptest.NewRecorder()
	c.ServeHTTP(w, r)
	return w
}
func eventFiles(t *testing.T, dir string) []string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(dir, "events-*.json"))
	if err != nil {
		t.Fatal(err)
	}
	return files
}
func noPending(t *testing.T, dir string) {
	t.Helper()
	files, _ := filepath.Glob(filepath.Join(dir, ".pending-*"))
	if len(files) != 0 {
		t.Fatalf("pending files: %v", files)
	}
}

func TestExpandedBatchLimits(t *testing.T) {
	for _, tc := range []struct {
		name, body, query string
		limit             int64
		events            int
		status            int
	}{
		{"exact", `{"event":"x"}`, "", 16, 1, 200},
		{"one byte over", `{"event":"x"}`, "", 15, 1, 413},
		{"count", `{"event":"x"}{"event":"y"}`, "", 4096, 1, 413},
		{"metadata amplification", strings.Repeat(`{"event":"x"}`, 100), "?host=" + strings.Repeat("a", 1000), 4096, 100, 413},
		{"escaped metadata", `{"event":"x"}`, "?host=%3C%3C%3C", 40, 1, 413},
		{"query length", `{"event":"x"}`, "?unused=" + strings.Repeat("a", 8192), 4096, 1, 413},
		{"query field count", `{"event":"x"}`, "?" + strings.Repeat("a=1&", 32) + "b=2", 4096, 1, 413},
		{"metadata length", `{"event":"x"}`, "?host=" + strings.Repeat("a", 1025), 4096, 1, 413},
		{"malformed query", `{"event":"x"}`, "?host=%zz", 4096, 1, 413},
		{"late invalid event", `{"event":"valid"}{`, "", 4096, 2, 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			c := testCollector(t, dir, "test-token", 4096)
			c.limits.maxExpandedBytes = tc.limit
			c.limits.maxEvents = tc.events
			w := ingest(c, tc.body, tc.query, "Splunk test-token")
			if w.Code != tc.status {
				t.Fatalf("status %d want %d: %s", w.Code, tc.status, w.Body.String())
			}
			files := eventFiles(t, dir)
			if tc.status != 200 && len(files) != 0 {
				t.Fatal("rejected batch published")
			}
			if tc.status == 200 {
				if len(files) != 1 {
					t.Fatal("missing file")
				}
				data, _ := os.ReadFile(files[0])
				if int64(len(data)) > tc.limit {
					t.Fatal("output limit exceeded")
				}
				var events []json.RawMessage
				if json.Unmarshal(data, &events) != nil {
					t.Fatal("invalid JSON")
				}
			}
			noPending(t, dir)
		})
	}
}

func TestStorageQuotaRaceAndRecovery(t *testing.T) {
	for _, kind := range []string{"bytes", "files"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			c := testCollector(t, dir, "", 4096)
			if kind == "bytes" {
				c.storage.limits.maxStorageBytes = 32
			} else {
				c.storage.limits.maxFiles = 2
			}
			var wg sync.WaitGroup
			statuses := make(chan int, 12)
			for range 12 {
				wg.Go(func() {
					w := ingest(c, `{"event":"x"}`, "", "")
					statuses <- w.Code
					if w.Code == 503 && w.Header().Get("Retry-After") != "1" {
						t.Error("missing retry advice")
					}
				})
			}
			wg.Wait()
			close(statuses)
			accepted := 0
			for status := range statuses {
				if status == 200 {
					accepted++
				} else if status != 503 {
					t.Fatalf("unexpected %d", status)
				}
			}
			if accepted != 2 {
				t.Fatalf("accepted %d, want 2", accepted)
			}
			files := eventFiles(t, dir)
			if len(files) != 2 {
				t.Fatal(len(files))
			}
			os.Remove(files[0])
			if w := ingest(c, `{"event":"x"}`, "", ""); w.Code != 200 {
				t.Fatalf("retention recovery: %d", w.Code)
			}
			noPending(t, dir)
		})
	}
}

func TestStorageReservesAndReadiness(t *testing.T) {
	dir := t.TempDir()
	c := testCollector(t, dir, "", 4096)
	for _, tc := range []struct {
		name          string
		bytes, inodes uint64
		hasInodes     bool
	}{
		{"bytes", uint64(c.storage.limits.minFreeBytes), 1 << 20, true},
		{"inodes", 1 << 40, uint64(c.storage.limits.minFreeInodes), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c.storage.freeSpace = func() (uint64, uint64, bool, error) { return tc.bytes, tc.inodes, tc.hasInodes, nil }
			if w := ingest(c, `{"event":"x"}`, "", ""); w.Code != 503 {
				t.Fatal(w.Code)
			}
			w := httptest.NewRecorder()
			c.ServeHTTP(w, httptest.NewRequest("GET", "/services/collector/ready", nil))
			if w.Code != 503 {
				t.Fatal(w.Code)
			}
			w = httptest.NewRecorder()
			c.ServeHTTP(w, httptest.NewRequest("GET", "/services/collector/health", nil))
			if w.Code != 200 {
				t.Fatal(w.Code)
			}
			noPending(t, dir)
		})
	}
	c.storage.freeSpace = func() (uint64, uint64, bool, error) { return 1 << 40, 0, false, nil }
	w := httptest.NewRecorder()
	c.ServeHTTP(w, httptest.NewRequest("GET", "/services/collector/ready", nil))
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	c.storage.mu.Lock()
	w = httptest.NewRecorder()
	c.ServeHTTP(w, httptest.NewRequest("GET", "/services/collector/ready", nil))
	c.storage.mu.Unlock()
	if w.Code != 503 {
		t.Fatal(w.Code)
	}

	for _, pressure := range []error{syscall.ENOSPC, syscall.EDQUOT} {
		c.storage.freeSpace = func() (uint64, uint64, bool, error) { return 0, 0, false, pressure }
		if w := ingest(c, `{"event":"x"}`, "", ""); w.Code != 503 {
			t.Fatal(w.Code)
		}
	}
	c.storage.freeSpace = func() (uint64, uint64, bool, error) { return 0, 0, false, errors.New("stat failure") }
	if w := ingest(c, `{"event":"x"}`, "", ""); w.Code != 500 {
		t.Fatal(w.Code)
	}
	noPending(t, dir)
}

func TestStorageExistingFilesAndLock(t *testing.T) {
	dir := t.TempDir()
	l := defaultLimits()
	l.maxStorageBytes = 20
	if err := os.WriteFile(filepath.Join(dir, ".pending-orphan"), bytes.Repeat([]byte("x"), 10), 0600); err != nil {
		t.Fatal(err)
	}
	s, err := openStorage(dir, l)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if other, err := openStorage(dir, l); err == nil {
		other.Close()
		t.Fatal("second writer accepted")
	}
	c := newCollector("", l, s, nil)
	if w := ingest(c, `{"event":"x"}`, "", ""); w.Code != 503 {
		t.Fatal(w.Code)
	}
	if len(eventFiles(t, dir)) != 0 {
		t.Fatal("quota ignored orphan")
	}
	os.Remove(filepath.Join(dir, ".pending-orphan"))
	if w := ingest(c, `{"event":"x"}`, "", ""); w.Code != 200 {
		t.Fatal(w.Code)
	}
	files := eventFiles(t, dir)
	info, _ := os.Stat(files[0])
	if info.Mode().Perm() != 0600 {
		t.Fatal(info.Mode())
	}
	// A restart must account for existing events rather than reset the byte budget.
	s.Close()
	s2, err := openStorage(dir, l)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if w := ingest(newCollector("", l, s2, nil), `{"event":"x"}`, "", ""); w.Code != 503 {
		t.Fatal(w.Code)
	}
}

func TestRejectUnsafeDirectoryAndLock(t *testing.T) {
	for _, mode := range []os.FileMode{0777, 0770, 0702} {
		dir := t.TempDir()
		os.Chmod(dir, mode)
		if s, err := openStorage(dir, defaultLimits()); err == nil {
			s.Close()
			t.Fatalf("accepted mode %o", mode)
		}
		info, _ := os.Stat(dir)
		if info.Mode().Perm() != mode {
			t.Fatal("silently changed permissions")
		}
	}
	dir := t.TempDir()
	target := filepath.Join(t.TempDir(), "target")
	os.WriteFile(target, []byte("unchanged"), 0600)
	os.Symlink(target, filepath.Join(dir, ".hec.lock"))
	if s, err := openStorage(dir, defaultLimits()); err == nil {
		s.Close()
		t.Fatal("symlink lock accepted")
	}
	data, _ := os.ReadFile(target)
	if string(data) != "unchanged" {
		t.Fatal("symlink target changed")
	}
}

func TestStorageCancellation(t *testing.T) {
	dir := t.TempDir()
	c := testCollector(t, dir, "", 4096)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := c.storage.store(ctx, []json.RawMessage{json.RawMessage(`{"event":"x"}`)}, 16); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if len(eventFiles(t, dir)) != 0 {
		t.Fatal("published canceled batch")
	}
	noPending(t, dir)
}

func TestAdmissionAndRateLimit(t *testing.T) {
	c := testCollector(t, t.TempDir(), "", 4096)
	c.active = make(chan struct{}, 1)
	c.active <- struct{}{}
	if w := ingest(c, `{"event":"x"}`, "", ""); w.Code != 503 {
		t.Fatal(w.Code)
	}
	<-c.active
	if w := ingest(c, `{"event":"x"}`, "", ""); w.Code != 200 {
		t.Fatal(w.Code)
	}
	c.token = "test-token"
	c.rate = newRateLimit(1, 1)
	c.rate.rate = 0 // Deterministic: no refill during this test.
	if w := ingest(c, `{"event":"x"}`, "", ""); w.Code != 401 {
		t.Fatal(w.Code)
	}
	if w := ingest(c, `{"event":"x"}`, "", "Splunk test-token"); w.Code != 503 {
		t.Fatal(w.Code)
	}
	w := httptest.NewRecorder()
	c.ServeHTTP(w, httptest.NewRequest("GET", "/services/collector/health", nil))
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
}

func TestAuditRedactionAndSampling(t *testing.T) {
	var output bytes.Buffer
	c := testCollector(t, t.TempDir(), "private-token", 4096)
	c.audit = newAuditLogger(&output)
	c.audit.rate.rate = 0
	for i := 0; i < 30; i++ {
		r := httptest.NewRequest("POST", "/services/collector?host=private-query", strings.NewReader(`{"event":"private-body"}`))
		r.Header.Set("Authorization", "Splunk private-wrong-token")
		r.Header.Set("X-Forwarded-For", "spoofed-peer")
		r.Header.Set("X-Request-ID", "untrusted-id")
		r.RemoteAddr = "192.0.2.1:1234"
		w := httptest.NewRecorder()
		c.ServeHTTP(w, r)
		if w.Code != 403 || w.Header().Get("X-Request-ID") == "" {
			t.Fatal("missing rejection/id")
		}
	}
	c.audit.flush()
	for _, secret := range []string{"private-token", "private-query", "private-body", "private-wrong-token", "spoofed-peer", "untrusted-id"} {
		if strings.Contains(output.String(), secret) {
			t.Fatalf("audit leaked %s", secret)
		}
	}
	lines := strings.Split(strings.TrimSpace(output.String()), "\n")
	if len(lines) != 21 {
		t.Fatalf("records=%d", len(lines))
	}
	var summary struct {
		Type       string
		Suppressed int
		Counts     map[string]int
	}
	if err := json.Unmarshal([]byte(lines[20]), &summary); err != nil {
		t.Fatal(err)
	}
	if summary.Type != "security_summary" || summary.Suppressed != 10 || summary.Counts["ingest:auth_rejected"] != 30 {
		t.Fatalf("summary=%+v", summary)
	}
	for _, line := range lines[:20] {
		var record map[string]any
		if json.Unmarshal([]byte(line), &record) != nil {
			t.Fatal("non-JSON audit")
		}
		if record["peer"] != "192.0.2.1" || record["outcome"] != "auth_rejected" {
			t.Fatal(record)
		}
	}
}

func TestCLIConfigSecretsAndLimits(t *testing.T) {
	lookup := func(string) string { return "environment-only-secret" }
	for _, args := range [][]string{{"-h"}, {"-unknown", "argument-secret"}, {"-max-events", "argument-secret"}} {
		var output bytes.Buffer
		_, err := parseConfig(args, lookup, &output)
		if err == nil {
			t.Fatal("expected help/error")
		}
		if strings.Contains(output.String()+err.Error(), "environment-only-secret") || strings.Contains(output.String()+err.Error(), "argument-secret") {
			t.Fatal("CLI secret disclosure")
		}
	}
	c, err := parseConfig(nil, lookup, io.Discard)
	if err != nil || c.token != "environment-only-secret" {
		t.Fatal(err)
	}
	c, err = parseConfig([]string{"-token=", "-no-auth"}, lookup, io.Discard)
	if err != nil || c.token != "" {
		t.Fatal("explicit empty token not preserved", err)
	}
	if _, err := parseConfig([]string{"-token="}, lookup, io.Discard); err == nil {
		t.Fatal("accepted missing auth")
	}
	for _, name := range []string{"max-body-bytes", "max-expanded-bytes", "max-events", "max-query-bytes", "max-metadata-bytes", "max-storage-bytes", "max-files", "min-free-bytes", "min-free-inodes", "max-connections", "max-inflight", "requests-per-second"} {
		if _, err := parseConfig([]string{"-" + name, "0"}, lookup, io.Discard); err == nil {
			t.Fatal(name)
		}
	}
	if _, err := parseConfig([]string{"-max-body-bytes", "9223372036854775807"}, lookup, io.Discard); err == nil {
		t.Fatal("overflow accepted")
	}
	if _, err := parseConfig([]string{"-h"}, lookup, io.Discard); !errors.Is(err, flag.ErrHelp) {
		t.Fatal(err)
	}
}

func rsaTestCertificate(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true, IsCA: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, pool
}

func TestTLSPolicy(t *testing.T) {
	pair, pool := rsaTestCertificate(t)
	for _, tc := range []struct {
		name            string
		version, cipher uint16
		accepted        bool
	}{
		{"3DES rejected", tls.VersionTLS12, tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA, false},
		{"CBC rejected", tls.VersionTLS12, tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, false},
		{"TLS11 rejected", tls.VersionTLS11, tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, false},
		{"TLS12 AEAD", tls.VersionTLS12, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, true},
		{"TLS13", tls.VersionTLS13, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			left, right := net.Pipe()
			defer left.Close()
			defer right.Close()
			deadline := time.Now().Add(3 * time.Second)
			left.SetDeadline(deadline)
			right.SetDeadline(deadline)
			server := tls.Server(left, serverTLSConfig(pair))
			client := tls.Client(right, &tls.Config{MinVersion: tc.version, MaxVersion: tc.version, RootCAs: pool, ServerName: "localhost", CipherSuites: []uint16{tc.cipher}})
			result := make(chan error, 1)
			go func() { result <- server.Handshake() }()
			err := client.Handshake()
			right.Close()
			serverErr := <-result
			if (err == nil) != tc.accepted || (serverErr == nil) != tc.accepted {
				t.Fatalf("client=%v server=%v", err, serverErr)
			}
		})
	}
}

func TestConnectionCapSharedAndReleased(t *testing.T) {
	slots := make(chan struct{}, 1)
	var listeners []*limitedListener
	for range 2 {
		raw, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		l := &limitedListener{Listener: raw, slots: slots}
		listeners = append(listeners, l)
		defer l.Close()
	}
	accepted := make(chan net.Conn, 2)
	results := make(chan error, 2)
	for _, l := range listeners {
		go func() {
			conn, err := l.Accept()
			if err == nil {
				accepted <- conn
			}
			results <- err
		}()
	}
	first, err := net.DialTimeout("tcp", listeners[0].Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	var held net.Conn
	select {
	case held = <-accepted:
	case <-time.After(time.Second):
		t.Fatal("not accepted")
	}
	defer held.Close()
	excess, err := net.DialTimeout("tcp", listeners[1].Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer excess.Close()
	excess.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 1)
	if _, err = excess.Read(buf); err == nil {
		t.Fatal("excess remained open")
	} else if e, ok := err.(net.Error); ok && e.Timeout() {
		t.Fatal("excess not promptly closed")
	}
	held.Close()
	held.Close()
	next, err := net.DialTimeout("tcp", listeners[1].Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	select {
	case conn := <-accepted:
		conn.Close()
	case <-time.After(time.Second):
		t.Fatal("slot not released")
	}
	for range 2 {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
}

func TestIngestionCancellationAndMalformedGzip(t *testing.T) {
	dir := t.TempDir()
	c := testCollector(t, dir, "", 4096)
	r := httptest.NewRequest("POST", "/services/collector", strings.NewReader(`{"event":"x"}`))
	ctx, cancel := context.WithCancel(r.Context())
	cancel()
	c.ServeHTTP(httptest.NewRecorder(), r.WithContext(ctx))
	r = httptest.NewRequest("POST", "/services/collector", strings.NewReader("invalid gzip"))
	r.Header.Set("Content-Encoding", "gzip")
	w := httptest.NewRecorder()
	c.ServeHTTP(w, r)
	if w.Code != 400 {
		t.Fatal(w.Code)
	}
	if len(eventFiles(t, dir)) != 0 {
		t.Fatal("published invalid/canceled input")
	}
	noPending(t, dir)
}
