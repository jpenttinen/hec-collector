package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestRealCLISecurity(t *testing.T) {
	dir := t.TempDir()
	binary := filepath.Join(dir, "hec")
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	build := exec.CommandContext(ctx, filepath.Join(runtime.GOROOT(), "bin", "go"), "build", "-o", binary, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v %s", err, out)
	}
	env := []string{}
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, "HEC_TOKEN=") {
			env = append(env, entry)
		}
	}
	env = append(env, "HEC_TOKEN=cli-only-secret")
	for _, args := range [][]string{{"-h"}, {"-unknown"}} {
		cmd := exec.CommandContext(ctx, binary, args...)
		cmd.Env = env
		out, err := cmd.CombinedOutput()
		if args[0] == "-h" && err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(out, []byte("cli-only-secret")) {
			t.Fatal("help/error leaked environment token")
		}
	}
	pair, pool := rsaTestCertificate(t)
	certFile, keyFile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: pair.Certificate[0]}), 0600)
	key, err := x509.MarshalPKCS8PrivateKey(pair.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), 0600)
	events := filepath.Join(dir, "events")
	logFile := filepath.Join(dir, "stderr.log")
	output, err := os.Create(logFile)
	if err != nil {
		t.Fatal(err)
	}
	defer output.Close()
	cmd := exec.CommandContext(ctx, binary, "-http-addr", "127.0.0.1:0", "-https-addr", "127.0.0.1:0", "-tls-cert", certFile, "-tls-key", keyFile, "-events-dir", events, "-max-files", "1", "-max-connections", "2")
	cmd.Env = env
	cmd.Stderr = output
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	stopped := false
	defer func() {
		if !stopped {
			cmd.Process.Kill()
			<-done
		}
	}()
	pattern := regexp.MustCompile(`listening on (127\.0\.0\.1:\d+) \(TLS=(false|true)\)`)
	addresses := map[string]string{}
	deadline := time.Now().Add(5 * time.Second)
	for len(addresses) < 2 && time.Now().Before(deadline) {
		data, _ := os.ReadFile(logFile)
		for _, match := range pattern.FindAllStringSubmatch(string(data), -1) {
			addresses[match[2]] = match[1]
		}
		if len(addresses) < 2 {
			time.Sleep(10 * time.Millisecond)
		}
	}
	if len(addresses) != 2 {
		t.Fatal("listeners did not start")
	}
	client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}, DisableKeepAlives: true}}
	defer client.CloseIdleConnections()
	call := func(scheme, endpoint, method, body, token string, want int) {
		t.Helper()
		address := addresses["false"]
		if scheme == "https" {
			address = addresses["true"]
		}
		req, err := http.NewRequest(method, scheme+"://"+address+endpoint, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		if token != "" {
			req.Header.Set("Authorization", "Splunk "+token)
		}
		res, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, res.Body)
		res.Body.Close()
		if res.StatusCode != want {
			t.Fatalf("%s %s status=%d want=%d", scheme, endpoint, res.StatusCode, want)
		}
		if res.Header.Get("X-Request-ID") == "" {
			t.Fatal("missing request ID")
		}
	}
	call("http", "/services/collector", "POST", `{"event":"private-payload"}`, "wrong-secret", 403)
	call("https", "/services/collector/ready", "GET", "", "", 200)
	call("https", "/services/collector?host=private-query", "POST", `{"event":"private-payload"}`, "cli-only-secret", 200)
	call("http", "/services/collector/ready", "GET", "", "", 503)
	call("http", "/services/collector", "POST", `{"event":"x"}`, "cli-only-secret", 503)
	files := eventFiles(t, events)
	if len(files) != 1 {
		t.Fatal("quota not enforced")
	}
	os.Remove(files[0])
	call("http", "/services/collector/ready", "GET", "", "", 200)
	// HTTP and TLS sockets share the same cap before headers/handshake. Their
	// absolute header deadlines also close both stalled connections.
	var held []net.Conn
	for _, secure := range []string{"false", "true"} {
		conn, err := net.DialTimeout("tcp", addresses[secure], time.Second)
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, conn)
		defer conn.Close()
		if secure == "false" {
			fmt.Fprint(conn, "GET /services/collector/health HTTP/1.1\r\nHost: localhost\r\n")
		}
	}
	// Allow acceptance before checking refusal on the third connection.
	time.Sleep(50 * time.Millisecond)
	excess, err := net.DialTimeout("tcp", addresses["false"], time.Second)
	if err != nil {
		t.Fatal(err)
	}
	excess.SetReadDeadline(time.Now().Add(time.Second))
	var b [1]byte
	if _, err := excess.Read(b[:]); err == nil {
		t.Fatal("excess socket open")
	} else if e, ok := err.(net.Error); ok && e.Timeout() {
		t.Fatal("excess socket not refused")
	}
	excess.Close()
	for _, conn := range held {
		conn.SetReadDeadline(time.Now().Add(7 * time.Second))
		if _, err := conn.Read(b[:]); err == nil {
			t.Fatal("stalled connection sent unexpected data")
		} else if e, ok := err.(net.Error); ok && e.Timeout() {
			t.Fatal("server deadline not enforced")
		}
	}
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		stopped = true
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(12 * time.Second):
		t.Fatal("shutdown timed out")
	}
	data, _ := os.ReadFile(logFile)
	for _, secret := range []string{"cli-only-secret", "wrong-secret", "private-payload", "private-query"} {
		if bytes.Contains(data, []byte(secret)) {
			t.Fatal("runtime logs leaked input")
		}
	}
	if !bytes.Contains(data, []byte("security_summary")) || !bytes.Contains(data, []byte("auth_rejected")) {
		t.Fatal("missing audit/summary")
	}
	s, err := openStorage(events, defaultLimits())
	if err != nil {
		t.Fatalf("lock not released: %v", err)
	}
	s.Close()
	noPending(t, events)
	unsafeDir := filepath.Join(dir, "unsafe")
	os.Mkdir(unsafeDir, 0700)
	os.Chmod(unsafeDir, 0777)
	unsafe := exec.CommandContext(ctx, binary, "-events-dir", unsafeDir, "-http-addr", "127.0.0.1:0")
	unsafe.Env = env
	if _, err := unsafe.CombinedOutput(); err == nil {
		t.Fatal("CLI accepted unsafe directory")
	}
}
