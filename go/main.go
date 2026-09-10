package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"
)

type config struct {
	httpAddr, httpsAddr, certFile, keyFile, directory, token string
	noAuth                                                   bool
	limits                                                   limits
}

func parseConfig(args []string, getenv func(string) string, output io.Writer) (config, error) {
	c := config{limits: defaultLimits()}
	f := flag.NewFlagSet("hec", flag.ContinueOnError)
	// Errors may contain argument values. Only deliberately requested help prints
	// usage, and the secret is loaded after parsing so defaults cannot disclose it.
	f.SetOutput(io.Discard)
	f.StringVar(&c.httpAddr, "http-addr", "127.0.0.1:8088", "HTTP listen address; empty disables HTTP")
	f.StringVar(&c.httpsAddr, "https-addr", "", "HTTPS listen address; empty disables HTTPS")
	f.StringVar(&c.certFile, "tls-cert", "", "TLS certificate PEM file")
	f.StringVar(&c.keyFile, "tls-key", "", "TLS private key PEM file")
	f.StringVar(&c.directory, "events-dir", "./events", "Directory for stored JSON events")
	f.StringVar(&c.token, "token", "", "HEC token (defaults to HEC_TOKEN)")
	f.BoolVar(&c.noAuth, "no-auth", false, "Explicitly allow unauthenticated ingestion")
	l := &c.limits
	f.Int64Var(&l.maxBodyBytes, "max-body-bytes", l.maxBodyBytes, "Maximum compressed and decompressed request size")
	f.Int64Var(&l.maxExpandedBytes, "max-expanded-bytes", l.maxExpandedBytes, "Maximum serialized event array bytes")
	f.IntVar(&l.maxEvents, "max-events", l.maxEvents, "Maximum events per batch")
	f.IntVar(&l.maxQueryBytes, "max-query-bytes", l.maxQueryBytes, "Maximum encoded query bytes (at most 32 fields)")
	f.IntVar(&l.maxMetadataBytes, "max-metadata-bytes", l.maxMetadataBytes, "Maximum query-default value bytes")
	f.Int64Var(&l.maxStorageBytes, "max-storage-bytes", l.maxStorageBytes, "Maximum logical size of event directory entries")
	f.IntVar(&l.maxFiles, "max-files", l.maxFiles, "Maximum event directory entries, excluding .hec.lock")
	f.Int64Var(&l.minFreeBytes, "min-free-bytes", l.minFreeBytes, "Filesystem free-space reserve")
	f.IntVar(&l.minFreeInodes, "min-free-inodes", l.minFreeInodes, "Filesystem free-inode reserve")
	f.IntVar(&l.maxConnections, "max-connections", l.maxConnections, "Combined HTTP/HTTPS connection limit")
	f.IntVar(&l.maxInflight, "max-inflight", l.maxInflight, "Maximum concurrent ingestion requests")
	f.IntVar(&l.requestsPerSecond, "requests-per-second", l.requestsPerSecond, "Ingestion/ACK/readiness attempts per second and burst")
	if err := f.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			f.SetOutput(output)
			f.PrintDefaults()
			return c, flag.ErrHelp
		}
		return c, errors.New("invalid command line; use -h for usage")
	}
	if f.NArg() != 0 {
		return c, errors.New("unexpected positional arguments")
	}
	explicitToken := false
	f.Visit(func(f *flag.Flag) {
		if f.Name == "token" {
			explicitToken = true
		}
	})
	if !explicitToken {
		c.token = getenv("HEC_TOKEN")
	}
	if c.httpAddr == "" && c.httpsAddr == "" {
		return c, errors.New("enable at least one HTTP or HTTPS listener")
	}
	if l.maxBodyBytes <= 0 || l.maxBodyBytes >= 1<<63-1 || l.maxExpandedBytes < 3 || l.maxEvents <= 0 || l.maxQueryBytes <= 0 || l.maxMetadataBytes <= 0 || l.maxStorageBytes <= 0 || l.maxFiles <= 0 || l.minFreeBytes <= 0 || l.minFreeInodes <= 0 || l.maxConnections <= 0 || l.maxInflight <= 0 || l.requestsPerSecond <= 0 {
		return c, errors.New("limits must be positive; max-body-bytes must be less than MaxInt64 and max-expanded-bytes at least 3")
	}
	if c.token == "" && !c.noAuth {
		return c, errors.New("set HEC_TOKEN, -token, or explicitly use -no-auth")
	}
	if c.noAuth && c.token != "" {
		return c, errors.New("-no-auth and a configured token are mutually exclusive")
	}
	return c, nil
}

func serverTLSConfig(pair tls.Certificate) *tls.Config {
	// AEAD-only TLS 1.2 policy also withstands legacy GODEBUG overrides.
	return &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}, CipherSuites: []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	}}
}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}
func run() error {
	cfg, err := parseConfig(os.Args[1:], os.Getenv, os.Stderr)
	if errors.Is(err, flag.ErrHelp) {
		return nil
	}
	if err != nil {
		return err
	}
	var tlsConfig *tls.Config
	if cfg.httpsAddr != "" {
		pair, err := tls.LoadX509KeyPair(cfg.certFile, cfg.keyFile)
		if err != nil {
			return fmt.Errorf("load TLS certificate: %w", err)
		}
		tlsConfig = serverTLSConfig(pair)
	}
	cfg.directory, err = filepath.Abs(cfg.directory)
	if err != nil {
		return err
	}
	storage, err := openStorage(cfg.directory, cfg.limits)
	if err != nil {
		return fmt.Errorf("initialize events directory: %w", err)
	}
	defer storage.Close()
	audit := newAuditLogger(os.Stderr)
	defer audit.flush()
	c := newCollector(cfg.token, cfg.limits, storage, audit)
	slots := make(chan struct{}, cfg.limits.maxConnections)
	var listeners []net.Listener
	defer func() {
		for _, l := range listeners {
			l.Close()
		}
	}()
	var servers []*http.Server
	for _, endpoint := range []struct {
		address string
		secure  bool
	}{{cfg.httpAddr, false}, {cfg.httpsAddr, true}} {
		if endpoint.address == "" {
			continue
		}
		listener, err := net.Listen("tcp", endpoint.address)
		if err != nil {
			return err
		}
		listener = &limitedListener{Listener: listener, slots: slots, audit: audit}
		if endpoint.secure {
			listener = tls.NewListener(listener, tlsConfig)
		}
		listeners = append(listeners, listener)
		// Suppress net/http's raw peer/TLS error logs; normalized outcomes go through
		// the bounded audit logger. Timeouts also cover the TLS handshake.
		servers = append(servers, &http.Server{Handler: c, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 32 << 10, ErrorLog: log.New(io.Discard, "", 0)})
		log.Printf("listening on %s (TLS=%t), events directory: %s, runtime: %s", listener.Addr(), endpoint.secure, cfg.directory, runtime.Version())
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	failures := make(chan error, len(servers))
	for i, s := range servers {
		go func(s *http.Server, l net.Listener) { failures <- s.Serve(l) }(s, listeners[i])
	}
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	var serveErr error
wait:
	for {
		select {
		case <-ctx.Done():
			break wait
		case serveErr = <-failures:
			break wait
		case <-ticker.C:
			audit.flush()
		}
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, s := range servers {
		if err := s.Shutdown(shutdownCtx); err != nil {
			s.Close()
		}
	}
	if errors.Is(serveErr, http.ErrServerClosed) {
		return nil
	}
	return serveErr
}
