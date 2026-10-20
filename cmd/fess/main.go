package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	fencedb "fence/db"
	"fence/internal/api"
	"fence/internal/gateway"
	"fence/internal/runtimebus"
	"fence/ui"
	"golang.org/x/sys/unix"
)

var version = "dev"

func main() {
	if err := run(); err != nil {
		log.Print(err)
		os.Exit(1)
	}
}
func env(key, def string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return def
}
func loadEnv(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for n := 1; sc.Scan(); n++ {
		s := strings.TrimSpace(sc.Text())
		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		key, val, ok := strings.Cut(s, "=")
		key = strings.TrimSpace(key)
		if !ok || key == "" {
			return fmt.Errorf("%s:%d: expected KEY=value", path, n)
		}
		val = strings.TrimSpace(val)
		if len(val) >= 2 && ((val[0] == '"' && val[len(val)-1] == '"') || (val[0] == '\'' && val[len(val)-1] == '\'')) {
			val = val[1 : len(val)-1]
		}
		if _, exists := os.LookupEnv(key); !exists {
			if err := os.Setenv(key, val); err != nil {
				return err
			}
		}
	}
	return sc.Err()
}
func run() (runErr error) {
	if len(os.Args) > 1 && os.Args[1] == "version" {
		fmt.Println("FESS", version)
		return nil
	}
	// Configuration is data, never shell-evaluated. Explicit process env takes precedence.
	config := os.Getenv("FESS_CONFIG")
	if config != "" {
		if err := loadEnv(config); err != nil {
			return err
		}
	}
	if len(os.Args) > 1 && os.Args[1] == "migrate" {
		return migrateCommand(os.Args[2:])
	}
	flags := flag.NewFlagSet("fess", flag.ContinueOnError)
	data := flags.String("data-dir", env("FESS_DATA_DIR", "./data"), "persistent data directory")
	backend := flags.String("db", env("FESS_DB", "sqlite"), "sqlite or postgres")
	dsn := flags.String("dsn", env("FESS_DATABASE_URL", env("POSTGRES_DSN", "")), "database path or PostgreSQL DSN")
	admin := flags.String("admin", env("FESS_ADMIN_ADDR", "127.0.0.1:8082"), "management UI and API listener")
	httpAddr := flags.String("http", env("WAF_LISTEN_ADDR", ":80"), "WAF HTTP listener")
	httpsAddr := flags.String("https", env("WAF_TLS_LISTEN_ADDR", ":443"), "WAF HTTPS listener; empty disables")
	if err := flags.Parse(os.Args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %s", strings.Join(flags.Args(), " "))
	}
	if err := os.MkdirAll(*data, 0700); err != nil {
		return err
	}
	unlock, err := lockData(*data)
	if err != nil {
		return err
	}
	defer unlock()
	if *dsn == "" && *backend == "sqlite" {
		*dsn = filepath.Join(*data, "fess.db")
	}
	if *backend == "sqlite" {
		if err := secureSQLiteFile(*dsn); err != nil {
			return err
		}
		unlockDB, err := lockFile(*dsn + ".lock")
		if err != nil {
			return err
		}
		defer unlockDB()
	}
	if err := ensureSecret(*data); err != nil {
		return err
	}
	geo := filepath.Join(*data, "geoip")
	if err := os.MkdirAll(geo, 0700); err != nil {
		return err
	}
	for k, v := range map[string]string{"FENCE_GEOIP_DATA_DIR": geo, "GEOIP_MMDB_PATH": filepath.Join(geo, "GeoLite2-Country.mmdb"), "GEOIP_ASN_MMDB_PATH": filepath.Join(geo, "GeoLite2-ASN.mmdb")} {
		if _, ok := os.LookupEnv(k); !ok {
			os.Setenv(k, v)
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	d, err := fencedb.Open(ctx, *backend, *dsn)
	if err != nil {
		return err
	}
	defer d.Close()
	if err = fencedb.ApplyMigrations(ctx, d); err != nil {
		return err
	}
	bus := runtimebus.New()
	defer func() { bus.Close(); runErr = errors.Join(runErr, gateway.Close()) }()
	apiHandler, err := api.New(ctx, d, bus)
	if err != nil {
		return err
	}
	gw, tlsConfig, err := gateway.New(ctx, d, bus)
	if err != nil {
		return err
	}
	management := http.NewServeMux()
	management.Handle("/api/", apiHandler)
	management.Handle("/healthz", apiHandler)
	management.Handle("/metrics", apiHandler)
	management.Handle("/", ui.Handler())
	type endpoint struct {
		addr    string
		handler http.Handler
		tls     *tls.Config
	}
	endpoints := []endpoint{{*admin, management, nil}, {*httpAddr, gw, nil}}
	if *httpsAddr != "" {
		endpoints = append(endpoints, endpoint{*httpsAddr, gw, tlsConfig})
	}
	var servers []*http.Server
	var listeners []net.Listener
	defer func() {
		for _, ln := range listeners {
			ln.Close()
		}
	}()
	for _, ep := range endpoints {
		ln, err := net.Listen("tcp", ep.addr)
		if err != nil {
			return fmt.Errorf("listen %s: %w", ep.addr, err)
		}
		listeners = append(listeners, ln)
		if ep.tls != nil {
			ln = tls.NewListener(ln, ep.tls)
		}
		servers = append(servers, &http.Server{Handler: ep.handler, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 90 * time.Second})
		listeners[len(listeners)-1] = ln
	}
	errs := make(chan error, len(servers))
	for i, srv := range servers {
		go func(s *http.Server, ln net.Listener) { errs <- s.Serve(ln) }(srv, listeners[i])
	}
	log.Printf("FESS %s ready; database=%s admin=%s http=%s https=%s", version, *backend, *admin, *httpAddr, *httpsAddr)
	var serveErr error
	select {
	case <-ctx.Done():
	case serveErr = <-errs:
		stop()
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	for _, s := range servers {
		if err := s.Shutdown(shutdownCtx); err != nil {
			s.Close()
			if serveErr == nil {
				serveErr = err
			}
		}
	}
	if errors.Is(serveErr, http.ErrServerClosed) {
		return nil
	}
	return serveErr
}
func lockData(dir string) (func(), error) {
	return lockFile(filepath.Join(dir, "fess.lock"))
}
func lockFile(path string) (func(), error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("FESS is running or migration is in progress for %s", path)
	}
	return func() { unix.Flock(int(f.Fd()), unix.LOCK_UN); f.Close() }, nil
}
func secureSQLiteFile(path string) error {
	if strings.ContainsAny(path, "?\x00") || strings.HasPrefix(path, "file:") {
		return fmt.Errorf("use a plain SQLite file path")
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Chmod(0600)
}
func ensureSecret(dir string) error {
	if os.Getenv("FENCE_JWT_SECRET") != "" {
		return nil
	}
	path := filepath.Join(dir, "jwt.secret")
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		raw := make([]byte, 32)
		if _, err = rand.Read(raw); err != nil {
			return err
		}
		b = []byte(hex.EncodeToString(raw))
		if err = os.WriteFile(path, b, 0600); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	if len(strings.TrimSpace(string(b))) < 32 {
		return fmt.Errorf("invalid JWT secret in %s", path)
	}
	return os.Setenv("FENCE_JWT_SECRET", strings.TrimSpace(string(b)))
}
