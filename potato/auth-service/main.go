// Edge forward-auth service.
//
// Sits behind Caddy on the potato. Caddy's forward_auth directive hits
// /auth/check on every request that isn't /auth/* itself. We respond 200 if
// the visitor presents a valid signed session cookie; otherwise 302 to the
// login page (browsers) or 401 (API clients). Tokens are issued out-of-band
// via POST /auth/admin/tokens and shared with the visitor; on first successful
// /auth/verify we bind a long-lived session cookie so they don't have to
// re-enter the token.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

type config struct {
	listen         string
	hostname       string // public gate hostname (potato), e.g. your-host.example.org
	pi4PublicURL   string // where to bounce authorized users, e.g. https://your-host.example.org:8443
	sessionKey     []byte
	adminToken     string
	sessionTTL     time.Duration
	dbPath         string
	trustForwarded bool
	verifyLimit    int           // attempts per window, per IP
	verifyWindow   time.Duration // rate-limit window
}

func loadConfig() (*config, error) {
	c := &config{
		listen:         envOr("AUTH_LISTEN", ":8080"),
		hostname:       os.Getenv("AUTH_HOSTNAME"),
		pi4PublicURL:   strings.TrimRight(os.Getenv("AUTH_PI4_PUBLIC_URL"), "/"),
		adminToken:     os.Getenv("AUTH_ADMIN_TOKEN"),
		dbPath:         envOr("AUTH_DB_PATH", "/data/auth.db"),
		trustForwarded: strings.EqualFold(os.Getenv("AUTH_TRUST_FORWARDED"), "true"),
	}
	if c.hostname == "" {
		return nil, errors.New("AUTH_HOSTNAME is required")
	}
	if c.pi4PublicURL == "" {
		return nil, errors.New("AUTH_PI4_PUBLIC_URL is required (e.g. https://your-host.example.org:8443)")
	}
	if c.adminToken == "" || len(c.adminToken) < 24 {
		return nil, errors.New("AUTH_ADMIN_TOKEN must be set (>=24 chars)")
	}
	rawKey := os.Getenv("AUTH_SESSION_KEY")
	if len(rawKey) < 32 {
		return nil, errors.New("AUTH_SESSION_KEY must be >=32 chars (use `openssl rand -base64 48`)")
	}
	c.sessionKey = []byte(rawKey)

	ttl, err := time.ParseDuration(envOr("AUTH_SESSION_TTL", "720h"))
	if err != nil {
		return nil, fmt.Errorf("AUTH_SESSION_TTL: %w", err)
	}
	c.sessionTTL = ttl

	c.verifyLimit = envInt("AUTH_VERIFY_LIMIT", 5)
	win, err := time.ParseDuration(envOr("AUTH_VERIFY_WINDOW", "15m"))
	if err != nil {
		return nil, fmt.Errorf("AUTH_VERIFY_WINDOW: %w", err)
	}
	c.verifyWindow = win
	return c, nil
}

func envOr(k, def string) string {
	if v, ok := os.LookupEnv(k); ok && v != "" {
		return v
	}
	return def
}

func envInt(k string, def int) int {
	v := os.Getenv(k)
	if v == "" {
		return def
	}
	var n int
	_, err := fmt.Sscanf(v, "%d", &n)
	if err != nil || n <= 0 {
		return def
	}
	return n
}

func main() {
	healthcheck := flag.Bool("healthcheck", false, "probe the local listener and exit")
	flag.Parse()

	if *healthcheck {
		// Used as the container HEALTHCHECK. Just confirm the listener is up.
		c := &http.Client{Timeout: 2 * time.Second}
		resp, err := c.Get("http://127.0.0.1:8080/auth/healthz")
		if err != nil || resp.StatusCode != 200 {
			os.Exit(1)
		}
		os.Exit(0)
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	cfg, err := loadConfig()
	if err != nil {
		slog.Error("config", "err", err)
		os.Exit(2)
	}

	store, err := openStore(cfg.dbPath)
	if err != nil {
		slog.Error("store", "err", err)
		os.Exit(2)
	}
	defer store.Close()

	srv := newServer(cfg, store)

	httpSrv := &http.Server{
		Addr:              cfg.listen,
		Handler:           srv,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	// Graceful shutdown.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutdownCtx)
	}()

	slog.Info("auth-svc up", "listen", cfg.listen, "hostname", cfg.hostname, "session_ttl", cfg.sessionTTL)
	if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		slog.Error("listen", "err", err)
		os.Exit(1)
	}
}

// realIP returns the client IP. With AUTH_TRUST_FORWARDED=true (we're only
// reachable from Caddy on the edge network), trust X-Real-IP / X-Forwarded-For.
func (s *server) realIP(r *http.Request) string {
	if s.cfg.trustForwarded {
		if v := r.Header.Get("X-Real-IP"); v != "" {
			return v
		}
		if v := r.Header.Get("X-Forwarded-For"); v != "" {
			// Leftmost is original client.
			if i := strings.IndexByte(v, ','); i >= 0 {
				return strings.TrimSpace(v[:i])
			}
			return strings.TrimSpace(v)
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
