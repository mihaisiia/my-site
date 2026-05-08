package main

import (
	"net/http"
	"sync"
	"time"
)

// server wires routes + shared deps. Kept tiny so tests can drive it.
type server struct {
	cfg   *config
	store *store
	mux   *http.ServeMux

	// In-memory leaky bucket per IP for /auth/verify. fail2ban handles
	// persistent abuse via a UDR firewall block; this is the in-app gate.
	mu      sync.Mutex
	buckets map[string]*bucket
}

type bucket struct {
	hits  int
	reset time.Time
}

func newServer(cfg *config, st *store) *server {
	s := &server{
		cfg:     cfg,
		store:   st,
		mux:     http.NewServeMux(),
		buckets: make(map[string]*bucket),
	}
	s.routes()
	go s.gcLoop()
	return s
}

func (s *server) routes() {
	s.mux.HandleFunc("GET /auth/healthz", s.handleHealthz)
	s.mux.HandleFunc("GET /auth/check", s.handleCheck)
	s.mux.HandleFunc("GET /auth/login", s.handleLoginGET)
	s.mux.HandleFunc("POST /auth/verify", s.handleVerifyPOST)
	s.mux.HandleFunc("POST /auth/logout", s.handleLogout)
	s.mux.HandleFunc("POST /auth/admin/tokens", s.handleAdminIssueToken)
	s.mux.HandleFunc("DELETE /auth/admin/tokens/{id}", s.handleAdminRevokeToken)
	s.mux.HandleFunc("DELETE /auth/admin/sessions/{id}", s.handleAdminRevokeSession)
}

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

// allow returns true if the IP is under the verify-rate limit. Increments on
// allow; on deny it does NOT increment further (so a flood doesn't extend the
// ban window indefinitely past the natural reset).
func (s *server) allow(ip string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	b, ok := s.buckets[ip]
	if !ok || now.After(b.reset) {
		s.buckets[ip] = &bucket{hits: 1, reset: now.Add(s.cfg.verifyWindow)}
		return true
	}
	if b.hits >= s.cfg.verifyLimit {
		return false
	}
	b.hits++
	return true
}

// gcLoop drops expired buckets so memory stays bounded.
func (s *server) gcLoop() {
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	for range t.C {
		now := time.Now()
		s.mu.Lock()
		for ip, b := range s.buckets {
			if now.After(b.reset) {
				delete(s.buckets, ip)
			}
		}
		s.mu.Unlock()
	}
}
