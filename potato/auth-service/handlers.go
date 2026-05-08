package main

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const sessionCookieName = "auth_session"

func (s *server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
}

// /auth/check is the forward_auth target. Behavior depends on X-Auth-Mode:
//
//   - "bounce" (set by the potato Caddy): we are the public gate. Valid
//     cookie → 302 to the pi4 public URL so the bulk of the traffic flows
//     pi4↔user direct. Invalid cookie → 302 to the login page (browser) or
//     401 (API).
//   - "gate"   (set by the pi4 Caddy): we are the per-request authoriser.
//     Valid cookie → 200 (request continues to the pi4 backend). Invalid
//     cookie → 302 to the login page on the potato (absolute URL, since the
//     302 will be returned to a client connected to the pi4) or 401.
//
// In both modes invalid-cookie 302s are absolute (https://${HOSTNAME}/...)
// so they work whether forward_auth was triggered from potato or pi4.
func (s *server) handleCheck(w http.ResponseWriter, r *http.Request) {
	mode := r.Header.Get("X-Auth-Mode") // "bounce" | "gate" | ""

	if sess, ok := s.validSession(r); ok {
		w.Header().Set("X-Auth-User", sess.id)
		w.Header().Set("X-Auth-Token-Id", sess.tokenID)
		if mode == "bounce" {
			// Authorized — kick the user over to the pi4. We preserve the
			// original path/query via X-Forwarded-Uri (Caddy sets it).
			s.bounceToPi4(w, r)
			return
		}
		w.WriteHeader(http.StatusOK)
		return
	}
	s.unauthorized(w, r)
}

func (s *server) validSession(r *http.Request) (session, bool) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return session{}, false
	}
	sess, err := s.verifySessionCookie(cookie.Value)
	if err != nil {
		return session{}, false
	}
	live, err := s.store.SessionLive(r.Context(), sess.id)
	if err != nil || !live {
		return session{}, false
	}
	return sess, true
}

// bounceToPi4 issues a 302 to https://<pi4>:<port><X-Forwarded-Uri>. The
// browser already has the cookie scoped to the bare hostname, so it'll reuse
// it on the pi4 (cookies don't isolate by port).
func (s *server) bounceToPi4(w http.ResponseWriter, r *http.Request) {
	uri := r.Header.Get("X-Forwarded-Uri")
	if uri == "" || !strings.HasPrefix(uri, "/") {
		uri = "/"
	}
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, s.cfg.pi4PublicURL+uri, http.StatusFound)
}

// unauthorized: 302 for HTML callers, 401 otherwise. The original URL travels
// through Caddy's forward_auth via X-Forwarded-* and we round-trip it as a
// `next` query so the user lands where they meant to go (on the pi4) after
// successful verify.
func (s *server) unauthorized(w http.ResponseWriter, r *http.Request) {
	wantsHTML := strings.Contains(r.Header.Get("Accept"), "text/html")
	if !wantsHTML {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	next := r.Header.Get("X-Forwarded-Uri")
	if next == "" || !strings.HasPrefix(next, "/") {
		next = "/"
	}
	// Absolute URL so the redirect resolves correctly even when the 302 is
	// returned through forward_auth on the pi4.
	loginURL := "https://" + s.cfg.hostname + "/auth/login?next=" + url.QueryEscape(next)
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, loginURL, http.StatusFound)
}

func (s *server) handleLoginGET(w http.ResponseWriter, r *http.Request) {
	next := r.URL.Query().Get("next")
	if next == "" || !strings.HasPrefix(next, "/") {
		next = "/"
	}
	flash := r.URL.Query().Get("err")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = loginTmpl.Execute(w, loginData{Next: next, Err: flash})
}

func (s *server) handleVerifyPOST(w http.ResponseWriter, r *http.Request) {
	ip := s.realIP(r)
	if !s.allow(ip) {
		slog.Warn("verify rate-limited", "ip", ip)
		http.Error(w, "too many attempts", http.StatusTooManyRequests)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	token := strings.TrimSpace(r.PostFormValue("token"))
	next := r.PostFormValue("next")
	if next == "" || !strings.HasPrefix(next, "/") {
		next = "/"
	}

	tokenID, err := s.store.ConsumeOrTouchToken(r.Context(), token)
	if err != nil {
		// Generic error so we don't leak token validity beyond yes/no.
		slog.Info("verify failed", "ip", ip, "reason", err.Error())
		// 401 (not 400/404) so fail2ban's filter catches consistently.
		// Render the login page again with a flash.
		http.Redirect(w, r, "/auth/login?err=invalid&next="+url.QueryEscape(next), http.StatusFound)
		return
	}

	sess, signed, err := s.newSessionCookie(tokenID)
	if err != nil {
		slog.Error("session sign", "err", err)
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}
	if err := s.store.PutSession(r.Context(), sess.id, tokenID, ip, sess.expires); err != nil {
		slog.Error("session persist", "err", err)
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    signed,
		Path:     "/",
		Domain:   s.cfg.hostname,
		Expires:  sess.expires,
		MaxAge:   int(s.cfg.sessionTTL.Seconds()),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
	slog.Info("session created", "ip", ip, "session_id", sess.id, "token_id", tokenID)
	// After auth always punt to the pi4 (high-bandwidth host). The cookie
	// follows because cookies don't isolate by port within the same eTLD+1.
	target := s.cfg.pi4PublicURL + next
	http.Redirect(w, r, target, http.StatusFound)
}

func (s *server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookieName); err == nil {
		if sess, err := s.verifySessionCookie(c.Value); err == nil {
			_ = s.store.RevokeSession(r.Context(), sess.id)
		}
	}
	// Always clear, even if we couldn't decode the cookie.
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		Domain:   s.cfg.hostname,
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
	w.WriteHeader(http.StatusNoContent)
}

// --- Admin endpoints. Bearer auth via AUTH_ADMIN_TOKEN.

func (s *server) requireAdmin(r *http.Request) bool {
	got := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if !strings.HasPrefix(got, prefix) {
		return false
	}
	provided := got[len(prefix):]
	return subtle.ConstantTimeCompare([]byte(provided), []byte(s.cfg.adminToken)) == 1
}

type issueTokenReq struct {
	Note    string `json:"note"`
	TTLDays int    `json:"ttl_days"`
}

type issueTokenResp struct {
	ID      string    `json:"id"`
	Token   string    `json:"token"` // shown once
	Expires time.Time `json:"expires_at"`
}

func (s *server) handleAdminIssueToken(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	var req issueTokenReq
	if r.ContentLength > 0 {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
	}
	if req.TTLDays <= 0 {
		req.TTLDays = 30
	}

	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}
	plaintext := base64.RawURLEncoding.EncodeToString(raw)
	expires := time.Now().Add(time.Duration(req.TTLDays) * 24 * time.Hour)

	id, err := s.store.PutToken(r.Context(), plaintext, req.Note, expires)
	if err != nil {
		slog.Error("token persist", "err", err)
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(issueTokenResp{ID: id, Token: plaintext, Expires: expires})
}

func (s *server) handleAdminRevokeToken(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	id := r.PathValue("id")
	if err := s.store.RevokeToken(r.Context(), id); err != nil {
		if errors.Is(err, errNotFound) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) handleAdminRevokeSession(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	id := r.PathValue("id")
	if err := s.store.RevokeSession(r.Context(), id); err != nil {
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
