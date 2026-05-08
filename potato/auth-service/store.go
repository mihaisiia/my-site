package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

var errNotFound = errors.New("not found")

type store struct {
	db *sql.DB
}

func openStore(path string) (*store, error) {
	dsn := fmt.Sprintf("file:%s?_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // SQLite + writers: keep it simple.
	if err := db.Ping(); err != nil {
		return nil, err
	}
	if err := migrate(db); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &store{db: db}, nil
}

func (s *store) Close() error { return s.db.Close() }

func migrate(db *sql.DB) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS tokens (
			id          TEXT PRIMARY KEY,
			hash        TEXT NOT NULL UNIQUE,
			note        TEXT NOT NULL DEFAULT '',
			created_at  INTEGER NOT NULL,
			expires_at  INTEGER NOT NULL,
			revoked_at  INTEGER,
			last_used   INTEGER
		)`,
		`CREATE INDEX IF NOT EXISTS tokens_expires ON tokens(expires_at)`,
		`CREATE TABLE IF NOT EXISTS sessions (
			id          TEXT PRIMARY KEY,
			token_id    TEXT NOT NULL REFERENCES tokens(id) ON DELETE CASCADE,
			ip          TEXT NOT NULL,
			created_at  INTEGER NOT NULL,
			expires_at  INTEGER NOT NULL,
			revoked_at  INTEGER
		)`,
		`CREATE INDEX IF NOT EXISTS sessions_token ON sessions(token_id)`,
		`CREATE INDEX IF NOT EXISTS sessions_expires ON sessions(expires_at)`,
	}
	for _, q := range stmts {
		if _, err := db.Exec(q); err != nil {
			return fmt.Errorf("migrate: %w (%s)", err, q)
		}
	}
	return nil
}

// PutToken stores a NEW token (the plaintext is hashed; we never store it).
// Returns the token's ID (used to reference it in sessions and admin ops).
func (s *store) PutToken(ctx context.Context, plaintext, note string, expires time.Time) (string, error) {
	id, err := randID()
	if err != nil {
		return "", err
	}
	h := hashToken(plaintext)
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO tokens (id, hash, note, created_at, expires_at) VALUES (?, ?, ?, ?, ?)`,
		id, h, note, time.Now().Unix(), expires.Unix())
	if err != nil {
		return "", err
	}
	return id, nil
}

// ConsumeOrTouchToken validates a plaintext token. Tokens are reusable (they
// stay valid until their expiry or until revoked); we just record last_used so
// admin tooling can show which tokens are alive.
//
// Returns the token's ID on success. Returns a generic error on failure
// (caller must NOT leak details to the client).
func (s *store) ConsumeOrTouchToken(ctx context.Context, plaintext string) (string, error) {
	if plaintext == "" {
		return "", errors.New("empty")
	}
	h := hashToken(plaintext)
	var (
		id        string
		expiresAt int64
		revokedAt sql.NullInt64
	)
	err := s.db.QueryRowContext(ctx,
		`SELECT id, expires_at, revoked_at FROM tokens WHERE hash = ?`, h).
		Scan(&id, &expiresAt, &revokedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return "", errors.New("unknown")
	}
	if err != nil {
		return "", err
	}
	if revokedAt.Valid {
		return "", errors.New("revoked")
	}
	if time.Now().Unix() > expiresAt {
		return "", errors.New("expired")
	}
	_, _ = s.db.ExecContext(ctx, `UPDATE tokens SET last_used = ? WHERE id = ?`, time.Now().Unix(), id)
	return id, nil
}

func (s *store) RevokeToken(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE tokens SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`,
		time.Now().Unix(), id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errNotFound
	}
	// Also revoke any live sessions minted from it.
	_, err = s.db.ExecContext(ctx, `UPDATE sessions SET revoked_at = ? WHERE token_id = ? AND revoked_at IS NULL`,
		time.Now().Unix(), id)
	return err
}

func (s *store) PutSession(ctx context.Context, id, tokenID, ip string, expires time.Time) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO sessions (id, token_id, ip, created_at, expires_at) VALUES (?, ?, ?, ?, ?)`,
		id, tokenID, ip, time.Now().Unix(), expires.Unix())
	return err
}

// SessionLive: cookie HMAC already passed; this just confirms the row exists,
// isn't revoked, and isn't expired. Belt-and-suspenders against stolen cookies
// after we've revoked the parent token.
func (s *store) SessionLive(ctx context.Context, id string) (bool, error) {
	var (
		expiresAt int64
		revokedAt sql.NullInt64
	)
	err := s.db.QueryRowContext(ctx,
		`SELECT expires_at, revoked_at FROM sessions WHERE id = ?`, id).
		Scan(&expiresAt, &revokedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if revokedAt.Valid {
		return false, nil
	}
	if time.Now().Unix() > expiresAt {
		return false, nil
	}
	return true, nil
}

func (s *store) RevokeSession(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE sessions SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`,
		time.Now().Unix(), id)
	return err
}

func hashToken(plaintext string) string {
	sum := sha256.Sum256([]byte(plaintext))
	return hex.EncodeToString(sum[:])
}

func randID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
