package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// session is the parsed cookie payload.
type session struct {
	id      string    // random 16-byte session ID, base64url
	tokenID string    // token ID this session was minted from
	expires time.Time // wall-clock expiry; HMAC binds it
}

// Cookie format: v1.<base64url(id)>.<base64url(tokenID)>.<expiresUnix>.<base64url(hmac)>
// HMAC is over: "v1\x00" + id + "\x00" + tokenID + "\x00" + expiresUnix
// We use a versioned prefix so we can rotate the format later.
const cookieVersion = "v1"

func (s *server) newSessionCookie(tokenID string) (session, string, error) {
	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		return session{}, "", err
	}
	id := base64.RawURLEncoding.EncodeToString(idBytes)
	exp := time.Now().Add(s.cfg.sessionTTL)
	signed := signCookie(s.cfg.sessionKey, id, tokenID, exp)
	return session{id: id, tokenID: tokenID, expires: exp}, signed, nil
}

func signCookie(key []byte, id, tokenID string, exp time.Time) string {
	expStr := strconv.FormatInt(exp.Unix(), 10)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(cookieVersion))
	mac.Write([]byte{0})
	mac.Write([]byte(id))
	mac.Write([]byte{0})
	mac.Write([]byte(tokenID))
	mac.Write([]byte{0})
	mac.Write([]byte(expStr))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	idEnc := base64.RawURLEncoding.EncodeToString([]byte(id))
	tidEnc := base64.RawURLEncoding.EncodeToString([]byte(tokenID))
	return fmt.Sprintf("%s.%s.%s.%s.%s", cookieVersion, idEnc, tidEnc, expStr, sig)
}

var errBadCookie = errors.New("bad cookie")

func (s *server) verifySessionCookie(raw string) (session, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 5 || parts[0] != cookieVersion {
		return session{}, errBadCookie
	}
	idBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return session{}, errBadCookie
	}
	tidBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return session{}, errBadCookie
	}
	expUnix, err := strconv.ParseInt(parts[3], 10, 64)
	if err != nil {
		return session{}, errBadCookie
	}
	exp := time.Unix(expUnix, 0)
	if time.Now().After(exp) {
		return session{}, errBadCookie
	}
	id := string(idBytes)
	tokenID := string(tidBytes)

	want := signCookie(s.cfg.sessionKey, id, tokenID, exp)
	if subtle.ConstantTimeCompare([]byte(want), []byte(raw)) != 1 {
		return session{}, errBadCookie
	}
	return session{id: id, tokenID: tokenID, expires: exp}, nil
}
