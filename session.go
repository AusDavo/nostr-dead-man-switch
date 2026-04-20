package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	sessionCookieName = "dms_session"
	sessionTTL        = 30 * 24 * time.Hour
	sessionSecretLen  = 32
	csrfTokenTTL      = 1 * time.Hour
)

type sessionManager struct {
	secret []byte
}

func newSessionManager(secretPath string) (*sessionManager, error) {
	secret, err := loadOrCreateSessionSecret(secretPath)
	if err != nil {
		return nil, err
	}
	return &sessionManager{secret: secret}, nil
}

func loadOrCreateSessionSecret(path string) ([]byte, error) {
	if data, err := os.ReadFile(path); err == nil {
		decoded, err := hex.DecodeString(strings.TrimSpace(string(data)))
		if err == nil && len(decoded) == sessionSecretLen {
			return decoded, nil
		}
	}

	secret := make([]byte, sessionSecretLen)
	if _, err := rand.Read(secret); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, []byte(hex.EncodeToString(secret)), 0600); err != nil {
		return nil, err
	}
	return secret, nil
}

// rotateSessionSecret writes a new secret to path, invalidating all sessions.
func rotateSessionSecret(path string) error {
	secret := make([]byte, sessionSecretLen)
	if _, err := rand.Read(secret); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(hex.EncodeToString(secret)), 0600)
}

// issue returns a cookie value binding the pubkey to an expiry with an HMAC.
// Format: base64url(pubkeyHex|expiryUnix|hmac)
func (s *sessionManager) issue(pubkey string) string {
	exp := time.Now().Add(sessionTTL).Unix()
	payload := pubkey + "|" + strconv.FormatInt(exp, 10)
	mac := s.sign(payload)
	return base64.RawURLEncoding.EncodeToString([]byte(payload + "|" + mac))
}

func (s *sessionManager) verify(cookie string) (string, error) {
	raw, err := base64.RawURLEncoding.DecodeString(cookie)
	if err != nil {
		return "", err
	}
	parts := strings.Split(string(raw), "|")
	if len(parts) != 3 {
		return "", errors.New("malformed session cookie")
	}
	pubkey, expStr, mac := parts[0], parts[1], parts[2]

	expected := s.sign(pubkey + "|" + expStr)
	if !hmac.Equal([]byte(mac), []byte(expected)) {
		return "", errors.New("bad signature")
	}

	exp, err := strconv.ParseInt(expStr, 10, 64)
	if err != nil {
		return "", err
	}
	if time.Now().Unix() > exp {
		return "", errors.New("session expired")
	}
	return pubkey, nil
}

func (s *sessionManager) sign(payload string) string {
	h := hmac.New(sha256.New, s.secret)
	h.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

func (s *sessionManager) setCookie(w http.ResponseWriter, r *http.Request, value string) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https"),
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().Add(sessionTTL),
	})
}

func (s *sessionManager) clearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	})
}

// issueCSRFToken returns an HMAC-signed token bound to pubkey and a short
// TTL. Stateless: verified later with the same session secret. Format:
// base64url(pubkey|expiryUnix|hmac).
func (s *sessionManager) issueCSRFToken(pubkey string) string {
	exp := time.Now().Add(csrfTokenTTL).Unix()
	payload := pubkey + "|" + strconv.FormatInt(exp, 10)
	mac := s.sign("csrf|" + payload)
	return base64.RawURLEncoding.EncodeToString([]byte(payload + "|" + mac))
}

// verifyCSRFToken checks that token was issued for pubkey and has not
// expired.
func (s *sessionManager) verifyCSRFToken(pubkey, token string) bool {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return false
	}
	parts := strings.Split(string(raw), "|")
	if len(parts) != 3 {
		return false
	}
	tokPub, expStr, mac := parts[0], parts[1], parts[2]
	if tokPub != pubkey {
		return false
	}
	expected := s.sign("csrf|" + tokPub + "|" + expStr)
	if !hmac.Equal([]byte(mac), []byte(expected)) {
		return false
	}
	exp, err := strconv.ParseInt(expStr, 10, 64)
	if err != nil {
		return false
	}
	return time.Now().Unix() <= exp
}

func (s *sessionManager) pubkeyFromRequest(r *http.Request) string {
	c, err := r.Cookie(sessionCookieName)
	if err != nil {
		return ""
	}
	pubkey, err := s.verify(c.Value)
	if err != nil {
		return ""
	}
	return pubkey
}
