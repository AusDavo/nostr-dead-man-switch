package main

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newTestSessionManager(t *testing.T) *sessionManager {
	t.Helper()
	path := filepath.Join(t.TempDir(), "session_secret")
	sm, err := newSessionManager(path)
	if err != nil {
		t.Fatalf("newSessionManager: %v", err)
	}
	return sm
}

func TestSession_IssueVerify(t *testing.T) {
	sm := newTestSessionManager(t)
	pubkey := "abc123"
	c := sm.issue(pubkey)
	got, err := sm.verify(c)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got != pubkey {
		t.Fatalf("pubkey = %s, want %s", got, pubkey)
	}
}

func TestSession_Tampered(t *testing.T) {
	sm := newTestSessionManager(t)
	c := sm.issue("alice")

	// Decode, mutate, re-encode with the same HMAC (should fail HMAC check).
	raw, _ := base64.RawURLEncoding.DecodeString(c)
	parts := strings.Split(string(raw), "|")
	parts[0] = "bob"
	bad := base64.RawURLEncoding.EncodeToString([]byte(strings.Join(parts, "|")))

	if _, err := sm.verify(bad); err == nil {
		t.Fatalf("expected tamper detection")
	}
}

func TestSession_Expired(t *testing.T) {
	sm := newTestSessionManager(t)
	// Manually forge an expired but correctly signed cookie.
	expired := "alice|" + "1" // unix epoch 1
	mac := sm.sign(expired)
	c := base64.RawURLEncoding.EncodeToString([]byte(expired + "|" + mac))

	if _, err := sm.verify(c); err == nil {
		t.Fatalf("expected expiry rejection")
	}
}

func TestSession_RotateInvalidatesCookies(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "session_secret")

	sm1, err := newSessionManager(path)
	if err != nil {
		t.Fatal(err)
	}
	c := sm1.issue("alice")

	if err := rotateSessionSecret(path); err != nil {
		t.Fatal(err)
	}

	sm2, err := newSessionManager(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sm2.verify(c); err == nil {
		t.Fatalf("cookie signed by old secret should not verify under new secret")
	}
}

func TestSession_SecretPersists(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "session_secret")

	sm1, err := newSessionManager(path)
	if err != nil {
		t.Fatal(err)
	}
	c := sm1.issue("alice")

	// New manager reading the same file should verify the cookie.
	sm2, err := newSessionManager(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sm2.verify(c); err != nil {
		t.Fatalf("cookie should survive manager restart: %v", err)
	}
}

func TestSession_SecretFilePermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "session_secret")

	if _, err := newSessionManager(path); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0600 {
		t.Fatalf("session_secret perms = %o, want 600", mode)
	}
}

func TestSession_NoCookieRequest(t *testing.T) {
	sm := newTestSessionManager(t)
	_ = time.Now()
	// Verify malformed cookies don't panic and return empty pubkey.
	for _, bad := range []string{"", "not-base64!", "YWJjZGVm"} {
		if _, err := sm.verify(bad); err == nil {
			t.Fatalf("verify(%q) should error", bad)
		}
	}
}
