package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip19"
)

// revealFixture is a federation-mode dashboard with a real Sealer and a
// real sealed watcher nsec on disk, so the reveal handler can round-trip.
type revealFixture struct {
	srv         *httptest.Server
	d           *DeadManSwitch
	subjectSk   string
	subjectPk   string
	subjectNpub string
	watcherSk   string
	watcherNsec string
}

func newRevealFixture(t *testing.T) *revealFixture {
	t.Helper()
	dir := t.TempDir()

	subjectSk := nostr.GeneratePrivateKey()
	subjectPk, _ := nostr.GetPublicKey(subjectSk)
	subjectNpub, err := nip19.EncodePublicKey(subjectPk)
	if err != nil {
		t.Fatal(err)
	}
	watcherSk := nostr.GeneratePrivateKey()
	watcherPk, _ := nostr.GetPublicKey(watcherSk)
	watcherNsec, err := nip19.EncodePrivateKey(watcherSk)
	if err != nil {
		t.Fatal(err)
	}

	store, err := NewUserStore(filepath.Join(dir, "users"))
	if err != nil {
		t.Fatal(err)
	}
	wl, err := LoadWhitelist(filepath.Join(dir, "whitelist.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := wl.Add(subjectNpub, ""); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateUser(subjectNpub); err != nil {
		t.Fatal(err)
	}

	storeKey := make([]byte, 32)
	for i := range storeKey {
		storeKey[i] = byte(i + 1)
	}
	sealer, err := NewSealer(base64.StdEncoding.EncodeToString(storeKey))
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := sealer.Seal(subjectNpub, []byte(watcherSk))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveSealedNsec(subjectNpub, sealed); err != nil {
		t.Fatal(err)
	}
	uc := &UserConfig{
		SubjectNpub:      subjectNpub,
		WatcherPubkeyHex: watcherPk,
		SilenceThreshold: Duration{24 * time.Hour},
		WarningInterval:  Duration{time.Hour},
		WarningCount:     1,
		CheckInterval:    Duration{time.Minute},
		UpdatedAt:        time.Now(),
	}
	if err := store.SaveConfig(subjectNpub, uc); err != nil {
		t.Fatal(err)
	}

	r := NewRegistry(&HostConfig{}, store, wl, sealer, context.Background())
	// Register a dummy running supervised entry so any watcher lookups succeed
	// — the reveal flow doesn't need a live goroutine, just store + sealer.
	ff := newFakeFactory()
	r.newWatcher = ff.make
	if err := r.Start(subjectNpub); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.StopAll() })

	cfg := &Config{FederationV1: true, StateFile: filepath.Join(dir, "state.json")}
	sm, err := newSessionManager(filepath.Join(dir, "session_secret"))
	if err != nil {
		t.Fatal(err)
	}
	d := &DeadManSwitch{
		cfg:        cfg,
		sessions:   sm,
		challenges: &challengeStore{m: map[string]time.Time{}},
		registry:   r,
		startedAt:  time.Now(),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/admin/watcher", d.requireAuth(d.handleWatcherSetup))
	mux.HandleFunc("/admin/watcher/reveal/challenge", d.requireAuth(d.handleWatcherRevealChallenge))
	mux.HandleFunc("/admin/watcher/reveal", d.requireAuth(d.handleWatcherReveal))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	return &revealFixture{
		srv:         srv,
		d:           d,
		subjectSk:   subjectSk,
		subjectPk:   subjectPk,
		subjectNpub: subjectNpub,
		watcherSk:   watcherSk,
		watcherNsec: watcherNsec,
	}
}

func (fx *revealFixture) cookie() *http.Cookie {
	return &http.Cookie{Name: sessionCookieName, Value: fx.d.sessions.issue(fx.subjectPk)}
}

func (fx *revealFixture) csrf() string {
	return fx.d.sessions.issueCSRFToken(fx.subjectPk)
}

func (fx *revealFixture) getChallenge(t *testing.T) string {
	t.Helper()
	req, _ := http.NewRequest("GET", fx.srv.URL+"/admin/watcher/reveal/challenge", nil)
	req.AddCookie(fx.cookie())
	resp, err := fx.srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("challenge status=%d body=%s", resp.StatusCode, b)
	}
	var cr struct{ Challenge string }
	if err := json.NewDecoder(resp.Body).Decode(&cr); err != nil {
		t.Fatal(err)
	}
	if cr.Challenge == "" {
		t.Fatal("empty challenge")
	}
	return cr.Challenge
}

func (fx *revealFixture) postReveal(t *testing.T, signedEvent []byte, csrfToken string, cookie *http.Cookie) *http.Response {
	t.Helper()
	body, _ := json.Marshal(map[string]json.RawMessage{"signedEvent": signedEvent})
	req, _ := http.NewRequest("POST", fx.srv.URL+"/admin/watcher/reveal", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if csrfToken != "" {
		req.Header.Set("X-CSRF-Token", csrfToken)
	}
	if cookie != nil {
		req.AddCookie(cookie)
	}
	resp, err := fx.srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestRevealNsec_HappyPath(t *testing.T) {
	fx := newRevealFixture(t)

	challenge := fx.getChallenge(t)
	signed := signChallenge(t, fx.subjectSk, challenge)

	resp := fx.postReveal(t, signed, fx.csrf(), fx.cookie())
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("reveal status=%d body=%s", resp.StatusCode, b)
	}
	var out struct{ Nsec string }
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.Nsec != fx.watcherNsec {
		t.Fatalf("revealed nsec mismatch:\n got: %s\nwant: %s", out.Nsec, fx.watcherNsec)
	}
}

func TestRevealNsec_WrongSigner(t *testing.T) {
	fx := newRevealFixture(t)

	challenge := fx.getChallenge(t)
	// Sign with a different key than the session cookie's pubkey.
	attackerSk := nostr.GeneratePrivateKey()
	signed := signChallenge(t, attackerSk, challenge)

	resp := fx.postReveal(t, signed, fx.csrf(), fx.cookie())
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("wrong-signer status=%d body=%s, want 401", resp.StatusCode, b)
	}
}

func TestRevealNsec_MissingCSRF(t *testing.T) {
	fx := newRevealFixture(t)

	challenge := fx.getChallenge(t)
	signed := signChallenge(t, fx.subjectSk, challenge)

	resp := fx.postReveal(t, signed, "", fx.cookie())
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("missing-csrf status=%d body=%s, want 403", resp.StatusCode, b)
	}
}

func TestRevealNsec_UnknownChallenge(t *testing.T) {
	fx := newRevealFixture(t)

	// Sign a challenge the server never issued.
	signed := signChallenge(t, fx.subjectSk, "deadbeef"+strings.Repeat("0", 56))

	resp := fx.postReveal(t, signed, fx.csrf(), fx.cookie())
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("unknown-challenge status=%d body=%s, want 400", resp.StatusCode, b)
	}
}

func TestRevealNsec_Unauthenticated(t *testing.T) {
	fx := newRevealFixture(t)

	// No session cookie — requireAuth should redirect to /login.
	req, _ := http.NewRequest("POST", fx.srv.URL+"/admin/watcher/reveal", bytes.NewReader([]byte("{}")))
	noFollow := &http.Client{
		Transport: fx.srv.Client().Transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := noFollow.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("unauth status=%d, want 303", resp.StatusCode)
	}
}

func TestWatcherSetup_AlreadySetupShowsWatcherNpub(t *testing.T) {
	fx := newRevealFixture(t)

	req, _ := http.NewRequest("GET", fx.srv.URL+"/admin/watcher", nil)
	req.AddCookie(fx.cookie())
	resp, err := fx.srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("setup status=%d", resp.StatusCode)
	}
	watcherPk, _ := nostr.GetPublicKey(fx.watcherSk)
	watcherNpub, _ := nip19.EncodePublicKey(watcherPk)
	if !strings.Contains(string(body), watcherNpub) {
		t.Fatalf("AlreadySetup page missing watcher npub %s; body len=%d", watcherNpub, len(body))
	}
	if !strings.Contains(string(body), "Reveal nsec") {
		t.Fatal("AlreadySetup page missing Reveal nsec button")
	}
	if !strings.Contains(string(body), "Follow") && !strings.Contains(string(body), "follow") {
		t.Fatal("AlreadySetup page missing follow-encouragement copy")
	}
}
