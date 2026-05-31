package main

import (
	"context"
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

// signupFixture wires a federation dashboard with a fake-factory registry
// (so tryStart after redemption is a harmless ErrNotEnrolled no-op) and an
// InviteCodes seeded with configuredCodes. Returns the live whitelist and
// invites so tests can assert enrollment side-effects directly.
type signupFixture struct {
	srv     *httptest.Server
	d       *DeadManSwitch
	wl      *Whitelist
	invites *InviteCodes
}

func newSignupFixture(t *testing.T, configuredCodes []string) *signupFixture {
	t.Helper()
	dir := t.TempDir()

	store, err := NewUserStore(filepath.Join(dir, "users"))
	if err != nil {
		t.Fatal(err)
	}
	wl, err := LoadWhitelist(filepath.Join(dir, "whitelist.json"))
	if err != nil {
		t.Fatal(err)
	}
	ff := newFakeFactory()
	reg := NewRegistry(&HostConfig{StateDir: dir}, store, wl, nil, context.Background())
	reg.newWatcher = ff.make
	t.Cleanup(reg.StopAll)

	invites, err := LoadInviteCodes(dir, configuredCodes)
	if err != nil {
		t.Fatal(err)
	}

	cfg := &Config{FederationV1: true, StateDir: dir, StateFile: filepath.Join(dir, "state.json")}
	sm, err := newSessionManager(filepath.Join(dir, "session_secret"))
	if err != nil {
		t.Fatal(err)
	}
	d := &DeadManSwitch{
		cfg:        cfg,
		sessions:   sm,
		challenges: &challengeStore{m: map[string]time.Time{}},
		registry:   reg,
		invites:    invites,
		startedAt:  time.Now(),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/login", d.handleLogin)
	mux.HandleFunc("/admin", d.requireAuth(d.handleAdmin))
	mux.HandleFunc("/admin/signup", d.requireAuth(d.handleSignupLanding))
	mux.HandleFunc("/admin/watcher", d.requireAuth(d.handleWatcherSetup))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	return &signupFixture{srv: srv, d: d, wl: wl, invites: invites}
}

func (fx *signupFixture) get(t *testing.T, pk, path string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest("GET", fx.srv.URL+path, nil)
	if pk != "" {
		req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: fx.d.sessions.issue(pk)})
	}
	resp, err := noRedirectClient(t, fx.srv.Client()).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func newTestNpub(t *testing.T) string {
	t.Helper()
	sk := nostr.GeneratePrivateKey()
	pk, _ := nostr.GetPublicKey(sk)
	npub, _ := nip19.EncodePublicKey(pk)
	return npub
}

func pkOf(npub string) string {
	_, v, _ := nip19.Decode(npub)
	return v.(string)
}

func TestSignupUnauthedRedirectsToLogin(t *testing.T) {
	fx := newSignupFixture(t, nil)
	resp := fx.get(t, "", "/admin/signup?code=ABC123")
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", resp.StatusCode)
	}
	// Must bounce to /login but preserve the invite destination so the
	// code survives the sign-in round-trip.
	loc := resp.Header.Get("Location")
	if !strings.HasPrefix(loc, "/login") {
		t.Fatalf("Location = %q, want /login…", loc)
	}
	if !strings.Contains(loc, "next=") || !strings.Contains(loc, "code%3DABC123") {
		t.Fatalf("Location = %q, want a next= carrying the signup code", loc)
	}
}

func TestSignupNoCodeShowsClosedPage(t *testing.T) {
	fx := newSignupFixture(t, nil)
	npub := newTestNpub(t)
	resp := fx.get(t, pkOf(npub), "/admin/signup")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	s := string(body)
	if !strings.Contains(s, "invite-only") {
		t.Fatalf("closed page missing invite-only copy")
	}
	// Their own npub is shown so they can share it; no secrets leak.
	if !strings.Contains(s, npub) {
		t.Fatalf("closed page should show the visitor's npub")
	}
}

func TestSignupValidCodeEnrollsAndRedirects(t *testing.T) {
	fx := newSignupFixture(t, []string{"GOODCODE"})
	npub := newTestNpub(t)

	resp := fx.get(t, pkOf(npub), "/admin/signup?code=GOODCODE")
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "/admin/watcher" {
		t.Fatalf("Location = %q, want /admin/watcher", loc)
	}
	if !fx.wl.Contains(npub) {
		t.Fatal("valid-code signup did not whitelist the npub")
	}
	var plan string
	for _, e := range fx.wl.List() {
		if e.Npub == npub {
			plan = e.PlanKind
		}
	}
	if plan != "invite" {
		t.Fatalf("plan = %q, want invite", plan)
	}
}

func TestSignupCodeUsedByOtherShowsInvalid(t *testing.T) {
	fx := newSignupFixture(t, []string{"GOODCODE"})
	first := newTestNpub(t)
	if err := fx.invites.Redeem("GOODCODE", first); err != nil {
		t.Fatal(err)
	}

	second := newTestNpub(t)
	resp := fx.get(t, pkOf(second), "/admin/signup?code=GOODCODE")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (invalid-code page)", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "can't be used") {
		t.Fatalf("expected invalid-code copy")
	}
	if fx.wl.Contains(second) {
		t.Fatal("second npub must not be enrolled on a spent code")
	}
}

func TestSignupWhitelistedRedirectsToAdmin(t *testing.T) {
	fx := newSignupFixture(t, nil)
	npub := newTestNpub(t)
	if err := fx.wl.Add(npub, ""); err != nil {
		t.Fatal(err)
	}
	resp := fx.get(t, pkOf(npub), "/admin/signup")
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "/admin" {
		t.Fatalf("Location = %q, want /admin", loc)
	}
}
