package main

import (
	"context"
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

// federationDashboardFixture wires a DeadManSwitch with a federation
// Registry and the full HTTP mux (same routes as startServer). Used to
// assert that the dashboard serves non-empty pages in federation mode.
type federationDashboardFixture struct {
	srv *httptest.Server
	d   *DeadManSwitch
	ff  *fakeFactory
	r   *Registry
}

func newFederationDashboard(t *testing.T, enrolled []string) *federationDashboardFixture {
	t.Helper()
	dir := t.TempDir()

	store, err := NewUserStore(filepath.Join(dir, "users"))
	if err != nil {
		t.Fatalf("NewUserStore: %v", err)
	}
	wl, err := LoadWhitelist(filepath.Join(dir, "whitelist.json"))
	if err != nil {
		t.Fatalf("LoadWhitelist: %v", err)
	}
	ff := newFakeFactory()
	r := NewRegistry(&HostConfig{}, store, wl, nil, context.Background())
	r.newWatcher = ff.make

	for _, n := range enrolled {
		if err := wl.Add(n, ""); err != nil {
			t.Fatalf("whitelist.Add: %v", err)
		}
		if err := store.CreateUser(n); err != nil {
			t.Fatalf("CreateUser: %v", err)
		}
		if err := store.SaveConfigBytes(n, []byte("{}")); err != nil {
			t.Fatalf("SaveConfigBytes: %v", err)
		}
		if err := r.Start(n); err != nil {
			t.Fatalf("Start: %v", err)
		}
	}
	t.Cleanup(func() { r.StopAll() })

	cfg := &Config{
		FederationV1: true,
		StateFile:    filepath.Join(dir, "state.json"),
	}
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
	mux.HandleFunc("/", d.handleStatus)
	mux.HandleFunc("/health", d.handleHealth)
	mux.HandleFunc("/login", d.handleLogin)
	mux.HandleFunc("/login/challenge", d.handleLoginChallenge)
	mux.HandleFunc("/login/verify", d.handleLoginVerify)
	mux.HandleFunc("/logout", d.handleLogout)
	mux.HandleFunc("/admin", d.requireAuth(d.handleAdmin))
	mux.HandleFunc("/config", d.requireAuth(d.handleConfig))
	mux.HandleFunc("/admin/config", d.requireAuth(d.handleAdminConfig))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return &federationDashboardFixture{srv: srv, d: d, ff: ff, r: r}
}

func TestFederationModeBootsHTTPServer(t *testing.T) {
	sk := nostr.GeneratePrivateKey()
	pk, _ := nostr.GetPublicKey(sk)
	npub, err := nip19.EncodePublicKey(pk)
	if err != nil {
		t.Fatal(err)
	}

	fx := newFederationDashboard(t, []string{npub})

	client := fx.srv.Client()
	resp, err := client.Get(fx.srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET / status = %d, want 200", resp.StatusCode)
	}
	if !strings.Contains(string(body), "federation") {
		t.Fatalf("status page missing federation header; body=%s", string(body))
	}
	if !strings.Contains(string(body), truncateMiddle(npub, 24)) {
		t.Fatalf("status page missing enrolled npub")
	}

	resp, err = client.Get(fx.srv.URL + "/login")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /login status = %d, want 200", resp.StatusCode)
	}

	resp, err = client.Get(fx.srv.URL + "/health")
	if err != nil {
		t.Fatal(err)
	}
	var health map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&health); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if health["mode"] != "federation" {
		t.Fatalf("health mode = %v, want federation", health["mode"])
	}
}

func TestFederationModeNoWatchersRendersEmpty(t *testing.T) {
	fx := newFederationDashboard(t, nil)

	resp, err := fx.srv.Client().Get(fx.srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET / status = %d, want 200", resp.StatusCode)
	}
	if !strings.Contains(string(body), "No watchers") {
		t.Fatalf("empty state page missing 'No watchers' hint")
	}
}
