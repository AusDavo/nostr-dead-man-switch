package main

import (
	"bytes"
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
	if !strings.Contains(string(body), "Watchers") {
		t.Fatalf("status page missing Watchers card; body=%s", string(body))
	}
	if strings.Contains(string(body), "npub1") {
		t.Fatalf("public / should not leak per-user npubs; body=%s", string(body))
	}
	if !strings.Contains(string(body), ">1<") {
		t.Fatalf("aggregate total should render as 1; body=%s", string(body))
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

// insertRunningWatcher inserts a *UserWatcher into the registry's
// internal map without starting a goroutine. Registry.Get(npub) will
// return w. Only for tests: production code goes through Start.
func insertRunningWatcher(r *Registry, npub string, w *UserWatcher) {
	done := make(chan struct{})
	close(done)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.watchers[npub] = &supervised{
		w:        w,
		concrete: w,
		cancel:   func() {},
		done:     done,
		uc:       w.Config(),
	}
}

// adminConfigFixture spins up a real *UserWatcher (with a captured
// publishFn) behind a federation-mode dashboard. Used for POST
// /admin/config tests.
type adminConfigFixture struct {
	srv         *httptest.Server
	d           *DeadManSwitch
	subjectSk   string
	subjectPk   string
	subjectNpub string
	store       *UserStore
	watcher     *UserWatcher
	published   *[]nostr.Event
}

func newAdminConfigFixture(t *testing.T) *adminConfigFixture {
	t.Helper()
	dir := t.TempDir()

	subjectSk := nostr.GeneratePrivateKey()
	subjectPk, _ := nostr.GetPublicKey(subjectSk)
	subjectNpub, err := nip19.EncodePublicKey(subjectPk)
	if err != nil {
		t.Fatal(err)
	}
	watcherSk := nostr.GeneratePrivateKey()

	store, err := NewUserStore(filepath.Join(dir, "users"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CreateUser(subjectNpub); err != nil {
		t.Fatal(err)
	}

	wl, err := LoadWhitelist(filepath.Join(dir, "whitelist.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := wl.Add(subjectNpub, ""); err != nil {
		t.Fatal(err)
	}

	host := &HostConfig{Relays: []string{"wss://relay.example.invalid"}}
	uc := &UserConfig{
		SubjectNpub:      subjectNpub,
		Relays:           []string{"wss://relay.example.invalid"},
		SilenceThreshold: Duration{24 * time.Hour},
		WarningInterval:  Duration{2 * time.Hour},
		WarningCount:     2,
		CheckInterval:    Duration{time.Minute},
		UpdatedAt:        time.Unix(1700000000, 0).UTC(),
	}
	if err := store.SaveConfig(subjectNpub, uc); err != nil {
		t.Fatal(err)
	}

	watcher, err := NewUserWatcher(host, uc, watcherSk, store)
	if err != nil {
		t.Fatal(err)
	}
	published := []nostr.Event{}
	watcher.publishFn = func(ctx context.Context, relays []string, ev nostr.Event) error {
		published = append(published, ev)
		return nil
	}

	r := NewRegistry(host, store, wl, nil, context.Background())
	insertRunningWatcher(r, subjectNpub, watcher)

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
	mux.HandleFunc("/login", d.handleLogin)
	mux.HandleFunc("/login/challenge", d.handleLoginChallenge)
	mux.HandleFunc("/login/verify", d.handleLoginVerify)
	mux.HandleFunc("/admin/config", d.requireAuth(d.handleAdminConfig))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	return &adminConfigFixture{
		srv:         srv,
		d:           d,
		subjectSk:   subjectSk,
		subjectPk:   subjectPk,
		subjectNpub: subjectNpub,
		store:       store,
		watcher:     watcher,
		published:   &published,
	}
}

func (fx *adminConfigFixture) sessionCookie() *http.Cookie {
	return &http.Cookie{Name: sessionCookieName, Value: fx.d.sessions.issue(fx.subjectPk)}
}

func (fx *adminConfigFixture) csrfToken() string {
	return fx.d.sessions.issueCSRFToken(fx.subjectPk)
}

func noRedirectClient(t *testing.T, base *http.Client) *http.Client {
	t.Helper()
	return &http.Client{
		Transport: base.Transport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func TestAdminConfigPublishes(t *testing.T) {
	fx := newAdminConfigFixture(t)

	newCfg := map[string]any{
		"subject_npub":      fx.subjectNpub,
		"silence_threshold": "48h0m0s",
		"warning_interval":  "3h0m0s",
		"warning_count":     3,
		"check_interval":    "1m0s",
		"relays":            []string{"wss://relay.example.invalid"},
	}
	payload, _ := json.Marshal(newCfg)

	req, _ := http.NewRequest("POST", fx.srv.URL+"/admin/config", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", fx.csrfToken())
	req.AddCookie(fx.sessionCookie())

	client := noRedirectClient(t, fx.srv.Client())
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d body=%s, want 303", resp.StatusCode, string(body))
	}
	if loc := resp.Header.Get("Location"); loc != "/admin/config" {
		t.Fatalf("Location = %q, want /admin/config", loc)
	}
	if len(*fx.published) != 1 {
		t.Fatalf("published %d events, want 1", len(*fx.published))
	}

	// Persisted UserConfig on disk reflects the new values (modulo
	// UpdatedAt, which PublishConfigDM assigns).
	stored, err := fx.store.LoadConfig(fx.subjectNpub)
	if err != nil {
		t.Fatal(err)
	}
	if stored.WarningCount != 3 {
		t.Fatalf("stored warning_count = %d, want 3", stored.WarningCount)
	}
	if stored.SilenceThreshold.Duration != 48*time.Hour {
		t.Fatalf("stored silence_threshold = %s, want 48h", stored.SilenceThreshold.Duration)
	}
}

func TestAdminConfigAcceptsPickerDuration(t *testing.T) {
	fx := newAdminConfigFixture(t)

	newCfg := map[string]any{
		"subject_npub":      fx.subjectNpub,
		"silence_threshold": "30d",
		"warning_interval":  "2d",
		"warning_count":     2,
		"check_interval":    "1h",
		"relays":            []string{"wss://relay.example.invalid"},
	}
	payload, _ := json.Marshal(newCfg)

	req, _ := http.NewRequest("POST", fx.srv.URL+"/admin/config", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", fx.csrfToken())
	req.AddCookie(fx.sessionCookie())

	client := noRedirectClient(t, fx.srv.Client())
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d body=%s, want 303", resp.StatusCode, string(body))
	}

	stored, err := fx.store.LoadConfig(fx.subjectNpub)
	if err != nil {
		t.Fatal(err)
	}
	if stored.SilenceThreshold.Duration != 30*24*time.Hour {
		t.Fatalf("stored silence_threshold = %s, want 720h", stored.SilenceThreshold.Duration)
	}
	if stored.WarningInterval.Duration != 2*24*time.Hour {
		t.Fatalf("stored warning_interval = %s, want 48h", stored.WarningInterval.Duration)
	}
	if stored.CheckInterval.Duration != time.Hour {
		t.Fatalf("stored check_interval = %s, want 1h", stored.CheckInterval.Duration)
	}
}

func TestAdminConfigRejectsInvalidCSRF(t *testing.T) {
	fx := newAdminConfigFixture(t)

	payload := []byte(`{"subject_npub":"` + fx.subjectNpub + `"}`)
	req, _ := http.NewRequest("POST", fx.srv.URL+"/admin/config", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", "not-a-real-token")
	req.AddCookie(fx.sessionCookie())

	resp, err := fx.srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
	if len(*fx.published) != 0 {
		t.Fatalf("should not have published on CSRF failure")
	}
}

func TestAdminConfigRejectsNotRunning(t *testing.T) {
	fx := newAdminConfigFixture(t)

	otherSk := nostr.GeneratePrivateKey()
	otherPk, _ := nostr.GetPublicKey(otherSk)
	cookie := &http.Cookie{Name: sessionCookieName, Value: fx.d.sessions.issue(otherPk)}
	csrf := fx.d.sessions.issueCSRFToken(otherPk)

	payload := []byte(`{}`)
	req, _ := http.NewRequest("POST", fx.srv.URL+"/admin/config", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", csrf)
	req.AddCookie(cookie)

	resp, err := fx.srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
}

func TestAdminConfigRejectsBadJSON(t *testing.T) {
	fx := newAdminConfigFixture(t)

	req, _ := http.NewRequest("POST", fx.srv.URL+"/admin/config",
		bytes.NewReader([]byte(`{"this is not json`)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", fx.csrfToken())
	req.AddCookie(fx.sessionCookie())

	resp, err := fx.srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestAdminConfigLegacyIs503(t *testing.T) {
	// Build a DeadManSwitch with legacy Config (FederationV1=false) and
	// confirm POST /admin/config returns 503.
	sk := nostr.GeneratePrivateKey()
	pk, _ := nostr.GetPublicKey(sk)

	srv, d := testServer(t, pk)
	defer srv.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/login/challenge", d.handleLoginChallenge)
	mux.HandleFunc("/login/verify", d.handleLoginVerify)
	mux.HandleFunc("/admin/config", d.requireAuth(d.handleAdminConfig))
	legacySrv := httptest.NewServer(mux)
	defer legacySrv.Close()

	cookie := &http.Cookie{Name: sessionCookieName, Value: d.sessions.issue(pk)}
	req, _ := http.NewRequest("POST", legacySrv.URL+"/admin/config",
		bytes.NewReader([]byte(`{}`)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", d.sessions.issueCSRFToken(pk))
	req.AddCookie(cookie)
	resp, err := legacySrv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", resp.StatusCode)
	}
}

func TestAdminConfigGetRendersForm(t *testing.T) {
	fx := newAdminConfigFixture(t)

	req, _ := http.NewRequest("GET", fx.srv.URL+"/admin/config", nil)
	req.AddCookie(fx.sessionCookie())
	resp, err := fx.srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	s := string(body)
	for _, needle := range []string{
		`data-k="silence_threshold"`,
		`data-k="warning_interval"`,
		`id="warning_count"`,
		`data-k="check_interval"`,
		`id="relays"`,
		`id="add-action"`,
		`id="action-template"`,
		`id="save"`,
	} {
		if !strings.Contains(s, needle) {
			t.Fatalf("form missing %s", needle)
		}
	}
	// Initial UserConfig payload should be inlined verbatim as a JS literal.
	if !strings.Contains(s, `"subject_npub":"`+fx.subjectNpub+`"`) {
		t.Fatalf("initial JSON did not embed subject_npub; body=%s", s)
	}
}

func TestAdminConfigGetRedirectsWhenNoWatcher(t *testing.T) {
	fx := newAdminConfigFixture(t)

	otherSk := nostr.GeneratePrivateKey()
	otherPk, _ := nostr.GetPublicKey(otherSk)
	cookie := &http.Cookie{Name: sessionCookieName, Value: fx.d.sessions.issue(otherPk)}

	client := noRedirectClient(t, fx.srv.Client())
	req, _ := http.NewRequest("GET", fx.srv.URL+"/admin/config", nil)
	req.AddCookie(cookie)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "/admin/watcher" {
		t.Fatalf("Location = %q, want /admin/watcher", loc)
	}
}

func TestAdminConfigSecretMaskPreserved(t *testing.T) {
	fx := newAdminConfigFixture(t)

	// Seed the watcher with a secret so the mask merge has something to
	// preserve. Update the in-memory *UserWatcher + on-disk UserConfig.
	uc := fx.watcher.Config()
	uc.Actions = []Action{
		{Type: "email", Config: map[string]any{
			"smtp_host": "smtp.example.com",
			"smtp_user": "bot@example.com",
			"smtp_pass": "super-secret-old",
			"to":        "you@example.com",
			"subject":   "hi",
			"body":      "body",
		}},
	}
	uc.UpdatedAt = time.Now()
	fx.watcher.ReloadConfig(uc)
	if err := fx.store.SaveConfig(fx.subjectNpub, uc); err != nil {
		t.Fatal(err)
	}

	// Client POSTs back the config with smtp_pass = maskedDisplay, meaning
	// "I didn't touch it; keep what's there".
	payload := map[string]any{
		"subject_npub":      fx.subjectNpub,
		"silence_threshold": "48h0m0s",
		"warning_interval":  "3h0m0s",
		"warning_count":     2,
		"check_interval":    "1m0s",
		"relays":            []string{"wss://relay.example.invalid"},
		"actions": []map[string]any{{
			"type": "email",
			"config": map[string]any{
				"smtp_host": "smtp.example.com",
				"smtp_user": "bot@example.com",
				"smtp_pass": maskedDisplay,
				"to":        "you@example.com",
				"subject":   "hi",
				"body":      "body",
			},
		}},
	}
	raw, _ := json.Marshal(payload)

	req, _ := http.NewRequest("POST", fx.srv.URL+"/admin/config", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", fx.csrfToken())
	req.AddCookie(fx.sessionCookie())

	resp, err := noRedirectClient(t, fx.srv.Client()).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", resp.StatusCode)
	}
	stored, err := fx.store.LoadConfig(fx.subjectNpub)
	if err != nil {
		t.Fatal(err)
	}
	if len(stored.Actions) != 1 {
		t.Fatalf("expected 1 action, got %d", len(stored.Actions))
	}
	pass := getString(stored.Actions[0].Config, "smtp_pass")
	if pass != "super-secret-old" {
		t.Fatalf("smtp_pass = %q, want old value preserved", pass)
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
