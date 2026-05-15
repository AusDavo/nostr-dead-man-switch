package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip19"
)

// watcherSetupFixture wires a full federation-mode dashboard using the
// real Registry factory (Sealer + UserStore + Whitelist). Unlike
// newFederationDashboard / adminConfigFixture this is the path actually
// exercised by the bootstrap flow, since handleWatcherGenerate and
// handleWatcherImport need to call registry.Start(npub) successfully.
type watcherSetupFixture struct {
	srv      *httptest.Server
	d        *DeadManSwitch
	store    *UserStore
	sealer   *Sealer
	reg      *Registry
	userPk   string
	userSk   string
	userNpub string
}

func newWatcherSetupFixture(t *testing.T) *watcherSetupFixture {
	t.Helper()
	dir := t.TempDir()

	sealer := testSealer(t)
	store, err := NewUserStore(filepath.Join(dir, "users"))
	if err != nil {
		t.Fatal(err)
	}
	wl, err := LoadWhitelist(filepath.Join(dir, "whitelist.json"))
	if err != nil {
		t.Fatal(err)
	}

	userSk := nostr.GeneratePrivateKey()
	userPk, _ := nostr.GetPublicKey(userSk)
	userNpub, err := nip19.EncodePublicKey(userPk)
	if err != nil {
		t.Fatal(err)
	}
	if err := wl.Add(userNpub, ""); err != nil {
		t.Fatal(err)
	}

	// Non-routable relay so the Monitor spawned by registry.Start
	// doesn't hit the network. Each goroutine will cycle on dial
	// errors; t.Cleanup below stops them.
	host := &HostConfig{
		Relays:   []string{"wss://127.0.0.1:1"},
		StateDir: dir,
	}
	reg := NewRegistry(host, store, wl, sealer, context.Background())
	t.Cleanup(reg.StopAll)

	cfg := &Config{
		FederationV1: true,
		Relays:       host.Relays,
		StateDir:     dir,
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
		registry:   reg,
		startedAt:  time.Now(),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/login", d.handleLogin)
	mux.HandleFunc("/admin/watcher", d.requireAuth(d.handleWatcherSetup))
	mux.HandleFunc("/admin/watcher/generate", d.requireAuth(d.handleWatcherGenerate))
	mux.HandleFunc("/admin/watcher/import", d.requireAuth(d.handleWatcherImport))
	mux.HandleFunc("/admin/watcher/retry-start", d.requireAuth(d.handleWatcherRetryStart))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	return &watcherSetupFixture{
		srv:      srv,
		d:        d,
		store:    store,
		sealer:   sealer,
		reg:      reg,
		userPk:   userPk,
		userSk:   userSk,
		userNpub: userNpub,
	}
}

func (fx *watcherSetupFixture) sessionCookie() *http.Cookie {
	return &http.Cookie{Name: sessionCookieName, Value: fx.d.sessions.issue(fx.userPk)}
}

func (fx *watcherSetupFixture) csrf() string {
	return fx.d.sessions.issueCSRFToken(fx.userPk)
}

func TestWatcherSetupUnauthedRedirects(t *testing.T) {
	fx := newWatcherSetupFixture(t)

	client := noRedirectClient(t, fx.srv.Client())
	resp, err := client.Get(fx.srv.URL + "/admin/watcher")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "/login" {
		t.Fatalf("Location = %q, want /login", loc)
	}
}

func TestWatcherSetupAuthedShowsForms(t *testing.T) {
	fx := newWatcherSetupFixture(t)

	req, _ := http.NewRequest("GET", fx.srv.URL+"/admin/watcher", nil)
	req.AddCookie(fx.sessionCookie())
	resp, err := fx.srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d body=%s, want 200", resp.StatusCode, string(body))
	}
	s := string(body)
	if !strings.Contains(s, `action="/admin/watcher/generate"`) {
		t.Fatalf("missing generate form; body=%s", s)
	}
	if !strings.Contains(s, `action="/admin/watcher/import"`) {
		t.Fatalf("missing import form")
	}
	if !strings.Contains(s, truncateMiddle(fx.userNpub, 24)) {
		t.Fatalf("page missing (truncated) user npub")
	}
}

func TestWatcherSetupAlreadyConfigured(t *testing.T) {
	fx := newWatcherSetupFixture(t)
	if err := fx.store.CreateUser(fx.userNpub); err != nil {
		t.Fatal(err)
	}
	if err := fx.store.SaveSealedNsec(fx.userNpub, "sentinel"); err != nil {
		t.Fatal(err)
	}

	req, _ := http.NewRequest("GET", fx.srv.URL+"/admin/watcher", nil)
	req.AddCookie(fx.sessionCookie())
	resp, err := fx.srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), "Reveal nsec") {
		t.Fatalf("expected reveal-nsec affordance on already-set-up page; body=%s", string(body))
	}
	if strings.Contains(string(body), `action="/admin/watcher/generate"`) {
		t.Fatalf("should not offer generate form when already set up")
	}
}

// Enrolled-but-not-running: the bootstrap page must surface the
// stashed Start error and a Retry button, while still offering the
// existing reveal-nsec affordance so the user can back up their key
// before doing anything drastic.
func TestWatcherSetupRendersStartErrorState(t *testing.T) {
	fx := newWatcherSetupFixture(t)
	if err := fx.store.CreateUser(fx.userNpub); err != nil {
		t.Fatal(err)
	}
	if err := fx.store.SaveSealedNsec(fx.userNpub, "sentinel"); err != nil {
		t.Fatal(err)
	}
	fx.reg.mu.Lock()
	fx.reg.lastStartErr[fx.userNpub] = "simulated boot-time start failure"
	fx.reg.mu.Unlock()

	req, _ := http.NewRequest("GET", fx.srv.URL+"/admin/watcher", nil)
	req.AddCookie(fx.sessionCookie())
	resp, err := fx.srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	s := string(body)

	if !strings.Contains(s, "Watcher is not running") {
		t.Fatalf("missing recovery banner; body=%s", s)
	}
	if !strings.Contains(s, "simulated boot-time start failure") {
		t.Fatal("error string not rendered")
	}
	if !strings.Contains(s, `action="/admin/watcher/retry-start"`) {
		t.Fatal("missing retry-start form")
	}
	if !strings.Contains(s, "Reveal nsec") {
		t.Fatal("reveal-nsec affordance must remain available in the recovery state")
	}
}

func TestWatcherRetryStartNoSealedNsecRedirectsToWatcher(t *testing.T) {
	fx := newWatcherSetupFixture(t)

	form := url.Values{"csrf_token": {fx.csrf()}}
	req, _ := http.NewRequest("POST", fx.srv.URL+"/admin/watcher/retry-start",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(fx.sessionCookie())

	client := noRedirectClient(t, fx.srv.Client())
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

func TestWatcherRetryStartRecoversOnSuccess(t *testing.T) {
	fx := newWatcherSetupFixture(t)

	// First enroll the user end-to-end via the existing generate flow so
	// the sealed nsec and config.json are real and decryptable.
	genForm := url.Values{"csrf_token": {fx.csrf()}}
	genReq, _ := http.NewRequest("POST", fx.srv.URL+"/admin/watcher/generate",
		strings.NewReader(genForm.Encode()))
	genReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	genReq.AddCookie(fx.sessionCookie())
	genResp, err := fx.srv.Client().Do(genReq)
	if err != nil {
		t.Fatal(err)
	}
	genResp.Body.Close()
	if !fx.reg.IsRunning(fx.userNpub) {
		t.Fatal("precondition: watcher should be running after generate")
	}

	// Now simulate a boot-time failure: stop the watcher and stash an
	// error as if ReloadWhitelist had tried and failed.
	if err := fx.reg.Stop(fx.userNpub); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	fx.reg.mu.Lock()
	fx.reg.lastStartErr[fx.userNpub] = "simulated boot failure"
	fx.reg.mu.Unlock()

	form := url.Values{"csrf_token": {fx.csrf()}}
	req, _ := http.NewRequest("POST", fx.srv.URL+"/admin/watcher/retry-start",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(fx.sessionCookie())

	client := noRedirectClient(t, fx.srv.Client())
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "/admin" {
		t.Fatalf("Location = %q, want /admin", loc)
	}
	if !fx.reg.IsRunning(fx.userNpub) {
		t.Fatal("watcher should be running after successful retry")
	}
	if got := fx.reg.LastStartError(fx.userNpub); got != "" {
		t.Fatalf("LastStartError = %q, want empty after recovery", got)
	}
}

func TestWatcherRetryStartCSRFRequired(t *testing.T) {
	fx := newWatcherSetupFixture(t)

	req, _ := http.NewRequest("POST", fx.srv.URL+"/admin/watcher/retry-start",
		strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(fx.sessionCookie())

	resp, err := fx.srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
}

func TestWatcherGeneratePersistsAndStarts(t *testing.T) {
	fx := newWatcherSetupFixture(t)

	form := url.Values{"csrf_token": {fx.csrf()}}
	req, _ := http.NewRequest("POST", fx.srv.URL+"/admin/watcher/generate",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(fx.sessionCookie())

	resp, err := fx.srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d body=%s, want 200", resp.StatusCode, string(body))
	}
	if !strings.Contains(string(body), "nsec1") {
		t.Fatalf("response missing nsec1 string")
	}
	if !fx.store.HasSealedNsec(fx.userNpub) {
		t.Fatal("sealed nsec was not persisted")
	}
	uc, err := fx.store.LoadConfig(fx.userNpub)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if uc.WatcherPubkeyHex == "" {
		t.Fatal("UserConfig missing WatcherPubkeyHex after generate")
	}
	// registry.Start() should have been called.
	if !fx.reg.IsRunning(fx.userNpub) {
		t.Fatal("registry.IsRunning should be true after generate")
	}
}

func TestWatcherGenerateSecondCallConflicts(t *testing.T) {
	fx := newWatcherSetupFixture(t)

	post := func() *http.Response {
		form := url.Values{"csrf_token": {fx.csrf()}}
		req, _ := http.NewRequest("POST", fx.srv.URL+"/admin/watcher/generate",
			strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(fx.sessionCookie())
		resp, err := fx.srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}

	resp := post()
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("first generate status = %d", resp.StatusCode)
	}

	resp = post()
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("second generate status = %d, want 409", resp.StatusCode)
	}
}

func TestWatcherGenerateRejectsBadCSRF(t *testing.T) {
	fx := newWatcherSetupFixture(t)

	form := url.Values{"csrf_token": {"not-a-real-token"}}
	req, _ := http.NewRequest("POST", fx.srv.URL+"/admin/watcher/generate",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(fx.sessionCookie())
	resp, err := fx.srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
	if fx.store.HasSealedNsec(fx.userNpub) {
		t.Fatal("CSRF failure must not persist any state")
	}
}

func TestWatcherImportBadNsec(t *testing.T) {
	fx := newWatcherSetupFixture(t)

	form := url.Values{"csrf_token": {fx.csrf()}, "nsec": {"not a real nsec"}}
	req, _ := http.NewRequest("POST", fx.srv.URL+"/admin/watcher/import",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(fx.sessionCookie())
	resp, err := fx.srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
	if fx.store.HasSealedNsec(fx.userNpub) {
		t.Fatal("failed import must not persist state")
	}
}

func TestWatcherImportGoodNsec(t *testing.T) {
	fx := newWatcherSetupFixture(t)

	botSk := nostr.GeneratePrivateKey()
	botPk, _ := nostr.GetPublicKey(botSk)
	nsec, _ := nip19.EncodePrivateKey(botSk)

	form := url.Values{"csrf_token": {fx.csrf()}, "nsec": {nsec}}
	req, _ := http.NewRequest("POST", fx.srv.URL+"/admin/watcher/import",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(fx.sessionCookie())

	client := noRedirectClient(t, fx.srv.Client())
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "/admin" {
		t.Fatalf("Location = %q, want /admin", loc)
	}
	uc, err := fx.store.LoadConfig(fx.userNpub)
	if err != nil {
		t.Fatal(err)
	}
	if uc.WatcherPubkeyHex != botPk {
		t.Fatalf("UserConfig pubkey = %q, want %q", uc.WatcherPubkeyHex, botPk)
	}
	if !fx.reg.IsRunning(fx.userNpub) {
		t.Fatal("registry should have started watcher after import")
	}
}

func TestAdminFederationRedirectsWhenNoWatcher(t *testing.T) {
	fx := newWatcherSetupFixture(t)
	mux := http.NewServeMux()
	mux.HandleFunc("/admin", fx.d.requireAuth(fx.d.handleAdmin))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := noRedirectClient(t, srv.Client())
	req, _ := http.NewRequest("GET", srv.URL+"/admin", nil)
	req.AddCookie(fx.sessionCookie())
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

func TestAdminFederationRendersHubAfterEnroll(t *testing.T) {
	fx := newWatcherSetupFixture(t)

	// Enroll via the import flow so the fixture's Registry truly has a
	// running watcher for this subject.
	botSk := nostr.GeneratePrivateKey()
	nsec, _ := nip19.EncodePrivateKey(botSk)
	form := url.Values{"csrf_token": {fx.csrf()}, "nsec": {nsec}}
	req, _ := http.NewRequest("POST", fx.srv.URL+"/admin/watcher/import",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(fx.sessionCookie())
	resp, err := noRedirectClient(t, fx.srv.Client()).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("import status = %d", resp.StatusCode)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/admin", fx.d.requireAuth(fx.d.handleAdmin))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	req, _ = http.NewRequest("GET", srv.URL+"/admin", nil)
	req.AddCookie(fx.sessionCookie())
	resp, err = srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d body=%s, want 200", resp.StatusCode, string(body))
	}
	s := string(body)
	if !strings.Contains(s, `href="/admin/config"`) {
		t.Fatalf("hub missing /admin/config link; body=%s", s)
	}
	if !strings.Contains(s, "Timer") || !strings.Contains(s, "Activity") {
		t.Fatalf("hub missing core cards; body=%s", s)
	}
	// Host-relay should appear in the relay card.
	if !strings.Contains(s, "wss://127.0.0.1:1") {
		t.Fatalf("hub missing host relay row")
	}
}

// enrollForCheckIn imports a bot nsec so fx.reg has a running watcher
// for fx.userNpub, then returns a test server wired with /admin and
// /admin/check-in against the same DeadManSwitch.
func enrollForCheckIn(t *testing.T, fx *watcherSetupFixture) *httptest.Server {
	t.Helper()
	botSk := nostr.GeneratePrivateKey()
	nsec, _ := nip19.EncodePrivateKey(botSk)
	form := url.Values{"csrf_token": {fx.csrf()}, "nsec": {nsec}}
	req, _ := http.NewRequest("POST", fx.srv.URL+"/admin/watcher/import",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(fx.sessionCookie())
	resp, err := noRedirectClient(t, fx.srv.Client()).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("import status = %d", resp.StatusCode)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/admin", fx.d.requireAuth(fx.d.handleAdmin))
	mux.HandleFunc("/admin/check-in", fx.d.requireAuth(fx.d.handleAdminCheckIn))
	mux.HandleFunc("/admin/rearm", fx.d.requireAuth(fx.d.handleAdminRearm))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestAdminCheckInButtonRendersInHub(t *testing.T) {
	fx := newWatcherSetupFixture(t)
	srv := enrollForCheckIn(t, fx)

	req, _ := http.NewRequest("GET", srv.URL+"/admin", nil)
	req.AddCookie(fx.sessionCookie())
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	s := string(body)
	if !strings.Contains(s, `action="/admin/check-in"`) {
		t.Fatalf("hub missing check-in form; body=%s", s)
	}
	if !strings.Contains(s, "Check in now") {
		t.Fatalf("hub missing check-in label")
	}
}

func TestAdminCheckInAdvancesLastSeen(t *testing.T) {
	fx := newWatcherSetupFixture(t)
	srv := enrollForCheckIn(t, fx)

	// Age the state so the check-in has something observable to move.
	w := fx.reg.Get(fx.userNpub)
	if w == nil {
		t.Fatal("registry.Get returned nil after enroll")
	}
	w.state.mu.Lock()
	w.state.LastSeen = time.Now().Add(-48 * time.Hour)
	w.state.WarningSent = 1
	w.state.mu.Unlock()

	form := url.Values{"csrf_token": {fx.csrf()}}
	req, _ := http.NewRequest("POST", srv.URL+"/admin/check-in",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(fx.sessionCookie())

	resp, err := noRedirectClient(t, srv.Client()).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "/admin" {
		t.Fatalf("Location = %q, want /admin", loc)
	}

	w.state.mu.Lock()
	defer w.state.mu.Unlock()
	if time.Since(w.state.LastSeen) > time.Minute {
		t.Fatalf("LastSeen not advanced: %v", w.state.LastSeen)
	}
	if w.state.WarningSent != 0 {
		t.Fatalf("WarningSent = %d, want 0", w.state.WarningSent)
	}
}

func TestAdminCheckInRejectsBadCSRF(t *testing.T) {
	fx := newWatcherSetupFixture(t)
	srv := enrollForCheckIn(t, fx)

	form := url.Values{"csrf_token": {"not-a-real-token"}}
	req, _ := http.NewRequest("POST", srv.URL+"/admin/check-in",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(fx.sessionCookie())
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
}

func TestAdminCheckInRefusedWhenTriggered(t *testing.T) {
	fx := newWatcherSetupFixture(t)
	srv := enrollForCheckIn(t, fx)

	w := fx.reg.Get(fx.userNpub)
	if w == nil {
		t.Fatal("registry.Get returned nil after enroll")
	}
	triggeredAt := time.Now().Add(-1 * time.Hour)
	w.state.mu.Lock()
	w.state.Triggered = true
	w.state.TriggeredAt = &triggeredAt
	w.state.mu.Unlock()

	// Button should be suppressed from the hub template.
	getReq, _ := http.NewRequest("GET", srv.URL+"/admin", nil)
	getReq.AddCookie(fx.sessionCookie())
	getResp, err := srv.Client().Do(getReq)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(getResp.Body)
	getResp.Body.Close()
	if strings.Contains(string(body), `action="/admin/check-in"`) {
		t.Fatalf("triggered hub still renders check-in form; body=%s", string(body))
	}

	// And the endpoint itself must refuse even if someone POSTs directly.
	form := url.Values{"csrf_token": {fx.csrf()}}
	req, _ := http.NewRequest("POST", srv.URL+"/admin/check-in",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(fx.sessionCookie())
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("status = %d, want 409", resp.StatusCode)
	}
}

func TestAdminRearmButtonOnlyWhenTriggered(t *testing.T) {
	fx := newWatcherSetupFixture(t)
	srv := enrollForCheckIn(t, fx)

	// Untriggered: button absent.
	req, _ := http.NewRequest("GET", srv.URL+"/admin", nil)
	req.AddCookie(fx.sessionCookie())
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if strings.Contains(string(body), `action="/admin/rearm"`) {
		t.Fatalf("untriggered hub rendered rearm form; body=%s", string(body))
	}

	// Flip the watcher into triggered state, re-render, expect the button.
	w := fx.reg.Get(fx.userNpub)
	if w == nil {
		t.Fatal("registry.Get returned nil after enroll")
	}
	triggeredAt := time.Now().Add(-time.Hour)
	w.state.mu.Lock()
	w.state.Triggered = true
	w.state.TriggeredAt = &triggeredAt
	w.state.mu.Unlock()

	req2, _ := http.NewRequest("GET", srv.URL+"/admin", nil)
	req2.AddCookie(fx.sessionCookie())
	resp2, err := srv.Client().Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	body2, _ := io.ReadAll(resp2.Body)
	resp2.Body.Close()
	if !strings.Contains(string(body2), `action="/admin/rearm"`) {
		t.Fatalf("triggered hub missing rearm form; body=%s", string(body2))
	}
	if !strings.Contains(string(body2), "Re-arm switch") {
		t.Fatalf("triggered hub missing Re-arm label")
	}
}

func TestAdminRearmClearsTriggeredState(t *testing.T) {
	fx := newWatcherSetupFixture(t)
	srv := enrollForCheckIn(t, fx)

	w := fx.reg.Get(fx.userNpub)
	if w == nil {
		t.Fatal("registry.Get returned nil after enroll")
	}
	triggeredAt := time.Now().Add(-time.Hour)
	w.state.mu.Lock()
	w.state.Triggered = true
	w.state.TriggeredAt = &triggeredAt
	w.state.WarningSent = 2
	w.state.LastSeen = time.Now().Add(-48 * time.Hour)
	w.state.mu.Unlock()

	form := url.Values{"csrf_token": {fx.csrf()}}
	req, _ := http.NewRequest("POST", srv.URL+"/admin/rearm",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(fx.sessionCookie())

	resp, err := noRedirectClient(t, srv.Client()).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "/admin" {
		t.Fatalf("Location = %q, want /admin", loc)
	}

	// Rearm restarts the watcher — re-fetch the (new) one and verify
	// state on it. The new UserWatcher loaded the cleared state from
	// disk in its constructor.
	w2 := fx.reg.Get(fx.userNpub)
	if w2 == nil {
		t.Fatal("registry.Get returned nil after Rearm")
	}
	w2.state.mu.Lock()
	defer w2.state.mu.Unlock()
	if w2.state.Triggered {
		t.Error("state.Triggered = true after rearm, want false")
	}
	if w2.state.TriggeredAt != nil {
		t.Errorf("state.TriggeredAt = %v after rearm, want nil", w2.state.TriggeredAt)
	}
	if w2.state.WarningSent != 0 {
		t.Errorf("state.WarningSent = %d after rearm, want 0", w2.state.WarningSent)
	}
	if time.Since(w2.state.LastSeen) > time.Minute {
		t.Errorf("state.LastSeen = %v, not advanced to ~now", w2.state.LastSeen)
	}
}

func TestAdminRearmRejectsUntriggered(t *testing.T) {
	fx := newWatcherSetupFixture(t)
	srv := enrollForCheckIn(t, fx)

	form := url.Values{"csrf_token": {fx.csrf()}}
	req, _ := http.NewRequest("POST", srv.URL+"/admin/rearm",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(fx.sessionCookie())
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("status = %d, want 409", resp.StatusCode)
	}
}

func TestAdminRearmRejectsBadCSRF(t *testing.T) {
	fx := newWatcherSetupFixture(t)
	srv := enrollForCheckIn(t, fx)

	form := url.Values{"csrf_token": {"not-a-real-token"}}
	req, _ := http.NewRequest("POST", srv.URL+"/admin/rearm",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(fx.sessionCookie())
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
}

func TestWatcherSetupLegacyMode(t *testing.T) {
	// Construct a legacy-mode DeadManSwitch and assert /admin/watcher 503s.
	sk := nostr.GeneratePrivateKey()
	pk, _ := nostr.GetPublicKey(sk)

	srv, d := testServer(t, pk)
	defer srv.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/admin/watcher", d.requireAuth(d.handleWatcherSetup))
	legacySrv := httptest.NewServer(mux)
	defer legacySrv.Close()

	cookie := &http.Cookie{Name: sessionCookieName, Value: d.sessions.issue(pk)}
	req, _ := http.NewRequest("GET", legacySrv.URL+"/admin/watcher", nil)
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
