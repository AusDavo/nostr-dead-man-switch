package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip19"
)

// rosterFixture wires a federation dashboard with a configured admin
// identity, the real Registry factory (so enrolled users get real
// UserWatchers), and the roster + signup routes mounted. The factory is
// wrapped to swap each watcher's execActions for a recorder so the revoke
// invariant test can assert zero action dispatches.
type rosterFixture struct {
	srv       *httptest.Server
	d         *DeadManSwitch
	store     *UserStore
	wl        *Whitelist
	reg       *Registry
	execCalls *atomic.Int32

	adminPk, adminNpub string
	userPk, userNpub   string
}

func newRosterFixture(t *testing.T) *rosterFixture {
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

	adminSk := nostr.GeneratePrivateKey()
	adminPk, _ := nostr.GetPublicKey(adminSk)
	adminNpub, _ := nip19.EncodePublicKey(adminPk)
	if err := wl.Add(adminNpub, "admin (auto)"); err != nil {
		t.Fatal(err)
	}
	if err := wl.SetPlanKind(adminNpub, "admin"); err != nil {
		t.Fatal(err)
	}

	host := &HostConfig{
		Relays:   []string{"wss://127.0.0.1:1"}, // non-routable; Monitor never connects
		StateDir: dir,
	}
	reg := NewRegistry(host, store, wl, sealer, context.Background())
	t.Cleanup(reg.StopAll)

	// Wrap the factory to record any action dispatch.
	var execCalls atomic.Int32
	orig := reg.newWatcher
	reg.newWatcher = func(npub string) (supervisedWatcher, *UserWatcher, *UserConfig, error) {
		w, concrete, uc, err := orig(npub)
		if concrete != nil {
			concrete.execActions = func(_ context.Context, _ *HostConfig, _ *UserConfig,
				_, _, _ string, _ []Action) {
				execCalls.Add(1)
			}
		}
		return w, concrete, uc, err
	}

	// Enroll a regular (non-admin) user with a running watcher.
	userSk := nostr.GeneratePrivateKey()
	userPk, _ := nostr.GetPublicKey(userSk)
	userNpub, _ := nip19.EncodePublicKey(userPk)
	if err := wl.Add(userNpub, ""); err != nil {
		t.Fatal(err)
	}
	if err := wl.SetPlanKind(userNpub, "invite"); err != nil {
		t.Fatal(err)
	}
	watcherSk := nostr.GeneratePrivateKey()
	watcherPk, _ := nostr.GetPublicKey(watcherSk)
	sealed, err := sealer.Seal(userNpub, []byte(watcherSk))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CreateUser(userNpub); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveSealedNsec(userNpub, sealed); err != nil {
		t.Fatal(err)
	}
	uc := &UserConfig{
		SubjectNpub:      userNpub,
		WatcherPubkeyHex: watcherPk,
		SilenceThreshold: Duration{time.Hour},
		WarningInterval:  Duration{time.Hour},
		WarningCount:     1,
		CheckInterval:    Duration{time.Hour},
		UpdatedAt:        time.Now(),
	}
	if err := store.SaveConfig(userNpub, uc); err != nil {
		t.Fatal(err)
	}
	if err := reg.Start(userNpub); err != nil {
		t.Fatalf("Start user: %v", err)
	}

	invites, err := LoadInviteCodes(dir, nil)
	if err != nil {
		t.Fatal(err)
	}

	cfg := &Config{
		FederationV1:   true,
		Relays:         host.Relays,
		StateDir:       dir,
		StateFile:      filepath.Join(dir, "state.json"),
		adminPubkeyHex: adminPk,
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
		invites:    invites,
		startedAt:  time.Now(),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/login", d.handleLogin)
	mux.HandleFunc("/admin/roster", d.requireAuth(d.handleRoster))
	mux.HandleFunc("/admin/roster/grant", d.requireAuth(d.handleRosterGrant))
	mux.HandleFunc("/admin/roster/revoke", d.requireAuth(d.handleRosterRevoke))
	mux.HandleFunc("/admin/roster/invite/new", d.requireAuth(d.handleRosterInviteNew))
	mux.HandleFunc("/admin/roster/invite/revoke", d.requireAuth(d.handleRosterInviteRevoke))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	return &rosterFixture{
		srv:       srv,
		d:         d,
		store:     store,
		wl:        wl,
		reg:       reg,
		execCalls: &execCalls,
		adminPk:   adminPk,
		adminNpub: adminNpub,
		userPk:    userPk,
		userNpub:  userNpub,
	}
}

func (fx *rosterFixture) cookie(pk string) *http.Cookie {
	return &http.Cookie{Name: sessionCookieName, Value: fx.d.sessions.issue(pk)}
}

func (fx *rosterFixture) postForm(t *testing.T, pk, path string, form url.Values) *http.Response {
	t.Helper()
	form.Set("csrf_token", fx.d.sessions.issueCSRFToken(pk))
	req, _ := http.NewRequest("POST", fx.srv.URL+path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(fx.cookie(pk))
	resp, err := noRedirectClient(t, fx.srv.Client()).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestRevokeNeverTriggersActions(t *testing.T) {
	fx := newRosterFixture(t)

	if !fx.reg.IsRunning(fx.userNpub) {
		t.Fatal("precondition: user watcher should be running")
	}

	form := url.Values{}
	form.Set("npub", fx.userNpub)
	resp := fx.postForm(t, fx.adminPk, "/admin/roster/revoke", form)
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("revoke status = %d, want 303", resp.StatusCode)
	}

	// Zero action dispatches — the safety invariant.
	if n := fx.execCalls.Load(); n != 0 {
		t.Fatalf("revoke fired %d actions, want 0", n)
	}
	// The full teardown ran in order: Stop (not running), DeleteUser
	// (no dir), Remove (not whitelisted).
	if fx.reg.IsRunning(fx.userNpub) {
		t.Error("Stop did not run: watcher still running")
	}
	if fx.store.HasUser(fx.userNpub) {
		t.Error("DeleteUser did not run: user dir still present")
	}
	if fx.wl.Contains(fx.userNpub) {
		t.Error("Remove did not run: still whitelisted")
	}
}

func TestRosterAdminGate(t *testing.T) {
	fx := newRosterFixture(t)
	client := noRedirectClient(t, fx.srv.Client())

	// Non-admin authed session → 403 on GET /admin/roster.
	req, _ := http.NewRequest("GET", fx.srv.URL+"/admin/roster", nil)
	req.AddCookie(fx.cookie(fx.userPk))
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("non-admin GET /admin/roster = %d, want 403", resp.StatusCode)
	}

	// Non-admin authed session (valid CSRF) → 403 on the POSTs.
	for _, path := range []string{
		"/admin/roster/grant",
		"/admin/roster/revoke",
		"/admin/roster/invite/new",
		"/admin/roster/invite/revoke",
	} {
		resp := fx.postForm(t, fx.userPk, path, url.Values{})
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("non-admin POST %s = %d, want 403", path, resp.StatusCode)
		}
	}
}

func TestRosterGrantAndRevoke(t *testing.T) {
	fx := newRosterFixture(t)

	granteeSk := nostr.GeneratePrivateKey()
	granteePk, _ := nostr.GetPublicKey(granteeSk)
	granteeNpub, _ := nip19.EncodePublicKey(granteePk)

	form := url.Values{}
	form.Set("npub", granteeNpub)
	resp := fx.postForm(t, fx.adminPk, "/admin/roster/grant", form)
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("grant status = %d, want 303", resp.StatusCode)
	}
	if !fx.wl.Contains(granteeNpub) {
		t.Fatal("grant did not add npub to whitelist")
	}
	var plan string
	for _, e := range fx.wl.List() {
		if e.Npub == granteeNpub {
			plan = e.PlanKind
		}
	}
	if plan != "free" {
		t.Fatalf("granted plan = %q, want free", plan)
	}

	// Revoke the grantee.
	rform := url.Values{}
	rform.Set("npub", granteeNpub)
	resp = fx.postForm(t, fx.adminPk, "/admin/roster/revoke", rform)
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("revoke status = %d, want 303", resp.StatusCode)
	}
	if fx.wl.Contains(granteeNpub) {
		t.Fatal("revoke did not remove npub from whitelist")
	}
}

func TestRosterAdminCanView(t *testing.T) {
	fx := newRosterFixture(t)
	req, _ := http.NewRequest("GET", fx.srv.URL+"/admin/roster", nil)
	req.AddCookie(fx.cookie(fx.adminPk))
	resp, err := fx.srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("admin GET /admin/roster = %d, want 200", resp.StatusCode)
	}
}
