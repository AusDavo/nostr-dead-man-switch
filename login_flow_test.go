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

// testServer wires up just the auth handlers on a minimal DeadManSwitch,
// avoiding the monitor + state machinery.
func testServer(t *testing.T, watchPubkeyHex string) (*httptest.Server, *DeadManSwitch) {
	t.Helper()

	cfg := &Config{
		StateFile:      filepath.Join(t.TempDir(), "state.json"),
		watchPubkeyHex: watchPubkeyHex,
	}

	sm, err := newSessionManager(filepath.Join(filepath.Dir(cfg.StateFile), "session_secret"))
	if err != nil {
		t.Fatal(err)
	}

	d := &DeadManSwitch{
		cfg:        cfg,
		sessions:   sm,
		challenges: &challengeStore{m: map[string]time.Time{}},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/login", d.handleLogin)
	mux.HandleFunc("/login/challenge", d.handleLoginChallenge)
	mux.HandleFunc("/login/verify", d.handleLoginVerify)
	mux.HandleFunc("/logout", d.handleLogout)
	mux.HandleFunc("/admin", d.requireAuth(d.handleAdmin))

	return httptest.NewServer(mux), d
}

func signChallenge(t *testing.T, sk, challenge string) []byte {
	t.Helper()
	ev := nostr.Event{
		Kind:      authEventKind,
		CreatedAt: nostr.Now(),
		Tags:      nostr.Tags{{"challenge", challenge}},
		Content:   "test",
	}
	if err := ev.Sign(sk); err != nil {
		t.Fatalf("sign: %v", err)
	}
	raw, _ := json.Marshal(ev)
	return raw
}

func TestLoginFlow_HappyPath(t *testing.T) {
	sk := nostr.GeneratePrivateKey()
	pk, _ := nostr.GetPublicKey(sk)

	srv, _ := testServer(t, pk)
	defer srv.Close()

	client := srv.Client()

	// /admin without cookie → redirect to /login.
	noFollow := &http.Client{
		Transport: client.Transport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := noFollow.Get(srv.URL + "/admin")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("unauth /admin status = %d, want 303", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "/login" {
		t.Fatalf("redirect to %q, want /login", loc)
	}

	// Get a challenge.
	resp, err = client.Get(srv.URL + "/login/challenge")
	if err != nil {
		t.Fatal(err)
	}
	var cr struct{ Challenge string }
	if err := json.NewDecoder(resp.Body).Decode(&cr); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if cr.Challenge == "" {
		t.Fatal("empty challenge")
	}

	// Sign and verify.
	signed := signChallenge(t, sk, cr.Challenge)
	body, _ := json.Marshal(map[string]json.RawMessage{"signedEvent": signed})
	resp, err = client.Post(srv.URL+"/login/verify", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(resp.Body)
		t.Fatalf("verify status = %d, body = %s", resp.StatusCode, msg)
	}
	var cookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == sessionCookieName {
			cookie = c
			break
		}
	}
	resp.Body.Close()
	if cookie == nil {
		t.Fatal("no session cookie set on successful verify")
	}

	// /admin with cookie → 200 containing npub.
	req, _ := http.NewRequest("GET", srv.URL+"/admin", nil)
	req.AddCookie(cookie)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	bodyBytes, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("authed /admin status = %d", resp.StatusCode)
	}
	if !strings.Contains(string(bodyBytes), "npub1") {
		t.Fatalf("admin page missing npub (got len=%d)", len(bodyBytes))
	}
}

func TestLoginFlow_WrongPubkey(t *testing.T) {
	expectedSk := nostr.GeneratePrivateKey()
	expectedPk, _ := nostr.GetPublicKey(expectedSk)

	attackerSk := nostr.GeneratePrivateKey()

	srv, _ := testServer(t, expectedPk)
	defer srv.Close()
	client := srv.Client()

	resp, _ := client.Get(srv.URL + "/login/challenge")
	var cr struct{ Challenge string }
	json.NewDecoder(resp.Body).Decode(&cr)
	resp.Body.Close()

	signed := signChallenge(t, attackerSk, cr.Challenge)
	body, _ := json.Marshal(map[string]json.RawMessage{"signedEvent": signed})
	resp, _ = client.Post(srv.URL+"/login/verify", "application/json", bytes.NewReader(body))
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong-pubkey verify status = %d, want 401", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestLoginFlow_ReplayRejected(t *testing.T) {
	sk := nostr.GeneratePrivateKey()
	pk, _ := nostr.GetPublicKey(sk)

	srv, _ := testServer(t, pk)
	defer srv.Close()
	client := srv.Client()

	resp, _ := client.Get(srv.URL + "/login/challenge")
	var cr struct{ Challenge string }
	json.NewDecoder(resp.Body).Decode(&cr)
	resp.Body.Close()

	signed := signChallenge(t, sk, cr.Challenge)
	body, _ := json.Marshal(map[string]json.RawMessage{"signedEvent": signed})

	// First attempt succeeds.
	resp, _ = client.Post(srv.URL+"/login/verify", "application/json", bytes.NewReader(body))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("first verify status = %d, want 200", resp.StatusCode)
	}
	resp.Body.Close()

	// Replay with the same signed event must be rejected (challenge consumed).
	resp, _ = client.Post(srv.URL+"/login/verify", "application/json", bytes.NewReader(body))
	if resp.StatusCode == http.StatusOK {
		t.Fatalf("replay should not succeed")
	}
	resp.Body.Close()
}

// federationTestServer wires a DeadManSwitch with a federation-mode
// Config and a Registry populated by the fakeFactory. enrolled npubs
// come up as running watchers; whitelistedOnly npubs exist in the
// whitelist but have no running watcher.
func federationTestServer(t *testing.T, enrolled, whitelistedOnly []string) (*httptest.Server, *DeadManSwitch) {
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
			t.Fatalf("Start %s: %v", n, err)
		}
	}
	for _, n := range whitelistedOnly {
		if err := wl.Add(n, ""); err != nil {
			t.Fatalf("whitelist.Add: %v", err)
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
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/login", d.handleLogin)
	mux.HandleFunc("/login/challenge", d.handleLoginChallenge)
	mux.HandleFunc("/login/verify", d.handleLoginVerify)
	mux.HandleFunc("/admin", d.requireAuth(d.handleAdmin))
	return httptest.NewServer(mux), d
}

func getChallengeAndVerify(t *testing.T, srv *httptest.Server, sk string) *http.Response {
	t.Helper()
	client := srv.Client()
	resp, err := client.Get(srv.URL + "/login/challenge")
	if err != nil {
		t.Fatal(err)
	}
	var cr struct{ Challenge string }
	if err := json.NewDecoder(resp.Body).Decode(&cr); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	signed := signChallenge(t, sk, cr.Challenge)
	body, _ := json.Marshal(map[string]json.RawMessage{"signedEvent": signed})
	resp, err = client.Post(srv.URL+"/login/verify", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestLoginVerify_FederationWhitelistedNpubSucceeds(t *testing.T) {
	sk := nostr.GeneratePrivateKey()
	pk, _ := nostr.GetPublicKey(sk)
	npub, err := nip19.EncodePublicKey(pk)
	if err != nil {
		t.Fatal(err)
	}

	srv, _ := federationTestServer(t, []string{npub}, nil)
	defer srv.Close()

	resp := getChallengeAndVerify(t, srv, sk)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d body=%s, want 200", resp.StatusCode, b)
	}
}

func TestLoginVerify_FederationNonWhitelistedFails(t *testing.T) {
	sk := nostr.GeneratePrivateKey()

	enrolled := nostr.GeneratePrivateKey()
	enrolledPk, _ := nostr.GetPublicKey(enrolled)
	enrolledNpub, _ := nip19.EncodePublicKey(enrolledPk)

	srv, _ := federationTestServer(t, []string{enrolledNpub}, nil)
	defer srv.Close()

	resp := getChallengeAndVerify(t, srv, sk)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d body=%s, want 401", resp.StatusCode, b)
	}
}

// A whitelisted user who has not yet bootstrapped a watcher must be
// able to sign in — that is the only way they can reach /admin/watcher
// and complete enrollment from the browser. Enrollment state is
// enforced downstream by handleAdminFederation, which redirects
// unenrolled sessions to /admin/watcher.
func TestLoginVerify_FederationWhitelistedUnenrolledSucceeds(t *testing.T) {
	sk := nostr.GeneratePrivateKey()
	pk, _ := nostr.GetPublicKey(sk)
	npub, _ := nip19.EncodePublicKey(pk)

	srv, _ := federationTestServer(t, nil, []string{npub})
	defer srv.Close()

	resp := getChallengeAndVerify(t, srv, sk)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d body=%s, want 200", resp.StatusCode, b)
	}
}

// End-to-end: a whitelisted but unenrolled user must be able to log in
// and then get bounced from /admin to /admin/watcher, where the
// bootstrap forms live. This is the on-ramp for new federation users
// and the only way to recover from a watcher that failed to start at
// boot.
func TestLoginFlow_FederationWhitelistedUnenrolledRedirectsToBootstrap(t *testing.T) {
	sk := nostr.GeneratePrivateKey()
	pk, _ := nostr.GetPublicKey(sk)
	npub, _ := nip19.EncodePublicKey(pk)

	srv, _ := federationTestServer(t, nil, []string{npub})
	defer srv.Close()

	resp := getChallengeAndVerify(t, srv, sk)
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("verify status = %d body=%s, want 200", resp.StatusCode, b)
	}
	var cookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == sessionCookieName {
			cookie = c
			break
		}
	}
	resp.Body.Close()
	if cookie == nil {
		t.Fatal("no session cookie set on successful verify")
	}

	noFollow := &http.Client{
		Transport: srv.Client().Transport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, _ := http.NewRequest("GET", srv.URL+"/admin", nil)
	req.AddCookie(cookie)
	adminResp, err := noFollow.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	adminResp.Body.Close()
	if adminResp.StatusCode != http.StatusSeeOther {
		t.Fatalf("/admin status = %d, want 303", adminResp.StatusCode)
	}
	if loc := adminResp.Header.Get("Location"); loc != "/admin/watcher" {
		t.Fatalf("/admin redirect to %q, want /admin/watcher", loc)
	}
}

func TestLoginVerify_LegacyStillMatchesSinglePubkey(t *testing.T) {
	// Legacy path: only the configured watch_pubkey signer may log in.
	sk := nostr.GeneratePrivateKey()
	pk, _ := nostr.GetPublicKey(sk)

	srv, _ := testServer(t, pk)
	defer srv.Close()

	resp := getChallengeAndVerify(t, srv, sk)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	// Attacker's signature is rejected.
	attacker := nostr.GeneratePrivateKey()
	srv2, _ := testServer(t, pk)
	defer srv2.Close()
	resp2 := getChallengeAndVerify(t, srv2, attacker)
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("attacker status = %d, want 401", resp2.StatusCode)
	}
}

func TestLoginFlow_WatchPubkeyUnset(t *testing.T) {
	sk := nostr.GeneratePrivateKey()

	srv, _ := testServer(t, "")
	defer srv.Close()
	client := srv.Client()

	resp, _ := client.Get(srv.URL + "/login/challenge")
	var cr struct{ Challenge string }
	json.NewDecoder(resp.Body).Decode(&cr)
	resp.Body.Close()

	signed := signChallenge(t, sk, cr.Challenge)
	body, _ := json.Marshal(map[string]json.RawMessage{"signedEvent": signed})
	resp, _ = client.Post(srv.URL+"/login/verify", "application/json", bytes.NewReader(body))
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("unset watch_pubkey verify status = %d, want 503", resp.StatusCode)
	}
	resp.Body.Close()
}
