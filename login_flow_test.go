package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nbd-wtf/go-nostr"
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
