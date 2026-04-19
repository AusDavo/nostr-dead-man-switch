package main

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nbd-wtf/go-nostr"
)

// configTestServer writes yamlBody to a temp config.yaml, calls LoadConfig,
// and wires just /login + /config on a minimal DeadManSwitch — the same
// pattern as testServer in login_flow_test.go.
func configTestServer(t *testing.T, yamlBody string) (*httptest.Server, *DeadManSwitch) {
	t.Helper()
	tmp := t.TempDir()
	cfgPath := filepath.Join(tmp, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte(yamlBody), 0600); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadConfig(cfgPath)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	sm, err := newSessionManager(filepath.Join(tmp, "session_secret"))
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
	mux.HandleFunc("/config", d.requireAuth(d.handleConfig))
	return httptest.NewServer(mux), d
}

func authedGet(t *testing.T, srv *httptest.Server, d *DeadManSwitch, path string) (*http.Response, string) {
	t.Helper()
	cookieVal := d.sessions.issue(d.cfg.watchPubkeyHex)
	req, _ := http.NewRequest("GET", srv.URL+path, nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: cookieVal})
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, string(body)
}

// minimalYAML builds a valid config.yaml with a random watch pubkey and bot
// key, plus a state_file under t.TempDir(). extra is appended verbatim.
func minimalYAML(t *testing.T, extra string) (yaml, watchHex, botHex string) {
	t.Helper()
	botSk := nostr.GeneratePrivateKey()
	watchSk := nostr.GeneratePrivateKey()
	watchPk, _ := nostr.GetPublicKey(watchSk)
	statePath := filepath.Join(t.TempDir(), "state.json")
	y := fmt.Sprintf(`watch_pubkey: "%s"
bot_nsec: "%s"
relays:
  - "wss://relay.example"
state_file: "%s"
%s`, watchPk, botSk, statePath, extra)
	return y, watchPk, botSk
}

func TestConfigView_UnauthedRedirectsToLogin(t *testing.T) {
	y, _, _ := minimalYAML(t, "")
	srv, _ := configTestServer(t, y)
	defer srv.Close()

	noFollow := &http.Client{
		Transport: srv.Client().Transport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := noFollow.Get(srv.URL + "/config")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("unauth /config status = %d, want 303", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "/login" {
		t.Fatalf("redirect to %q, want /login", loc)
	}
}

func TestConfigView_MasksEnvRefSecret(t *testing.T) {
	t.Setenv("SMTP_PASS", "hunter2-plaintext")

	y, _, _ := minimalYAML(t, `actions:
  - type: email
    config:
      smtp_host: smtp.example.com
      smtp_port: 587
      smtp_user: "user@example.com"
      smtp_pass: "${SMTP_PASS}"
      to: "recipient@example.com"
      subject: "Test"
      body: "Test body"
`)
	srv, d := configTestServer(t, y)
	defer srv.Close()

	resp, body := authedGet(t, srv, d, "/config")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if strings.Contains(body, "hunter2-plaintext") {
		t.Fatal("rendered page leaked $SMTP_PASS plaintext")
	}
	if !strings.Contains(body, "$SMTP_PASS") {
		t.Fatal("rendered page missing $SMTP_PASS annotation")
	}
}

func TestConfigView_MasksLiteralSecretByName(t *testing.T) {
	y, _, _ := minimalYAML(t, `actions:
  - type: email
    config:
      smtp_host: smtp.example.com
      smtp_port: 587
      smtp_user: "user@example.com"
      smtp_pass: "literalpw"
      to: "recipient@example.com"
      subject: "Test"
      body: "Test body"
`)
	srv, d := configTestServer(t, y)
	defer srv.Close()

	resp, body := authedGet(t, srv, d, "/config")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if strings.Contains(body, "literalpw") {
		t.Fatal("rendered page leaked literal smtp_pass")
	}
}

func TestConfigView_NonSecretURLShownPlaintext(t *testing.T) {
	y, _, _ := minimalYAML(t, `actions:
  - type: webhook
    config:
      url: "https://hooks.example.com/abc"
      method: "POST"
`)
	srv, d := configTestServer(t, y)
	defer srv.Close()

	resp, body := authedGet(t, srv, d, "/config")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if !strings.Contains(body, "https://hooks.example.com/abc") {
		t.Fatal("expected plaintext URL in rendered page")
	}
}

func TestConfigView_BotNsecAlwaysMasked(t *testing.T) {
	y, _, botHex := minimalYAML(t, "")
	srv, d := configTestServer(t, y)
	defer srv.Close()

	resp, body := authedGet(t, srv, d, "/config")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if strings.Contains(body, botHex) {
		t.Fatalf("rendered page leaked bot_nsec hex")
	}
}

func TestConfigView_MultiActionRendering(t *testing.T) {
	y, _, _ := minimalYAML(t, `actions:
  - type: email
    config:
      smtp_host: smtp.example.com
      smtp_port: 587
      smtp_user: "a@example.com"
      smtp_pass: "x"
      to: "alpha@example.com"
      subject: "s1"
      body: "b1"
  - type: email
    config:
      smtp_host: smtp.example.com
      smtp_port: 587
      smtp_user: "a@example.com"
      smtp_pass: "x"
      to: "bravo@example.com"
      subject: "s2"
      body: "b2"
`)
	srv, d := configTestServer(t, y)
	defer srv.Close()

	resp, body := authedGet(t, srv, d, "/config")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if !strings.Contains(body, "Action 1") || !strings.Contains(body, "Action 2") {
		t.Fatal("expected two action cards")
	}
	if !strings.Contains(body, "alpha@example.com") {
		t.Fatal("expected alpha@example.com in first action")
	}
	if !strings.Contains(body, "bravo@example.com") {
		t.Fatal("expected bravo@example.com in second action")
	}
}
