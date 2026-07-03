package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestExecuteNostrDM_ValidationErrors(t *testing.T) {
	cases := []struct {
		name    string
		config  map[string]any
		wantSub string
	}{
		{"missing to_npub", map[string]any{"content": "hi"}, "to_npub required"},
		{"blank to_npub", map[string]any{"to_npub": "   ", "content": "hi"}, "to_npub required"},
		{"missing content", map[string]any{"to_npub": "npub1xyz"}, "content required"},
		{"malformed npub", map[string]any{"to_npub": "not-an-npub", "content": "hi"}, "invalid to_npub"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := executeNostrDM(context.Background(), &HostConfig{}, &UserConfig{},
				"00", "00", tc.config)
			if err == nil {
				t.Fatalf("want error containing %q, got nil", tc.wantSub)
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("err = %v, want substring %q", err, tc.wantSub)
			}
		})
	}
}

func TestExecuteWebhook_HMACSigning(t *testing.T) {
	body := `{"event":"triggered"}`
	secret := "hunter2"

	// Reference signature computed independently of signWebhookBody.
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(body))
	wantSig := "sha256=" + hex.EncodeToString(mac.Sum(nil))

	cases := []struct {
		name    string
		config  map[string]any
		wantSig string
	}{
		{
			"secret set signs body",
			map[string]any{"body": body, "secret": secret},
			wantSig,
		},
		{
			"no secret sends no signature",
			map[string]any{"body": body},
			"",
		},
		{
			"empty secret sends no signature",
			map[string]any{"body": body, "secret": ""},
			"",
		},
		{
			"computed signature wins over headers entry",
			map[string]any{
				"body":    body,
				"secret":  secret,
				"headers": map[string]any{"X-Deadman-Signature": "sha256=forged"},
			},
			wantSig,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var gotSig string
			var gotBody []byte
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotSig = r.Header.Get("X-Deadman-Signature")
				gotBody, _ = io.ReadAll(r.Body)
			}))
			defer srv.Close()

			tc.config["url"] = srv.URL
			if err := executeWebhook(context.Background(), tc.config); err != nil {
				t.Fatalf("executeWebhook: %v", err)
			}
			if gotSig != tc.wantSig {
				t.Errorf("X-Deadman-Signature = %q, want %q", gotSig, tc.wantSig)
			}
			if string(gotBody) != body {
				t.Errorf("body = %q, want %q", gotBody, body)
			}
		})
	}
}

func TestSignWebhookBody_EmptyBody(t *testing.T) {
	// A GET-style webhook with no body must still produce a valid,
	// verifiable signature over the empty string.
	mac := hmac.New(sha256.New, []byte("s"))
	want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if got := signWebhookBody("s", ""); got != want {
		t.Errorf("signWebhookBody(s, \"\") = %q, want %q", got, want)
	}
}

func TestExecuteActionDispatch_NostrDMRoutes(t *testing.T) {
	// Dispatching "nostr_dm" must hit executeNostrDM's validation path, not
	// fall through to errUnknownActionType.
	err := executeAction(context.Background(), "nostr_dm", map[string]any{},
		&HostConfig{}, &UserConfig{}, "00", "00")
	if err == errUnknownActionType {
		t.Fatal("dispatcher returned errUnknownActionType; nostr_dm must be registered")
	}
	if err == nil {
		t.Fatal("want validation error from empty config, got nil")
	}
	if !strings.Contains(err.Error(), "to_npub required") {
		t.Fatalf("err = %v, want 'to_npub required'", err)
	}
}
