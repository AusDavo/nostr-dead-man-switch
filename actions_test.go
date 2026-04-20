package main

import (
	"context"
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
