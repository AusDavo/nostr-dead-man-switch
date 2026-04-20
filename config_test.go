package main

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTempConfig(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return path
}

func TestConfigDefaultsFederationV1WhenNoWatchPubkey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	body := `state_dir: ` + dir + `
whitelist_file: ` + filepath.Join(dir, "whitelist.json") + `
watcher_store_key_env: DEADMAN_WATCHER_KEY
relays:
  - wss://relay.example.invalid
silence_threshold: 7d
warning_interval: 1d
warning_count: 2
check_interval: 1h
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if !cfg.FederationV1 {
		t.Fatalf("FederationV1 = false, want true (watch_pubkey empty and federation_v1 not set)")
	}
}

func TestConfigKeepsLegacyWhenWatchPubkeySet(t *testing.T) {
	// Legacy path: watch_pubkey is set, federation_v1 omitted. Must stay false.
	path := writeTempConfig(t, `watch_pubkey: 3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d
bot_nsec: 0000000000000000000000000000000000000000000000000000000000000001
silence_threshold: 7d
warning_interval: 1d
warning_count: 2
check_interval: 1h
`)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.FederationV1 {
		t.Fatalf("FederationV1 = true, want false (watch_pubkey set, flag unset)")
	}
}

func TestConfigExplicitFederationV1FalseWins(t *testing.T) {
	// Explicit opt-out: watch_pubkey empty, but operator set federation_v1: false.
	path := writeTempConfig(t, `federation_v1: false
silence_threshold: 7d
warning_interval: 1d
warning_count: 2
check_interval: 1h
`)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.FederationV1 {
		t.Fatalf("FederationV1 = true, want false (explicit opt-out)")
	}
}

func TestConfigExplicitFederationV1TrueStaysTrue(t *testing.T) {
	// Belt-and-braces: watch_pubkey set but operator also set federation_v1: true.
	// Explicit wins.
	path := writeTempConfig(t, `watch_pubkey: 3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d
bot_nsec: 0000000000000000000000000000000000000000000000000000000000000001
federation_v1: true
silence_threshold: 7d
warning_interval: 1d
warning_count: 2
check_interval: 1h
`)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if !cfg.FederationV1 {
		t.Fatalf("FederationV1 = false, want true (explicit opt-in)")
	}
}
