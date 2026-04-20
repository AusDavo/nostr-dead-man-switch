package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nbd-wtf/go-nostr/nip19"
	"golang.org/x/crypto/chacha20poly1305"
)

func migrateTestSealer(t *testing.T) *Sealer {
	t.Helper()
	key := bytes.Repeat([]byte{0x33}, chacha20poly1305.KeySize)
	s, err := NewSealer(base64.StdEncoding.EncodeToString(key))
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	return s
}

func writeLegacyConfig(t *testing.T, dir string, stateContents []byte) (*Config, string) {
	t.Helper()
	stateFile := filepath.Join(dir, "state.json")
	if stateContents != nil {
		if err := os.WriteFile(stateFile, stateContents, 0o600); err != nil {
			t.Fatalf("writing legacy state: %v", err)
		}
	}
	configPath := filepath.Join(dir, "config.yaml")
	yaml := fmt.Sprintf(`watch_pubkey: 3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d
bot_nsec: 0000000000000000000000000000000000000000000000000000000000000001
silence_threshold: 7d
warning_interval: 1d
warning_count: 2
check_interval: 1h
state_file: %s
actions:
  - type: webhook
    config:
      url: https://example.com/hook
`, stateFile)
	if err := os.WriteFile(configPath, []byte(yaml), 0o600); err != nil {
		t.Fatalf("writing legacy config: %v", err)
	}
	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	return cfg, stateFile
}

func TestMigrateHappyPath(t *testing.T) {
	dir := t.TempDir()
	stateJSON := []byte(`{"last_seen":"2026-01-01T00:00:00Z"}`)
	cfg, stateFile := writeLegacyConfig(t, dir, stateJSON)

	store, err := NewUserStore(filepath.Join(dir, "users"))
	if err != nil {
		t.Fatalf("NewUserStore: %v", err)
	}
	wl, err := LoadWhitelist(filepath.Join(dir, "whitelist.json"))
	if err != nil {
		t.Fatalf("LoadWhitelist: %v", err)
	}
	sealer := migrateTestSealer(t)

	if err := Migrate(cfg, store, wl, sealer); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	expected, err := nip19.EncodePublicKey(cfg.watchPubkeyHex)
	if err != nil {
		t.Fatalf("EncodePublicKey: %v", err)
	}

	if !store.HasUser(expected) {
		t.Fatal("user dir missing after migrate")
	}
	if !store.HasSealedNsec(expected) {
		t.Fatal("sealed nsec missing after migrate")
	}

	uc, err := store.LoadConfig(expected)
	if err != nil {
		t.Fatalf("LoadConfig tenant: %v", err)
	}
	if uc.SubjectNpub != expected {
		t.Fatalf("SubjectNpub = %q", uc.SubjectNpub)
	}
	if uc.WatcherPubkeyHex != cfg.botPubkeyHex {
		t.Fatalf("WatcherPubkeyHex = %q, want %q", uc.WatcherPubkeyHex, cfg.botPubkeyHex)
	}
	if uc.SilenceThreshold.Duration != cfg.SilenceThreshold.Duration {
		t.Fatalf("SilenceThreshold = %v, want %v", uc.SilenceThreshold.Duration, cfg.SilenceThreshold.Duration)
	}
	if uc.WarningCount != cfg.WarningCount {
		t.Fatalf("WarningCount = %d, want %d", uc.WarningCount, cfg.WarningCount)
	}
	if len(uc.Actions) != 1 || uc.Actions[0].Type != "webhook" {
		t.Fatalf("Actions = %+v", uc.Actions)
	}
	if uc.Relays != nil {
		t.Fatalf("Relays should be nil (fall back to host), got %v", uc.Relays)
	}
	if uc.UpdatedAt.IsZero() {
		t.Fatal("UpdatedAt is zero")
	}

	copied, err := os.ReadFile(filepath.Join(store.UserDir(expected), "state.json"))
	if err != nil {
		t.Fatalf("reading tenant state: %v", err)
	}
	if !bytes.Equal(copied, stateJSON) {
		t.Fatalf("tenant state mismatch")
	}

	bak, err := os.ReadFile(stateFile + ".bak")
	if err != nil {
		t.Fatalf("reading .bak: %v", err)
	}
	if !bytes.Equal(bak, stateJSON) {
		t.Fatalf(".bak mismatch")
	}

	orig, err := os.ReadFile(stateFile)
	if err != nil {
		t.Fatalf("reading original: %v", err)
	}
	if !bytes.Equal(orig, stateJSON) {
		t.Fatalf("original state should be left in place")
	}

	if !wl.Contains(expected) {
		t.Fatal("whitelist missing tenant after migrate")
	}
	entries := wl.List()
	var found *WhitelistEntry
	for i := range entries {
		if entries[i].Npub == expected {
			found = &entries[i]
			break
		}
	}
	if found == nil || !strings.Contains(found.Note, "migrated from legacy") {
		t.Fatalf("whitelist entry = %+v", found)
	}
}

func TestMigrateSealedNsecDecryptsToOriginalHex(t *testing.T) {
	dir := t.TempDir()
	cfg, _ := writeLegacyConfig(t, dir, []byte("{}"))

	store, _ := NewUserStore(filepath.Join(dir, "users"))
	wl, _ := LoadWhitelist(filepath.Join(dir, "whitelist.json"))
	sealer := migrateTestSealer(t)

	if err := Migrate(cfg, store, wl, sealer); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	npub, _ := nip19.EncodePublicKey(cfg.watchPubkeyHex)
	sealed, err := store.LoadSealedNsec(npub)
	if err != nil {
		t.Fatalf("LoadSealedNsec: %v", err)
	}
	pt, err := sealer.Unseal(npub, sealed)
	if err != nil {
		t.Fatalf("Unseal: %v", err)
	}
	if string(pt) != cfg.botPrivkeyHex {
		t.Fatalf("unsealed = %q want %q", pt, cfg.botPrivkeyHex)
	}
}

func TestMigrateIdempotent(t *testing.T) {
	dir := t.TempDir()
	cfg, _ := writeLegacyConfig(t, dir, []byte("{}"))

	store, _ := NewUserStore(filepath.Join(dir, "users"))
	wl, _ := LoadWhitelist(filepath.Join(dir, "whitelist.json"))
	sealer := migrateTestSealer(t)

	if err := Migrate(cfg, store, wl, sealer); err != nil {
		t.Fatalf("first Migrate: %v", err)
	}
	if err := Migrate(cfg, store, wl, sealer); err != nil {
		t.Fatalf("second Migrate: %v", err)
	}

	list, err := store.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("store has %d users after two Migrate calls, want 1", len(list))
	}
}

func TestMigrateNoopWhenLegacyFieldsEmpty(t *testing.T) {
	dir := t.TempDir()
	store, _ := NewUserStore(filepath.Join(dir, "users"))
	wl, _ := LoadWhitelist(filepath.Join(dir, "whitelist.json"))
	sealer := migrateTestSealer(t)

	cfg := &Config{}
	if err := Migrate(cfg, store, wl, sealer); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	list, _ := store.List()
	if len(list) != 0 {
		t.Fatalf("store has %d users, want 0", len(list))
	}
	if len(wl.List()) != 0 {
		t.Fatalf("whitelist has %d entries, want 0", len(wl.List()))
	}
}

func TestMigrateSealerNilLeavesNoPartialFiles(t *testing.T) {
	dir := t.TempDir()
	stateJSON := []byte(`{"last_seen":"2026-01-01T00:00:00Z"}`)
	cfg, stateFile := writeLegacyConfig(t, dir, stateJSON)

	store, _ := NewUserStore(filepath.Join(dir, "users"))
	wl, _ := LoadWhitelist(filepath.Join(dir, "whitelist.json"))

	err := Migrate(cfg, store, wl, nil)
	if err == nil {
		t.Fatal("Migrate with nil sealer should return error")
	}
	if !strings.Contains(err.Error(), "sealer") {
		t.Fatalf("error should mention sealer: %v", err)
	}

	list, _ := store.List()
	if len(list) != 0 {
		t.Fatalf("partial users after nil-sealer migrate: %v", list)
	}
	if _, err := os.Stat(stateFile + ".bak"); err == nil {
		t.Fatal(".bak written despite nil sealer")
	}
	if len(wl.List()) != 0 {
		t.Fatal("whitelist mutated despite nil sealer")
	}
}
