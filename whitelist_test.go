package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadWhitelistMissingFileIsEmpty(t *testing.T) {
	path := filepath.Join(t.TempDir(), "whitelist.json")
	wl, err := LoadWhitelist(path)
	if err != nil {
		t.Fatalf("LoadWhitelist: %v", err)
	}
	if got := wl.List(); len(got) != 0 {
		t.Fatalf("expected empty whitelist, got %v", got)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("LoadWhitelist should not create file; stat: %v", err)
	}
}

func TestWhitelistAddPersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "whitelist.json")
	wl, _ := LoadWhitelist(path)
	npub := testNpub(t)
	if err := wl.Add(npub, "alice"); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if !wl.Contains(npub) {
		t.Fatal("Contains false after Add")
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat whitelist.json: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("perms = %o, want 0600", info.Mode().Perm())
	}

	reloaded, err := LoadWhitelist(path)
	if err != nil {
		t.Fatalf("LoadWhitelist after Add: %v", err)
	}
	got := reloaded.List()
	if len(got) != 1 || got[0].Npub != npub || got[0].Note != "alice" {
		t.Fatalf("reloaded = %+v", got)
	}
	if got[0].AddedAt.IsZero() {
		t.Fatal("AddedAt is zero")
	}
}

func TestWhitelistAddIsDedupe(t *testing.T) {
	path := filepath.Join(t.TempDir(), "whitelist.json")
	wl, _ := LoadWhitelist(path)
	npub := testNpub(t)
	if err := wl.Add(npub, "alice"); err != nil {
		t.Fatalf("Add 1: %v", err)
	}
	first := wl.List()[0].AddedAt

	time.Sleep(2 * time.Millisecond)

	if err := wl.Add(npub, "alice-again"); err != nil {
		t.Fatalf("Add 2: %v", err)
	}
	entries := wl.List()
	if len(entries) != 1 {
		t.Fatalf("dedup broken, got %d entries", len(entries))
	}
	if !entries[0].AddedAt.Equal(first) {
		t.Fatalf("AddedAt should be preserved on dedup: first %v now %v", first, entries[0].AddedAt)
	}
	if entries[0].Note != "alice" {
		t.Fatalf("Note should be preserved on dedup: got %q", entries[0].Note)
	}
}

func TestWhitelistAddRejectsHex(t *testing.T) {
	path := filepath.Join(t.TempDir(), "whitelist.json")
	wl, _ := LoadWhitelist(path)
	err := wl.Add("3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d", "")
	if err == nil {
		t.Fatal("Add accepted hex-only input")
	}
	if !errors.Is(err, ErrInvalidNpub) {
		t.Fatalf("got %v, want ErrInvalidNpub", err)
	}
}

func TestWhitelistRemove(t *testing.T) {
	path := filepath.Join(t.TempDir(), "whitelist.json")
	wl, _ := LoadWhitelist(path)
	npub := testNpub(t)
	if err := wl.Add(npub, ""); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := wl.Remove(npub); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if wl.Contains(npub) {
		t.Fatal("still contains after Remove")
	}
	// Remove on absent is a no-op.
	if err := wl.Remove(npub); err != nil {
		t.Fatalf("Remove absent: %v", err)
	}
}

func TestWhitelistReloadPicksUpExternalEdits(t *testing.T) {
	path := filepath.Join(t.TempDir(), "whitelist.json")
	wl, _ := LoadWhitelist(path)
	npub := testNpub(t)

	// Write a file directly as if another process had added an entry.
	payload := whitelistFile{
		Version: 1,
		Npubs: []WhitelistEntry{
			{Npub: npub, AddedAt: time.Now().UTC(), Note: "external"},
		},
	}
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	if wl.Contains(npub) {
		t.Fatal("whitelist saw external edit before Reload")
	}
	if err := wl.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if !wl.Contains(npub) {
		t.Fatal("whitelist did not pick up external edit after Reload")
	}
}

func TestHandleWhitelistCLINoFlagsIsNoop(t *testing.T) {
	var buf bytes.Buffer
	path := filepath.Join(t.TempDir(), "whitelist.json")
	handled, err := handleWhitelistCLI(&buf, path, "", "", "", false)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if handled {
		t.Fatal("handled=true with no flags set")
	}
	if buf.Len() != 0 {
		t.Fatalf("unexpected output: %q", buf.String())
	}
}

func TestHandleWhitelistCLIAddListRemove(t *testing.T) {
	path := filepath.Join(t.TempDir(), "whitelist.json")
	npub := testNpub(t)

	var buf bytes.Buffer
	handled, err := handleWhitelistCLI(&buf, path, npub, "alice", "", false)
	if err != nil || !handled {
		t.Fatalf("add: handled=%v err=%v", handled, err)
	}
	if !strings.Contains(buf.String(), "added "+npub) {
		t.Fatalf("add output: %q", buf.String())
	}

	buf.Reset()
	handled, err = handleWhitelistCLI(&buf, path, "", "", "", true)
	if err != nil || !handled {
		t.Fatalf("list: handled=%v err=%v", handled, err)
	}
	if !strings.Contains(buf.String(), npub) || !strings.Contains(buf.String(), "alice") {
		t.Fatalf("list output missing entry: %q", buf.String())
	}

	buf.Reset()
	handled, err = handleWhitelistCLI(&buf, path, "", "", npub, false)
	if err != nil || !handled {
		t.Fatalf("remove: handled=%v err=%v", handled, err)
	}
	if !strings.Contains(buf.String(), "removed "+npub) {
		t.Fatalf("remove output: %q", buf.String())
	}

	// List again to confirm empty.
	buf.Reset()
	if _, err := handleWhitelistCLI(&buf, path, "", "", "", true); err != nil {
		t.Fatalf("final list: %v", err)
	}
	if !strings.Contains(buf.String(), "0 entries") {
		t.Fatalf("final list output: %q", buf.String())
	}
}

func TestConfigDefaultsFederationFields(t *testing.T) {
	// Write a minimal legacy config to a tempfile, load it, assert the
	// new federation defaults are resolved.
	dir := t.TempDir()
	stateFile := filepath.Join(dir, "state.json")
	configPath := filepath.Join(dir, "config.yaml")

	yaml := `watch_pubkey: 3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d
bot_nsec: 0000000000000000000000000000000000000000000000000000000000000001
silence_threshold: 7d
warning_interval: 1d
warning_count: 2
check_interval: 1h
state_file: ` + stateFile + `
`
	if err := os.WriteFile(configPath, []byte(yaml), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.StateDir != dir {
		t.Fatalf("StateDir = %q, want %q", cfg.StateDir, dir)
	}
	if cfg.WatcherStoreKeyEnv != "DEADMAN_WATCHER_KEY" {
		t.Fatalf("WatcherStoreKeyEnv = %q", cfg.WatcherStoreKeyEnv)
	}
	wantWL := filepath.Join(dir, "whitelist.json")
	if cfg.WhitelistFile != wantWL {
		t.Fatalf("WhitelistFile = %q, want %q", cfg.WhitelistFile, wantWL)
	}
	if cfg.FederationV1 {
		t.Fatal("FederationV1 should default to false")
	}
}
