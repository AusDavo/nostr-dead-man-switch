package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nbd-wtf/go-nostr/nip19"
)

// testNpub derives a valid bech32 npub from a stable hex pubkey so tests
// don't depend on any external fixture.
func testNpub(t *testing.T) string {
	t.Helper()
	const pk = "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d"
	n, err := nip19.EncodePublicKey(pk)
	if err != nil {
		t.Fatalf("EncodePublicKey: %v", err)
	}
	return n
}

func TestUserStoreNewCreatesRoot(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "users")
	u, err := NewUserStore(dir)
	if err != nil {
		t.Fatalf("NewUserStore: %v", err)
	}
	info, err := os.Stat(u.Root())
	if err != nil {
		t.Fatalf("stat root: %v", err)
	}
	if !info.IsDir() {
		t.Fatal("root is not a directory")
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("root perms = %o, want 0700", info.Mode().Perm())
	}
}

func TestUserStoreRejectsRelativeRoot(t *testing.T) {
	if _, err := NewUserStore("relative/path"); err == nil {
		t.Fatal("expected error for relative root")
	}
}

func TestUserStoreCreateUserPerms(t *testing.T) {
	u, err := NewUserStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewUserStore: %v", err)
	}
	npub := testNpub(t)
	if err := u.CreateUser(npub); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	info, err := os.Stat(u.UserDir(npub))
	if err != nil {
		t.Fatalf("stat user dir: %v", err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("user dir perms = %o, want 0700", info.Mode().Perm())
	}
	if !u.HasUser(npub) {
		t.Fatal("HasUser returned false after CreateUser")
	}
}

func TestUserStoreCreateUserIdempotent(t *testing.T) {
	u, _ := NewUserStore(t.TempDir())
	npub := testNpub(t)
	if err := u.CreateUser(npub); err != nil {
		t.Fatalf("first CreateUser: %v", err)
	}
	if err := u.CreateUser(npub); err != nil {
		t.Fatalf("second CreateUser: %v", err)
	}
}

func TestUserStoreConfigRoundTrip(t *testing.T) {
	u, _ := NewUserStore(t.TempDir())
	npub := testNpub(t)
	if err := u.CreateUser(npub); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	payload := []byte(`{"subject_npub":"` + npub + `"}`)
	if err := u.SaveConfigBytes(npub, payload); err != nil {
		t.Fatalf("SaveConfigBytes: %v", err)
	}
	got, err := u.LoadConfigBytes(npub)
	if err != nil {
		t.Fatalf("LoadConfigBytes: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("round-trip: got %q want %q", got, payload)
	}

	info, err := os.Stat(filepath.Join(u.UserDir(npub), "config.json"))
	if err != nil {
		t.Fatalf("stat config.json: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("config.json perms = %o, want 0600", info.Mode().Perm())
	}
}

func TestUserStoreSaveLeavesNoTempFiles(t *testing.T) {
	u, _ := NewUserStore(t.TempDir())
	npub := testNpub(t)
	if err := u.CreateUser(npub); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := u.SaveConfigBytes(npub, []byte("{}")); err != nil {
		t.Fatalf("SaveConfigBytes: %v", err)
	}
	entries, err := os.ReadDir(u.UserDir(npub))
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Fatalf("temp file left behind: %s", e.Name())
		}
	}
}

func TestUserStoreList(t *testing.T) {
	u, _ := NewUserStore(t.TempDir())
	npub := testNpub(t)
	if err := u.CreateUser(npub); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	// No config yet → not listed.
	got, err := u.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("List before config: got %v, want empty", got)
	}

	// Stray files and a non-npub dir should be ignored.
	if err := os.WriteFile(filepath.Join(u.Root(), "stray.txt"), []byte("x"), 0o600); err != nil {
		t.Fatalf("writing stray file: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(u.Root(), "not-an-npub"), 0o700); err != nil {
		t.Fatalf("mkdir not-an-npub: %v", err)
	}

	if err := u.SaveConfigBytes(npub, []byte("{}")); err != nil {
		t.Fatalf("SaveConfigBytes: %v", err)
	}
	got, err = u.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 1 || got[0] != npub {
		t.Fatalf("List = %v, want [%s]", got, npub)
	}
}

func TestUserStoreSealedNsec(t *testing.T) {
	u, _ := NewUserStore(t.TempDir())
	npub := testNpub(t)
	if err := u.CreateUser(npub); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if u.HasSealedNsec(npub) {
		t.Fatal("HasSealedNsec true before SaveSealedNsec")
	}
	const sealed = "AREREREREREREREREREREREREREREREREeQQlQ8Ga4+dZPU3B2di/gOO/JRNDI6iYyO5nulm"
	if err := u.SaveSealedNsec(npub, sealed); err != nil {
		t.Fatalf("SaveSealedNsec: %v", err)
	}
	if !u.HasSealedNsec(npub) {
		t.Fatal("HasSealedNsec false after SaveSealedNsec")
	}
	got, err := u.LoadSealedNsec(npub)
	if err != nil {
		t.Fatalf("LoadSealedNsec: %v", err)
	}
	if got != sealed {
		t.Fatalf("LoadSealedNsec: got %q want %q", got, sealed)
	}
	info, err := os.Stat(filepath.Join(u.UserDir(npub), "watcher.nsec.enc"))
	if err != nil {
		t.Fatalf("stat sealed: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("sealed nsec perms = %o, want 0600", info.Mode().Perm())
	}
}

func TestUserStoreStateRoundTrip(t *testing.T) {
	u, _ := NewUserStore(t.TempDir())
	npub := testNpub(t)
	if err := u.CreateUser(npub); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	// Missing state.json → fresh NewState(), no error.
	got, err := u.LoadUserState(npub)
	if err != nil {
		t.Fatalf("LoadUserState (missing): %v", err)
	}
	if got == nil || !got.LastSeen.IsZero() || got.WarningSent != 0 {
		t.Fatalf("missing state should be empty, got %+v", got)
	}

	s := NewState()
	s.RecordEvent("abc123", time.Unix(1700000000, 0).UTC())
	s.RecordWarning()
	if err := u.SaveUserState(npub, s); err != nil {
		t.Fatalf("SaveUserState: %v", err)
	}

	loaded, err := u.LoadUserState(npub)
	if err != nil {
		t.Fatalf("LoadUserState: %v", err)
	}
	if !loaded.LastSeen.Equal(s.LastSeen) {
		t.Fatalf("LastSeen = %v, want %v", loaded.LastSeen, s.LastSeen)
	}
	if loaded.LastEventID != "abc123" {
		t.Fatalf("LastEventID = %q", loaded.LastEventID)
	}
	// RecordWarning bumps WarningSent; RecordEvent resets it to 0, so
	// issue order matters. In this test RecordEvent is called first.
	if loaded.WarningSent != 1 {
		t.Fatalf("WarningSent = %d, want 1", loaded.WarningSent)
	}

	info, err := os.Stat(filepath.Join(u.UserDir(npub), "state.json"))
	if err != nil {
		t.Fatalf("stat state.json: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("state.json perms = %o, want 0600", info.Mode().Perm())
	}
}

func TestUserStoreDMCacheRoundTrip(t *testing.T) {
	u, _ := NewUserStore(t.TempDir())
	npub := testNpub(t)
	if err := u.CreateUser(npub); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	got, err := u.LoadDMCache(npub)
	if err != nil {
		t.Fatalf("LoadDMCache (missing): %v", err)
	}
	if got == nil || !got.LastAppliedCreatedAt.IsZero() || len(got.Seen) != 0 {
		t.Fatalf("missing cache should be empty, got %+v", got)
	}

	c := &ConfigDMCache{}
	now := time.Unix(1700000000, 0).UTC()
	c.Record("ev1", now)
	c.Promote("ev1", now)
	if err := u.SaveDMCache(npub, c); err != nil {
		t.Fatalf("SaveDMCache: %v", err)
	}

	loaded, err := u.LoadDMCache(npub)
	if err != nil {
		t.Fatalf("LoadDMCache: %v", err)
	}
	if loaded.LastAppliedEventID != "ev1" {
		t.Fatalf("LastAppliedEventID = %q", loaded.LastAppliedEventID)
	}
	if !loaded.LastAppliedCreatedAt.Equal(now) {
		t.Fatalf("LastAppliedCreatedAt = %v, want %v", loaded.LastAppliedCreatedAt, now)
	}
	if _, ok := loaded.Seen["ev1"]; !ok {
		t.Fatalf("Seen missing ev1: %v", loaded.Seen)
	}

	info, err := os.Stat(filepath.Join(u.UserDir(npub), "config_dm_cache.json"))
	if err != nil {
		t.Fatalf("stat cache: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("config_dm_cache.json perms = %o, want 0600", info.Mode().Perm())
	}
}

func TestUserStoreDeleteUser(t *testing.T) {
	u, _ := NewUserStore(t.TempDir())
	npub := testNpub(t)
	if err := u.CreateUser(npub); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := u.SaveConfigBytes(npub, []byte("{}")); err != nil {
		t.Fatalf("SaveConfigBytes: %v", err)
	}
	if err := u.DeleteUser(npub); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}
	if u.HasUser(npub) {
		t.Fatal("HasUser true after DeleteUser")
	}
}

func TestUserStoreAtomicWriteDoesNotClobberOnFailure(t *testing.T) {
	// With atomicWrite, a fresh SaveConfigBytes creates a temp file then
	// renames. If we pre-populate config.json and then simulate a failed
	// write by manually dropping a stale .tmp file, the real config.json
	// should be untouched.
	u, _ := NewUserStore(t.TempDir())
	npub := testNpub(t)
	if err := u.CreateUser(npub); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	original := []byte(`{"v":1}`)
	if err := u.SaveConfigBytes(npub, original); err != nil {
		t.Fatalf("SaveConfigBytes: %v", err)
	}

	// Simulate an aborted concurrent write by writing a stale temp file.
	stale := filepath.Join(u.UserDir(npub), "config.json.deadbeef.tmp")
	if err := os.WriteFile(stale, []byte("garbage"), 0o600); err != nil {
		t.Fatalf("writing stale tmp: %v", err)
	}

	got, err := u.LoadConfigBytes(npub)
	if err != nil {
		t.Fatalf("LoadConfigBytes: %v", err)
	}
	if string(got) != string(original) {
		t.Fatalf("config.json clobbered: got %q want %q", got, original)
	}
}

func TestUserStoreRejectsInvalidNpub(t *testing.T) {
	u, _ := NewUserStore(t.TempDir())
	cases := []string{
		"",
		"npub1",
		"npub1malformedxxx",
		"3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d", // hex only
		"nsec1abcdef",
	}
	for _, bad := range cases {
		t.Run(bad, func(t *testing.T) {
			if err := u.CreateUser(bad); err == nil {
				t.Fatalf("CreateUser(%q) accepted, want rejection", bad)
			} else if !errors.Is(err, ErrInvalidNpub) {
				t.Fatalf("CreateUser(%q) = %v, want ErrInvalidNpub", bad, err)
			}
			if err := u.SaveConfigBytes(bad, []byte("{}")); err == nil {
				t.Fatalf("SaveConfigBytes(%q) accepted, want rejection", bad)
			}
			if err := u.SaveSealedNsec(bad, "x"); err == nil {
				t.Fatalf("SaveSealedNsec(%q) accepted, want rejection", bad)
			}
		})
	}
}

func TestUserStoreLoadConfigMigratesLegacyToV1(t *testing.T) {
	u, _ := NewUserStore(t.TempDir())
	npub := testNpub(t)
	if err := u.CreateUser(npub); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	legacy := []byte(`{
  "subject_npub": "` + npub + `",
  "silence_threshold": "1h0m0s",
  "warning_interval": "30m0s",
  "warning_count": 1,
  "check_interval": "5m0s",
  "actions": [],
  "updated_at": "2026-05-01T00:00:00Z"
}`)
	if err := u.SaveConfigBytes(npub, legacy); err != nil {
		t.Fatalf("SaveConfigBytes: %v", err)
	}

	c, err := u.LoadConfig(npub)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if c.SchemaVersion != userCfgSchemaCurrent {
		t.Fatalf("SchemaVersion = %d, want %d", c.SchemaVersion, userCfgSchemaCurrent)
	}
	if c.SubjectNpub != npub {
		t.Fatalf("SubjectNpub = %q, want %q", c.SubjectNpub, npub)
	}

	raw, err := u.LoadConfigBytes(npub)
	if err != nil {
		t.Fatalf("LoadConfigBytes: %v", err)
	}
	if !strings.Contains(string(raw), `"schema_version": 1`) {
		t.Fatalf("on-disk config.json not stamped:\n%s", raw)
	}
}

func TestUserStoreLoadConfigForwardVersionRefused(t *testing.T) {
	u, _ := NewUserStore(t.TempDir())
	npub := testNpub(t)
	if err := u.CreateUser(npub); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := u.SaveConfigBytes(npub, []byte(`{"schema_version": 99, "subject_npub":"`+npub+`"}`)); err != nil {
		t.Fatalf("SaveConfigBytes: %v", err)
	}
	_, err := u.LoadConfig(npub)
	if err == nil {
		t.Fatal("expected error for forward-version config.json")
	}
	if !strings.Contains(err.Error(), "newer than this binary supports") {
		t.Fatalf("error %q lacks expected substring", err.Error())
	}
}

func TestUserStoreSaveConfigStampsSchemaVersion(t *testing.T) {
	u, _ := NewUserStore(t.TempDir())
	npub := testNpub(t)
	if err := u.CreateUser(npub); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	c := &UserConfig{
		SubjectNpub:      npub,
		SilenceThreshold: Duration{Duration: time.Hour},
		UpdatedAt:        time.Now().UTC(),
	}
	if err := u.SaveConfig(npub, c); err != nil {
		t.Fatalf("SaveConfig: %v", err)
	}
	if c.SchemaVersion != userCfgSchemaCurrent {
		t.Fatalf("SchemaVersion not stamped in-memory: %d", c.SchemaVersion)
	}
	raw, err := u.LoadConfigBytes(npub)
	if err != nil {
		t.Fatalf("LoadConfigBytes: %v", err)
	}
	if !strings.Contains(string(raw), `"schema_version": 1`) {
		t.Fatalf("on-disk config.json not stamped:\n%s", raw)
	}
}

func TestUserStoreLoadUserStateMigratesLegacyToV1(t *testing.T) {
	u, _ := NewUserStore(t.TempDir())
	npub := testNpub(t)
	if err := u.CreateUser(npub); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	legacy := []byte(`{
  "last_seen": "2026-05-01T00:00:00Z",
  "last_event_id": "ev1",
  "warnings_sent": 0,
  "triggered": false
}`)
	statePath := filepath.Join(u.UserDir(npub), "state.json")
	if err := os.WriteFile(statePath, legacy, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	s, err := u.LoadUserState(npub)
	if err != nil {
		t.Fatalf("LoadUserState: %v", err)
	}
	if s.SchemaVersion != stateSchemaCurrent {
		t.Fatalf("SchemaVersion = %d, want %d", s.SchemaVersion, stateSchemaCurrent)
	}
	if s.LastEventID != "ev1" {
		t.Fatalf("LastEventID = %q, want ev1", s.LastEventID)
	}

	raw, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !strings.Contains(string(raw), `"schema_version": 1`) {
		t.Fatalf("on-disk state.json not stamped:\n%s", raw)
	}
}

func TestUserStoreLoadUserStateForwardVersionRefused(t *testing.T) {
	u, _ := NewUserStore(t.TempDir())
	npub := testNpub(t)
	if err := u.CreateUser(npub); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	statePath := filepath.Join(u.UserDir(npub), "state.json")
	if err := os.WriteFile(statePath, []byte(`{"schema_version": 99}`), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	_, err := u.LoadUserState(npub)
	if err == nil {
		t.Fatal("expected error for forward-version state.json")
	}
	if !strings.Contains(err.Error(), "newer than this binary supports") {
		t.Fatalf("error %q lacks expected substring", err.Error())
	}
}
