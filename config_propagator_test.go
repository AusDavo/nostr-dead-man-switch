package main

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip19"
)

type propagatorFixture struct {
	t     *testing.T
	store *UserStore
	npub  string
	cache *ConfigDMCache
}

func newPropagatorFixture(t *testing.T) *propagatorFixture {
	t.Helper()
	const priv = "0000000000000000000000000000000000000000000000000000000000000001"
	pub, err := nostr.GetPublicKey(priv)
	if err != nil {
		t.Fatalf("GetPublicKey: %v", err)
	}
	npub, err := nip19.EncodePublicKey(pub)
	if err != nil {
		t.Fatalf("EncodePublicKey: %v", err)
	}
	store, err := NewUserStore(filepath.Join(t.TempDir(), "users"))
	if err != nil {
		t.Fatalf("NewUserStore: %v", err)
	}
	if err := store.CreateUser(npub); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	return &propagatorFixture{
		t:     t,
		store: store,
		npub:  npub,
		cache: &ConfigDMCache{},
	}
}

func (f *propagatorFixture) newConfig(updatedAt time.Time) *UserConfig {
	return &UserConfig{
		SubjectNpub:      f.npub,
		SilenceThreshold: Duration{24 * time.Hour},
		WarningInterval:  Duration{2 * time.Hour},
		WarningCount:     2,
		CheckInterval:    Duration{time.Minute},
		Actions:          []Action{{Type: "webhook", Config: map[string]any{"url": "https://example.invalid"}}},
		UpdatedAt:        updatedAt,
	}
}

func (f *propagatorFixture) event(id string, createdAt time.Time) *nostr.Event {
	return &nostr.Event{ID: id, CreatedAt: nostr.Timestamp(createdAt.Unix()), Kind: 4}
}

func TestApplyInboundDM_Happy(t *testing.T) {
	f := newPropagatorFixture(t)
	uc := f.newConfig(time.Unix(1700000000, 0).UTC())
	payload, _ := json.Marshal(uc)
	ev := f.event("ev-1", uc.UpdatedAt)

	applied, err := applyInboundDM(f.store, f.npub, f.cache, ev, payload)
	if err != nil {
		t.Fatalf("applyInboundDM: %v", err)
	}
	if applied == nil {
		t.Fatal("applied = nil")
	}

	onDisk, err := f.store.LoadConfig(f.npub)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if !onDisk.UpdatedAt.Equal(uc.UpdatedAt) {
		t.Fatalf("on-disk UpdatedAt = %v, want %v", onDisk.UpdatedAt, uc.UpdatedAt)
	}
	if f.cache.LastAppliedEventID != "ev-1" {
		t.Fatalf("LastAppliedEventID = %q", f.cache.LastAppliedEventID)
	}
	if !f.cache.LastAppliedCreatedAt.Equal(uc.UpdatedAt) {
		t.Fatalf("LastAppliedCreatedAt = %v", f.cache.LastAppliedCreatedAt)
	}
	if !f.cache.Has("ev-1") {
		t.Fatal("Seen missing ev-1 after apply")
	}
}

func TestApplyInboundDM_Stale(t *testing.T) {
	f := newPropagatorFixture(t)
	t1 := time.Unix(1700000000, 0).UTC()
	t0 := t1.Add(-time.Hour)
	f.cache.Promote("seed", t1)

	uc := f.newConfig(t0)
	payload, _ := json.Marshal(uc)
	ev := f.event("ev-2", t0)

	_, err := applyInboundDM(f.store, f.npub, f.cache, ev, payload)
	if !errors.Is(err, ErrStaleDM) {
		t.Fatalf("err = %v, want ErrStaleDM", err)
	}
	if _, err := f.store.LoadConfig(f.npub); err == nil {
		t.Fatal("config.json should not exist on stale apply")
	}
	if !f.cache.Has("ev-2") {
		t.Fatal("stale event id should still be recorded in cache")
	}
	if f.cache.LastAppliedEventID != "seed" {
		t.Fatalf("LastAppliedEventID = %q; should not advance on stale", f.cache.LastAppliedEventID)
	}
}

func TestApplyInboundDM_Tie(t *testing.T) {
	f := newPropagatorFixture(t)
	t0 := time.Unix(1700000000, 0).UTC()
	f.cache.Promote("seed", t0)

	uc := f.newConfig(t0)
	payload, _ := json.Marshal(uc)
	ev := f.event("ev-tie", t0)

	_, err := applyInboundDM(f.store, f.npub, f.cache, ev, payload)
	if !errors.Is(err, ErrStaleDM) {
		t.Fatalf("err = %v, want ErrStaleDM (tie is stale)", err)
	}
}

func TestApplyInboundDM_DuplicateEventID(t *testing.T) {
	f := newPropagatorFixture(t)
	t0 := time.Unix(1700000000, 0).UTC()
	f.cache.Record("ev-3", t0)

	uc := f.newConfig(t0)
	payload, _ := json.Marshal(uc)
	ev := f.event("ev-3", t0)

	_, err := applyInboundDM(f.store, f.npub, f.cache, ev, payload)
	if !errors.Is(err, ErrAlreadyApplied) {
		t.Fatalf("err = %v, want ErrAlreadyApplied", err)
	}
	if _, err := f.store.LoadConfig(f.npub); err == nil {
		t.Fatal("config.json should not exist on duplicate")
	}
}

func TestApplyInboundDM_BadJSON(t *testing.T) {
	f := newPropagatorFixture(t)
	ev := f.event("ev-4", time.Unix(1700000000, 0).UTC())

	_, err := applyInboundDM(f.store, f.npub, f.cache, ev, []byte("not-json"))
	if err == nil || errors.Is(err, ErrStaleDM) || errors.Is(err, ErrAlreadyApplied) {
		t.Fatalf("err = %v, want JSON error", err)
	}
	if !f.cache.Has("ev-4") {
		t.Fatal("cache should record bad-JSON event id to avoid reparsing")
	}
	if _, err := f.store.LoadConfig(f.npub); err == nil {
		t.Fatal("config.json should not exist after bad JSON")
	}
}

func TestApplyInboundDM_FailedValidate(t *testing.T) {
	f := newPropagatorFixture(t)
	uc := f.newConfig(time.Unix(1700000000, 0).UTC())
	uc.SilenceThreshold = Duration{0} // invalid
	payload, _ := json.Marshal(uc)
	ev := f.event("ev-5", uc.UpdatedAt)

	_, err := applyInboundDM(f.store, f.npub, f.cache, ev, payload)
	if err == nil {
		t.Fatal("expected validation error")
	}
	if !f.cache.Has("ev-5") {
		t.Fatal("cache should record invalid event id")
	}
	if _, err := f.store.LoadConfig(f.npub); err == nil {
		t.Fatal("config.json should not exist after validation failure")
	}
}

func TestApplyInboundDM_SubjectMismatch(t *testing.T) {
	f := newPropagatorFixture(t)
	const otherPriv = "0000000000000000000000000000000000000000000000000000000000000009"
	otherPub, _ := nostr.GetPublicKey(otherPriv)
	otherNpub, _ := nip19.EncodePublicKey(otherPub)

	uc := f.newConfig(time.Unix(1700000000, 0).UTC())
	uc.SubjectNpub = otherNpub
	payload, _ := json.Marshal(uc)
	ev := f.event("ev-6", uc.UpdatedAt)

	_, err := applyInboundDM(f.store, f.npub, f.cache, ev, payload)
	if !errors.Is(err, ErrSubjectMismatch) {
		t.Fatalf("err = %v, want ErrSubjectMismatch", err)
	}
	if !f.cache.Has("ev-6") {
		t.Fatal("cache should record mismatched event id")
	}
}
