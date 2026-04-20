package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/nbd-wtf/go-nostr"
)

// ErrStaleDM is returned by applyInboundDM when the event's created_at
// is not strictly greater than the cache's LastAppliedCreatedAt. The
// caller still records the event id in the cache so we don't keep
// decrypting the same stale payload on every relay reconnect.
var ErrStaleDM = errors.New("propagator: stale self-dm")

// ErrAlreadyApplied is returned when the event id is already present in
// the cache (either our own publish or a repeat from another relay).
// Signals a no-op with no further IO.
var ErrAlreadyApplied = errors.New("propagator: event already applied")

// ErrSubjectMismatch is returned when the decrypted payload's
// SubjectNpub differs from the npub the watcher owns. A peer must not
// be able to cross-assign a config between tenants.
var ErrSubjectMismatch = errors.New("propagator: subject npub mismatch")

// applyInboundDM applies a decrypted self-DM payload to disk. It
// validates the UserConfig, enforces newest-created_at-wins against the
// cache, persists config.json, and updates config_dm_cache.json.
//
// Caller holds any locks guarding cache; this function is pure logic
// over the provided *UserStore and *ConfigDMCache. The caller is also
// responsible for invoking the registry reload after a successful apply.
//
// Returns the applied *UserConfig on success, or one of ErrStaleDM /
// ErrAlreadyApplied / ErrSubjectMismatch / a wrapped JSON or validation
// error. In every non-ErrAlreadyApplied branch, the event id is
// recorded in the cache before returning so repeat deliveries are a
// cheap lookup.
func applyInboundDM(store *UserStore, npub string, cache *ConfigDMCache,
	ev *nostr.Event, payload []byte) (*UserConfig, error) {
	if ev == nil {
		return nil, fmt.Errorf("propagator: nil event")
	}
	if cache.Has(ev.ID) {
		return nil, ErrAlreadyApplied
	}

	createdAt := time.Unix(int64(ev.CreatedAt), 0)

	var uc UserConfig
	if err := json.Unmarshal(payload, &uc); err != nil {
		cache.Record(ev.ID, createdAt)
		_ = store.SaveDMCache(npub, cache)
		return nil, fmt.Errorf("propagator: decoding payload: %w", err)
	}

	if uc.SubjectNpub != "" && uc.SubjectNpub != npub {
		cache.Record(ev.ID, createdAt)
		_ = store.SaveDMCache(npub, cache)
		return nil, fmt.Errorf("%w: got %q want %q", ErrSubjectMismatch, uc.SubjectNpub, npub)
	}
	uc.SubjectNpub = npub

	if err := uc.Validate(); err != nil {
		cache.Record(ev.ID, createdAt)
		_ = store.SaveDMCache(npub, cache)
		return nil, fmt.Errorf("propagator: validating payload: %w", err)
	}

	if !createdAt.After(cache.LastAppliedCreatedAt) {
		cache.Record(ev.ID, createdAt)
		_ = store.SaveDMCache(npub, cache)
		return nil, ErrStaleDM
	}

	if err := store.SaveConfig(npub, &uc); err != nil {
		return nil, fmt.Errorf("propagator: saving config: %w", err)
	}

	cache.Record(ev.ID, createdAt)
	cache.Promote(ev.ID, createdAt)
	if err := store.SaveDMCache(npub, cache); err != nil {
		return nil, fmt.Errorf("propagator: saving cache: %w", err)
	}
	return &uc, nil
}
