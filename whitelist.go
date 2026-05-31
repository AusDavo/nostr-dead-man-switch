package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// WhitelistEntry is one row of the whitelist.json file. Note is optional
// ("alice", "migrated from legacy single-switch", etc.).
type WhitelistEntry struct {
	Npub    string    `json:"npub"`
	AddedAt time.Time `json:"added_at"`
	Note    string    `json:"note,omitempty"`
	// PlanKind is "admin" | "invite" | "free" | "" (grandfathered).
	// Empty means a v1 entry that predates plan tracking; it is treated
	// as enrolled and never auto-modified.
	PlanKind string `json:"plan_kind,omitempty"`
	// PaidUntil and LastInvoiceID are reserved for v2 (Lightning billing
	// + expiry sweeps). They are never read in v1 code; they exist only
	// so v2 can skip a schema migration.
	PaidUntil     *time.Time `json:"paid_until,omitempty"`
	LastInvoiceID string     `json:"last_invoice_id,omitempty"`
}

// whitelistFile is the on-disk schema. Version: 1 = pre-plan, 2 = adds
// plan_kind. loadLocked ignores the version field, so a v1 file decodes
// cleanly (PlanKind == ""); the first mutation rewrites it at version 2.
type whitelistFile struct {
	Version int              `json:"version"`
	Npubs   []WhitelistEntry `json:"npubs"`
}

// Whitelist is the set of subject npubs the host will accept for
// federation. Persisted to a JSON file with mode 0600. Safe for
// concurrent readers; Add/Remove/Reload take an exclusive lock.
type Whitelist struct {
	path    string
	mu      sync.RWMutex
	entries []WhitelistEntry
}

// LoadWhitelist reads path and returns a Whitelist. A missing file is
// not an error: it yields an empty whitelist whose first Add will create
// the file.
func LoadWhitelist(path string) (*Whitelist, error) {
	w := &Whitelist{path: path}
	if err := w.loadLocked(); err != nil {
		return nil, err
	}
	return w, nil
}

// Reload re-reads the file under an exclusive lock. Used by the SIGHUP
// handler once runtime consumers land (#6/#8).
func (w *Whitelist) Reload() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.loadLocked()
}

// Contains reports whether the whitelist currently contains npub.
func (w *Whitelist) Contains(npub string) bool {
	w.mu.RLock()
	defer w.mu.RUnlock()
	for _, e := range w.entries {
		if e.Npub == npub {
			return true
		}
	}
	return false
}

// Add inserts npub if not already present. Duplicate adds are a no-op
// (the existing entry's AddedAt and Note are preserved). Invalid npubs
// are rejected before any IO.
func (w *Whitelist) Add(npub, note string) error {
	if err := validateNpub(npub); err != nil {
		return fmt.Errorf("whitelist: %w", err)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, e := range w.entries {
		if e.Npub == npub {
			return nil
		}
	}
	w.entries = append(w.entries, WhitelistEntry{
		Npub:    npub,
		AddedAt: time.Now().UTC(),
		Note:    note,
	})
	return w.saveLocked()
}

// SetPlanKind sets the PlanKind of an existing entry and persists the
// file. Returns an error if npub is not present. Used to tag an entry
// as "admin" (auto-enroll), "invite" (code redemption), or "free"
// (admin grant) after it has been Added.
func (w *Whitelist) SetPlanKind(npub, kind string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	for i := range w.entries {
		if w.entries[i].Npub == npub {
			w.entries[i].PlanKind = kind
			return w.saveLocked()
		}
	}
	return fmt.Errorf("whitelist: npub not present: %s", npub)
}

// Remove drops npub from the whitelist. Removing a non-present npub is
// a no-op; the file is not rewritten.
func (w *Whitelist) Remove(npub string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	filtered := make([]WhitelistEntry, 0, len(w.entries))
	removed := false
	for _, e := range w.entries {
		if e.Npub == npub {
			removed = true
			continue
		}
		filtered = append(filtered, e)
	}
	if !removed {
		return nil
	}
	w.entries = filtered
	return w.saveLocked()
}

// List returns a snapshot copy of the current entries.
func (w *Whitelist) List() []WhitelistEntry {
	w.mu.RLock()
	defer w.mu.RUnlock()
	out := make([]WhitelistEntry, len(w.entries))
	copy(out, w.entries)
	return out
}

func (w *Whitelist) loadLocked() error {
	data, err := os.ReadFile(w.path)
	if err != nil {
		if os.IsNotExist(err) {
			w.entries = nil
			return nil
		}
		return fmt.Errorf("whitelist: reading %s: %w", w.path, err)
	}
	var f whitelistFile
	if err := json.Unmarshal(data, &f); err != nil {
		return fmt.Errorf("whitelist: decoding %s: %w", w.path, err)
	}
	w.entries = f.Npubs
	return nil
}

func (w *Whitelist) saveLocked() error {
	if err := os.MkdirAll(filepath.Dir(w.path), 0o700); err != nil {
		return fmt.Errorf("whitelist: ensuring dir: %w", err)
	}
	f := whitelistFile{Version: 2, Npubs: w.entries}
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return fmt.Errorf("whitelist: encoding: %w", err)
	}
	return atomicWrite(w.path, data, 0o600)
}

// handleWhitelistCLI processes the four whitelist flags and writes
// one-line confirmations to out. Returns handled=true if any flag fired,
// in which case main should return without starting the service.
func handleWhitelistCLI(out io.Writer, path, add, note, remove string, list bool) (bool, error) {
	if add == "" && remove == "" && !list {
		return false, nil
	}
	wl, err := LoadWhitelist(path)
	if err != nil {
		return true, err
	}
	if add != "" {
		if err := wl.Add(add, note); err != nil {
			return true, err
		}
		fmt.Fprintf(out, "added %s to whitelist (%s)\n", add, path)
	}
	if remove != "" {
		if err := wl.Remove(remove); err != nil {
			return true, err
		}
		fmt.Fprintf(out, "removed %s from whitelist (%s)\n", remove, path)
	}
	if list {
		entries := wl.List()
		fmt.Fprintf(out, "whitelist has %d entries (%s)\n", len(entries), path)
		for _, e := range entries {
			plan := e.PlanKind
			if plan == "" {
				plan = "-"
			}
			suffix := ""
			if e.Note != "" {
				suffix = " -- " + e.Note
			}
			fmt.Fprintf(out, "  %s  plan=%s  added %s%s\n", e.Npub, plan, e.AddedAt.Format(time.RFC3339), suffix)
		}
	}
	return true, nil
}
