package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/nbd-wtf/go-nostr/nip19"
)

// Migrate imports a legacy single-switch deployment into the per-user
// layout. Idempotent: returns nil without side effects if the store
// already has tenants, or if cfg lacks legacy watch_pubkey/bot_nsec
// fields (e.g. a fresh federation-v1 install).
//
// The legacy state.json is copied into the tenant directory and a .bak
// is written next to the original; the original is intentionally left
// in place for one-release overlap with pre-migration binaries.
func Migrate(cfg *Config, store *UserStore, wl *Whitelist, sealer *Sealer) error {
	if sealer == nil {
		return errors.New("migrate: sealer is required")
	}

	existing, err := store.List()
	if err != nil {
		return fmt.Errorf("migrate: listing store: %w", err)
	}
	if len(existing) > 0 {
		return nil
	}
	if cfg.WatchPubkey == "" || cfg.BotNsec == "" {
		return nil
	}

	npub, err := nip19.EncodePublicKey(cfg.watchPubkeyHex)
	if err != nil {
		return fmt.Errorf("migrate: encoding subject npub: %w", err)
	}

	// Seal first so a crypto failure never leaves partial files on disk.
	sealed, err := sealer.Seal(npub, []byte(cfg.botPrivkeyHex))
	if err != nil {
		return fmt.Errorf("migrate: sealing nsec: %w", err)
	}

	if err := store.CreateUser(npub); err != nil {
		return fmt.Errorf("migrate: creating user: %w", err)
	}

	uc := &UserConfig{
		SubjectNpub:      npub,
		WatcherPubkeyHex: cfg.botPubkeyHex,
		Relays:           nil,
		SilenceThreshold: cfg.SilenceThreshold,
		WarningInterval:  cfg.WarningInterval,
		WarningCount:     cfg.WarningCount,
		CheckInterval:    cfg.CheckInterval,
		Actions:          cfg.Actions,
		UpdatedAt:        time.Now().UTC(),
	}
	if err := store.SaveConfig(npub, uc); err != nil {
		return fmt.Errorf("migrate: saving user config: %w", err)
	}

	if cfg.StateFile != "" {
		if err := migrateStateFile(cfg.StateFile, filepath.Join(store.UserDir(npub), "state.json")); err != nil {
			return fmt.Errorf("migrate: state file: %w", err)
		}
	}

	if err := store.SaveSealedNsec(npub, sealed); err != nil {
		return fmt.Errorf("migrate: saving sealed nsec: %w", err)
	}

	if err := wl.Add(npub, "migrated from legacy single-switch"); err != nil {
		return fmt.Errorf("migrate: whitelisting: %w", err)
	}

	log.Printf("[migrate] imported legacy single-switch as tenant %s", npub)
	return nil
}

// migrateStateFile copies the legacy state file into the tenant directory
// and writes a sibling .bak next to the original. If the original is
// absent, migration is a no-op (a freshly-provisioned legacy install).
func migrateStateFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("reading %s: %w", src, err)
	}
	if err := atomicWrite(dst, data, 0o600); err != nil {
		return fmt.Errorf("writing tenant copy: %w", err)
	}
	if err := atomicWrite(src+".bak", data, 0o600); err != nil {
		return fmt.Errorf("writing backup: %w", err)
	}
	return nil
}
