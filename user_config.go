package main

import (
	"errors"
	"fmt"
	"time"
)

// UserConfig is the per-user on-disk config.json payload. One of these
// lives at <StateDir>/users/<npub>/config.json and is owned entirely by
// that tenant.
type UserConfig struct {
	SubjectNpub      string    `json:"subject_npub"`
	WatcherPubkeyHex string    `json:"watcher_pubkey_hex,omitempty"`
	Relays           []string  `json:"relays,omitempty"`
	SilenceThreshold Duration  `json:"silence_threshold"`
	WarningInterval  Duration  `json:"warning_interval"`
	WarningCount     int       `json:"warning_count"`
	CheckInterval    Duration  `json:"check_interval"`
	Actions          []Action  `json:"actions"`
	UpdatedAt        time.Time `json:"updated_at"`
}

// Validate enforces the invariants the registry relies on. Actions may
// be empty (a fresh tenant hasn't configured any yet).
func (c *UserConfig) Validate() error {
	if c == nil {
		return errors.New("user_config: nil")
	}
	if err := validateNpub(c.SubjectNpub); err != nil {
		return fmt.Errorf("user_config: subject_npub: %w", err)
	}
	if c.SilenceThreshold.Duration <= 0 {
		return errors.New("user_config: silence_threshold must be > 0")
	}
	if c.WarningCount < 0 {
		return errors.New("user_config: warning_count must be >= 0")
	}
	if c.WarningCount > 0 && c.WarningInterval.Duration <= 0 {
		return errors.New("user_config: warning_interval must be > 0 when warning_count > 0")
	}
	if c.UpdatedAt.IsZero() {
		return errors.New("user_config: updated_at is zero")
	}
	return nil
}
