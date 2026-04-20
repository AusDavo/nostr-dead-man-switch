package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/nbd-wtf/go-nostr/nip19"
)

// UserStore owns the on-disk per-user layout under <root> (typically
// <StateDir>/users). Each subject npub gets its own 0700 directory
// containing config.json, state.json, and watcher.nsec.enc. All file
// writes go through atomicWrite with mode 0600.
//
// UserStore is pure storage: it does not hold a Sealer or any crypto
// material. Callers compose (sealer.Seal → SaveSealedNsec) themselves.
type UserStore struct {
	root string
}

// NewUserStore validates that root is an absolute path and ensures the
// directory exists with mode 0700.
func NewUserStore(root string) (*UserStore, error) {
	if !filepath.IsAbs(root) {
		return nil, fmt.Errorf("userstore: root must be absolute, got %q", root)
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, fmt.Errorf("userstore: creating root: %w", err)
	}
	return &UserStore{root: root}, nil
}

// Root returns the absolute path to the store's root directory.
func (u *UserStore) Root() string { return u.root }

// UserDir returns the on-disk directory path for the given npub.
// Does no validation and no IO.
func (u *UserStore) UserDir(npub string) string {
	return filepath.Join(u.root, npub)
}

// HasUser reports whether a directory for this npub exists under root.
func (u *UserStore) HasUser(npub string) bool {
	info, err := os.Stat(u.UserDir(npub))
	return err == nil && info.IsDir()
}

// CreateUser validates the npub and creates its 0700 directory if absent.
// Idempotent: no error if the directory already exists.
func (u *UserStore) CreateUser(npub string) error {
	if err := validateNpub(npub); err != nil {
		return err
	}
	if err := os.MkdirAll(u.UserDir(npub), 0o700); err != nil {
		return fmt.Errorf("userstore: creating user dir: %w", err)
	}
	return nil
}

// DeleteUser removes the user's entire directory tree.
func (u *UserStore) DeleteUser(npub string) error {
	if err := validateNpub(npub); err != nil {
		return err
	}
	return os.RemoveAll(u.UserDir(npub))
}

// List returns every bech32 npub under the store root that has a
// config.json present. Stray files or dirs without a config are ignored.
func (u *UserStore) List() ([]string, error) {
	entries, err := os.ReadDir(u.root)
	if err != nil {
		return nil, fmt.Errorf("userstore: reading root: %w", err)
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		if err := validateNpub(name); err != nil {
			continue
		}
		if _, err := os.Stat(filepath.Join(u.root, name, "config.json")); err != nil {
			continue
		}
		out = append(out, name)
	}
	return out, nil
}

// LoadConfigBytes returns the raw JSON bytes of a user's config.json.
func (u *UserStore) LoadConfigBytes(npub string) ([]byte, error) {
	if err := validateNpub(npub); err != nil {
		return nil, err
	}
	return os.ReadFile(filepath.Join(u.UserDir(npub), "config.json"))
}

// SaveConfigBytes atomically writes raw JSON bytes to a user's config.json
// with mode 0600. The user directory must already exist (call CreateUser
// first).
func (u *UserStore) SaveConfigBytes(npub string, data []byte) error {
	if err := validateNpub(npub); err != nil {
		return err
	}
	return atomicWrite(filepath.Join(u.UserDir(npub), "config.json"), data, 0o600)
}

// LoadConfig reads and decodes the user's config.json into a UserConfig.
func (u *UserStore) LoadConfig(npub string) (*UserConfig, error) {
	data, err := u.LoadConfigBytes(npub)
	if err != nil {
		return nil, err
	}
	var c UserConfig
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("userstore: decoding config.json: %w", err)
	}
	return &c, nil
}

// SaveConfig encodes the UserConfig and atomically writes it to
// config.json with mode 0600. Validation is the caller's responsibility.
func (u *UserStore) SaveConfig(npub string, c *UserConfig) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("userstore: encoding config.json: %w", err)
	}
	return u.SaveConfigBytes(npub, data)
}

// LoadUserState reads state.json for the given npub. A missing file is
// not an error: a fresh NewState() is returned so first-boot callers can
// proceed without a special case.
func (u *UserStore) LoadUserState(npub string) (*State, error) {
	if err := validateNpub(npub); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(filepath.Join(u.UserDir(npub), "state.json"))
	if err != nil {
		if os.IsNotExist(err) {
			return NewState(), nil
		}
		return nil, fmt.Errorf("userstore: reading state.json: %w", err)
	}
	var s State
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("userstore: decoding state.json: %w", err)
	}
	return &s, nil
}

// SaveUserState atomically writes state.json with mode 0600.
func (u *UserStore) SaveUserState(npub string, s *State) error {
	if err := validateNpub(npub); err != nil {
		return err
	}
	s.mu.Lock()
	data, err := json.MarshalIndent(s, "", "  ")
	s.mu.Unlock()
	if err != nil {
		return fmt.Errorf("userstore: encoding state.json: %w", err)
	}
	return atomicWrite(filepath.Join(u.UserDir(npub), "state.json"), data, 0o600)
}

// HasSealedNsec reports whether watcher.nsec.enc exists for this user.
func (u *UserStore) HasSealedNsec(npub string) bool {
	_, err := os.Stat(filepath.Join(u.UserDir(npub), "watcher.nsec.enc"))
	return err == nil
}

// LoadSealedNsec returns the sealed nsec blob as produced by Sealer.Seal
// (base64 string). Whitespace is trimmed.
func (u *UserStore) LoadSealedNsec(npub string) (string, error) {
	if err := validateNpub(npub); err != nil {
		return "", err
	}
	data, err := os.ReadFile(filepath.Join(u.UserDir(npub), "watcher.nsec.enc"))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

// SaveSealedNsec atomically writes the sealed nsec blob with mode 0600.
func (u *UserStore) SaveSealedNsec(npub string, sealed string) error {
	if err := validateNpub(npub); err != nil {
		return err
	}
	return atomicWrite(filepath.Join(u.UserDir(npub), "watcher.nsec.enc"), []byte(sealed), 0o600)
}

// ErrInvalidNpub is returned by UserStore operations that receive a
// malformed subject npub. Directory names are the canonical bech32
// npub1… form; hex-only input is rejected here so nothing hits disk.
var ErrInvalidNpub = errors.New("userstore: invalid npub")

func validateNpub(s string) error {
	if !strings.HasPrefix(s, "npub1") {
		return fmt.Errorf("%w: missing npub1 prefix", ErrInvalidNpub)
	}
	prefix, data, err := nip19.Decode(s)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidNpub, err)
	}
	if prefix != "npub" {
		return fmt.Errorf("%w: wrong bech32 prefix %q", ErrInvalidNpub, prefix)
	}
	hexStr, ok := data.(string)
	if !ok || len(hexStr) != 64 {
		return fmt.Errorf("%w: decoded value not 32-byte hex", ErrInvalidNpub)
	}
	if _, err := hex.DecodeString(hexStr); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidNpub, err)
	}
	return nil
}

// atomicWrite writes data to a randomly-named sibling temp file, fsyncs
// it, then renames it over path. Any partial temp file is cleaned up on
// error. A crash mid-write leaves the previous version of path intact.
func atomicWrite(path string, data []byte, mode os.FileMode) error {
	var rnd [8]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return fmt.Errorf("userstore: random: %w", err)
	}
	tmp := fmt.Sprintf("%s.%s.tmp", path, hex.EncodeToString(rnd[:]))
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return fmt.Errorf("userstore: opening temp: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("userstore: writing temp: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("userstore: syncing temp: %w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("userstore: closing temp: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("userstore: rename: %w", err)
	}
	return nil
}
