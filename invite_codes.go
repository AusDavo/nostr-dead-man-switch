package main

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// revokedSentinel is recorded as the redeemer of a revoked code, so the
// code can never be redeemed by a real npub and the audit trail survives.
const revokedSentinel = "__revoked__"

// inviteCodeBytes is the number of crypto/rand bytes per minted code.
// 6 bytes → 10 base32 chars (no padding), readable to share over a DM.
const inviteCodeBytes = 6

var (
	// ErrCodeUsed is returned by Redeem when the code was already redeemed
	// (or revoked) by a different npub.
	ErrCodeUsed = errors.New("invite: code already used")
	// ErrCodeInvalid is returned by Redeem for an unknown code (neither
	// configured nor minted).
	ErrCodeInvalid = errors.New("invite: code invalid")
)

// codeEncoding is std base32 (uppercase A–Z, 2–7) without padding.
var codeEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// usedEntry records who redeemed a code and when. A revoked code stores
// Npub == revokedSentinel.
type usedEntry struct {
	Npub       string    `json:"npub"`
	RedeemedAt time.Time `json:"redeemed_at"`
}

type mintedFile struct {
	Version int      `json:"version"`
	Codes   []string `json:"codes"`
}

type usedFile struct {
	Version int                  `json:"version"`
	Used    map[string]usedEntry `json:"used"`
}

// InviteCodeView is a roster-UI projection of a single code: its value,
// where it came from, and its redemption state.
type InviteCodeView struct {
	Code       string
	Source     string // "configured" | "minted"
	State      string // "available" | "redeemed" | "revoked"
	UsedBy     string // redeemer npub, revokedSentinel, or ""
	RedeemedAt time.Time
}

// InviteCodes tracks the set of valid invite codes (configured at boot ∪
// runtime-minted) and the single-use ledger of redeemed/revoked codes.
// All operations are guarded by mu; persistence uses atomicWrite.
type InviteCodes struct {
	path     string // invite_codes.json (minted)
	usedPath string // invite_codes_used.json (ledger)

	mu         sync.Mutex
	configured map[string]bool
	minted     map[string]bool
	used       map[string]usedEntry
}

// normalizeCode trims whitespace and uppercases so codes shared over a DM
// match regardless of how the user typed them.
func normalizeCode(code string) string {
	return strings.ToUpper(strings.TrimSpace(code))
}

// LoadInviteCodes loads the minted-code list and used-code ledger from
// stateDir and seeds the configured set from configured. A missing file
// is not an error.
func LoadInviteCodes(stateDir string, configured []string) (*InviteCodes, error) {
	c := &InviteCodes{
		path:       filepath.Join(stateDir, "invite_codes.json"),
		usedPath:   filepath.Join(stateDir, "invite_codes_used.json"),
		configured: map[string]bool{},
		minted:     map[string]bool{},
		used:       map[string]usedEntry{},
	}
	for _, code := range configured {
		if n := normalizeCode(code); n != "" {
			c.configured[n] = true
		}
	}
	if data, err := os.ReadFile(c.path); err == nil {
		var mf mintedFile
		if err := json.Unmarshal(data, &mf); err != nil {
			return nil, fmt.Errorf("invite: decoding %s: %w", c.path, err)
		}
		for _, code := range mf.Codes {
			if n := normalizeCode(code); n != "" {
				c.minted[n] = true
			}
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("invite: reading %s: %w", c.path, err)
	}
	if data, err := os.ReadFile(c.usedPath); err == nil {
		var uf usedFile
		if err := json.Unmarshal(data, &uf); err != nil {
			return nil, fmt.Errorf("invite: decoding %s: %w", c.usedPath, err)
		}
		for code, entry := range uf.Used {
			c.used[normalizeCode(code)] = entry
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("invite: reading %s: %w", c.usedPath, err)
	}
	return c, nil
}

// knownLocked reports whether code is configured or minted. Caller holds mu.
func (c *InviteCodes) knownLocked(code string) bool {
	return c.configured[code] || c.minted[code]
}

// IsValid reports whether code is configured-or-minted and not yet used.
func (c *InviteCodes) IsValid(code string) bool {
	code = normalizeCode(code)
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, used := c.used[code]; used {
		return false
	}
	return c.knownLocked(code)
}

// IsUsedBy returns the redeemer npub (or revokedSentinel) and whether the
// code has been used at all.
func (c *InviteCodes) IsUsedBy(code string) (string, bool) {
	code = normalizeCode(code)
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.used[code]
	if !ok {
		return "", false
	}
	return entry.Npub, true
}

// Redeem atomically validates and marks a code used by npub in one locked
// critical section, so two callers racing the same code cannot both win.
//   - already used by the same npub → nil (idempotent re-entry)
//   - already used by a different npub (or revoked) → ErrCodeUsed
//   - unknown code → ErrCodeInvalid
//   - valid + unused → marked used, nil
func (c *InviteCodes) Redeem(code, npub string) error {
	code = normalizeCode(code)
	c.mu.Lock()
	defer c.mu.Unlock()
	if entry, ok := c.used[code]; ok {
		if entry.Npub == npub {
			return nil
		}
		return fmt.Errorf("%w: %s", ErrCodeUsed, code)
	}
	if !c.knownLocked(code) {
		return fmt.Errorf("%w: %s", ErrCodeInvalid, code)
	}
	c.used[code] = usedEntry{Npub: npub, RedeemedAt: time.Now().UTC()}
	if err := c.saveUsedLocked(); err != nil {
		delete(c.used, code)
		return err
	}
	return nil
}

// Mint generates a fresh crypto/rand code, records it as minted, and
// persists the minted list. Returns the new code.
func (c *InviteCodes) Mint() (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var code string
	for {
		buf := make([]byte, inviteCodeBytes)
		if _, err := rand.Read(buf); err != nil {
			return "", fmt.Errorf("invite: random: %w", err)
		}
		code = codeEncoding.EncodeToString(buf)
		if !c.knownLocked(code) {
			if _, used := c.used[code]; !used {
				break
			}
		}
	}
	c.minted[code] = true
	if err := c.saveMintedLocked(); err != nil {
		delete(c.minted, code)
		return "", err
	}
	return code, nil
}

// RevokeCode marks a code used by the revoked sentinel so it can never be
// redeemed, preserving the audit trail. Unknown codes are recorded as
// revoked too (defensive: stops a configured code being added later).
func (c *InviteCodes) RevokeCode(code string) error {
	code = normalizeCode(code)
	c.mu.Lock()
	defer c.mu.Unlock()
	prev, existed := c.used[code]
	c.used[code] = usedEntry{Npub: revokedSentinel, RedeemedAt: time.Now().UTC()}
	if err := c.saveUsedLocked(); err != nil {
		if existed {
			c.used[code] = prev
		} else {
			delete(c.used, code)
		}
		return err
	}
	return nil
}

// ListCodes returns a roster-UI view of every configured and minted code,
// sorted by code for stable rendering.
func (c *InviteCodes) ListCodes() []InviteCodeView {
	c.mu.Lock()
	defer c.mu.Unlock()
	seen := map[string]string{} // code -> source
	for code := range c.configured {
		seen[code] = "configured"
	}
	for code := range c.minted {
		// minted wins the label only if not already configured
		if _, ok := seen[code]; !ok {
			seen[code] = "minted"
		}
	}
	out := make([]InviteCodeView, 0, len(seen))
	for code, source := range seen {
		v := InviteCodeView{Code: code, Source: source, State: "available"}
		if entry, ok := c.used[code]; ok {
			v.UsedBy = entry.Npub
			v.RedeemedAt = entry.RedeemedAt
			if entry.Npub == revokedSentinel {
				v.State = "revoked"
			} else {
				v.State = "redeemed"
			}
		}
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Code < out[j].Code })
	return out
}

func (c *InviteCodes) saveMintedLocked() error {
	codes := make([]string, 0, len(c.minted))
	for code := range c.minted {
		codes = append(codes, code)
	}
	sort.Strings(codes)
	data, err := json.MarshalIndent(mintedFile{Version: 1, Codes: codes}, "", "  ")
	if err != nil {
		return fmt.Errorf("invite: encoding minted: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(c.path), 0o700); err != nil {
		return fmt.Errorf("invite: ensuring dir: %w", err)
	}
	return atomicWrite(c.path, data, 0o600)
}

func (c *InviteCodes) saveUsedLocked() error {
	data, err := json.MarshalIndent(usedFile{Version: 1, Used: c.used}, "", "  ")
	if err != nil {
		return fmt.Errorf("invite: encoding used: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(c.usedPath), 0o700); err != nil {
		return fmt.Errorf("invite: ensuring dir: %w", err)
	}
	return atomicWrite(c.usedPath, data, 0o600)
}
