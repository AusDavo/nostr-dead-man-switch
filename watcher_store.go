package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
)

const sealFormatVersion byte = 0x01

var ErrUnsupportedVersion = errors.New("watcher_store: unsupported seal format version")

// Sealer encrypts per-user secrets (currently watcher nsecs) at rest.
// The host-wide storeKey is held in memory; each Seal/Unseal call derives
// a per-user key as SHA256(storeKey || npub) so a leak of one user's
// derived key does not compromise any other user.
type Sealer struct {
	storeKey []byte
}

// NewSealer accepts a base64-encoded 32-byte store key (std encoding,
// with or without padding; surrounding whitespace is trimmed).
func NewSealer(storeKeyB64 string) (*Sealer, error) {
	trimmed := strings.TrimSpace(storeKeyB64)
	key, err := decodeBase64(trimmed)
	if err != nil {
		return nil, fmt.Errorf("watcher_store: decoding store key: %w", err)
	}
	if len(key) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("watcher_store: store key must be %d bytes, got %d", chacha20poly1305.KeySize, len(key))
	}
	return &Sealer{storeKey: key}, nil
}

// NewSealerFromEnv reads the named environment variable and constructs
// a Sealer. Returns an error (never panics); callers decide the startup
// policy when the variable is unset.
func NewSealerFromEnv(envVarName string) (*Sealer, error) {
	v := os.Getenv(envVarName)
	if strings.TrimSpace(v) == "" {
		return nil, fmt.Errorf("watcher_store: env var %s unset", envVarName)
	}
	return NewSealer(v)
}

// Seal encrypts plaintext under a per-user key derived from the subject npub.
// The returned string is base64(version | nonce | ciphertext).
func (s *Sealer) Seal(npub string, plaintext []byte) (string, error) {
	var nonce [chacha20poly1305.NonceSizeX]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", fmt.Errorf("watcher_store: reading nonce: %w", err)
	}
	return s.sealWithNonce(npub, plaintext, nonce[:])
}

// sealWithNonce is the deterministic core of Seal. Exposed to the test
// package only so known-answer tests can pin the wire format.
func (s *Sealer) sealWithNonce(npub string, plaintext, nonce []byte) (string, error) {
	if len(nonce) != chacha20poly1305.NonceSizeX {
		return "", fmt.Errorf("watcher_store: nonce must be %d bytes", chacha20poly1305.NonceSizeX)
	}
	aead, err := chacha20poly1305.NewX(s.deriveKey(npub))
	if err != nil {
		return "", fmt.Errorf("watcher_store: constructing AEAD: %w", err)
	}
	ct := aead.Seal(nil, nonce, plaintext, nil)
	blob := make([]byte, 0, 1+len(nonce)+len(ct))
	blob = append(blob, sealFormatVersion)
	blob = append(blob, nonce...)
	blob = append(blob, ct...)
	return base64.StdEncoding.EncodeToString(blob), nil
}

// Unseal decrypts a blob previously produced by Seal for the same npub.
func (s *Sealer) Unseal(npub, sealed string) ([]byte, error) {
	blob, err := decodeBase64(sealed)
	if err != nil {
		return nil, fmt.Errorf("watcher_store: decoding base64: %w", err)
	}
	minLen := 1 + chacha20poly1305.NonceSizeX + chacha20poly1305.Overhead
	if len(blob) < minLen {
		return nil, errors.New("watcher_store: sealed blob too short")
	}
	if blob[0] != sealFormatVersion {
		return nil, ErrUnsupportedVersion
	}
	nonce := blob[1 : 1+chacha20poly1305.NonceSizeX]
	ct := blob[1+chacha20poly1305.NonceSizeX:]
	aead, err := chacha20poly1305.NewX(s.deriveKey(npub))
	if err != nil {
		return nil, fmt.Errorf("watcher_store: constructing AEAD: %w", err)
	}
	pt, err := aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, fmt.Errorf("watcher_store: decrypting: %w", err)
	}
	return pt, nil
}

func (s *Sealer) deriveKey(npub string) []byte {
	h := sha256.New()
	h.Write(s.storeKey)
	h.Write([]byte(npub))
	return h.Sum(nil)
}

// decodeBase64 accepts std-encoded base64 with or without padding, which
// matches both `openssl rand -base64 32` output and raw-encoded blobs.
func decodeBase64(s string) ([]byte, error) {
	if strings.ContainsAny(s, "=") {
		return base64.StdEncoding.DecodeString(s)
	}
	return base64.RawStdEncoding.DecodeString(s)
}
