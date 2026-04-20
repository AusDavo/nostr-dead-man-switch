package main

import (
	"bytes"
	"encoding/base64"
	"errors"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

func testSealer(t *testing.T) *Sealer {
	t.Helper()
	// 32 bytes of 0x42. Stable across runs so known-answer vectors below
	// remain reproducible.
	key := bytes.Repeat([]byte{0x42}, chacha20poly1305.KeySize)
	s, err := NewSealer(base64.StdEncoding.EncodeToString(key))
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	return s
}

func TestSealerRoundTrip(t *testing.T) {
	s := testSealer(t)
	npub := "npub1exampleexampleexampleexampleexampleexampleexampleexamplee"
	pt := []byte("nsec1supersecretwatcherkeypretendthisishex")

	sealed, err := s.Seal(npub, pt)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	got, err := s.Unseal(npub, sealed)
	if err != nil {
		t.Fatalf("Unseal: %v", err)
	}
	if !bytes.Equal(got, pt) {
		t.Fatalf("round-trip mismatch: got %q want %q", got, pt)
	}
}

func TestSealerPerUserIsolation(t *testing.T) {
	s := testSealer(t)
	npubA := "npub1alice000000000000000000000000000000000000000000000000000"
	npubB := "npub1bob000000000000000000000000000000000000000000000000000000"
	pt := []byte("alice-only")

	sealed, err := s.Seal(npubA, pt)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if _, err := s.Unseal(npubB, sealed); err == nil {
		t.Fatal("Unseal under wrong npub should fail AEAD tag but succeeded")
	}
}

func TestSealerWrongStoreKey(t *testing.T) {
	s := testSealer(t)
	npub := "npub1x"
	sealed, err := s.Seal(npub, []byte("payload"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	otherKey := bytes.Repeat([]byte{0x77}, chacha20poly1305.KeySize)
	other, err := NewSealer(base64.StdEncoding.EncodeToString(otherKey))
	if err != nil {
		t.Fatalf("NewSealer other: %v", err)
	}
	if _, err := other.Unseal(npub, sealed); err == nil {
		t.Fatal("Unseal with wrong store key should fail but succeeded")
	}
}

func TestSealerTamperedCiphertext(t *testing.T) {
	s := testSealer(t)
	npub := "npub1x"
	sealed, err := s.Seal(npub, []byte("payload"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	blob, err := base64.StdEncoding.DecodeString(sealed)
	if err != nil {
		t.Fatalf("decoding: %v", err)
	}
	// Flip a bit deep inside the ciphertext (past version byte + nonce).
	blob[1+chacha20poly1305.NonceSizeX+2] ^= 0x01
	tampered := base64.StdEncoding.EncodeToString(blob)

	if _, err := s.Unseal(npub, tampered); err == nil {
		t.Fatal("Unseal of tampered ciphertext should fail but succeeded")
	}
}

func TestSealerUnsupportedVersion(t *testing.T) {
	s := testSealer(t)
	npub := "npub1x"
	sealed, err := s.Seal(npub, []byte("payload"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	blob, err := base64.StdEncoding.DecodeString(sealed)
	if err != nil {
		t.Fatalf("decoding: %v", err)
	}
	blob[0] = 0x02
	bumped := base64.StdEncoding.EncodeToString(blob)

	_, err = s.Unseal(npub, bumped)
	if !errors.Is(err, ErrUnsupportedVersion) {
		t.Fatalf("expected ErrUnsupportedVersion, got %v", err)
	}
}

func TestSealerTooShort(t *testing.T) {
	s := testSealer(t)
	if _, err := s.Unseal("npub1x", base64.StdEncoding.EncodeToString([]byte{0x01, 0x02, 0x03})); err == nil {
		t.Fatal("Unseal of truncated blob should fail")
	}
}

func TestSealerGarbageBase64(t *testing.T) {
	s := testSealer(t)
	if _, err := s.Unseal("npub1x", "!!!not-base64!!!"); err == nil {
		t.Fatal("Unseal of garbage base64 should fail")
	}
}

func TestNewSealerRejectsWrongLength(t *testing.T) {
	short := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x01}, 16))
	if _, err := NewSealer(short); err == nil {
		t.Fatal("NewSealer should reject 16-byte key but accepted it")
	}
}

func TestNewSealerTrimsWhitespace(t *testing.T) {
	key := bytes.Repeat([]byte{0x05}, chacha20poly1305.KeySize)
	padded := "  " + base64.StdEncoding.EncodeToString(key) + "\n"
	if _, err := NewSealer(padded); err != nil {
		t.Fatalf("NewSealer with whitespace padding: %v", err)
	}
}

func TestNewSealerFromEnvUnset(t *testing.T) {
	t.Setenv("TEST_WATCHER_STORE_KEY", "")
	if _, err := NewSealerFromEnv("TEST_WATCHER_STORE_KEY"); err == nil {
		t.Fatal("NewSealerFromEnv should reject empty env var")
	}
}

func TestNewSealerFromEnvSet(t *testing.T) {
	key := bytes.Repeat([]byte{0x09}, chacha20poly1305.KeySize)
	t.Setenv("TEST_WATCHER_STORE_KEY", base64.StdEncoding.EncodeToString(key))
	if _, err := NewSealerFromEnv("TEST_WATCHER_STORE_KEY"); err != nil {
		t.Fatalf("NewSealerFromEnv: %v", err)
	}
}

// TestSealerKnownAnswer pins the on-disk wire format. If this breaks,
// either the format version has changed (update the constant and the
// expected blob) or a bug was introduced.
func TestSealerKnownAnswer(t *testing.T) {
	s := testSealer(t)
	npub := "npub1known00000000000000000000000000000000000000000000000000"
	plaintext := []byte("hello watcher")
	nonce := bytes.Repeat([]byte{0x11}, chacha20poly1305.NonceSizeX)

	const expected = "AREREREREREREREREREREREREREREREREeQQlQ8Ga4+dZPU3B2di/gOO/JRNDI6iYyO5nulm"

	got, err := s.sealWithNonce(npub, plaintext, nonce)
	if err != nil {
		t.Fatalf("sealWithNonce: %v", err)
	}
	if got != expected {
		t.Fatalf("wire format changed\n got:  %s\n want: %s", got, expected)
	}

	// Sanity: decoding the expected blob should round-trip back to plaintext.
	round, err := s.Unseal(npub, expected)
	if err != nil {
		t.Fatalf("Unseal expected: %v", err)
	}
	if !bytes.Equal(round, plaintext) {
		t.Fatalf("round-trip of expected blob mismatch: %q", round)
	}
}
