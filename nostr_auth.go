package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/nbd-wtf/go-nostr"
)

const (
	authEventKind      = 22242
	challengeTTL       = 5 * time.Minute
	challengeByteLen   = 32
	challengeJanitorIn = time.Minute
)

type challengeStore struct {
	mu sync.Mutex
	m  map[string]time.Time
}

func newChallengeStore() *challengeStore {
	s := &challengeStore{m: make(map[string]time.Time)}
	go s.janitor()
	return s
}

func (s *challengeStore) issue() (string, error) {
	b := make([]byte, challengeByteLen)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	c := hex.EncodeToString(b)
	s.mu.Lock()
	s.m[c] = time.Now().Add(challengeTTL)
	s.mu.Unlock()
	return c, nil
}

func (s *challengeStore) consume(c string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	exp, ok := s.m[c]
	if !ok {
		return false
	}
	delete(s.m, c)
	return time.Now().Before(exp)
}

func (s *challengeStore) janitor() {
	ticker := time.NewTicker(challengeJanitorIn)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		s.mu.Lock()
		for c, exp := range s.m {
			if now.After(exp) {
				delete(s.m, c)
			}
		}
		s.mu.Unlock()
	}
}

// verifyAuthEvent validates a NIP-07-style HTTP auth event (kind 22242).
// It checks that the event has the expected challenge in its tags, was
// created within the challenge TTL, is signed by expectedPubkey, and has
// a valid signature. Returns the pubkey on success.
func verifyAuthEvent(raw []byte, expectedChallenge, expectedPubkey string) (string, error) {
	var ev nostr.Event
	if err := json.Unmarshal(raw, &ev); err != nil {
		return "", errors.New("invalid event json")
	}

	if ev.Kind != authEventKind {
		return "", errors.New("wrong event kind")
	}

	tag := ev.Tags.GetFirst([]string{"challenge", expectedChallenge})
	if tag == nil {
		return "", errors.New("challenge mismatch")
	}

	eventTime := ev.CreatedAt.Time()
	if d := time.Since(eventTime); d > challengeTTL || d < -challengeTTL {
		return "", errors.New("event timestamp out of range")
	}

	if expectedPubkey != "" && ev.PubKey != expectedPubkey {
		return "", errors.New("pubkey not authorized")
	}

	ok, err := ev.CheckSignature()
	if err != nil {
		return "", err
	}
	if !ok {
		return "", errors.New("invalid signature")
	}

	return ev.PubKey, nil
}
