package main

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/nbd-wtf/go-nostr"
)

func TestChallengeStore_IssueConsume(t *testing.T) {
	s := &challengeStore{m: make(map[string]time.Time)}

	c, err := s.issue()
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if len(c) != challengeByteLen*2 {
		t.Fatalf("challenge hex len = %d, want %d", len(c), challengeByteLen*2)
	}
	if !s.consume(c) {
		t.Fatalf("first consume should succeed")
	}
	if s.consume(c) {
		t.Fatalf("second consume should fail (one-time use)")
	}
}

func TestChallengeStore_Expired(t *testing.T) {
	s := &challengeStore{m: make(map[string]time.Time)}
	s.m["stale"] = time.Now().Add(-time.Second)
	if s.consume("stale") {
		t.Fatalf("expired challenge should not be consumable")
	}
}

func TestVerifyAuthEvent_HappyPath(t *testing.T) {
	sk := nostr.GeneratePrivateKey()
	pk, _ := nostr.GetPublicKey(sk)

	challenge := "deadbeef"
	ev := nostr.Event{
		Kind:      authEventKind,
		CreatedAt: nostr.Now(),
		Tags:      nostr.Tags{{"challenge", challenge}},
		Content:   "test",
	}
	if err := ev.Sign(sk); err != nil {
		t.Fatalf("sign: %v", err)
	}
	raw, _ := json.Marshal(ev)

	got, err := verifyAuthEvent(raw, challenge, pk)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got != pk {
		t.Fatalf("pubkey = %s, want %s", got, pk)
	}
}

func TestVerifyAuthEvent_WrongPubkey(t *testing.T) {
	sk := nostr.GeneratePrivateKey()
	wrongSk := nostr.GeneratePrivateKey()
	wrongPk, _ := nostr.GetPublicKey(wrongSk)

	ev := nostr.Event{
		Kind:      authEventKind,
		CreatedAt: nostr.Now(),
		Tags:      nostr.Tags{{"challenge", "x"}},
	}
	ev.Sign(sk)
	raw, _ := json.Marshal(ev)

	if _, err := verifyAuthEvent(raw, "x", wrongPk); err == nil {
		t.Fatalf("expected pubkey mismatch error")
	}
}

func TestVerifyAuthEvent_WrongChallenge(t *testing.T) {
	sk := nostr.GeneratePrivateKey()
	pk, _ := nostr.GetPublicKey(sk)

	ev := nostr.Event{
		Kind:      authEventKind,
		CreatedAt: nostr.Now(),
		Tags:      nostr.Tags{{"challenge", "issued"}},
	}
	ev.Sign(sk)
	raw, _ := json.Marshal(ev)

	if _, err := verifyAuthEvent(raw, "different", pk); err == nil {
		t.Fatalf("expected challenge mismatch error")
	}
}

func TestVerifyAuthEvent_WrongKind(t *testing.T) {
	sk := nostr.GeneratePrivateKey()
	pk, _ := nostr.GetPublicKey(sk)

	ev := nostr.Event{
		Kind:      1,
		CreatedAt: nostr.Now(),
		Tags:      nostr.Tags{{"challenge", "x"}},
	}
	ev.Sign(sk)
	raw, _ := json.Marshal(ev)

	if _, err := verifyAuthEvent(raw, "x", pk); err == nil {
		t.Fatalf("expected wrong-kind error")
	}
}

func TestVerifyAuthEvent_TamperedSignature(t *testing.T) {
	sk := nostr.GeneratePrivateKey()
	pk, _ := nostr.GetPublicKey(sk)

	ev := nostr.Event{
		Kind:      authEventKind,
		CreatedAt: nostr.Now(),
		Tags:      nostr.Tags{{"challenge", "x"}},
		Content:   "original",
	}
	ev.Sign(sk)
	ev.Content = "tampered"
	raw, _ := json.Marshal(ev)

	if _, err := verifyAuthEvent(raw, "x", pk); err == nil {
		t.Fatalf("expected tampered-content/signature error")
	}
}

func TestVerifyAuthEvent_StaleTimestamp(t *testing.T) {
	sk := nostr.GeneratePrivateKey()
	pk, _ := nostr.GetPublicKey(sk)

	ev := nostr.Event{
		Kind:      authEventKind,
		CreatedAt: nostr.Timestamp(time.Now().Add(-2 * challengeTTL).Unix()),
		Tags:      nostr.Tags{{"challenge", "x"}},
	}
	ev.Sign(sk)
	raw, _ := json.Marshal(ev)

	if _, err := verifyAuthEvent(raw, "x", pk); err == nil {
		t.Fatalf("expected stale-timestamp error")
	}
}
