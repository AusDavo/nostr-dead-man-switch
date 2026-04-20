package main

import (
	"testing"
	"time"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip04"
)

const (
	testWatcherPriv = "0000000000000000000000000000000000000000000000000000000000000003"
	testOtherPriv   = "0000000000000000000000000000000000000000000000000000000000000004"
)

func testWatcherPub(t *testing.T) string {
	t.Helper()
	pub, err := nostr.GetPublicKey(testWatcherPriv)
	if err != nil {
		t.Fatalf("GetPublicKey: %v", err)
	}
	return pub
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	pub := testWatcherPub(t)
	payload := []byte(`{"hello":"federation"}`)
	created := time.Unix(1700000000, 0).UTC()

	ev, err := encryptSelfDM(testWatcherPriv, pub, payload, created)
	if err != nil {
		t.Fatalf("encryptSelfDM: %v", err)
	}
	if ev.Kind != 4 {
		t.Fatalf("Kind = %d", ev.Kind)
	}
	if ev.PubKey != pub {
		t.Fatalf("PubKey = %q", ev.PubKey)
	}
	if len(ev.Tags) == 0 || ev.Tags[0][0] != "p" || ev.Tags[0][1] != pub {
		t.Fatalf("p-tag = %+v", ev.Tags)
	}
	ok, err := ev.CheckSignature()
	if err != nil || !ok {
		t.Fatalf("signature invalid: ok=%v err=%v", ok, err)
	}

	got, gotCreated, err := decryptSelfDM(testWatcherPriv, pub, ev)
	if err != nil {
		t.Fatalf("decryptSelfDM: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("plaintext = %q, want %q", got, payload)
	}
	if !gotCreated.Equal(created) {
		t.Fatalf("createdAt = %v, want %v", gotCreated, created)
	}
}

func TestDecryptSelfDM_WrongAuthor(t *testing.T) {
	pub := testWatcherPub(t)
	otherPub, err := nostr.GetPublicKey(testOtherPriv)
	if err != nil {
		t.Fatalf("GetPublicKey: %v", err)
	}
	ev, err := encryptSelfDM(testOtherPriv, otherPub, []byte("hi"), time.Unix(1700000000, 0))
	if err != nil {
		t.Fatalf("encryptSelfDM: %v", err)
	}
	if _, _, err := decryptSelfDM(testWatcherPriv, pub, ev); err == nil {
		t.Fatal("expected author-mismatch error")
	}
}

func TestDecryptSelfDM_FallbackToNIP04(t *testing.T) {
	pub := testWatcherPub(t)
	shared, err := nip04.ComputeSharedSecret(pub, testWatcherPriv)
	if err != nil {
		t.Fatalf("ComputeSharedSecret: %v", err)
	}
	content, err := nip04.Encrypt("legacy-payload", shared)
	if err != nil {
		t.Fatalf("nip04.Encrypt: %v", err)
	}
	ev := nostr.Event{
		PubKey:    pub,
		CreatedAt: nostr.Timestamp(time.Unix(1700000000, 0).Unix()),
		Kind:      4,
		Content:   content,
		Tags:      nostr.Tags{nostr.Tag{"p", pub}},
	}
	if err := ev.Sign(testWatcherPriv); err != nil {
		t.Fatalf("sign: %v", err)
	}

	got, _, err := decryptSelfDM(testWatcherPriv, pub, &ev)
	if err != nil {
		t.Fatalf("decryptSelfDM: %v", err)
	}
	if string(got) != "legacy-payload" {
		t.Fatalf("plaintext = %q", got)
	}
}

func TestDecryptSelfDM_BothFail(t *testing.T) {
	pub := testWatcherPub(t)
	ev := nostr.Event{
		PubKey:    pub,
		CreatedAt: nostr.Timestamp(time.Unix(1700000000, 0).Unix()),
		Kind:      4,
		Content:   "not-a-real-ciphertext",
		Tags:      nostr.Tags{nostr.Tag{"p", pub}},
	}
	if err := ev.Sign(testWatcherPriv); err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, _, err := decryptSelfDM(testWatcherPriv, pub, &ev); err == nil {
		t.Fatal("expected decrypt error on garbage")
	}
}

func TestSelfDMFilter_Shape(t *testing.T) {
	pub := testWatcherPub(t)
	since := nostr.Timestamp(1700000000)
	f := selfDMFilter(pub, &since, 20)
	if len(f.Kinds) != 1 || f.Kinds[0] != 4 {
		t.Fatalf("Kinds = %v", f.Kinds)
	}
	if len(f.Authors) != 1 || f.Authors[0] != pub {
		t.Fatalf("Authors = %v", f.Authors)
	}
	ps, ok := f.Tags["p"]
	if !ok || len(ps) != 1 || ps[0] != pub {
		t.Fatalf("#p tag = %v", f.Tags)
	}
	if f.Limit != 20 {
		t.Fatalf("Limit = %d", f.Limit)
	}
	if f.Since == nil || *f.Since != since {
		t.Fatalf("Since = %v", f.Since)
	}

	f2 := selfDMFilter(pub, nil, 5)
	if f2.Since != nil {
		t.Fatalf("expected nil Since when not provided")
	}
}
