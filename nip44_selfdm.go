package main

import (
	"fmt"
	"time"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip04"
	"github.com/nbd-wtf/go-nostr/nip44"
)

// encryptSelfDM builds a kind-4 event whose content is a NIP-44
// ciphertext of payload, sealed with a conversation key derived from
// (watcherPub, watcherPriv) self-to-self. The event is tagged
// `p=watcherPubHex` so relay policies that require a recipient tag on
// kind-4 still accept it, and signed with watcherPrivHex.
func encryptSelfDM(watcherPrivHex, watcherPubHex string, payload []byte, createdAt time.Time) (*nostr.Event, error) {
	convKey, err := nip44.GenerateConversationKey(watcherPubHex, watcherPrivHex)
	if err != nil {
		return nil, fmt.Errorf("encryptSelfDM: conversation key: %w", err)
	}
	ciphertext, err := nip44.Encrypt(string(payload), convKey)
	if err != nil {
		return nil, fmt.Errorf("encryptSelfDM: encrypt: %w", err)
	}
	ev := nostr.Event{
		PubKey:    watcherPubHex,
		CreatedAt: nostr.Timestamp(createdAt.Unix()),
		Kind:      4,
		Content:   ciphertext,
		Tags:      nostr.Tags{nostr.Tag{"p", watcherPubHex}},
	}
	if err := ev.Sign(watcherPrivHex); err != nil {
		return nil, fmt.Errorf("encryptSelfDM: sign: %w", err)
	}
	return &ev, nil
}

// decryptSelfDM recovers the plaintext payload and created-at from a
// self-DM event. It first attempts NIP-44; on failure it falls back to
// NIP-04 for legacy tolerance. Author match is load-bearing: events
// whose PubKey != watcherPubHex are rejected outright. A mismatching
// p-tag is tolerated silently because some relays mangle tags.
func decryptSelfDM(watcherPrivHex, watcherPubHex string, ev *nostr.Event) ([]byte, time.Time, error) {
	if ev == nil {
		return nil, time.Time{}, fmt.Errorf("decryptSelfDM: nil event")
	}
	if ev.Kind != 4 {
		return nil, time.Time{}, fmt.Errorf("decryptSelfDM: kind=%d, want 4", ev.Kind)
	}
	if ev.PubKey != watcherPubHex {
		return nil, time.Time{}, fmt.Errorf("decryptSelfDM: author mismatch")
	}

	convKey, err := nip44.GenerateConversationKey(watcherPubHex, watcherPrivHex)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("decryptSelfDM: conversation key: %w", err)
	}
	if plain, err := nip44.Decrypt(ev.Content, convKey); err == nil {
		return []byte(plain), time.Unix(int64(ev.CreatedAt), 0), nil
	} else {
		nip44Err := err
		shared, sErr := nip04.ComputeSharedSecret(watcherPubHex, watcherPrivHex)
		if sErr != nil {
			return nil, time.Time{}, fmt.Errorf("decryptSelfDM: %w", nip44Err)
		}
		if plain, dErr := nip04.Decrypt(ev.Content, shared); dErr == nil {
			return []byte(plain), time.Unix(int64(ev.CreatedAt), 0), nil
		}
		return nil, time.Time{}, fmt.Errorf("decryptSelfDM: %w", nip44Err)
	}
}

// selfDMFilter builds a subscription filter for the watcher's self-DMs:
// kind=4, authored by and p-tagged to watcherPubHex, bounded by since
// and limit.
func selfDMFilter(watcherPubHex string, since *nostr.Timestamp, limit int) nostr.Filter {
	f := nostr.Filter{
		Kinds:   []int{4},
		Authors: []string{watcherPubHex},
		Tags:    nostr.TagMap{"p": []string{watcherPubHex}},
		Limit:   limit,
	}
	if since != nil {
		f.Since = since
	}
	return f
}
