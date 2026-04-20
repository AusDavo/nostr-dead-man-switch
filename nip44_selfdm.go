package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip04"
	"github.com/nbd-wtf/go-nostr/nip44"
)

// selfDMInbox is the output channel type for subscribeSelfDMs. It is
// buffered and never closed by the subscriber; callers terminate the
// subscription by cancelling the ctx passed to subscribeSelfDMs.
type selfDMInbox <-chan *nostr.Event

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

// querySelfDMs issues a one-shot QuerySync against each relay and merges
// the results, deduping by event id. Per-relay failures are logged but
// do not fail the whole call — config propagation should survive one or
// more unreachable relays. Ctx cancellation aborts in-flight work.
func querySelfDMs(ctx context.Context, relays []string, watcherPubHex string,
	since *nostr.Timestamp, limit int) ([]*nostr.Event, error) {
	filter := selfDMFilter(watcherPubHex, since, limit)
	seen := make(map[string]bool)
	var merged []*nostr.Event
	for _, url := range relays {
		if ctx.Err() != nil {
			return merged, ctx.Err()
		}
		relay, err := nostr.RelayConnect(ctx, url)
		if err != nil {
			log.Printf("[selfdm] query connect failed %s: %v", url, err)
			continue
		}
		events, err := relay.QuerySync(ctx, filter)
		relay.Close()
		if err != nil {
			log.Printf("[selfdm] query failed %s: %v", url, err)
			continue
		}
		for _, ev := range events {
			if seen[ev.ID] {
				continue
			}
			seen[ev.ID] = true
			merged = append(merged, ev)
		}
	}
	return merged, nil
}

// subscribeSelfDMs starts one goroutine per relay that reconnects on
// disconnect and pushes received events onto a single buffered channel.
// Runs until ctx is Done; the returned channel is never closed. Mirrors
// the reconnect cadence of Monitor.subscribeRelay (30s / 5s backoff)
// with a filter specific to self-DMs.
func subscribeSelfDMs(ctx context.Context, relays []string, watcherPubHex string,
	since nostr.Timestamp) (selfDMInbox, error) {
	out := make(chan *nostr.Event, 64)
	for _, url := range relays {
		go subscribeSelfDMRelay(ctx, url, watcherPubHex, since, out)
	}
	return (selfDMInbox)(out), nil
}

func subscribeSelfDMRelay(ctx context.Context, url string, watcherPubHex string,
	since nostr.Timestamp, out chan<- *nostr.Event) {
	for {
		if ctx.Err() != nil {
			return
		}
		relay, err := nostr.RelayConnect(ctx, url)
		if err != nil {
			log.Printf("[selfdm] connect failed %s: %v", url, err)
			sleepCtx(ctx, 30*time.Second)
			continue
		}
		sub, err := relay.Subscribe(ctx, nostr.Filters{selfDMFilter(watcherPubHex, &since, 0)})
		if err != nil {
			log.Printf("[selfdm] subscribe failed %s: %v", url, err)
			relay.Close()
			sleepCtx(ctx, 5*time.Second)
			continue
		}
		for ev := range sub.Events {
			if ev.CreatedAt > since {
				since = ev.CreatedAt
			}
			select {
			case <-ctx.Done():
				relay.Close()
				return
			case out <- ev:
			default:
				log.Printf("[selfdm] inbox full, dropping event %s", ev.ID)
			}
		}
		log.Printf("[selfdm] sub closed on %s, reconnecting...", url)
		relay.Close()
		sleepCtx(ctx, 5*time.Second)
	}
}
