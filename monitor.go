package main

import (
	"context"
	"log"
	"time"

	"github.com/nbd-wtf/go-nostr"
)

type Monitor struct {
	cfg     *Config
	eventCh chan *nostr.Event
}

func NewMonitor(cfg *Config) *Monitor {
	return &Monitor{
		cfg:     cfg,
		eventCh: make(chan *nostr.Event, 100),
	}
}

func (m *Monitor) Events() <-chan *nostr.Event {
	return m.eventCh
}

func (m *Monitor) Start(ctx context.Context, since time.Time) {
	ts := nostr.Timestamp(since.Unix())
	for _, url := range m.cfg.Relays {
		go m.subscribeRelay(ctx, url, ts)
	}
}

func (m *Monitor) subscribeRelay(ctx context.Context, url string, since nostr.Timestamp) {
	for {
		if ctx.Err() != nil {
			return
		}

		relay, err := nostr.RelayConnect(ctx, url)
		if err != nil {
			log.Printf("[monitor] connect failed %s: %v", url, err)
			sleepCtx(ctx, 30*time.Second)
			continue
		}

		log.Printf("[monitor] connected to %s", url)

		filters := nostr.Filters{{
			Authors: []string{m.cfg.watchPubkeyHex},
			Since:   &since,
		}}

		sub, err := relay.Subscribe(ctx, filters)
		if err != nil {
			log.Printf("[monitor] subscribe failed %s: %v", url, err)
			relay.Close()
			sleepCtx(ctx, 30*time.Second)
			continue
		}

		for ev := range sub.Events {
			if ev.CreatedAt > since {
				since = ev.CreatedAt
			}
			select {
			case m.eventCh <- ev:
			default:
				log.Printf("[monitor] channel full, dropping event")
			}
		}

		log.Printf("[monitor] subscription closed on %s, reconnecting...", url)
		relay.Close()
		sleepCtx(ctx, 5*time.Second)
	}
}

// FetchLatestEvent queries relays for the most recent event from the watched pubkey.
func (m *Monitor) FetchLatestEvent(ctx context.Context) (*nostr.Event, error) {
	for _, url := range m.cfg.Relays {
		relay, err := nostr.RelayConnect(ctx, url)
		if err != nil {
			continue
		}
		events, err := relay.QuerySync(ctx, nostr.Filter{
			Authors: []string{m.cfg.watchPubkeyHex},
			Limit:   1,
		})
		relay.Close()
		if err == nil && len(events) > 0 {
			return events[0], nil
		}
	}
	return nil, nil
}

func sleepCtx(ctx context.Context, d time.Duration) {
	select {
	case <-ctx.Done():
	case <-time.After(d):
	}
}
