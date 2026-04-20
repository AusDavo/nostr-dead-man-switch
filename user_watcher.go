package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sort"
	"sync"
	"time"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip19"
)

// userWatcherExecActions and userWatcherSendDM are the test seams for
// the package-level ExecuteActions and SendWarningDM. UserWatcher.Run
// invokes them instead of the package functions directly so tests can
// inject recorders.
type userWatcherExecActions func(ctx context.Context, host *HostConfig, uc *UserConfig,
	watcherPrivHex, watcherPubHex, subjectPubHex string, actions []Action)

type userWatcherSendDM func(ctx context.Context, host *HostConfig, uc *UserConfig,
	watcherPrivHex, watcherPubHex, subjectPubHex string, warningNum int) error

// userWatcherPublish is the test seam for publishToRelays. PublishConfigDM
// calls it instead of the package function so tests can capture events
// without bringing up real relays.
type userWatcherPublish func(ctx context.Context, relays []string, ev nostr.Event) error

// userWatcherQueryFn / userWatcherSubFn are test seams for the relay-IO
// helpers in nip44_selfdm.go. Defaulted to the real implementations in
// NewUserWatcher; tests overwrite with canned channels/slices.
type userWatcherQueryFn func(ctx context.Context, relays []string, watcherPubHex string,
	since *nostr.Timestamp, limit int) ([]*nostr.Event, error)

type userWatcherSubFn func(ctx context.Context, relays []string, watcherPubHex string,
	since nostr.Timestamp) (selfDMInbox, error)

// WatcherSnapshot is an instantaneous, read-only view of a watcher for
// the status endpoints (wired up in #8).
type WatcherSnapshot struct {
	Npub          string
	LastSeen      time.Time
	WarningsSent  int
	Triggered     bool
	TriggeredAt   *time.Time
	RelayStatuses []RelayStatus
}

// UserWatcher owns one tenant's evaluate loop: its State, per-user
// Monitor, and persistence. Lifecycle is owned by the Registry; call
// Run exactly once, then Stop to unwind.
type UserWatcher struct {
	host        *HostConfig
	watcherPriv string // hex, in-memory only
	watcherPub  string // hex
	subjectPub  string // hex
	store       *UserStore
	monitor     *Monitor
	state       *State

	mu      sync.RWMutex // guards userCfg
	userCfg *UserConfig

	runMu  sync.Mutex // guards cancel; released before waiting on done
	cancel context.CancelFunc
	done   chan struct{}

	cacheMu  sync.Mutex // guards dmCache (separate from mu to avoid lock-ordering with ReloadConfig)
	dmCache  *ConfigDMCache

	reloadFn func(npub string) error // registry.Reload; may be nil in tests

	now         func() time.Time
	execActions userWatcherExecActions
	sendDM      userWatcherSendDM
	publishFn   userWatcherPublish
	queryFn     userWatcherQueryFn
	subFn       userWatcherSubFn
}

// NewUserWatcher validates the UserConfig, loads state from the store,
// derives the watcher pubkey, and constructs a Monitor scoped to the
// subject. Returns an error if the UserConfig is invalid, the nsec
// cannot produce a pubkey, or the state file exists but is unreadable.
func NewUserWatcher(host *HostConfig, uc *UserConfig, watcherPrivHex string,
	store *UserStore) (*UserWatcher, error) {
	if host == nil {
		return nil, fmt.Errorf("user_watcher: host is nil")
	}
	if err := uc.Validate(); err != nil {
		return nil, fmt.Errorf("user_watcher: %w", err)
	}
	prefix, v, err := nip19.Decode(uc.SubjectNpub)
	if err != nil || prefix != "npub" {
		return nil, fmt.Errorf("user_watcher: decoding subject npub: %w", err)
	}
	subjectPub, ok := v.(string)
	if !ok {
		return nil, fmt.Errorf("user_watcher: subject npub decoded to non-hex")
	}
	watcherPub, err := nostr.GetPublicKey(watcherPrivHex)
	if err != nil {
		return nil, fmt.Errorf("user_watcher: deriving watcher pubkey: %w", err)
	}

	state, err := store.LoadUserState(uc.SubjectNpub)
	if err != nil {
		return nil, fmt.Errorf("user_watcher: loading state: %w", err)
	}

	cache, err := store.LoadDMCache(uc.SubjectNpub)
	if err != nil {
		return nil, fmt.Errorf("user_watcher: loading dm cache: %w", err)
	}

	relays := uc.Relays
	if len(relays) == 0 {
		relays = host.Relays
	}

	return &UserWatcher{
		host:        host,
		watcherPriv: watcherPrivHex,
		watcherPub:  watcherPub,
		subjectPub:  subjectPub,
		store:       store,
		monitor:     NewMonitor(relays, subjectPub),
		state:       state,
		userCfg:     uc,
		dmCache:     cache,
		done:        make(chan struct{}),
		now:         time.Now,
		execActions: ExecuteActions,
		sendDM:      SendWarningDM,
		publishFn:   publishToRelays,
		queryFn:     querySelfDMs,
		subFn:       subscribeSelfDMs,
	}, nil
}

// Run blocks until ctx is cancelled. On exit it persists the latest
// state via the UserStore before returning. Safe to call exactly once.
func (w *UserWatcher) Run(ctx context.Context) error {
	defer close(w.done)

	runCtx, cancel := context.WithCancel(ctx)
	w.runMu.Lock()
	w.cancel = cancel
	w.runMu.Unlock()
	defer cancel()

	w.mu.RLock()
	npub := w.userCfg.SubjectNpub
	checkInterval := w.userCfg.CheckInterval.Duration
	threshold := w.userCfg.SilenceThreshold.Duration
	warnInterval := w.userCfg.WarningInterval.Duration
	warnCount := w.userCfg.WarningCount
	w.mu.RUnlock()

	w.state.mu.Lock()
	triggered := w.state.Triggered
	triggeredAt := w.state.TriggeredAt
	lastSeenZero := w.state.LastSeen.IsZero()
	w.state.mu.Unlock()

	if triggered {
		log.Printf("[watcher %s] already triggered at %v; idle until state is cleared", npub, triggeredAt)
		<-runCtx.Done()
		return nil
	}

	if lastSeenZero {
		log.Printf("[watcher %s] no previous state, fetching latest event", npub)
		ev, err := w.monitor.FetchLatestEvent(runCtx)
		if err == nil && ev != nil {
			w.state.RecordEvent(ev.ID, time.Unix(int64(ev.CreatedAt), 0))
			log.Printf("[watcher %s] seeded last_seen from kind=%d", npub, ev.Kind)
		} else {
			w.state.RecordEvent("", w.now())
			log.Printf("[watcher %s] no events found, seeding last_seen with now", npub)
		}
		if err := w.store.SaveUserState(npub, w.state); err != nil {
			log.Printf("[watcher %s] initial state save: %v", npub, err)
		}
	}

	log.Printf("[watcher %s] threshold=%s warning_interval=%s warnings=%d check=%s",
		npub, threshold, warnInterval, warnCount, checkInterval)

	if err := w.hydrateConfig(runCtx); err != nil {
		log.Printf("[watcher %s] hydrate: %v", npub, err)
	}
	go w.runInbox(runCtx)

	w.state.mu.Lock()
	since := w.state.LastSeen
	w.state.mu.Unlock()
	w.monitor.Start(runCtx, since)

	ticker := time.NewTicker(checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-runCtx.Done():
			if err := w.store.SaveUserState(npub, w.state); err != nil {
				log.Printf("[watcher %s] final save: %v", npub, err)
			} else {
				log.Printf("[watcher %s] persisted state", npub)
			}
			return nil

		case ev := <-w.monitor.Events():
			created := time.Unix(int64(ev.CreatedAt), 0)
			idShort := ev.ID
			if len(idShort) > 12 {
				idShort = idShort[:12]
			}
			log.Printf("[watcher %s] event kind=%d id=%s at %s", npub, ev.Kind, idShort, created.Format(time.RFC3339))
			w.state.RecordEvent(ev.ID, created)
			if err := w.store.SaveUserState(npub, w.state); err != nil {
				log.Printf("[watcher %s] state save: %v", npub, err)
			}

		case <-ticker.C:
			w.evaluate(runCtx)
		}
	}
}

// evaluate runs one pass of the silence-threshold/warning/trigger
// decision tree. Split out of Run so tests can drive it with a fake
// clock without touching the Monitor or ticker.
func (w *UserWatcher) evaluate(ctx context.Context) {
	w.mu.RLock()
	uc := w.userCfg
	w.mu.RUnlock()

	npub := uc.SubjectNpub
	threshold := uc.SilenceThreshold.Duration
	warnInterval := uc.WarningInterval.Duration
	warnCount := uc.WarningCount

	w.state.mu.Lock()
	if w.state.Triggered {
		w.state.mu.Unlock()
		return
	}
	silence := w.now().Sub(w.state.LastSeen)
	warningsSent := w.state.WarningSent
	w.state.mu.Unlock()

	log.Printf("[watcher %s] silent=%s threshold=%s warnings=%d/%d",
		npub, silence.Round(time.Minute), threshold, warningsSent, warnCount)

	if silence < threshold {
		return
	}

	pastThreshold := silence - threshold
	triggerAfter := warnInterval * time.Duration(warnCount)
	if pastThreshold >= triggerAfter {
		log.Printf("[watcher %s] TRIGGERED", npub)
		w.state.RecordTrigger()
		if err := w.store.SaveUserState(npub, w.state); err != nil {
			log.Printf("[watcher %s] trigger save: %v", npub, err)
		}
		w.execActions(ctx, w.host, uc, w.watcherPriv, w.watcherPub, w.subjectPub, uc.Actions)
		return
	}

	// warnInterval is guaranteed >0 here because warnCount>0 is the only
	// way to reach this branch without triggering above; Validate enforces
	// the pairing.
	expected := int(pastThreshold/warnInterval) + 1
	if expected > warnCount {
		expected = warnCount
	}
	if warningsSent < expected {
		next := warningsSent + 1
		log.Printf("[watcher %s] sending warning DM %d/%d", npub, next, warnCount)
		if err := w.sendDM(ctx, w.host, uc, w.watcherPriv, w.watcherPub, w.subjectPub, next); err != nil {
			log.Printf("[watcher %s] DM failed: %v", npub, err)
		}
		w.state.RecordWarning()
		if err := w.store.SaveUserState(npub, w.state); err != nil {
			log.Printf("[watcher %s] warning save: %v", npub, err)
		}
	}
}

// Stop cancels Run's context and waits for Run to return. Idempotent:
// subsequent calls block on done and return once Run has exited.
func (w *UserWatcher) Stop() {
	w.runMu.Lock()
	cancel := w.cancel
	w.runMu.Unlock()
	if cancel != nil {
		cancel()
	}
	<-w.done
}

// ReloadConfig swaps the active UserConfig. Callers are responsible for
// handling relay changes: Registry.Reload compares the old and new
// Relays and restarts the watcher when they differ, because Monitor
// subscriptions are bound at Start time. Also refreshes the in-memory
// dmCache from disk so a Reload-after-apply doesn't keep a stale cache.
func (w *UserWatcher) ReloadConfig(uc *UserConfig) {
	w.mu.Lock()
	w.userCfg = uc
	npub := uc.SubjectNpub
	w.mu.Unlock()

	if cache, err := w.store.LoadDMCache(npub); err == nil {
		w.cacheMu.Lock()
		w.dmCache = cache
		w.cacheMu.Unlock()
	} else {
		log.Printf("[watcher %s] reload dm cache: %v", npub, err)
	}
}

// hydrateConfig runs once at the start of Run. It queries self-DMs
// across the watcher's effective relays, applies any new payloads in
// ascending created_at order, and triggers a registry reload if the
// local config changed. Best-effort: per-event failures are logged but
// do not abort the hydrate.
func (w *UserWatcher) hydrateConfig(ctx context.Context) error {
	w.mu.RLock()
	npub := w.userCfg.SubjectNpub
	w.mu.RUnlock()

	w.cacheMu.Lock()
	var since *nostr.Timestamp
	if !w.dmCache.LastAppliedCreatedAt.IsZero() {
		ts := nostr.Timestamp(w.dmCache.LastAppliedCreatedAt.Unix())
		since = &ts
	}
	w.cacheMu.Unlock()

	relays := w.effectiveRelays()
	events, err := w.queryFn(ctx, relays, w.watcherPub, since, 20)
	if err != nil {
		return fmt.Errorf("hydrateConfig: query: %w", err)
	}
	sort.Slice(events, func(i, j int) bool { return events[i].CreatedAt < events[j].CreatedAt })

	applied := false
	for _, ev := range events {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if w.applyOne(ev, npub, "hydrate") {
			applied = true
		}
	}

	if applied {
		if uc, err := w.store.LoadConfig(npub); err == nil {
			w.mu.Lock()
			w.userCfg = uc
			w.mu.Unlock()
		}
		if w.reloadFn != nil {
			go func() {
				if err := w.reloadFn(npub); err != nil {
					log.Printf("[watcher %s] reload after hydrate: %v", npub, err)
				}
			}()
		}
	}
	return nil
}

// runInbox subscribes to live self-DMs and applies each one as it
// arrives. Exits when ctx is Done. The goroutine may briefly outlive
// Run during a Stop+Start triggered from reloadFn — that's fine because
// it strictly selects on ctx.Done and does no further work after.
func (w *UserWatcher) runInbox(ctx context.Context) {
	w.mu.RLock()
	npub := w.userCfg.SubjectNpub
	w.mu.RUnlock()

	w.cacheMu.Lock()
	since := nostr.Timestamp(w.now().Unix())
	if last := w.dmCache.LastAppliedCreatedAt; !last.IsZero() && nostr.Timestamp(last.Unix()) > since {
		since = nostr.Timestamp(last.Unix())
	}
	w.cacheMu.Unlock()

	relays := w.effectiveRelays()
	inbox, err := w.subFn(ctx, relays, w.watcherPub, since)
	if err != nil {
		log.Printf("[watcher %s] inbox subscribe: %v", npub, err)
		return
	}

	for {
		select {
		case <-ctx.Done():
			return
		case ev := <-inbox:
			if ev == nil {
				continue
			}
			if w.applyOne(ev, npub, "inbox") && w.reloadFn != nil {
				go func() {
					if err := w.reloadFn(npub); err != nil {
						log.Printf("[watcher %s] reload after inbox: %v", npub, err)
					}
				}()
			}
		}
	}
}

// applyOne is the shared decrypt/apply path for hydrate and inbox. It
// returns true iff the event produced a config change on disk. Caller
// is responsible for any follow-on reloadFn call.
func (w *UserWatcher) applyOne(ev *nostr.Event, npub, source string) bool {
	w.cacheMu.Lock()
	defer w.cacheMu.Unlock()

	if w.dmCache.Has(ev.ID) {
		return false
	}
	payload, _, err := decryptSelfDM(w.watcherPriv, w.watcherPub, ev)
	if err != nil {
		w.dmCache.Record(ev.ID, time.Unix(int64(ev.CreatedAt), 0))
		_ = w.store.SaveDMCache(npub, w.dmCache)
		log.Printf("[watcher %s] %s decrypt %s: %v", npub, source, ev.ID, err)
		return false
	}
	_, err = applyInboundDM(w.store, npub, w.dmCache, ev, payload)
	if err != nil {
		if !errors.Is(err, ErrStaleDM) && !errors.Is(err, ErrAlreadyApplied) {
			log.Printf("[watcher %s] %s apply %s: %v", npub, source, ev.ID, err)
		}
		return false
	}
	log.Printf("[watcher %s] %s applied inbound DM %s", npub, source, ev.ID)
	return true
}

// PublishConfigDM seals uc as a kind-4 + NIP-44 self-DM and publishes
// it to the watcher's effective relays. UpdatedAt is assigned here to
// ensure strict monotonicity against the local cache, so a burst of
// dashboard saves can't race into a tie. On success, the new config is
// persisted locally and the published event id is recorded in the cache
// so our own inbox subscription ignores it.
func (w *UserWatcher) PublishConfigDM(ctx context.Context, uc *UserConfig) (*nostr.Event, error) {
	w.mu.RLock()
	npub := w.userCfg.SubjectNpub
	w.mu.RUnlock()
	uc.SubjectNpub = npub

	w.cacheMu.Lock()
	now := w.now()
	next := w.dmCache.LastAppliedCreatedAt.Add(time.Second)
	if next.After(now) {
		uc.UpdatedAt = next
	} else {
		uc.UpdatedAt = now
	}
	w.cacheMu.Unlock()

	if err := uc.Validate(); err != nil {
		return nil, fmt.Errorf("PublishConfigDM: validate: %w", err)
	}

	payload, err := json.Marshal(uc)
	if err != nil {
		return nil, fmt.Errorf("PublishConfigDM: marshal: %w", err)
	}
	ev, err := encryptSelfDM(w.watcherPriv, w.watcherPub, payload, uc.UpdatedAt)
	if err != nil {
		return nil, err
	}

	relays := w.effectiveRelaysFor(uc)
	if err := w.publishFn(ctx, relays, *ev); err != nil {
		return nil, fmt.Errorf("PublishConfigDM: publish: %w", err)
	}

	w.cacheMu.Lock()
	w.dmCache.Record(ev.ID, uc.UpdatedAt)
	w.dmCache.Promote(ev.ID, uc.UpdatedAt)
	if err := w.store.SaveDMCache(npub, w.dmCache); err != nil {
		log.Printf("[watcher %s] publish save cache: %v", npub, err)
	}
	w.cacheMu.Unlock()

	if err := w.store.SaveConfig(npub, uc); err != nil {
		return nil, fmt.Errorf("PublishConfigDM: save config: %w", err)
	}
	w.mu.Lock()
	w.userCfg = uc
	w.mu.Unlock()

	return ev, nil
}

func (w *UserWatcher) effectiveRelays() []string {
	w.mu.RLock()
	defer w.mu.RUnlock()
	if len(w.userCfg.Relays) > 0 {
		return append([]string(nil), w.userCfg.Relays...)
	}
	if w.host != nil {
		return append([]string(nil), w.host.Relays...)
	}
	return nil
}

func (w *UserWatcher) effectiveRelaysFor(uc *UserConfig) []string {
	if uc != nil && len(uc.Relays) > 0 {
		return append([]string(nil), uc.Relays...)
	}
	if w.host != nil {
		return append([]string(nil), w.host.Relays...)
	}
	return nil
}

// WatcherPrivHex returns the in-memory bot private key. Exposed so the
// /admin/config/test-action handler can fire a nostr_note on the user's
// behalf; never log this value.
func (w *UserWatcher) WatcherPrivHex() string { return w.watcherPriv }

// WatcherPubHex returns the bot public key (hex).
func (w *UserWatcher) WatcherPubHex() string { return w.watcherPub }

// Config returns a deep-copy snapshot of the current UserConfig. Callers
// may mutate the returned value safely; it is not shared with the
// watcher's internal state.
func (w *UserWatcher) Config() *UserConfig {
	w.mu.RLock()
	defer w.mu.RUnlock()
	if w.userCfg == nil {
		return nil
	}
	uc := *w.userCfg
	if w.userCfg.Relays != nil {
		uc.Relays = append([]string(nil), w.userCfg.Relays...)
	}
	if w.userCfg.Actions != nil {
		uc.Actions = append([]Action(nil), w.userCfg.Actions...)
	}
	return &uc
}

// Snapshot returns the current public-facing view of the watcher.
func (w *UserWatcher) Snapshot() WatcherSnapshot {
	w.mu.RLock()
	npub := w.userCfg.SubjectNpub
	w.mu.RUnlock()

	w.state.mu.Lock()
	snap := WatcherSnapshot{
		Npub:         npub,
		LastSeen:     w.state.LastSeen,
		WarningsSent: w.state.WarningSent,
		Triggered:    w.state.Triggered,
	}
	if w.state.TriggeredAt != nil {
		t := *w.state.TriggeredAt
		snap.TriggeredAt = &t
	}
	w.state.mu.Unlock()

	snap.RelayStatuses = w.monitor.Statuses()
	return snap
}
