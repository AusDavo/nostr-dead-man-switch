package main

import (
	"context"
	"fmt"
	"log"
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

	now         func() time.Time
	execActions userWatcherExecActions
	sendDM      userWatcherSendDM
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
		done:        make(chan struct{}),
		now:         time.Now,
		execActions: ExecuteActions,
		sendDM:      SendWarningDM,
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
// subscriptions are bound at Start time.
func (w *UserWatcher) ReloadConfig(uc *UserConfig) {
	w.mu.Lock()
	w.userCfg = uc
	w.mu.Unlock()
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
