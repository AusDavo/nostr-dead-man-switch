package main

import (
	"context"
	"encoding/json"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip19"
)

// watcherFixture is the minimum plumbing to drive UserWatcher.evaluate
// without touching real relays: a tempdir-backed UserStore, a clock we
// control, and recorders for ExecuteActions / SendWarningDM.
type watcherFixture struct {
	t              *testing.T
	w              *UserWatcher
	store          *UserStore
	npub           string
	now            time.Time
	execCalls      int
	execActions    []Action
	dmCalls        []int
	dmErr          error
	mu             sync.Mutex
	subjectPrivHex string
}

func newWatcherFixture(t *testing.T) *watcherFixture {
	t.Helper()

	// Stable keypair so the derived npub is predictable in logs.
	const subjectPriv = "0000000000000000000000000000000000000000000000000000000000000001"
	subjectPub, err := nostr.GetPublicKey(subjectPriv)
	if err != nil {
		t.Fatalf("GetPublicKey: %v", err)
	}
	subjectNpub, err := nip19.EncodePublicKey(subjectPub)
	if err != nil {
		t.Fatalf("EncodePublicKey: %v", err)
	}

	store, err := NewUserStore(filepath.Join(t.TempDir(), "users"))
	if err != nil {
		t.Fatalf("NewUserStore: %v", err)
	}
	if err := store.CreateUser(subjectNpub); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	host := &HostConfig{Relays: []string{"wss://example.invalid"}}
	uc := &UserConfig{
		SubjectNpub:      subjectNpub,
		SilenceThreshold: Duration{24 * time.Hour},
		WarningInterval:  Duration{2 * time.Hour},
		WarningCount:     2,
		CheckInterval:    Duration{time.Minute},
		Actions:          []Action{{Type: "webhook", Config: map[string]any{"url": "https://example.invalid"}}},
		UpdatedAt:        time.Unix(1700000000, 0).UTC(),
	}

	// Watcher priv distinct from subject.
	const watcherPriv = "0000000000000000000000000000000000000000000000000000000000000002"

	w, err := NewUserWatcher(host, uc, watcherPriv, store)
	if err != nil {
		t.Fatalf("NewUserWatcher: %v", err)
	}

	fx := &watcherFixture{
		t:              t,
		w:              w,
		store:          store,
		npub:           subjectNpub,
		now:            time.Unix(1700000000, 0).UTC(),
		subjectPrivHex: subjectPriv,
	}
	w.now = fx.nowFn
	w.execActions = fx.recordExec
	w.sendDM = fx.recordDM
	return fx
}

func (f *watcherFixture) nowFn() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.now
}

func (f *watcherFixture) advance(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.now = f.now.Add(d)
}

func (f *watcherFixture) recordExec(ctx context.Context, host *HostConfig, uc *UserConfig,
	priv, pub, subj string, actions []Action) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.execCalls++
	// Record a copy so callers freeing their slice doesn't change the fixture.
	f.execActions = append([]Action(nil), actions...)
}

func (f *watcherFixture) recordDM(ctx context.Context, host *HostConfig, uc *UserConfig,
	priv, pub, subj string, warningNum int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.dmCalls = append(f.dmCalls, warningNum)
	return f.dmErr
}

// seedLastSeen primes state so evaluate can compute silence against
// the fixture clock. lastSeen is set to now - silenceAgo.
func (f *watcherFixture) seedLastSeen(silenceAgo time.Duration) {
	f.w.state.mu.Lock()
	f.w.state.LastSeen = f.nowFn().Add(-silenceAgo)
	f.w.state.WarningSent = 0
	f.w.state.Triggered = false
	f.w.state.TriggeredAt = nil
	f.w.state.mu.Unlock()
}

func TestUserWatcherBelowThresholdNoOp(t *testing.T) {
	fx := newWatcherFixture(t)
	fx.seedLastSeen(1 * time.Hour) // threshold is 24h
	fx.w.evaluate(context.Background())
	if fx.execCalls != 0 {
		t.Fatalf("execCalls = %d, want 0", fx.execCalls)
	}
	if len(fx.dmCalls) != 0 {
		t.Fatalf("dmCalls = %v, want none", fx.dmCalls)
	}
}

func TestUserWatcherFirstWarningAtThreshold(t *testing.T) {
	fx := newWatcherFixture(t)
	fx.seedLastSeen(24 * time.Hour)
	fx.w.evaluate(context.Background())
	if len(fx.dmCalls) != 1 || fx.dmCalls[0] != 1 {
		t.Fatalf("dmCalls = %v, want [1]", fx.dmCalls)
	}
	fx.w.state.mu.Lock()
	defer fx.w.state.mu.Unlock()
	if fx.w.state.WarningSent != 1 {
		t.Fatalf("WarningSent = %d, want 1", fx.w.state.WarningSent)
	}
}

func TestUserWatcherSecondWarningAfterInterval(t *testing.T) {
	fx := newWatcherFixture(t)
	fx.seedLastSeen(24*time.Hour + 2*time.Hour) // past threshold + one interval
	fx.w.state.mu.Lock()
	fx.w.state.WarningSent = 1
	fx.w.state.mu.Unlock()

	fx.w.evaluate(context.Background())
	if len(fx.dmCalls) != 1 || fx.dmCalls[0] != 2 {
		t.Fatalf("dmCalls = %v, want [2]", fx.dmCalls)
	}
}

func TestUserWatcherTriggerAfterAllWarnings(t *testing.T) {
	fx := newWatcherFixture(t)
	// threshold 24h + interval 2h × count 2 = 28h silent → trigger.
	fx.seedLastSeen(28 * time.Hour)
	fx.w.state.mu.Lock()
	fx.w.state.WarningSent = 2
	fx.w.state.mu.Unlock()

	fx.w.evaluate(context.Background())
	if fx.execCalls != 1 {
		t.Fatalf("execCalls = %d, want 1", fx.execCalls)
	}
	fx.w.state.mu.Lock()
	defer fx.w.state.mu.Unlock()
	if !fx.w.state.Triggered {
		t.Fatal("Triggered = false, want true")
	}
	if fx.w.state.TriggeredAt == nil {
		t.Fatal("TriggeredAt = nil")
	}
}

func TestUserWatcherTriggeredIsIdempotent(t *testing.T) {
	fx := newWatcherFixture(t)
	fx.seedLastSeen(28 * time.Hour)
	fx.w.state.mu.Lock()
	fx.w.state.Triggered = true
	now := fx.nowFn()
	fx.w.state.TriggeredAt = &now
	fx.w.state.mu.Unlock()

	fx.w.evaluate(context.Background())
	fx.w.evaluate(context.Background())
	if fx.execCalls != 0 {
		t.Fatalf("execCalls = %d, want 0 (already-triggered)", fx.execCalls)
	}
	if len(fx.dmCalls) != 0 {
		t.Fatalf("dmCalls = %v, want none", fx.dmCalls)
	}
}

func TestUserWatcherEventResetsWarnings(t *testing.T) {
	fx := newWatcherFixture(t)
	// Start with a warning sent. Record an event — WarningSent resets.
	fx.w.state.mu.Lock()
	fx.w.state.LastSeen = fx.nowFn().Add(-25 * time.Hour)
	fx.w.state.WarningSent = 1
	fx.w.state.mu.Unlock()

	newCreated := fx.nowFn()
	fx.w.state.RecordEvent("new-event-id", newCreated)

	fx.w.state.mu.Lock()
	defer fx.w.state.mu.Unlock()
	if fx.w.state.WarningSent != 0 {
		t.Fatalf("WarningSent = %d after event, want 0", fx.w.state.WarningSent)
	}
	if !fx.w.state.LastSeen.Equal(newCreated) {
		t.Fatalf("LastSeen = %v, want %v", fx.w.state.LastSeen, newCreated)
	}
	if fx.w.state.LastEventID != "new-event-id" {
		t.Fatalf("LastEventID = %q", fx.w.state.LastEventID)
	}
}

func TestUserWatcherEmptyActionsTolerated(t *testing.T) {
	fx := newWatcherFixture(t)
	fx.w.mu.Lock()
	fx.w.userCfg.Actions = nil
	fx.w.mu.Unlock()

	fx.seedLastSeen(28 * time.Hour)
	fx.w.state.mu.Lock()
	fx.w.state.WarningSent = 2
	fx.w.state.mu.Unlock()

	fx.w.evaluate(context.Background())
	if fx.execCalls != 1 {
		t.Fatalf("execCalls = %d, want 1", fx.execCalls)
	}
	if len(fx.execActions) != 0 {
		t.Fatalf("execActions = %+v, want empty", fx.execActions)
	}
}

func TestUserWatcherReloadConfigSwapsUnderLock(t *testing.T) {
	fx := newWatcherFixture(t)
	updated := *fx.w.userCfg
	updated.SilenceThreshold = Duration{48 * time.Hour}
	fx.w.ReloadConfig(&updated)

	fx.seedLastSeen(30 * time.Hour) // below new 48h threshold
	fx.w.evaluate(context.Background())
	if fx.execCalls != 0 || len(fx.dmCalls) != 0 {
		t.Fatalf("reloaded threshold ignored: exec=%d dm=%v", fx.execCalls, fx.dmCalls)
	}
}

// fxDMEvent builds a valid self-DM event for the watcher in fx using
// fx.w.watcherPriv/Pub. The payload is a JSON-encoded UserConfig with
// the given updatedAt.
func (f *watcherFixture) dmEvent(t *testing.T, updatedAt time.Time, mutate func(uc *UserConfig)) *nostr.Event {
	t.Helper()
	uc := *f.w.userCfg
	uc.UpdatedAt = updatedAt
	if mutate != nil {
		mutate(&uc)
	}
	payload, err := json.Marshal(&uc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	ev, err := encryptSelfDM(f.w.watcherPriv, f.w.watcherPub, payload, updatedAt)
	if err != nil {
		t.Fatalf("encryptSelfDM: %v", err)
	}
	return ev
}

type reloadRecorder struct {
	count atomic.Int32
	ch    chan string
}

func newReloadRecorder() *reloadRecorder {
	return &reloadRecorder{ch: make(chan string, 8)}
}

func (r *reloadRecorder) fn(npub string) error {
	r.count.Add(1)
	select {
	case r.ch <- npub:
	default:
	}
	return nil
}

func (r *reloadRecorder) waitFor(t *testing.T, d time.Duration) {
	t.Helper()
	select {
	case <-r.ch:
	case <-time.After(d):
		t.Fatal("timeout waiting for reloadFn")
	}
}

func TestHydrateAppliesNewer(t *testing.T) {
	fx := newWatcherFixture(t)
	rr := newReloadRecorder()
	fx.w.reloadFn = rr.fn

	ev := fx.dmEvent(t, time.Unix(1700001000, 0).UTC(), func(uc *UserConfig) {
		uc.SilenceThreshold = Duration{48 * time.Hour}
	})
	fx.w.queryFn = func(ctx context.Context, relays []string, pub string,
		since *nostr.Timestamp, limit int) ([]*nostr.Event, error) {
		return []*nostr.Event{ev}, nil
	}

	if err := fx.w.hydrateConfig(context.Background()); err != nil {
		t.Fatalf("hydrate: %v", err)
	}

	onDisk, err := fx.store.LoadConfig(fx.npub)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if onDisk.SilenceThreshold.Duration != 48*time.Hour {
		t.Fatalf("SilenceThreshold = %v, want 48h", onDisk.SilenceThreshold.Duration)
	}
	rr.waitFor(t, time.Second)
}

func TestHydrateSkipsAlreadyApplied(t *testing.T) {
	fx := newWatcherFixture(t)
	rr := newReloadRecorder()
	fx.w.reloadFn = rr.fn

	ev := fx.dmEvent(t, time.Unix(1700001000, 0).UTC(), nil)
	fx.w.cacheMu.Lock()
	fx.w.dmCache.Record(ev.ID, time.Unix(int64(ev.CreatedAt), 0))
	fx.w.cacheMu.Unlock()

	fx.w.queryFn = func(ctx context.Context, relays []string, pub string,
		since *nostr.Timestamp, limit int) ([]*nostr.Event, error) {
		return []*nostr.Event{ev}, nil
	}

	if err := fx.w.hydrateConfig(context.Background()); err != nil {
		t.Fatalf("hydrate: %v", err)
	}
	if _, err := fx.store.LoadConfig(fx.npub); err == nil {
		t.Fatal("expected no config.json for already-applied event")
	}
	if rr.count.Load() != 0 {
		t.Fatalf("reloadFn fired %d times, want 0", rr.count.Load())
	}
}

func TestHydrateSkipsStale(t *testing.T) {
	fx := newWatcherFixture(t)
	rr := newReloadRecorder()
	fx.w.reloadFn = rr.fn

	// Seed cache with a newer LastApplied; incoming ev is older.
	newer := time.Unix(1700005000, 0).UTC()
	fx.w.cacheMu.Lock()
	fx.w.dmCache.Promote("seed", newer)
	fx.w.cacheMu.Unlock()

	ev := fx.dmEvent(t, time.Unix(1700001000, 0).UTC(), nil)
	fx.w.queryFn = func(ctx context.Context, relays []string, pub string,
		since *nostr.Timestamp, limit int) ([]*nostr.Event, error) {
		return []*nostr.Event{ev}, nil
	}

	if err := fx.w.hydrateConfig(context.Background()); err != nil {
		t.Fatalf("hydrate: %v", err)
	}
	if _, err := fx.store.LoadConfig(fx.npub); err == nil {
		t.Fatal("expected no config.json for stale event")
	}
	if rr.count.Load() != 0 {
		t.Fatalf("reloadFn fired %d times, want 0", rr.count.Load())
	}
}

func TestInboxAppliesLive(t *testing.T) {
	fx := newWatcherFixture(t)
	rr := newReloadRecorder()
	fx.w.reloadFn = rr.fn

	ev := fx.dmEvent(t, time.Unix(1700002000, 0).UTC(), func(uc *UserConfig) {
		uc.WarningCount = 5
	})

	ch := make(chan *nostr.Event, 2)
	ch <- ev
	fx.w.subFn = func(ctx context.Context, relays []string, pub string,
		since nostr.Timestamp) (selfDMInbox, error) {
		return (selfDMInbox)(ch), nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go fx.w.runInbox(ctx)

	rr.waitFor(t, time.Second)
	onDisk, err := fx.store.LoadConfig(fx.npub)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if onDisk.WarningCount != 5 {
		t.Fatalf("WarningCount = %d, want 5", onDisk.WarningCount)
	}
}

func TestInboxSkipsDuplicate(t *testing.T) {
	fx := newWatcherFixture(t)
	rr := newReloadRecorder()
	fx.w.reloadFn = rr.fn

	ev := fx.dmEvent(t, time.Unix(1700003000, 0).UTC(), nil)
	ch := make(chan *nostr.Event, 2)
	ch <- ev
	ch <- ev
	fx.w.subFn = func(ctx context.Context, relays []string, pub string,
		since nostr.Timestamp) (selfDMInbox, error) {
		return (selfDMInbox)(ch), nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go fx.w.runInbox(ctx)

	rr.waitFor(t, time.Second)
	time.Sleep(50 * time.Millisecond) // let the second event drain
	if got := rr.count.Load(); got != 1 {
		t.Fatalf("reloadFn fired %d times, want 1", got)
	}
}

func TestPublishConfigDMRoundTrip(t *testing.T) {
	fx := newWatcherFixture(t)

	var captured nostr.Event
	fx.w.publishFn = func(ctx context.Context, relays []string, ev nostr.Event) error {
		captured = ev
		return nil
	}

	uc := *fx.w.userCfg
	uc.WarningCount = 7
	uc.UpdatedAt = time.Time{} // PublishConfigDM assigns

	got, err := fx.w.PublishConfigDM(context.Background(), &uc)
	if err != nil {
		t.Fatalf("PublishConfigDM: %v", err)
	}
	if got.ID != captured.ID {
		t.Fatalf("captured ID = %q, want %q", captured.ID, got.ID)
	}

	payload, _, err := decryptSelfDM(fx.w.watcherPriv, fx.w.watcherPub, &captured)
	if err != nil {
		t.Fatalf("decryptSelfDM: %v", err)
	}
	var back UserConfig
	if err := json.Unmarshal(payload, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back.WarningCount != 7 {
		t.Fatalf("round-trip WarningCount = %d, want 7", back.WarningCount)
	}
	if back.SubjectNpub != fx.npub {
		t.Fatalf("SubjectNpub = %q", back.SubjectNpub)
	}

	onDisk, err := fx.store.LoadConfig(fx.npub)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if !onDisk.UpdatedAt.Equal(uc.UpdatedAt) {
		t.Fatalf("on-disk UpdatedAt = %v, want %v", onDisk.UpdatedAt, uc.UpdatedAt)
	}

	fx.w.cacheMu.Lock()
	defer fx.w.cacheMu.Unlock()
	if fx.w.dmCache.LastAppliedEventID != got.ID {
		t.Fatalf("cache LastAppliedEventID = %q", fx.w.dmCache.LastAppliedEventID)
	}
}

func TestPublishConfigDMMonotonic(t *testing.T) {
	fx := newWatcherFixture(t)
	fx.w.publishFn = func(ctx context.Context, relays []string, ev nostr.Event) error { return nil }

	// Fixture clock: time at fx.now. Seed cache LastApplied = now + 10s.
	future := fx.nowFn().Add(10 * time.Second)
	fx.w.cacheMu.Lock()
	fx.w.dmCache.Promote("seed", future)
	fx.w.cacheMu.Unlock()

	uc := *fx.w.userCfg
	uc.UpdatedAt = time.Time{}

	ev, err := fx.w.PublishConfigDM(context.Background(), &uc)
	if err != nil {
		t.Fatalf("PublishConfigDM: %v", err)
	}
	want := future.Add(time.Second)
	if !uc.UpdatedAt.Equal(want) {
		t.Fatalf("UpdatedAt = %v, want %v", uc.UpdatedAt, want)
	}
	if int64(ev.CreatedAt) != want.Unix() {
		t.Fatalf("ev.CreatedAt = %d, want %d", ev.CreatedAt, want.Unix())
	}
}

func TestUserWatcherSnapshotMirrorsState(t *testing.T) {
	fx := newWatcherFixture(t)
	fx.w.state.mu.Lock()
	fx.w.state.LastSeen = time.Unix(1700000000, 0).UTC()
	fx.w.state.WarningSent = 3
	fx.w.state.mu.Unlock()

	snap := fx.w.Snapshot()
	if snap.Npub != fx.npub {
		t.Fatalf("Npub = %q", snap.Npub)
	}
	if snap.WarningsSent != 3 {
		t.Fatalf("WarningsSent = %d", snap.WarningsSent)
	}
	if !snap.LastSeen.Equal(time.Unix(1700000000, 0).UTC()) {
		t.Fatalf("LastSeen = %v", snap.LastSeen)
	}
	if len(snap.RelayStatuses) != 1 {
		t.Fatalf("RelayStatuses = %v", snap.RelayStatuses)
	}
}
