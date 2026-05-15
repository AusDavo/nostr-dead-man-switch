package main

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nbd-wtf/go-nostr/nip19"
)

// fakeWatcher is a stand-in for UserWatcher in Registry tests. Run
// blocks until ctx cancels, optionally holding ctx-done for a delay to
// let tests assert StopAll is synchronous.
type fakeWatcher struct {
	npub      string
	stopped   atomic.Bool
	reloads   atomic.Int32
	triggered atomic.Bool
	holdDur   time.Duration
}

func (f *fakeWatcher) Run(ctx context.Context) error {
	<-ctx.Done()
	if f.holdDur > 0 {
		time.Sleep(f.holdDur)
	}
	f.stopped.Store(true)
	return nil
}

func (f *fakeWatcher) Stop()                       {}
func (f *fakeWatcher) ReloadConfig(uc *UserConfig) { f.reloads.Add(1) }
func (f *fakeWatcher) Snapshot() WatcherSnapshot {
	return WatcherSnapshot{Npub: f.npub, Triggered: f.triggered.Load()}
}

type fakeFactory struct {
	mu      sync.Mutex
	created []*fakeWatcher
	relays  map[string][]string
	holds   map[string]time.Duration
}

func newFakeFactory() *fakeFactory {
	return &fakeFactory{
		relays: map[string][]string{},
		holds:  map[string]time.Duration{},
	}
}

func (ff *fakeFactory) make(npub string) (supervisedWatcher, *UserWatcher, *UserConfig, error) {
	ff.mu.Lock()
	defer ff.mu.Unlock()
	f := &fakeWatcher{npub: npub, holdDur: ff.holds[npub]}
	ff.created = append(ff.created, f)
	uc := &UserConfig{
		SubjectNpub: npub,
		Relays:      append([]string(nil), ff.relays[npub]...),
	}
	return f, nil, uc, nil
}

func (ff *fakeFactory) countFor(npub string) int {
	ff.mu.Lock()
	defer ff.mu.Unlock()
	n := 0
	for _, f := range ff.created {
		if f.npub == npub {
			n++
		}
	}
	return n
}

func (ff *fakeFactory) latestFor(npub string) *fakeWatcher {
	ff.mu.Lock()
	defer ff.mu.Unlock()
	for i := len(ff.created) - 1; i >= 0; i-- {
		if ff.created[i].npub == npub {
			return ff.created[i]
		}
	}
	return nil
}

// npubFromSeed returns a deterministic bech32 npub from a one-byte
// "seed" so tests can build pools of distinct tenants without real
// keypairs.
func npubFromSeed(t *testing.T, seed byte) string {
	t.Helper()
	hexStr := strings.Repeat(fmt.Sprintf("%02x", seed), 32)
	n, err := nip19.EncodePublicKey(hexStr)
	if err != nil {
		t.Fatalf("EncodePublicKey: %v", err)
	}
	return n
}

type registryFixture struct {
	r     *Registry
	store *UserStore
	wl    *Whitelist
	ff    *fakeFactory
}

func newRegistryFixture(t *testing.T) *registryFixture {
	t.Helper()
	dir := t.TempDir()
	store, err := NewUserStore(filepath.Join(dir, "users"))
	if err != nil {
		t.Fatalf("NewUserStore: %v", err)
	}
	wl, err := LoadWhitelist(filepath.Join(dir, "whitelist.json"))
	if err != nil {
		t.Fatalf("LoadWhitelist: %v", err)
	}
	ff := newFakeFactory()
	r := NewRegistry(&HostConfig{}, store, wl, nil, context.Background())
	r.newWatcher = ff.make
	return &registryFixture{r: r, store: store, wl: wl, ff: ff}
}

// enroll whitelists npub and ensures a user directory with config.json
// exists, so Start passes the HasUser check.
func (fx *registryFixture) enroll(t *testing.T, npub string) {
	t.Helper()
	if err := fx.wl.Add(npub, ""); err != nil {
		t.Fatalf("whitelist.Add: %v", err)
	}
	if err := fx.store.CreateUser(npub); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := fx.store.SaveConfigBytes(npub, []byte("{}")); err != nil {
		t.Fatalf("SaveConfigBytes: %v", err)
	}
}

func TestRegistryStartStopBasic(t *testing.T) {
	fx := newRegistryFixture(t)
	npub := npubFromSeed(t, 0xaa)
	fx.enroll(t, npub)

	if err := fx.r.Start(npub); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if got := fx.r.List(); len(got) != 1 || got[0] != npub {
		t.Fatalf("List = %v, want [%s]", got, npub)
	}
	if err := fx.r.Stop(npub); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if got := fx.r.List(); len(got) != 0 {
		t.Fatalf("List after Stop = %v, want empty", got)
	}
	fake := fx.ff.latestFor(npub)
	if !fake.stopped.Load() {
		t.Fatal("fake watcher did not observe ctx cancel")
	}
}

func TestRegistryStartIdempotent(t *testing.T) {
	fx := newRegistryFixture(t)
	npub := npubFromSeed(t, 0xbb)
	fx.enroll(t, npub)

	if err := fx.r.Start(npub); err != nil {
		t.Fatalf("first Start: %v", err)
	}
	if err := fx.r.Start(npub); err != nil {
		t.Fatalf("second Start: %v", err)
	}
	if n := fx.ff.countFor(npub); n != 1 {
		t.Fatalf("fake count = %d, want 1", n)
	}
	fx.r.Stop(npub)
}

func TestRegistryStopAbsentIsNoOp(t *testing.T) {
	fx := newRegistryFixture(t)
	npub := npubFromSeed(t, 0xcc)
	if err := fx.r.Stop(npub); err != nil {
		t.Fatalf("Stop on absent: %v", err)
	}
}

func TestRegistryStartRejectsNonWhitelisted(t *testing.T) {
	fx := newRegistryFixture(t)
	npub := npubFromSeed(t, 0xdd)
	if err := fx.store.CreateUser(npub); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := fx.store.SaveConfigBytes(npub, []byte("{}")); err != nil {
		t.Fatalf("SaveConfigBytes: %v", err)
	}
	err := fx.r.Start(npub)
	if !errors.Is(err, ErrNotWhitelisted) {
		t.Fatalf("Start = %v, want ErrNotWhitelisted", err)
	}
}

func TestRegistryStartRejectsNonEnrolled(t *testing.T) {
	fx := newRegistryFixture(t)
	npub := npubFromSeed(t, 0xee)
	if err := fx.wl.Add(npub, ""); err != nil {
		t.Fatalf("whitelist.Add: %v", err)
	}
	err := fx.r.Start(npub)
	if !errors.Is(err, ErrNotEnrolled) {
		t.Fatalf("Start = %v, want ErrNotEnrolled", err)
	}
}

// A factory that fails on the configured npub once, then succeeds on
// subsequent calls. Lets tests exercise the "boot-time start failed,
// retry now works" flow that #19 introduces.
type flakyFactory struct {
	inner   func(npub string) (supervisedWatcher, *UserWatcher, *UserConfig, error)
	failFor map[string]int // npub → remaining failures
	mu      sync.Mutex
}

func (ff *flakyFactory) make(npub string) (supervisedWatcher, *UserWatcher, *UserConfig, error) {
	ff.mu.Lock()
	if ff.failFor[npub] > 0 {
		ff.failFor[npub]--
		ff.mu.Unlock()
		return nil, nil, nil, fmt.Errorf("simulated start failure for %s", npub)
	}
	ff.mu.Unlock()
	return ff.inner(npub)
}

func TestRegistryTryStartRecordsAndClearsError(t *testing.T) {
	fx := newRegistryFixture(t)
	npub := npubFromSeed(t, 0x11)
	fx.enroll(t, npub)

	flaky := &flakyFactory{inner: fx.ff.make, failFor: map[string]int{npub: 1}}
	fx.r.newWatcher = flaky.make

	if err := fx.r.tryStart(npub); err == nil {
		t.Fatal("expected first tryStart to fail")
	}
	if got := fx.r.LastStartError(npub); got == "" {
		t.Fatal("LastStartError should be set after a failed start")
	}

	if err := fx.r.tryStart(npub); err != nil {
		t.Fatalf("second tryStart: %v", err)
	}
	if got := fx.r.LastStartError(npub); got != "" {
		t.Fatalf("LastStartError = %q, want empty after success", got)
	}
	fx.r.Stop(npub)
}

func TestRegistryNotEnrolledDoesNotRecordError(t *testing.T) {
	fx := newRegistryFixture(t)
	npub := npubFromSeed(t, 0x12)
	if err := fx.wl.Add(npub, ""); err != nil {
		t.Fatalf("whitelist.Add: %v", err)
	}
	if err := fx.r.tryStart(npub); !errors.Is(err, ErrNotEnrolled) {
		t.Fatalf("tryStart = %v, want ErrNotEnrolled", err)
	}
	if got := fx.r.LastStartError(npub); got != "" {
		t.Fatalf("LastStartError = %q, want empty for ErrNotEnrolled", got)
	}
}

func TestRegistryStopClearsLastStartErr(t *testing.T) {
	fx := newRegistryFixture(t)
	npub := npubFromSeed(t, 0x13)
	fx.enroll(t, npub)

	flaky := &flakyFactory{inner: fx.ff.make, failFor: map[string]int{npub: 99}}
	fx.r.newWatcher = flaky.make

	_ = fx.r.tryStart(npub)
	if got := fx.r.LastStartError(npub); got == "" {
		t.Fatal("precondition: error not recorded")
	}
	if err := fx.r.Stop(npub); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if got := fx.r.LastStartError(npub); got != "" {
		t.Fatalf("LastStartError = %q, want empty after Stop", got)
	}
}

func TestRegistryReloadWhitelistRecordsStartError(t *testing.T) {
	fx := newRegistryFixture(t)
	npub := npubFromSeed(t, 0x14)
	fx.enroll(t, npub)

	flaky := &flakyFactory{inner: fx.ff.make, failFor: map[string]int{npub: 1}}
	fx.r.newWatcher = flaky.make

	if err := fx.r.ReloadWhitelist(); err != nil {
		t.Fatalf("ReloadWhitelist: %v", err)
	}
	if fx.r.IsRunning(npub) {
		t.Fatal("watcher should not be running after factory failure")
	}
	if got := fx.r.LastStartError(npub); got == "" {
		t.Fatal("LastStartError empty after failed ReloadWhitelist start")
	}

	// Next ReloadWhitelist retries Start (the watcher isn't running),
	// so the second call should clear the error and bring it up.
	if err := fx.r.ReloadWhitelist(); err != nil {
		t.Fatalf("second ReloadWhitelist: %v", err)
	}
	if !fx.r.IsRunning(npub) {
		t.Fatal("watcher should be running after retry")
	}
	if got := fx.r.LastStartError(npub); got != "" {
		t.Fatalf("LastStartError = %q, want empty after recovery", got)
	}
	fx.r.Stop(npub)
}

func TestRegistryReloadWhitelistDiff(t *testing.T) {
	fx := newRegistryFixture(t)
	a := npubFromSeed(t, 0x01)
	b := npubFromSeed(t, 0x02)
	c := npubFromSeed(t, 0x03)

	// Enroll all three (so any Start on the wl-loaded set can proceed).
	for _, n := range []string{a, b, c} {
		if err := fx.store.CreateUser(n); err != nil {
			t.Fatalf("CreateUser: %v", err)
		}
		if err := fx.store.SaveConfigBytes(n, []byte("{}")); err != nil {
			t.Fatalf("SaveConfigBytes: %v", err)
		}
	}

	// Whitelist A and C; only A and C start running.
	fx.wl.Add(a, "")
	fx.wl.Add(c, "")
	fx.r.Start(a)
	fx.r.Start(c)

	aFake := fx.ff.latestFor(a)

	// Whitelist now has A and B. Remove C, add B.
	fx.wl.Remove(c)
	fx.wl.Add(b, "")
	if err := fx.r.ReloadWhitelist(); err != nil {
		t.Fatalf("ReloadWhitelist: %v", err)
	}

	got := fx.r.List()
	if len(got) != 2 {
		t.Fatalf("List = %v, want {A,B}", got)
	}
	gotSet := map[string]bool{got[0]: true, got[1]: true}
	if !gotSet[a] || !gotSet[b] {
		t.Fatalf("List = %v, want {A,B}", got)
	}
	// A must be the same fake instance (not restarted).
	if cur := fx.ff.latestFor(a); cur != aFake {
		t.Fatal("A was restarted during ReloadWhitelist diff")
	}
	// C must have stopped.
	cFake := fx.ff.latestFor(c)
	if cFake == nil || !cFake.stopped.Load() {
		t.Fatal("C not stopped after removal")
	}

	fx.r.StopAll()
}

func TestRegistryReloadSameRelaysHotSwaps(t *testing.T) {
	fx := newRegistryFixture(t)
	npub := npubFromSeed(t, 0x10)
	fx.enroll(t, npub)

	// Matching relays on both factory (for the initial UserConfig
	// snapshot) and on-disk config (read by Reload).
	fx.ff.relays[npub] = []string{"wss://r1"}
	writeConfigRelays(t, fx.store, npub, []string{"wss://r1"})

	if err := fx.r.Start(npub); err != nil {
		t.Fatalf("Start: %v", err)
	}
	first := fx.ff.latestFor(npub)

	if err := fx.r.Reload(npub); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if fx.ff.countFor(npub) != 1 {
		t.Fatalf("Reload caused churn; fake count = %d", fx.ff.countFor(npub))
	}
	if first.reloads.Load() != 1 {
		t.Fatalf("ReloadConfig not called; got %d", first.reloads.Load())
	}
	fx.r.StopAll()
}

func TestRegistryReloadChangedRelaysRestarts(t *testing.T) {
	fx := newRegistryFixture(t)
	npub := npubFromSeed(t, 0x11)
	fx.enroll(t, npub)

	fx.ff.relays[npub] = []string{"wss://r1"}
	writeConfigRelays(t, fx.store, npub, []string{"wss://r1"})

	if err := fx.r.Start(npub); err != nil {
		t.Fatalf("Start: %v", err)
	}
	first := fx.ff.latestFor(npub)

	// Change relays on disk AND on the next factory call.
	fx.ff.relays[npub] = []string{"wss://r2"}
	writeConfigRelays(t, fx.store, npub, []string{"wss://r2"})

	if err := fx.r.Reload(npub); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if !first.stopped.Load() {
		t.Fatal("old watcher not stopped on relay change")
	}
	if fx.ff.countFor(npub) != 2 {
		t.Fatalf("expected 2 fakes after restart, got %d", fx.ff.countFor(npub))
	}
	fx.r.StopAll()
}

func TestRegistryStopAllWaitsForDone(t *testing.T) {
	fx := newRegistryFixture(t)
	npub := npubFromSeed(t, 0x20)
	fx.enroll(t, npub)

	fx.ff.holds[npub] = 50 * time.Millisecond
	if err := fx.r.Start(npub); err != nil {
		t.Fatalf("Start: %v", err)
	}
	fake := fx.ff.latestFor(npub)

	start := time.Now()
	fx.r.StopAll()
	elapsed := time.Since(start)
	if elapsed < 40*time.Millisecond {
		t.Fatalf("StopAll returned in %v, expected to wait for hold", elapsed)
	}
	if !fake.stopped.Load() {
		t.Fatal("fake not marked stopped after StopAll")
	}
}

func TestRegistryConcurrentStress(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping stress in short mode")
	}
	fx := newRegistryFixture(t)
	pool := make([]string, 10)
	for i := range pool {
		pool[i] = npubFromSeed(t, byte(0x40+i))
		fx.enroll(t, pool[i])
		writeConfigRelays(t, fx.store, pool[i], []string{"wss://r1"})
		fx.ff.relays[pool[i]] = []string{"wss://r1"}
	}

	var wg sync.WaitGroup
	workers := 20
	opsPerWorker := 100
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(seed int) {
			defer wg.Done()
			rng := rand.New(rand.NewSource(int64(seed)))
			for i := 0; i < opsPerWorker; i++ {
				npub := pool[rng.Intn(len(pool))]
				switch rng.Intn(3) {
				case 0:
					_ = fx.r.Start(npub)
				case 1:
					_ = fx.r.Stop(npub)
				case 2:
					_ = fx.r.Reload(npub)
				}
			}
		}(w)
	}
	wg.Wait()

	fx.r.StopAll()
	if got := fx.r.List(); len(got) != 0 {
		t.Fatalf("List after StopAll = %v, want empty", got)
	}
}

func TestRegistryRearmClearsStateAndRestarts(t *testing.T) {
	fx := newRegistryFixture(t)
	npub := npubFromSeed(t, 0xee)
	fx.enroll(t, npub)

	// Seed a triggered state on disk. After Rearm() Stops the running
	// watcher and re-Starts it, the registry will load this from disk,
	// clear it, save, and the next Start will see the cleared file.
	triggeredAt := time.Now().Add(-time.Hour)
	seeded := NewState()
	seeded.Triggered = true
	seeded.TriggeredAt = &triggeredAt
	seeded.WarningSent = 3
	seeded.LastSeen = triggeredAt.Add(-2 * time.Hour)
	seeded.LastEventID = "before-rearm"
	if err := fx.store.SaveUserState(npub, seeded); err != nil {
		t.Fatalf("SaveUserState: %v", err)
	}

	if err := fx.r.Start(npub); err != nil {
		t.Fatalf("Start: %v", err)
	}
	// Mark the fake watcher's snapshot as triggered so Rearm's gate passes.
	// (Real UserWatchers learn this from state on disk; the fake doesn't
	// touch state.json, so we set it explicitly.)
	fx.ff.latestFor(npub).triggered.Store(true)

	before := time.Now()
	if err := fx.r.Rearm(npub); err != nil {
		t.Fatalf("Rearm: %v", err)
	}

	// A second watcher should have been created — Rearm = Stop + Start.
	if n := fx.ff.countFor(npub); n != 2 {
		t.Fatalf("fake count after Rearm = %d, want 2", n)
	}

	got, err := fx.store.LoadUserState(npub)
	if err != nil {
		t.Fatalf("LoadUserState: %v", err)
	}
	if got.Triggered {
		t.Error("state.Triggered = true after Rearm, want false")
	}
	if got.TriggeredAt != nil {
		t.Errorf("state.TriggeredAt = %v after Rearm, want nil", got.TriggeredAt)
	}
	if got.WarningSent != 0 {
		t.Errorf("state.WarningSent = %d after Rearm, want 0", got.WarningSent)
	}
	if !got.LastSeen.After(before.Add(-time.Second)) {
		t.Errorf("state.LastSeen = %v, not advanced to ~now", got.LastSeen)
	}
	if !strings.HasPrefix(got.LastEventID, "rearm:") {
		t.Errorf("state.LastEventID = %q, want rearm: prefix", got.LastEventID)
	}

	fx.r.Stop(npub)
}

func TestRegistryRearmRejectsUntriggered(t *testing.T) {
	fx := newRegistryFixture(t)
	npub := npubFromSeed(t, 0xef)
	fx.enroll(t, npub)
	if err := fx.r.Start(npub); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer fx.r.Stop(npub)

	// Fake watcher's snapshot reports Triggered=false (default).
	err := fx.r.Rearm(npub)
	if !errors.Is(err, ErrNotTriggered) {
		t.Fatalf("Rearm err = %v, want ErrNotTriggered", err)
	}
	// Original watcher should still be running — Rearm bailed before Stop.
	if n := fx.ff.countFor(npub); n != 1 {
		t.Errorf("fake count = %d, want 1 (rejected Rearm should not restart)", n)
	}
}

func TestRegistryRearmRejectsNotRunning(t *testing.T) {
	fx := newRegistryFixture(t)
	npub := npubFromSeed(t, 0xf0)
	fx.enroll(t, npub)
	err := fx.r.Rearm(npub)
	if !errors.Is(err, ErrNotRunning) {
		t.Fatalf("Rearm on stopped watcher err = %v, want ErrNotRunning", err)
	}
}

func writeConfigRelays(t *testing.T, store *UserStore, npub string, relays []string) {
	t.Helper()
	uc := &UserConfig{
		SubjectNpub:      npub,
		Relays:           relays,
		SilenceThreshold: Duration{24 * time.Hour},
		WarningInterval:  Duration{2 * time.Hour},
		WarningCount:     2,
		CheckInterval:    Duration{time.Minute},
		UpdatedAt:        time.Unix(1700000000, 0).UTC(),
	}
	if err := store.SaveConfig(npub, uc); err != nil {
		t.Fatalf("SaveConfig: %v", err)
	}
}
