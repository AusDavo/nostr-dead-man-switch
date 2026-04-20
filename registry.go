package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"
)

// supervisedWatcher is the interface the Registry supervises. Real
// tenant goroutines use *UserWatcher; tests inject a fake.
type supervisedWatcher interface {
	Run(ctx context.Context) error
	Stop()
	ReloadConfig(uc *UserConfig)
	Snapshot() WatcherSnapshot
}

// supervised is one running watcher under the Registry.
type supervised struct {
	w      supervisedWatcher
	concrete *UserWatcher // nil when w is a test fake; populated by the real factory for Get()
	cancel context.CancelFunc
	done   chan struct{}

	mu sync.Mutex
	uc *UserConfig // snapshot of the config at start time, for Reload's relay diff
}

// Registry supervises per-tenant UserWatchers: one goroutine per
// whitelisted + enrolled npub. All lifecycle transitions (Start, Stop,
// Reload, ReloadWhitelist, StopAll) are safe for concurrent callers.
type Registry struct {
	host   *HostConfig
	store  *UserStore
	wl     *Whitelist
	sealer *Sealer

	// newWatcher is the factory for supervised watchers. Production uses
	// defaultNewWatcher; tests swap in a fake.
	newWatcher func(npub string) (supervisedWatcher, *UserWatcher, *UserConfig, error)

	mu       sync.RWMutex
	parent   context.Context
	watchers map[string]*supervised
}

// NewRegistry constructs a Registry bound to the given context. parent
// is the ancestor for every watcher goroutine; cancelling it cascades.
func NewRegistry(host *HostConfig, store *UserStore, wl *Whitelist,
	sealer *Sealer, parent context.Context) *Registry {
	r := &Registry{
		host:     host,
		store:    store,
		wl:       wl,
		sealer:   sealer,
		parent:   parent,
		watchers: map[string]*supervised{},
	}
	r.newWatcher = r.defaultNewWatcher
	return r
}

// ErrNotWhitelisted is returned by Start when the subject npub is not
// in the whitelist. Callers above the registry may treat this as a
// soft error (e.g. a stale whitelist snapshot).
var ErrNotWhitelisted = errors.New("registry: npub not whitelisted")

// ErrNotEnrolled is returned by Start when the subject npub is
// whitelisted but has no config.json on disk. This is the common state
// for a user who has been admitted but hasn't completed #7 yet.
var ErrNotEnrolled = errors.New("registry: npub not enrolled")

func (r *Registry) defaultNewWatcher(npub string) (supervisedWatcher, *UserWatcher, *UserConfig, error) {
	uc, err := r.store.LoadConfig(npub)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("registry: loading config for %s: %w", npub, err)
	}
	sealed, err := r.store.LoadSealedNsec(npub)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("registry: loading sealed nsec for %s: %w", npub, err)
	}
	if r.sealer == nil {
		return nil, nil, nil, fmt.Errorf("registry: sealer unavailable for %s", npub)
	}
	nsec, err := r.sealer.Unseal(npub, sealed)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("registry: unsealing nsec for %s: %w", npub, err)
	}
	w, err := NewUserWatcher(r.host, uc, string(nsec), r.store)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("registry: building watcher for %s: %w", npub, err)
	}
	w.reloadFn = r.Reload
	return w, w, uc, nil
}

// Start spins a watcher goroutine for npub. Idempotent: no-op if already
// running. Returns ErrNotWhitelisted / ErrNotEnrolled for policy
// rejections, or wrapped errors from the watcher factory.
func (r *Registry) Start(npub string) error {
	if !r.wl.Contains(npub) {
		return fmt.Errorf("%w: %s", ErrNotWhitelisted, npub)
	}

	r.mu.RLock()
	_, alreadyRunning := r.watchers[npub]
	r.mu.RUnlock()
	if alreadyRunning {
		return nil
	}

	if !r.store.HasUser(npub) {
		return fmt.Errorf("%w: %s", ErrNotEnrolled, npub)
	}

	w, concrete, uc, err := r.newWatcher(npub)
	if err != nil {
		return err
	}

	r.mu.Lock()
	if _, raced := r.watchers[npub]; raced {
		// Another goroutine won the race. Discard the speculatively-built
		// watcher; it hasn't been Run yet, so there's nothing to unwind.
		r.mu.Unlock()
		return nil
	}
	ctx, cancel := context.WithCancel(r.parent)
	s := &supervised{
		w:        w,
		concrete: concrete,
		cancel:   cancel,
		done:     make(chan struct{}),
		uc:       uc,
	}
	r.watchers[npub] = s
	r.mu.Unlock()

	go func() {
		defer close(s.done)
		if err := w.Run(ctx); err != nil {
			log.Printf("[registry] watcher %s exited: %v", npub, err)
		}
	}()
	return nil
}

// Stop cancels the watcher's context and waits for Run to return.
// Idempotent on absent npubs.
func (r *Registry) Stop(npub string) error {
	r.mu.Lock()
	s, ok := r.watchers[npub]
	if !ok {
		r.mu.Unlock()
		return nil
	}
	delete(r.watchers, npub)
	r.mu.Unlock()

	s.cancel()
	<-s.done
	return nil
}

// Reload re-reads the tenant's config.json. If the relay set changed,
// the watcher is stopped and re-started so the Monitor rebinds its
// subscriptions. Otherwise the new UserConfig is hot-swapped in place.
func (r *Registry) Reload(npub string) error {
	r.mu.RLock()
	s, running := r.watchers[npub]
	r.mu.RUnlock()
	if !running {
		return fmt.Errorf("registry: %s not running", npub)
	}

	uc, err := r.store.LoadConfig(npub)
	if err != nil {
		return fmt.Errorf("registry: loading config for %s: %w", npub, err)
	}

	s.mu.Lock()
	oldRelays := append([]string(nil), s.uc.Relays...)
	s.mu.Unlock()

	if !stringSlicesEqual(oldRelays, uc.Relays) {
		if err := r.Stop(npub); err != nil {
			return err
		}
		return r.Start(npub)
	}

	s.w.ReloadConfig(uc)
	s.mu.Lock()
	s.uc = uc
	s.mu.Unlock()
	return nil
}

// ReloadWhitelist re-reads whitelist.json and reconciles the running
// set. New whitelisted tenants with a config.json on disk are started;
// running tenants no longer on the whitelist are stopped. Existing
// tenants that remain whitelisted are left alone.
func (r *Registry) ReloadWhitelist() error {
	if err := r.wl.Reload(); err != nil {
		return fmt.Errorf("registry: reloading whitelist: %w", err)
	}

	r.mu.RLock()
	running := make(map[string]bool, len(r.watchers))
	for k := range r.watchers {
		running[k] = true
	}
	r.mu.RUnlock()

	list := r.wl.List()
	wanted := make(map[string]bool, len(list))
	for _, e := range list {
		wanted[e.Npub] = true
	}

	for npub := range running {
		if !wanted[npub] {
			if err := r.Stop(npub); err != nil {
				log.Printf("[whitelist] stop %s: %v", npub, err)
			}
		}
	}
	for npub := range wanted {
		if running[npub] {
			continue
		}
		if err := r.Start(npub); err != nil {
			if errors.Is(err, ErrNotEnrolled) {
				continue // waiting on #7 enrollment
			}
			log.Printf("[whitelist] start %s: %v", npub, err)
		}
	}

	r.mu.RLock()
	total := len(r.watchers)
	r.mu.RUnlock()
	log.Printf("[whitelist] reloaded: %d whitelisted, %d running", len(wanted), total)
	return nil
}

// StopAll cancels every watcher and waits for each to return. Called
// on process shutdown.
func (r *Registry) StopAll() {
	r.mu.Lock()
	items := make([]*supervised, 0, len(r.watchers))
	for _, s := range r.watchers {
		items = append(items, s)
	}
	r.watchers = map[string]*supervised{}
	r.mu.Unlock()

	var wg sync.WaitGroup
	for _, s := range items {
		wg.Add(1)
		go func(s *supervised) {
			defer wg.Done()
			s.cancel()
			<-s.done
		}(s)
	}
	wg.Wait()
}

// Sealer returns the *Sealer this registry was built with. May be nil
// in test fixtures that skip encryption.
func (r *Registry) Sealer() *Sealer { return r.sealer }

// Store returns the *UserStore this registry was built with.
func (r *Registry) Store() *UserStore { return r.store }

// Host returns the *HostConfig this registry was built with. Callers
// use it to seed new UserConfigs with host-level defaults.
func (r *Registry) Host() *HostConfig { return r.host }

// List returns the current set of running npubs.
func (r *Registry) List() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.watchers))
	for k := range r.watchers {
		out = append(out, k)
	}
	return out
}

// Get returns the concrete *UserWatcher for the given npub, or nil if
// none is running. Returns nil if the entry was inserted by a test fake
// rather than the real factory.
func (r *Registry) Get(npub string) *UserWatcher {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if s, ok := r.watchers[npub]; ok {
		return s.concrete
	}
	return nil
}

// IsWhitelisted is a convenience wrapper over the underlying Whitelist.
func (r *Registry) IsWhitelisted(npub string) bool {
	return r.wl.Contains(npub)
}

// IsRunning reports whether a watcher goroutine is currently running for
// npub. Distinct from Get, which returns the concrete *UserWatcher and is
// nil for entries inserted by a test fake.
func (r *Registry) IsRunning(npub string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.watchers[npub]
	return ok
}

// Snapshots returns a snapshot of every running watcher, in no particular
// order. Intended for the status landing page.
func (r *Registry) Snapshots() []WatcherSnapshot {
	r.mu.RLock()
	ws := make([]supervisedWatcher, 0, len(r.watchers))
	for _, s := range r.watchers {
		ws = append(ws, s.w)
	}
	r.mu.RUnlock()
	out := make([]WatcherSnapshot, 0, len(ws))
	for _, w := range ws {
		out = append(out, w.Snapshot())
	}
	return out
}

func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
