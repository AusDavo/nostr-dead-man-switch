package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
)

type DeadManSwitch struct {
	cfg        *Config
	state      *State          // nil in federation mode
	monitor    *Monitor        // nil in federation mode
	sessions   *sessionManager // nil in federation mode
	challenges *challengeStore // nil in federation mode
	registry   *Registry       // nil in legacy mode
	startedAt  time.Time

	// testAction is the per-pubkey cooldown gate for /admin/config/test-action;
	// prevents a stuck "test" button from nuking SMTP quotas.
	testAction testActionGate

	// execActionFn is the single-action dispatcher used by the test-action
	// handler. Defaulted to the package-level executeAction; tests can swap
	// it to capture the (type, config) pair without touching SMTP/nostr.
	execActionFn testActionExecFn
}

type testActionExecFn func(ctx context.Context, actionType string, config map[string]any,
	host *HostConfig, uc *UserConfig, watcherPrivHex, watcherPubHex string) error

func NewDeadManSwitch(cfg *Config, state *State) *DeadManSwitch {
	return &DeadManSwitch{
		cfg:        cfg,
		state:      state,
		monitor:    NewMonitor(cfg.Relays, cfg.watchPubkeyHex),
		challenges: newChallengeStore(),
	}
}

// legacyUserConfig builds a *UserConfig from the legacy single-switch
// Config fields so the shared ExecuteActions / SendWarningDM signatures
// work transparently on the legacy path. Relays stays nil so the
// host-level list is used.
func (d *DeadManSwitch) legacyUserConfig() *UserConfig {
	return &UserConfig{
		SubjectNpub:      d.cfg.WatchPubkey,
		WatcherPubkeyHex: d.cfg.botPubkeyHex,
		SilenceThreshold: d.cfg.SilenceThreshold,
		WarningInterval:  d.cfg.WarningInterval,
		WarningCount:     d.cfg.WarningCount,
		CheckInterval:    d.cfg.CheckInterval,
		Actions:          d.cfg.Actions,
	}
}

// Run dispatches to the federation or legacy supervisor based on
// cfg.FederationV1. The default is false; legacy callers see no
// behaviour change until #8 flips the default.
func (d *DeadManSwitch) Run(ctx context.Context) error {
	if d.cfg.FederationV1 {
		return d.runFederation(ctx)
	}
	return d.runLegacy(ctx)
}

func (d *DeadManSwitch) runLegacy(ctx context.Context) error {
	if d.state.Triggered {
		log.Printf("Switch already triggered at %s. Delete state file to re-arm.", d.state.TriggeredAt)
		return nil
	}

	// Bootstrap: fetch latest event if no state
	if d.state.LastSeen.IsZero() {
		log.Println("No previous state, fetching latest event...")
		ev, err := d.monitor.FetchLatestEvent(ctx)
		if err == nil && ev != nil {
			d.state.RecordEvent(ev.ID, time.Unix(int64(ev.CreatedAt), 0))
			d.state.Save(d.cfg.StateFile)
			log.Printf("Latest event: %s (kind %d)", time.Unix(int64(ev.CreatedAt), 0).Format(time.RFC3339), ev.Kind)
		} else {
			log.Println("No events found, using current time as baseline")
			d.state.RecordEvent("", time.Now())
			d.state.Save(d.cfg.StateFile)
		}
	}

	d.startedAt = time.Now()
	d.startServer(ctx)

	log.Printf("Monitoring %s across %d relays", d.cfg.WatchPubkey, len(d.cfg.Relays))
	log.Printf("Silence threshold: %s | Warning interval: %s | Warnings: %d",
		d.cfg.SilenceThreshold.Duration, d.cfg.WarningInterval.Duration, d.cfg.WarningCount)
	log.Printf("Last seen: %s (%s ago)",
		d.state.LastSeen.Format(time.RFC3339), time.Since(d.state.LastSeen).Round(time.Minute))

	d.monitor.Start(ctx, d.state.LastSeen)

	ticker := time.NewTicker(d.cfg.CheckInterval.Duration)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return d.state.Save(d.cfg.StateFile)

		case ev := <-d.monitor.Events():
			created := time.Unix(int64(ev.CreatedAt), 0)
			log.Printf("[event] kind=%d id=%s at %s", ev.Kind, ev.ID[:12], created.Format(time.RFC3339))
			d.state.RecordEvent(ev.ID, created)
			if err := d.state.Save(d.cfg.StateFile); err != nil {
				log.Printf("[state] save error: %v", err)
			}

		case <-ticker.C:
			d.evaluate(ctx)
		}
	}
}

func (d *DeadManSwitch) evaluate(ctx context.Context) {
	d.state.mu.Lock()
	silence := time.Since(d.state.LastSeen)
	warningsSent := d.state.WarningSent
	d.state.mu.Unlock()

	threshold := d.cfg.SilenceThreshold.Duration
	warningInterval := d.cfg.WarningInterval.Duration

	log.Printf("[check] silent %s | threshold %s | warnings %d/%d",
		silence.Round(time.Minute), threshold, warningsSent, d.cfg.WarningCount)

	if silence < threshold {
		return
	}

	pastThreshold := silence - threshold

	// Time to trigger?
	triggerAfter := warningInterval * time.Duration(d.cfg.WarningCount)
	if pastThreshold >= triggerAfter {
		log.Println("[TRIGGER] Dead man's switch activated!")
		d.state.RecordTrigger()
		d.state.Save(d.cfg.StateFile)
		ExecuteActions(ctx, d.cfg.Host(), d.legacyUserConfig(),
			d.cfg.botPrivkeyHex, d.cfg.botPubkeyHex, d.cfg.watchPubkeyHex, d.cfg.Actions)
		return
	}

	// Time for next warning?
	expectedWarnings := int(pastThreshold/warningInterval) + 1
	if expectedWarnings > d.cfg.WarningCount {
		expectedWarnings = d.cfg.WarningCount
	}

	if warningsSent < expectedWarnings {
		next := warningsSent + 1
		log.Printf("[warning] Sending DM %d/%d", next, d.cfg.WarningCount)
		if err := SendWarningDM(ctx, d.cfg.Host(), d.legacyUserConfig(),
			d.cfg.botPrivkeyHex, d.cfg.botPubkeyHex, d.cfg.watchPubkeyHex, next); err != nil {
			log.Printf("[warning] DM failed: %v", err)
		}
		d.state.RecordWarning()
		d.state.Save(d.cfg.StateFile)
	}
}

// runFederation wires the federated supervisor: Sealer → UserStore →
// Whitelist → Migrate → Registry → SIGHUP watcher. The HTTP dashboard
// is intentionally not started here — it's rewired by #8.
func (d *DeadManSwitch) runFederation(ctx context.Context) error {
	host := d.cfg.Host()

	sealer, err := NewSealerFromEnv(host.WatcherStoreKeyEnv)
	if err != nil {
		return fmt.Errorf("federation: sealer: %w", err)
	}

	store, err := NewUserStore(filepath.Join(host.StateDir, "users"))
	if err != nil {
		return fmt.Errorf("federation: store: %w", err)
	}

	wl, err := LoadWhitelist(host.WhitelistFile)
	if err != nil {
		return fmt.Errorf("federation: whitelist: %w", err)
	}

	if err := Migrate(d.cfg, store, wl, sealer); err != nil {
		return fmt.Errorf("federation: migrate: %w", err)
	}

	d.registry = NewRegistry(host, store, wl, sealer, ctx)
	d.startedAt = time.Now()

	go d.hupLoop(ctx)

	if err := d.registry.ReloadWhitelist(); err != nil {
		return fmt.Errorf("federation: initial whitelist load: %w", err)
	}

	log.Printf("[federation] registry running (%d watchers)", len(d.registry.List()))

	d.startServer(ctx)

	<-ctx.Done()
	d.registry.StopAll()
	return nil
}

// hupLoop reloads the whitelist on SIGHUP. SIGHUP is POSIX-only; on
// Windows the signal is never delivered and this goroutine simply
// blocks on ctx.Done until shutdown.
func (d *DeadManSwitch) hupLoop(ctx context.Context) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGHUP)
	defer signal.Stop(ch)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ch:
			log.Println("[whitelist] SIGHUP received, reloading")
			if err := d.registry.ReloadWhitelist(); err != nil {
				log.Printf("[whitelist] reload failed: %v", err)
			}
		}
	}
}
