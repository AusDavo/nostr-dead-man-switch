package main

import (
	"context"
	"log"
	"time"
)

type DeadManSwitch struct {
	cfg        *Config
	state      *State
	monitor    *Monitor
	sessions   *sessionManager
	challenges *challengeStore
	startedAt  time.Time
}

func NewDeadManSwitch(cfg *Config, state *State) *DeadManSwitch {
	return &DeadManSwitch{
		cfg:        cfg,
		state:      state,
		monitor:    NewMonitor(cfg),
		challenges: newChallengeStore(),
	}
}

func (d *DeadManSwitch) Run(ctx context.Context) error {
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
		ExecuteActions(ctx, d.cfg, d.cfg.Actions)
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
		if err := SendWarningDM(ctx, d.cfg, next); err != nil {
			log.Printf("[warning] DM failed: %v", err)
		}
		d.state.RecordWarning()
		d.state.Save(d.cfg.StateFile)
	}
}
