package main

import (
	"math/rand/v2"
	"time"
)

// Relay reconnect pacing, shared by Monitor.subscribeRelay and
// subscribeSelfDMRelay.
const (
	// relayBackoffMin is the first delay after a failed connect, and the
	// floor the sequence returns to once a subscription proves healthy.
	relayBackoffMin = 30 * time.Second
	// relayBackoffMax caps the sequence. A relay that is down for hours is
	// still retried four times an hour, which is fast enough to notice it
	// coming back.
	relayBackoffMax = 15 * time.Minute
	// relayReconnectDelay is the pause after a healthy subscription closes,
	// which is routine and expected rather than a fault.
	relayReconnectDelay = 5 * time.Second
	// relayHealthyAfter is how long a subscription must stay up before the
	// connection counts as good and the backoff resets. A relay that accepts
	// the connection and then drops the subscription immediately is flapping,
	// not working, so it keeps backing off.
	relayHealthyAfter = 60 * time.Second
)

// backoff yields an exponentially increasing, jittered delay for the relay
// reconnect loops.
//
// Without it a flapping relay costs a fixed retry rate forever: through
// Sep 2026 relay.damus.io refused roughly half of all websocket upgrades with
// a 503, and at a flat 30s retry that produced ~2,800 failed connects a day
// per subscriber goroutine — enough to bury every other line in the log —
// without reconnecting any sooner than backing off would have. The jitter
// stops several relay goroutines that failed together from resynchronising
// into bursts.
//
// A backoff is owned by one goroutine and is not safe for concurrent use.
type backoff struct {
	min time.Duration
	max time.Duration
	cur time.Duration
	// randFloat returns a value in [0, 1). Nil means rand.Float64; tests
	// override it to make the jitter deterministic.
	randFloat func() float64
}

func newBackoff(min, max time.Duration) *backoff {
	return &backoff{min: min, max: max, cur: min}
}

// next returns how long to wait before the next attempt and advances the
// sequence: min, 2*min, 4*min ... up to max, each jittered by ±25%.
func (b *backoff) next() time.Duration {
	d := b.cur
	if b.cur < b.max {
		b.cur *= 2
		if b.cur > b.max {
			b.cur = b.max
		}
	}
	return jitter(d, b.float())
}

// reset returns the sequence to its minimum delay.
func (b *backoff) reset() { b.cur = b.min }

func (b *backoff) float() float64 {
	if b.randFloat != nil {
		return b.randFloat()
	}
	return rand.Float64()
}

// jitter spreads d over [0.75d, 1.25d) for r in [0, 1).
func jitter(d time.Duration, r float64) time.Duration {
	return time.Duration(float64(d) * (0.75 + 0.5*r))
}
