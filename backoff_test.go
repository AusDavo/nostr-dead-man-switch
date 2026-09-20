package main

import (
	"testing"
	"time"
)

// fixedRand makes the ±25% jitter deterministic: r = 0.5 is the midpoint, so
// next() returns exactly the undithered delay.
func fixedRand(r float64) func() float64 { return func() float64 { return r } }

func TestBackoffDoublesToCap(t *testing.T) {
	b := newBackoff(30*time.Second, 15*time.Minute)
	b.randFloat = fixedRand(0.5)

	want := []time.Duration{
		30 * time.Second,
		1 * time.Minute,
		2 * time.Minute,
		4 * time.Minute,
		8 * time.Minute,
		15 * time.Minute,
		15 * time.Minute,
		15 * time.Minute,
	}
	for i, w := range want {
		if got := b.next(); got != w {
			t.Errorf("attempt %d: got %v, want %v", i+1, got, w)
		}
	}
}

func TestBackoffResetReturnsToMin(t *testing.T) {
	b := newBackoff(30*time.Second, 15*time.Minute)
	b.randFloat = fixedRand(0.5)

	for range 4 {
		b.next()
	}
	b.reset()
	if got := b.next(); got != 30*time.Second {
		t.Errorf("after reset: got %v, want %v", got, 30*time.Second)
	}
}

func TestBackoffJitterStaysInBand(t *testing.T) {
	// The real rand source, over enough draws to catch a band error.
	b := newBackoff(time.Minute, time.Minute)
	lo, hi := 45*time.Second, 75*time.Second
	var sawBelowMid, sawAboveMid bool
	for i := range 500 {
		d := b.next()
		if d < lo || d >= hi {
			t.Fatalf("draw %d: %v outside [%v, %v)", i, d, lo, hi)
		}
		if d < time.Minute {
			sawBelowMid = true
		}
		if d > time.Minute {
			sawAboveMid = true
		}
	}
	if !sawBelowMid || !sawAboveMid {
		t.Error("jitter did not vary in both directions; is it actually random?")
	}
}

func TestJitterBounds(t *testing.T) {
	d := 100 * time.Second
	if got := jitter(d, 0); got != 75*time.Second {
		t.Errorf("r=0: got %v, want 75s", got)
	}
	if got := jitter(d, 0.5); got != 100*time.Second {
		t.Errorf("r=0.5: got %v, want 100s", got)
	}
	// r is drawn from [0, 1), so 1.25d is the open upper bound.
	if got := jitter(d, 0.999999); got >= 125*time.Second {
		t.Errorf("r→1: got %v, want < 125s", got)
	}
}

// A flapping relay is the case this exists for: the delay after N failures
// must be far longer than the flat 30s it replaced.
func TestBackoffOutpacesFlatRetry(t *testing.T) {
	b := newBackoff(relayBackoffMin, relayBackoffMax)
	b.randFloat = fixedRand(0.5)

	var total time.Duration
	attempts := 0
	for total < time.Hour {
		total += b.next()
		attempts++
	}
	// A flat 30s retry makes 120 attempts an hour.
	if attempts > 12 {
		t.Errorf("made %d attempts in the first hour, want well under the flat-retry 120", attempts)
	}
}
