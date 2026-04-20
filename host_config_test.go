package main

import (
	"testing"
	"time"
)

func TestConfigHostCopiesFields(t *testing.T) {
	loc, _ := time.LoadLocation("UTC")
	c := &Config{
		Relays:             []string{"wss://r1", "wss://r2"},
		ListenAddr:         ":8080",
		Timezone:           "UTC",
		StateDir:           "/srv/dms",
		WatcherStoreKeyEnv: "DEADMAN_WATCHER_KEY",
		WhitelistFile:      "/srv/dms/whitelist.json",
		FederationV1:       true,
		location:           loc,
	}
	h := c.Host()
	if h.ListenAddr != ":8080" {
		t.Fatalf("ListenAddr = %q", h.ListenAddr)
	}
	if h.StateDir != "/srv/dms" {
		t.Fatalf("StateDir = %q", h.StateDir)
	}
	if !h.FederationV1 {
		t.Fatal("FederationV1 not propagated")
	}
	if h.Location != loc {
		t.Fatal("Location not propagated")
	}
	if len(h.Relays) != 2 || h.Relays[0] != "wss://r1" {
		t.Fatalf("Relays = %v", h.Relays)
	}
}

func TestConfigHostRelaysAreIndependent(t *testing.T) {
	c := &Config{Relays: []string{"wss://a"}}
	h := c.Host()
	h.Relays[0] = "wss://mutated"
	if c.Relays[0] != "wss://a" {
		t.Fatalf("Host() returned slice shares backing array; Config.Relays = %v", c.Relays)
	}
}
