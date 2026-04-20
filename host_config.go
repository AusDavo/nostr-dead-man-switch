package main

import "time"

// HostConfig exposes only the host-level fields of the runtime config.
// In federation mode the Registry and UserWatchers receive a *HostConfig
// built from the loaded Config, so per-tenant code paths never touch
// legacy single-switch fields like WatchPubkey or BotNsec.
type HostConfig struct {
	Relays             []string
	ListenAddr         string
	Timezone           string
	StateDir           string
	WatcherStoreKeyEnv string
	WhitelistFile      string
	FederationV1       bool
	Location           *time.Location
}

// Host returns a HostConfig snapshot of the current Config. A fresh
// struct is returned on every call, so callers can't mutate the
// underlying Config through the accessor.
func (c *Config) Host() *HostConfig {
	relays := make([]string, len(c.Relays))
	copy(relays, c.Relays)
	return &HostConfig{
		Relays:             relays,
		ListenAddr:         c.ListenAddr,
		Timezone:           c.Timezone,
		StateDir:           c.StateDir,
		WatcherStoreKeyEnv: c.WatcherStoreKeyEnv,
		WhitelistFile:      c.WhitelistFile,
		FederationV1:       c.FederationV1,
		Location:           c.location,
	}
}
