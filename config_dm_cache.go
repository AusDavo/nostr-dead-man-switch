package main

import "time"

// maxSeen bounds the ConfigDMCache.Seen map. The set is advisory — a
// tenant that misses an eviction round and re-processes an old DM will
// just re-apply-or-drop via the created_at monotonicity check. The cap
// exists to keep the JSON blob small on disk.
const maxSeen = 256

// ConfigDMCache records the self-DM event IDs we've already applied or
// rejected, and the high-water mark for applied created_at timestamps.
// Persisted per-tenant at <StateDir>/users/<npub>/config_dm_cache.json.
//
// The zero value is usable; Record will initialise the map on first
// write.
type ConfigDMCache struct {
	LastAppliedEventID   string           `json:"last_applied_event_id,omitempty"`
	LastAppliedCreatedAt time.Time        `json:"last_applied_created_at"`
	Seen                 map[string]int64 `json:"seen,omitempty"`
}

// Has reports whether eventID has been recorded in the cache, regardless
// of whether it was applied or dropped.
func (c *ConfigDMCache) Has(eventID string) bool {
	if c == nil || len(c.Seen) == 0 {
		return false
	}
	_, ok := c.Seen[eventID]
	return ok
}

// Record inserts eventID into the seen set, keyed by createdAt in unix
// seconds. If the set exceeds maxSeen, the oldest entry is evicted —
// scanning the full map is fine since maxSeen is small in practice and
// this runs at most once per received DM.
func (c *ConfigDMCache) Record(eventID string, createdAt time.Time) {
	if c == nil {
		return
	}
	if c.Seen == nil {
		c.Seen = map[string]int64{}
	}
	c.Seen[eventID] = createdAt.Unix()
	for len(c.Seen) > maxSeen {
		var (
			oldestID string
			oldestTS int64
			init     bool
		)
		for id, ts := range c.Seen {
			if !init || ts < oldestTS {
				oldestID = id
				oldestTS = ts
				init = true
			}
		}
		delete(c.Seen, oldestID)
	}
}

// Promote updates LastApplied* if createdAt is strictly greater than the
// current LastAppliedCreatedAt. Returns true if the cache moved forward.
func (c *ConfigDMCache) Promote(eventID string, createdAt time.Time) bool {
	if c == nil {
		return false
	}
	if !createdAt.After(c.LastAppliedCreatedAt) {
		return false
	}
	c.LastAppliedEventID = eventID
	c.LastAppliedCreatedAt = createdAt
	return true
}
