package main

import (
	"encoding/json"
	"log"
	"os"
	"sync"
	"time"
)

type State struct {
	mu            sync.Mutex `json:"-"`
	SchemaVersion int        `json:"schema_version"`
	LastSeen      time.Time  `json:"last_seen"`
	LastEventID   string     `json:"last_event_id"`
	WarningSent   int        `json:"warnings_sent"`
	Triggered     bool       `json:"triggered"`
	TriggeredAt   *time.Time `json:"triggered_at,omitempty"`
}

func NewState() *State {
	return &State{}
}

func LoadState(path string) (*State, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	migrated, didMigrate, err := migrateState(data)
	if err != nil {
		return nil, err
	}
	var s State
	if err := json.Unmarshal(migrated, &s); err != nil {
		return nil, err
	}
	s.SchemaVersion = stateSchemaCurrent
	if didMigrate {
		log.Printf("[schema] migrated state.json at %s to v%d", path, stateSchemaCurrent)
		if err := os.WriteFile(path, migrated, 0o644); err != nil {
			log.Printf("[schema] failed to rewrite migrated state.json at %s: %v (in-memory state is correct)", path, err)
		}
	}
	return &s, nil
}

func (s *State) Save(path string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.SchemaVersion = stateSchemaCurrent
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

func (s *State) RecordEvent(eventID string, createdAt time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if createdAt.After(s.LastSeen) {
		s.LastSeen = createdAt
		s.LastEventID = eventID
	}
	// Any activity resets warning state
	s.WarningSent = 0
}

func (s *State) RecordWarning() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.WarningSent++
}

func (s *State) RecordTrigger() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Triggered = true
	now := time.Now()
	s.TriggeredAt = &now
}
