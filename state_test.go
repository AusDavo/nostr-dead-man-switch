package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadState_LegacyUnversionedMigratesToV1(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	legacy := []byte(`{
  "last_seen": "2026-05-01T00:00:00Z",
  "last_event_id": "abc123",
  "warnings_sent": 2,
  "triggered": false
}`)
	if err := os.WriteFile(path, legacy, 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	s, err := LoadState(path)
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	if s.SchemaVersion != stateSchemaCurrent {
		t.Fatalf("SchemaVersion = %d, want %d", s.SchemaVersion, stateSchemaCurrent)
	}
	if s.LastEventID != "abc123" || s.WarningSent != 2 {
		t.Fatalf("legacy fields not preserved: %+v", s)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !strings.Contains(string(raw), `"schema_version": 1`) {
		t.Fatalf("on-disk file did not get schema_version stamped:\n%s", raw)
	}
}

func TestLoadState_V1RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	want := &State{
		SchemaVersion: stateSchemaCurrent,
		LastSeen:      time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC),
		LastEventID:   "deadbeef",
		WarningSent:   1,
	}
	if err := want.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := LoadState(path)
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	if got.SchemaVersion != want.SchemaVersion ||
		!got.LastSeen.Equal(want.LastSeen) ||
		got.LastEventID != want.LastEventID ||
		got.WarningSent != want.WarningSent {
		t.Fatalf("round-trip mismatch: got %+v want %+v", got, want)
	}
}

func TestLoadState_ForwardVersionRefused(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	forward := []byte(`{"schema_version": 99, "last_event_id": "x"}`)
	if err := os.WriteFile(path, forward, 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	_, err := LoadState(path)
	if err == nil {
		t.Fatal("expected error for forward-version state.json")
	}
	if !strings.Contains(err.Error(), "newer than this binary supports") {
		t.Fatalf("error %q lacks expected substring", err.Error())
	}
}

func TestSaveState_StampsSchemaVersion(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	s := &State{LastEventID: "abc"}
	if err := s.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var peek struct {
		SchemaVersion int `json:"schema_version"`
	}
	if err := json.Unmarshal(raw, &peek); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if peek.SchemaVersion != stateSchemaCurrent {
		t.Fatalf("on-disk schema_version = %d, want %d", peek.SchemaVersion, stateSchemaCurrent)
	}
}
