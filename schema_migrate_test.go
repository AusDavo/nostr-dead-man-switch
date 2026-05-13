package main

import (
	"testing"
)

func TestPeekSchemaVersion_AbsentReturnsZero(t *testing.T) {
	v, err := peekSchemaVersion([]byte(`{"last_event_id": "x"}`))
	if err != nil {
		t.Fatalf("peekSchemaVersion: %v", err)
	}
	if v != 0 {
		t.Fatalf("v = %d, want 0", v)
	}
}

func TestPeekSchemaVersion_PresentReturnsValue(t *testing.T) {
	v, err := peekSchemaVersion([]byte(`{"schema_version": 7, "last_event_id": "x"}`))
	if err != nil {
		t.Fatalf("peekSchemaVersion: %v", err)
	}
	if v != 7 {
		t.Fatalf("v = %d, want 7", v)
	}
}

func TestPeekSchemaVersion_MalformedJSONErrors(t *testing.T) {
	if _, err := peekSchemaVersion([]byte(`not json`)); err == nil {
		t.Fatal("expected error for malformed JSON")
	}
}
