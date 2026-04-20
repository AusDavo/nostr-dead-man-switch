package main

import (
	"fmt"
	"testing"
	"time"
)

func TestCacheHasRecordPromote(t *testing.T) {
	c := &ConfigDMCache{}
	if c.Has("a") {
		t.Fatal("fresh cache should not Has any id")
	}

	now := time.Unix(1700000000, 0).UTC()
	c.Record("a", now)
	if !c.Has("a") {
		t.Fatal("Has false after Record")
	}

	if promoted := c.Promote("a", now); !promoted {
		t.Fatal("first Promote should succeed")
	}
	if c.LastAppliedEventID != "a" {
		t.Fatalf("LastAppliedEventID = %q", c.LastAppliedEventID)
	}
	if !c.LastAppliedCreatedAt.Equal(now) {
		t.Fatalf("LastAppliedCreatedAt = %v, want %v", c.LastAppliedCreatedAt, now)
	}
}

func TestCacheRecordEvicts(t *testing.T) {
	c := &ConfigDMCache{}
	base := time.Unix(1700000000, 0).UTC()
	total := maxSeen + 10
	for i := 0; i < total; i++ {
		c.Record(fmt.Sprintf("id-%04d", i), base.Add(time.Duration(i)*time.Second))
	}
	if len(c.Seen) != maxSeen {
		t.Fatalf("len(Seen) = %d, want %d", len(c.Seen), maxSeen)
	}
	// The 10 oldest (id-0000..id-0009) should have been evicted.
	for i := 0; i < 10; i++ {
		id := fmt.Sprintf("id-%04d", i)
		if c.Has(id) {
			t.Fatalf("expected %q evicted", id)
		}
	}
	// The most recent should still be there.
	if !c.Has(fmt.Sprintf("id-%04d", total-1)) {
		t.Fatal("most recent id evicted")
	}
}

func TestCachePromoteOnlyGreater(t *testing.T) {
	c := &ConfigDMCache{}
	t0 := time.Unix(1700000000, 0).UTC()
	c.Promote("a", t0)

	// Equal is a no-op.
	if c.Promote("b", t0) {
		t.Fatal("Promote at same createdAt should be no-op")
	}
	if c.LastAppliedEventID != "a" {
		t.Fatalf("LastAppliedEventID = %q, want %q", c.LastAppliedEventID, "a")
	}

	// Older is a no-op.
	if c.Promote("c", t0.Add(-time.Second)) {
		t.Fatal("Promote at older createdAt should be no-op")
	}
	if c.LastAppliedEventID != "a" {
		t.Fatalf("LastAppliedEventID = %q, want %q", c.LastAppliedEventID, "a")
	}

	// Strictly newer moves the cache forward.
	if !c.Promote("d", t0.Add(time.Second)) {
		t.Fatal("Promote at newer createdAt should succeed")
	}
	if c.LastAppliedEventID != "d" {
		t.Fatalf("LastAppliedEventID = %q, want %q", c.LastAppliedEventID, "d")
	}
}
