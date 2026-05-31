package main

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
)

func TestInviteRedeemHappyPath(t *testing.T) {
	c, err := LoadInviteCodes(t.TempDir(), []string{"ABC123"})
	if err != nil {
		t.Fatal(err)
	}
	if !c.IsValid("ABC123") {
		t.Fatal("configured code should be valid before redemption")
	}
	if err := c.Redeem("ABC123", "npubAlice"); err != nil {
		t.Fatalf("Redeem: %v", err)
	}
	if c.IsValid("ABC123") {
		t.Fatal("code should no longer be valid after redemption")
	}
	by, used := c.IsUsedBy("ABC123")
	if !used || by != "npubAlice" {
		t.Fatalf("IsUsedBy = (%q,%v), want (npubAlice,true)", by, used)
	}
}

func TestInviteRedeemIdempotentSameNpub(t *testing.T) {
	c, _ := LoadInviteCodes(t.TempDir(), []string{"ABC123"})
	if err := c.Redeem("ABC123", "npubAlice"); err != nil {
		t.Fatal(err)
	}
	if err := c.Redeem("ABC123", "npubAlice"); err != nil {
		t.Fatalf("idempotent re-redeem should succeed, got %v", err)
	}
}

func TestInviteRedeemDifferentNpubFails(t *testing.T) {
	c, _ := LoadInviteCodes(t.TempDir(), []string{"ABC123"})
	if err := c.Redeem("ABC123", "npubAlice"); err != nil {
		t.Fatal(err)
	}
	err := c.Redeem("ABC123", "npubBob")
	if !errors.Is(err, ErrCodeUsed) {
		t.Fatalf("Redeem by other npub = %v, want ErrCodeUsed", err)
	}
}

func TestInviteRedeemUnknownCode(t *testing.T) {
	c, _ := LoadInviteCodes(t.TempDir(), nil)
	err := c.Redeem("NOPE", "npubAlice")
	if !errors.Is(err, ErrCodeInvalid) {
		t.Fatalf("Redeem unknown = %v, want ErrCodeInvalid", err)
	}
}

func TestInviteRevokedCannotRedeem(t *testing.T) {
	c, _ := LoadInviteCodes(t.TempDir(), []string{"XYZ789"})
	if err := c.RevokeCode("XYZ789"); err != nil {
		t.Fatal(err)
	}
	if c.IsValid("XYZ789") {
		t.Fatal("revoked code should not be valid")
	}
	err := c.Redeem("XYZ789", "npubAlice")
	if !errors.Is(err, ErrCodeUsed) {
		t.Fatalf("Redeem revoked = %v, want ErrCodeUsed", err)
	}
}

func TestInviteMintIsValidAndUnique(t *testing.T) {
	c, _ := LoadInviteCodes(t.TempDir(), nil)
	a, err := c.Mint()
	if err != nil {
		t.Fatal(err)
	}
	b, err := c.Mint()
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("Mint produced duplicate codes")
	}
	if !c.IsValid(a) || !c.IsValid(b) {
		t.Fatal("minted codes should be valid")
	}
	if err := c.Redeem(a, "npubAlice"); err != nil {
		t.Fatalf("redeem minted: %v", err)
	}
}

func TestInviteRedeemConcurrentSingleWinner(t *testing.T) {
	c, _ := LoadInviteCodes(t.TempDir(), []string{"RACE01"})
	const n = 32
	var wg sync.WaitGroup
	var winners atomic.Int32
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			if err := c.Redeem("RACE01", fmt.Sprintf("npub%d", i)); err == nil {
				winners.Add(1)
			}
		}(i)
	}
	wg.Wait()
	if got := winners.Load(); got != 1 {
		t.Fatalf("got %d winners, want exactly 1", got)
	}
}

func TestInvitePersistenceRoundTrips(t *testing.T) {
	dir := t.TempDir()
	c, _ := LoadInviteCodes(dir, []string{"CFG001"})
	minted, err := c.Mint()
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Redeem("CFG001", "npubAlice"); err != nil {
		t.Fatal(err)
	}

	// Reload from disk with the same configured set.
	c2, err := LoadInviteCodes(dir, []string{"CFG001"})
	if err != nil {
		t.Fatal(err)
	}
	if c2.IsValid("CFG001") {
		t.Fatal("redeemed configured code should still read as used after reload")
	}
	by, used := c2.IsUsedBy("CFG001")
	if !used || by != "npubAlice" {
		t.Fatalf("after reload IsUsedBy = (%q,%v), want (npubAlice,true)", by, used)
	}
	if !c2.IsValid(minted) {
		t.Fatal("minted code should persist as valid after reload")
	}
}

func TestInviteNormalizesCase(t *testing.T) {
	c, _ := LoadInviteCodes(t.TempDir(), []string{"ABC123"})
	if err := c.Redeem("abc123", "npubAlice"); err != nil {
		t.Fatalf("lowercase redeem should match configured code, got %v", err)
	}
}
