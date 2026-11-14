package pow

import (
	"strings"
	"testing"
	"time"
)

func TestContractExamplesVectors(t *testing.T) {
	now := time.Date(2026, 1, 5, 9, 0, 0, 0, time.UTC)

	// Vector from ClearedStack/muster contract/v1/examples/edits.json.
	if !Verify(
		"2026-01-05.208bd",
		"catalog.sample-calculator.description",
		"The sample description should say which made-up rule it follows.",
		"It reads as if no rule applies.",
		DefaultDifficulty,
		now,
	) {
		t.Fatal("expected edits.json vector 2026-01-05.208bd to verify")
	}

	// Vector from ClearedStack/muster contract/v1/examples/items-site-form.json.
	if !Verify(
		"2026-01-05.70b6f",
		"site-form",
		"A made-up tool a visitor asked for",
		"https://example.org/made-up/asked-for-1",
		DefaultDifficulty,
		now,
	) {
		t.Fatal("expected items-site-form.json vector 2026-01-05.70b6f to verify")
	}

	// Yesterday UTC must also verify.
	nextDay := time.Date(2026, 1, 6, 23, 59, 59, 0, time.UTC)
	if !Verify(
		"2026-01-05.208bd",
		"catalog.sample-calculator.description",
		"The sample description should say which made-up rule it follows.",
		"It reads as if no rule applies.",
		DefaultDifficulty,
		nextDay,
	) {
		t.Fatal("expected yesterday UTC token to verify")
	}

	// Two days old must be rejected.
	twoDaysLater := time.Date(2026, 1, 7, 0, 0, 0, 0, time.UTC)
	if Verify(
		"2026-01-05.208bd",
		"catalog.sample-calculator.description",
		"The sample description should say which made-up rule it follows.",
		"It reads as if no rule applies.",
		DefaultDifficulty,
		twoDaysLater,
	) {
		t.Fatal("expected two-day-old token to be rejected")
	}
}

func TestSolveAndRejectionCases(t *testing.T) {
	now := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	tok, err := Solve("2026-11-14", "catalog.sample-calculator.description", "Updated text", "Clarify citation", 12)
	if err != nil {
		t.Fatalf("Solve failed: %v", err)
	}
	if !Verify(tok, "catalog.sample-calculator.description", "Updated text", "Clarify citation", 12, now) {
		t.Fatalf("solved token %q did not verify", tok)
	}

	// Tampered payload must fail.
	if Verify(tok, "catalog.sample-calculator.description", "Tampered text", "Clarify citation", 12, now) {
		t.Fatal("tampered text must not verify")
	}

	// Uppercase hex or malformed tokens must fail.
	badTokens := []string{
		"",
		"2026-11-14.",
		"2026-11-14.ABCDEF",
		"2026-11-14." + strings.Repeat("a", 33),
		"2026/11/14.0",
		"not-a-token",
	}
	for _, bt := range badTokens {
		if Verify(bt, "a", "b", "c", 0, now) {
			t.Errorf("malformed token %q should have failed", bt)
		}
	}
}
