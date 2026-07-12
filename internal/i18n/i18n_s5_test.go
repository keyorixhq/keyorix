package i18n

import (
	"sync"
	"testing"
)

// TestInitializeForTesting covers the InitializeForTesting helper (was at 0%).
func TestInitializeForTesting(t *testing.T) {
	// Reset state so once.Do fires.
	globalLocalizer = nil
	once = sync.Once{}

	if err := InitializeForTesting(); err != nil {
		t.Fatalf("InitializeForTesting() unexpected error: %v", err)
	}
	if globalLocalizer == nil {
		t.Fatal("InitializeForTesting() did not set globalLocalizer")
	}
}

// TestResetForTesting covers the ResetForTesting helper (was at 0%).
func TestResetForTesting(t *testing.T) {
	// Make sure there is something to reset.
	globalLocalizer = nil
	once = sync.Once{}
	if err := InitializeForTesting(); err != nil {
		t.Fatalf("setup InitializeForTesting() error: %v", err)
	}
	if globalLocalizer == nil {
		t.Fatal("precondition: globalLocalizer should be set before reset")
	}

	ResetForTesting()

	if globalLocalizer != nil {
		t.Error("ResetForTesting() did not clear globalLocalizer")
	}

	// Verify once was also reset — a fresh Initialize should succeed.
	if err := InitializeForTesting(); err != nil {
		t.Fatalf("re-initialize after ResetForTesting() error: %v", err)
	}
	if globalLocalizer == nil {
		t.Error("re-initialize after ResetForTesting() did not set globalLocalizer")
	}
}
