package solewriter

import (
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// TestFenceGuard_MatchesTheStore: internal/storage/store keeps a copy of the
// fence's trigger prefix, guard function and its body, so that its
// system_metadata write-target check (TRIGGER-INTEGRITY-1, #3713) allows the
// fence's triggers there and removes any other. A drift would make that check
// drop the fence's triggers on every tick.
func TestFenceGuard_MatchesTheStore(t *testing.T) {
	if store.SoleWriterFenceTriggerPrefix != TriggerPrefix {
		t.Errorf("store.SoleWriterFenceTriggerPrefix = %q, want %q", store.SoleWriterFenceTriggerPrefix, TriggerPrefix)
	}
	if store.SoleWriterGuardFunc != guardFunc {
		t.Errorf("store.SoleWriterGuardFunc = %q, want %q", store.SoleWriterGuardFunc, guardFunc)
	}
	if store.SoleWriterGuardFuncBody != guardFuncBody() {
		t.Errorf("store.SoleWriterGuardFuncBody differs from guardFuncBody():\n%s\nwant\n%s", store.SoleWriterGuardFuncBody, guardFuncBody())
	}
	for _, s := range triggerSpecs("public") {
		if s.table == "system_metadata" && s.timing != "AFTER" {
			t.Errorf("fence trigger %s on system_metadata is %s; the store's check allows only AFTER fence triggers there", s.name, s.timing)
		}
	}
}
