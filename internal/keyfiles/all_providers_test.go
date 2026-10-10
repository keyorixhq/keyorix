package keyfiles

import (
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
)

// TestAllProviders_PrimaryThenFallbacksInOrder pins the contract the
// consistency checks rely on: primary first, then every fallback in
// declared order, and the result never aliases the Fallbacks backing array.
func TestAllProviders_PrimaryThenFallbacksInOrder(t *testing.T) {
	enc := &config.EncryptionConfig{}
	enc.KeyProvider.Type = "file"
	enc.KeyProvider.Fallbacks = []config.KeyProviderConfig{{Type: "a"}, {Type: "b"}}

	got := allProviders(enc)
	if len(got) != 3 || got[0].Type != "file" || got[1].Type != "a" || got[2].Type != "b" {
		t.Fatalf("unexpected provider order: %+v", got)
	}

	got[1].Type = "mutated"
	if enc.KeyProvider.Fallbacks[0].Type != "a" {
		t.Fatal("allProviders result aliases the Fallbacks slice")
	}
}

func TestAllProviders_NoFallbacks(t *testing.T) {
	enc := &config.EncryptionConfig{}
	enc.KeyProvider.Type = "file"
	if got := allProviders(enc); len(got) != 1 || got[0].Type != "file" {
		t.Fatalf("unexpected result: %+v", got)
	}
}
