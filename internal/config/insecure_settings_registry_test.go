package config

import (
	"strings"
	"testing"
)

// TestInsecureSettingsRegistry_EveryEntryHasThePrefixWarningAndAuditHook is
// the ADR-112 structural CI test: every registry entry must carry the
// insecure_ prefix (so it can't be enabled by accident or misread in
// review), a non-nil InEffect (the start-up warning's hook -- see
// server/main.go's warnInsecureSettingsInEffect, which loops this registry
// unconditionally), and a non-nil Value (the settings-diff audit's hook --
// see server/main.go's securityPostureSnapshot, which also loops this
// registry unconditionally). Because both consumers iterate the WHOLE
// registry with no per-entry opt-out, any entry satisfying this test is
// mechanically guaranteed warned-about and audited; this test is what makes
// that guarantee hold for every entry added in the future, not just the ones
// present today.
func TestInsecureSettingsRegistry_EveryEntryHasThePrefixWarningAndAuditHook(t *testing.T) {
	if len(InsecureSettingsRegistry) == 0 {
		t.Fatal("registry must not be empty")
	}
	seenNames := make(map[string]bool, len(InsecureSettingsRegistry))
	for _, e := range InsecureSettingsRegistry {
		t.Run(e.Name, func(t *testing.T) {
			if e.Name == "" {
				t.Fatal("entry has no Name")
			}
			leaf := e.Name
			if i := strings.LastIndex(leaf, "."); i >= 0 {
				leaf = leaf[i+1:]
			}
			if !strings.HasPrefix(leaf, "insecure_") {
				t.Errorf("Name %q's leaf segment %q must start with insecure_", e.Name, leaf)
			}
			if e.Describe == "" {
				t.Error("entry has no Describe")
			}
			if e.InEffect == nil {
				t.Error("entry has no InEffect -- the start-up warning loop can't evaluate it")
			}
			if e.Value == nil {
				t.Error("entry has no Value -- the settings-diff audit loop can't snapshot it")
			}
			if seenNames[e.Name] {
				t.Errorf("Name %q is registered more than once", e.Name)
			}
			seenNames[e.Name] = true
		})
	}
}

// Calling every entry's InEffect/Value against a zero-value *Config must
// never panic -- the start-up warning loop and the settings-diff snapshot
// both run this unconditionally on every boot, including the very first one
// before any encryption/SSO/etc. config exists. A nil-pointer-dereference
// here (e.g. a provider's *SAMLProviderConfig) would crash every server
// start, not just degrade a posture check.
func TestInsecureSettingsRegistry_ZeroValueConfigNeverPanics(t *testing.T) {
	cfg := &Config{}
	for _, e := range InsecureSettingsRegistry {
		t.Run(e.Name, func(t *testing.T) {
			_ = e.InEffect(cfg)
			_ = e.Value(cfg)
		})
	}
}
