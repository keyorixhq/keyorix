package config

import "testing"

// TestInsecureOmitShamirCommitment_BlankCountsAsOmitted (REVIEW-ENCRYPTIONOPS-1
// F6): the Shamir provider treats a whitespace-only shamir_commitment as unset,
// so the insecure-settings entry (start-up warning, settings diff, posture) must
// report it as in effect too; it compared against "" only.
func TestInsecureOmitShamirCommitment_BlankCountsAsOmitted(t *testing.T) {
	var e InsecureSetting
	for _, s := range InsecureSettingsRegistry {
		if s.Name == "storage.encryption.key_provider.insecure_omit_shamir_commitment_check" {
			e = s
		}
	}
	if e.InEffect == nil {
		t.Fatal("storage.encryption.key_provider.insecure_omit_shamir_commitment_check is not registered")
	}
	for commitment, want := range map[string]bool{
		"":      true,
		"  \n":  true,
		"ab12":  false,
		" ab12": false,
	} {
		cfg := &Config{}
		cfg.Storage.Encryption.Enabled = true
		cfg.Storage.Encryption.KeyProvider = KeyProviderConfig{Type: "shamir", ShamirCommitment: commitment}
		if got := e.InEffect(cfg); got != want {
			t.Errorf("shamir_commitment %q: InEffect = %v, want %v", commitment, got, want)
		}
		if got := e.Value(cfg) == "true"; got != want {
			t.Errorf("shamir_commitment %q: Value = %q, want in-effect %v", commitment, e.Value(cfg), want)
		}
	}
}
