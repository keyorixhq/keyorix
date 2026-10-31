package notifychan

import (
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
)

func TestMinSigningSecretLen_MatchesConfig(t *testing.T) {
	if minSigningSecretLen != config.MinWebhookSigningSecretLen {
		t.Fatalf("notifychan refuses below %d bytes but config validation below %d", minSigningSecretLen, config.MinWebhookSigningSecretLen)
	}
}

func forceSigningFIPS(t *testing.T, on bool) {
	t.Helper()
	prev := signingFIPSEnforced
	signingFIPSEnforced = func() bool { return on }
	t.Cleanup(func() { signingFIPSEnforced = prev })
}

func TestCheckSigningSecretLen_FIPSEnforced(t *testing.T) {
	forceSigningFIPS(t, true)
	if err := checkSigningSecretLen("13-byte-value"); err == nil || !strings.Contains(err.Error(), "at least 14") {
		t.Fatalf("13 bytes: want a refusal naming 14, got %v", err)
	}
	if err := checkSigningSecretLen("fourteen-bytes"); err != nil {
		t.Fatalf("14 bytes must pass: %v", err)
	}
}

func TestCheckSigningSecretLen_NotEnforcedUnchanged(t *testing.T) {
	forceSigningFIPS(t, false)
	if err := checkSigningSecretLen("x"); err != nil {
		t.Fatalf("default mode must sign with any secret, as before: %v", err)
	}
}
