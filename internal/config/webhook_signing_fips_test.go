package config

import (
	"strings"
	"testing"
)

func forceWebhookSigningFIPS(t *testing.T, on bool) {
	t.Helper()
	prev := webhookSigningFIPSEnforced
	webhookSigningFIPSEnforced = func() bool { return on }
	t.Cleanup(func() { webhookSigningFIPSEnforced = prev })
}

func webhookSigningConfig(enabled bool, secret string) *Config {
	return &Config{Notifications: NotificationsConfig{Webhook: NotificationWebhookConfig{
		Enabled: enabled, Endpoint: "https://siem.example.com/hook", SigningSecret: secret,
	}}}
}

// Under enforcement: a short secret on an enabled webhook is refused with the
// minimum named; 14 bytes, no secret, or a disabled webhook pass.
func TestValidateNotificationsSection_FIPSEnforced(t *testing.T) {
	t.Setenv("KEYORIX_NOTIFY_WEBHOOK_SIGNING_SECRET", "")
	forceWebhookSigningFIPS(t, true)
	err := validateNotificationsSection(webhookSigningConfig(true, "13-byte-value"))
	if err == nil || !strings.Contains(err.Error(), "at least 14 bytes") {
		t.Fatalf("13-byte secret: want a refusal naming 14 bytes, got %v", err)
	}
	for name, c := range map[string]*Config{
		"14 bytes":         webhookSigningConfig(true, "fourteen-bytes"),
		"no secret":        webhookSigningConfig(true, ""),
		"webhook disabled": webhookSigningConfig(false, "x"),
	} {
		if err := validateNotificationsSection(c); err != nil {
			t.Errorf("%s: unexpected refusal: %v", name, err)
		}
	}
	// The env var is what GetSigningSecret prefers, so it is what is checked.
	t.Setenv("KEYORIX_NOTIFY_WEBHOOK_SIGNING_SECRET", "env-short")
	if err := validateNotificationsSection(webhookSigningConfig(true, "")); err == nil {
		t.Fatal("a short secret from KEYORIX_NOTIFY_WEBHOOK_SIGNING_SECRET must be refused too")
	}
}

// Outside FIPS 140-only mode nothing changes: a short secret is accepted.
func TestValidateNotificationsSection_NotEnforcedUnchanged(t *testing.T) {
	t.Setenv("KEYORIX_NOTIFY_WEBHOOK_SIGNING_SECRET", "")
	forceWebhookSigningFIPS(t, false)
	if err := validateNotificationsSection(webhookSigningConfig(true, "x")); err != nil {
		t.Fatalf("default mode must accept any secret, as before: %v", err)
	}
}
