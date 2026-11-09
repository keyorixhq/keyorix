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

// Default mode: a short secret on an enabled webhook is accepted and warned
// about, naming its length and never its value; 14 bytes, no secret, or a
// disabled webhook stay silent.
func TestShortSigningSecretWarning_DefaultModeWarnsAndAccepts(t *testing.T) {
	t.Setenv("KEYORIX_NOTIFY_WEBHOOK_SIGNING_SECRET", "")
	forceWebhookSigningFIPS(t, false)
	short := webhookSigningConfig(true, "13-byte-value")
	msg := short.Notifications.Webhook.ShortSigningSecretWarning()
	if !strings.HasPrefix(msg, "WARNING: ") || !strings.Contains(msg, "is 13 bytes") || !strings.Contains(msg, "14-byte") {
		t.Fatalf("13-byte secret: want a warning naming 13 and 14 bytes, got %q", msg)
	}
	if strings.Contains(msg, "13-byte-value") {
		t.Fatalf("the warning must never contain the secret: %q", msg)
	}
	if err := validateNotificationsSection(short); err != nil {
		t.Fatalf("default mode must still accept the secret: %v", err)
	}
	for name, c := range map[string]*Config{
		"14 bytes":         webhookSigningConfig(true, "fourteen-bytes"),
		"no secret":        webhookSigningConfig(true, ""),
		"webhook disabled": webhookSigningConfig(false, "x"),
	} {
		if msg := c.Notifications.Webhook.ShortSigningSecretWarning(); msg != "" {
			t.Errorf("%s: unexpected warning: %q", name, msg)
		}
	}
	// The env var is what GetSigningSecret prefers, so it is what is checked.
	t.Setenv("KEYORIX_NOTIFY_WEBHOOK_SIGNING_SECRET", "env-short")
	fromEnv := webhookSigningConfig(true, "a-long-enough-file-value")
	if msg := fromEnv.Notifications.Webhook.ShortSigningSecretWarning(); !strings.Contains(msg, "is 9 bytes") {
		t.Fatalf("a short secret from KEYORIX_NOTIFY_WEBHOOK_SIGNING_SECRET must warn, got %q", msg)
	}
}

// Under enforcement the refusal stands, so there is nothing to warn about.
func TestShortSigningSecretWarning_FIPSEnforcedRefusesInstead(t *testing.T) {
	t.Setenv("KEYORIX_NOTIFY_WEBHOOK_SIGNING_SECRET", "")
	forceWebhookSigningFIPS(t, true)
	short := webhookSigningConfig(true, "13-byte-value")
	if msg := short.Notifications.Webhook.ShortSigningSecretWarning(); msg != "" {
		t.Fatalf("enforced mode must not warn, got %q", msg)
	}
	if err := validateNotificationsSection(short); err == nil || !strings.Contains(err.Error(), "at least 14 bytes") {
		t.Fatalf("enforced mode must still refuse, got %v", err)
	}
}
