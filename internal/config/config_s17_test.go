package config

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAuthConfig_GetAPIKey_EnvVar validates the KEYORIX_API_KEY environment
// variable overrides the file value.
func TestAuthConfig_GetAPIKey_EnvVar(t *testing.T) {
	t.Setenv("KEYORIX_API_KEY", "env-api-key")
	a := &AuthConfig{APIKey: "file-api-key"}
	assert.Equal(t, "env-api-key", a.GetAPIKey())
}

// TestAuthConfig_GetAPIKey_Fallback validates that the file value is used when
// the environment variable is absent.
func TestAuthConfig_GetAPIKey_Fallback(t *testing.T) {
	t.Setenv("KEYORIX_API_KEY", "")
	a := &AuthConfig{APIKey: "file-api-key"}
	assert.Equal(t, "file-api-key", a.GetAPIKey())
}

// TestLoginLockoutConfig_GetMaxAttempts_Default validates the default of 5 when
// MaxAttempts is unset or non-positive.
func TestLoginLockoutConfig_GetMaxAttempts_Default(t *testing.T) {
	assert.Equal(t, 5, LoginLockoutConfig{}.GetMaxAttempts())
	assert.Equal(t, 5, LoginLockoutConfig{MaxAttempts: 0}.GetMaxAttempts())
	assert.Equal(t, 5, LoginLockoutConfig{MaxAttempts: -1}.GetMaxAttempts())
}

// TestLoginLockoutConfig_GetMaxAttempts_Explicit validates a positive
// MaxAttempts is returned as-is.
func TestLoginLockoutConfig_GetMaxAttempts_Explicit(t *testing.T) {
	assert.Equal(t, 10, LoginLockoutConfig{MaxAttempts: 10}.GetMaxAttempts())
	assert.Equal(t, 1, LoginLockoutConfig{MaxAttempts: 1}.GetMaxAttempts())
}

// TestLoginLockoutConfig_GetWindow_Default validates the 15-minute default when
// Window is empty or unparseable.
func TestLoginLockoutConfig_GetWindow_Default(t *testing.T) {
	assert.Equal(t, 15*time.Minute, LoginLockoutConfig{}.GetWindow())
	assert.Equal(t, 15*time.Minute, LoginLockoutConfig{Window: "garbage"}.GetWindow())
	assert.Equal(t, 15*time.Minute, LoginLockoutConfig{Window: "-5m"}.GetWindow())
}

// TestLoginLockoutConfig_GetWindow_Explicit validates a valid duration is parsed.
func TestLoginLockoutConfig_GetWindow_Explicit(t *testing.T) {
	assert.Equal(t, 30*time.Minute, LoginLockoutConfig{Window: "30m"}.GetWindow())
	assert.Equal(t, time.Hour, LoginLockoutConfig{Window: "1h"}.GetWindow())
}

// TestLoginLockoutConfig_GetBaseCooldown_Default validates the 1-minute default
// when BaseCooldown is empty or unparseable.
func TestLoginLockoutConfig_GetBaseCooldown_Default(t *testing.T) {
	assert.Equal(t, time.Minute, LoginLockoutConfig{}.GetBaseCooldown())
	assert.Equal(t, time.Minute, LoginLockoutConfig{BaseCooldown: "not-a-duration"}.GetBaseCooldown())
}

// TestLoginLockoutConfig_GetBaseCooldown_Explicit validates a valid duration is
// parsed.
func TestLoginLockoutConfig_GetBaseCooldown_Explicit(t *testing.T) {
	assert.Equal(t, 2*time.Minute, LoginLockoutConfig{BaseCooldown: "2m"}.GetBaseCooldown())
	assert.Equal(t, 30*time.Second, LoginLockoutConfig{BaseCooldown: "30s"}.GetBaseCooldown())
}

// TestLoginLockoutConfig_GetMaxCooldown_Default validates the 1-hour default
// when MaxCooldown is empty or unparseable.
func TestLoginLockoutConfig_GetMaxCooldown_Default(t *testing.T) {
	assert.Equal(t, time.Hour, LoginLockoutConfig{}.GetMaxCooldown())
	assert.Equal(t, time.Hour, LoginLockoutConfig{MaxCooldown: "bad"}.GetMaxCooldown())
}

// TestLoginLockoutConfig_GetMaxCooldown_Explicit validates a valid duration is
// parsed.
func TestLoginLockoutConfig_GetMaxCooldown_Explicit(t *testing.T) {
	assert.Equal(t, 4*time.Hour, LoginLockoutConfig{MaxCooldown: "4h"}.GetMaxCooldown())
	assert.Equal(t, 30*time.Minute, LoginLockoutConfig{MaxCooldown: "30m"}.GetMaxCooldown())
}

// TestCheckpointNotaryConfig_GetTimeout_Default validates the 15-second default
// when Timeout is empty or unparseable.
func TestCheckpointNotaryConfig_GetTimeout_Default(t *testing.T) {
	assert.Equal(t, 15*time.Second, CheckpointNotaryConfig{}.GetTimeout())
	assert.Equal(t, 15*time.Second, CheckpointNotaryConfig{Timeout: "not-a-duration"}.GetTimeout())
	assert.Equal(t, 15*time.Second, CheckpointNotaryConfig{Timeout: ""}.GetTimeout())
}

// TestCheckpointNotaryConfig_GetTimeout_Explicit validates a valid duration is
// parsed.
func TestCheckpointNotaryConfig_GetTimeout_Explicit(t *testing.T) {
	assert.Equal(t, 30*time.Second, CheckpointNotaryConfig{Timeout: "30s"}.GetTimeout())
	assert.Equal(t, 5*time.Second, CheckpointNotaryConfig{Timeout: "5s"}.GetTimeout())
}

// TestSIEMConfig_GetToken_EnvVar validates the KEYORIX_SIEM_TOKEN environment
// variable overrides the file value.
func TestSIEMConfig_GetToken_EnvVar(t *testing.T) {
	t.Setenv("KEYORIX_SIEM_TOKEN", "env-siem-token")
	s := &SIEMConfig{Token: "file-siem-token"}
	assert.Equal(t, "env-siem-token", s.GetToken())
}

// TestSIEMConfig_GetToken_Fallback validates that the file value is used when
// the environment variable is absent.
func TestSIEMConfig_GetToken_Fallback(t *testing.T) {
	t.Setenv("KEYORIX_SIEM_TOKEN", "")
	s := &SIEMConfig{Token: "file-siem-token"}
	assert.Equal(t, "file-siem-token", s.GetToken())
}

// TestCredentialSMTPConfig_GetPassword_EnvVar validates the KEYORIX_SMTP_PASSWORD
// environment variable overrides the file value.
func TestCredentialSMTPConfig_GetPassword_EnvVar(t *testing.T) {
	t.Setenv("KEYORIX_SMTP_PASSWORD", "env-smtp-pass")
	s := &CredentialSMTPConfig{Password: "file-smtp-pass"}
	assert.Equal(t, "env-smtp-pass", s.GetPassword())
}

// TestCredentialSMTPConfig_GetPassword_Fallback validates that the file value is
// used when the environment variable is absent.
func TestCredentialSMTPConfig_GetPassword_Fallback(t *testing.T) {
	t.Setenv("KEYORIX_SMTP_PASSWORD", "")
	s := &CredentialSMTPConfig{Password: "file-smtp-pass"}
	assert.Equal(t, "file-smtp-pass", s.GetPassword())
}

// TestCredentialDeliveryConfig_DeliveryConfig validates that DeliveryConfig maps
// all fields correctly, including SMTP password resolution.
func TestCredentialDeliveryConfig_DeliveryConfig(t *testing.T) {
	t.Setenv("KEYORIX_SMTP_PASSWORD", "")
	c := &CredentialDeliveryConfig{
		Mode:    "smtp",
		BaseURL: "https://keyorix.example.com",
		SMTP: CredentialSMTPConfig{
			Host:     "smtp.example.com",
			Port:     587,
			Username: "noreply@example.com",
			Password: "file-smtp-pass",
			From:     "noreply@example.com",
			TLS:      "starttls",
		},
	}
	got := c.DeliveryConfig()
	assert.Equal(t, "smtp", got.Mode)
	assert.Equal(t, "https://keyorix.example.com", got.BaseURL)
	assert.Equal(t, "smtp.example.com", got.SMTP.Host)
	assert.Equal(t, 587, got.SMTP.Port)
	assert.Equal(t, "noreply@example.com", got.SMTP.Username)
	assert.Equal(t, "file-smtp-pass", got.SMTP.Password)
	assert.Equal(t, "noreply@example.com", got.SMTP.From)
	assert.Equal(t, "starttls", got.SMTP.TLS)
}

// TestCredentialDeliveryConfig_DeliveryConfig_EnvPassword validates that
// KEYORIX_SMTP_PASSWORD is picked up when mapping to delivery.Config.
func TestCredentialDeliveryConfig_DeliveryConfig_EnvPassword(t *testing.T) {
	t.Setenv("KEYORIX_SMTP_PASSWORD", "env-smtp-pass")
	c := &CredentialDeliveryConfig{
		SMTP: CredentialSMTPConfig{
			Host:     "smtp.example.com",
			Password: "file-smtp-pass",
		},
	}
	got := c.DeliveryConfig()
	assert.Equal(t, "env-smtp-pass", got.SMTP.Password)
}

// TestNotificationsConfig_GetSlackWebhookURL_EnvVar validates the
// KEYORIX_NOTIFY_SLACK_WEBHOOK environment variable overrides the config value.
func TestNotificationsConfig_GetSlackWebhookURL_EnvVar(t *testing.T) {
	t.Setenv("KEYORIX_NOTIFY_SLACK_WEBHOOK", "https://hooks.slack.com/env")
	n := &NotificationsConfig{
		Slack: NotificationChatConfig{WebhookURL: "https://hooks.slack.com/file"},
	}
	assert.Equal(t, "https://hooks.slack.com/env", n.GetSlackWebhookURL())
}

// TestNotificationsConfig_GetSlackWebhookURL_Fallback validates that the config
// value is used when the environment variable is absent.
func TestNotificationsConfig_GetSlackWebhookURL_Fallback(t *testing.T) {
	t.Setenv("KEYORIX_NOTIFY_SLACK_WEBHOOK", "")
	n := &NotificationsConfig{
		Slack: NotificationChatConfig{WebhookURL: "https://hooks.slack.com/file"},
	}
	assert.Equal(t, "https://hooks.slack.com/file", n.GetSlackWebhookURL())
}

// TestNotificationsConfig_GetTeamsWebhookURL_EnvVar validates the
// KEYORIX_NOTIFY_TEAMS_WEBHOOK environment variable overrides the config value.
func TestNotificationsConfig_GetTeamsWebhookURL_EnvVar(t *testing.T) {
	t.Setenv("KEYORIX_NOTIFY_TEAMS_WEBHOOK", "https://teams.microsoft.com/env")
	n := &NotificationsConfig{
		Teams: NotificationChatConfig{WebhookURL: "https://teams.microsoft.com/file"},
	}
	assert.Equal(t, "https://teams.microsoft.com/env", n.GetTeamsWebhookURL())
}

// TestNotificationsConfig_GetTeamsWebhookURL_Fallback validates that the config
// value is used when the environment variable is absent.
func TestNotificationsConfig_GetTeamsWebhookURL_Fallback(t *testing.T) {
	t.Setenv("KEYORIX_NOTIFY_TEAMS_WEBHOOK", "")
	n := &NotificationsConfig{
		Teams: NotificationChatConfig{WebhookURL: "https://teams.microsoft.com/file"},
	}
	assert.Equal(t, "https://teams.microsoft.com/file", n.GetTeamsWebhookURL())
}

// TestNotificationEmailConfig_GetPassword_EnvVar validates the
// KEYORIX_NOTIFY_SMTP_PASSWORD environment variable overrides the config value.
func TestNotificationEmailConfig_GetPassword_EnvVar(t *testing.T) {
	t.Setenv("KEYORIX_NOTIFY_SMTP_PASSWORD", "env-notify-pass")
	e := &NotificationEmailConfig{Password: "file-notify-pass"}
	assert.Equal(t, "env-notify-pass", e.GetPassword())
}

// TestNotificationEmailConfig_GetPassword_Fallback validates that the config
// value is used when the environment variable is absent.
func TestNotificationEmailConfig_GetPassword_Fallback(t *testing.T) {
	t.Setenv("KEYORIX_NOTIFY_SMTP_PASSWORD", "")
	e := &NotificationEmailConfig{Password: "file-notify-pass"}
	assert.Equal(t, "file-notify-pass", e.GetPassword())
}

// TestNotificationWebhookConfig_GetSigningSecret_EnvVar validates the
// KEYORIX_NOTIFY_WEBHOOK_SIGNING_SECRET environment variable overrides the config
// value.
func TestNotificationWebhookConfig_GetSigningSecret_EnvVar(t *testing.T) {
	t.Setenv("KEYORIX_NOTIFY_WEBHOOK_SIGNING_SECRET", "env-signing-secret")
	w := &NotificationWebhookConfig{SigningSecret: "file-signing-secret"}
	assert.Equal(t, "env-signing-secret", w.GetSigningSecret())
}

// TestNotificationWebhookConfig_GetSigningSecret_Fallback validates that the
// config value is used when the environment variable is absent.
func TestNotificationWebhookConfig_GetSigningSecret_Fallback(t *testing.T) {
	t.Setenv("KEYORIX_NOTIFY_WEBHOOK_SIGNING_SECRET", "")
	w := &NotificationWebhookConfig{SigningSecret: "file-signing-secret"}
	assert.Equal(t, "file-signing-secret", w.GetSigningSecret())
}

// TestNotificationWebhookConfig_GetSigningSecret_Empty validates that empty
// SigningSecret with no env var returns an empty string.
func TestNotificationWebhookConfig_GetSigningSecret_Empty(t *testing.T) {
	t.Setenv("KEYORIX_NOTIFY_WEBHOOK_SIGNING_SECRET", "")
	w := &NotificationWebhookConfig{}
	assert.Equal(t, "", w.GetSigningSecret())
}

// TestLoadConfig_CallsLoad validates that LoadConfig is a thin wrapper over
// Load("") and returns a non-nil Config when KEYORIX_CONFIG_PATH points to a
// valid file.
func TestLoadConfig_CallsLoad(t *testing.T) {
	dir := t.TempDir()
	p := dir + "/keyorix.yaml"
	require.NoError(t, os.WriteFile(p, []byte("locale:\n  language: es\n"), 0o600))
	t.Setenv("KEYORIX_CONFIG_PATH", p)
	cfg, err := LoadConfig()
	require.NoError(t, err)
	require.NotNil(t, cfg)
	assert.Equal(t, "es", cfg.Locale.Language)
}

// TestLoadConfig_ErrorPropagates validates that LoadConfig propagates a Load
// error (e.g. missing file).
func TestLoadConfig_ErrorPropagates(t *testing.T) {
	t.Setenv("KEYORIX_CONFIG_PATH", "/nonexistent/path/keyorix.yaml")
	_, err := LoadConfig()
	require.Error(t, err)
}
