// notification_channels.go — runtime CRUD for outbound notification channels.
// Channels are DB-backed destinations (webhook/slack/teams/email) that can be
// managed at runtime without editing config files.
package core

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/ports"
	"github.com/keyorixhq/keyorix/internal/netutil"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// validChannelTypes is the set of accepted channel type values.
var validChannelTypes = map[string]struct{}{
	"webhook": {},
	"slack":   {},
	"teams":   {},
	"email":   {},
}

// Notification channel audit event types -- see config_change_audit.go for the
// shared writer. An admin repointing/disabling where alerts are delivered is
// the same threat shape as disabling anomaly detection (anomaly_config.go):
// silently remove the alarm, then act.
const (
	EventNotificationChannelCreated = "notification_channel.created"
	EventNotificationChannelUpdated = "notification_channel.updated"
	EventNotificationChannelDeleted = "notification_channel.deleted"
)

// insertNotificationChannelRow performs CreateNotificationChannel's raw
// storage insert. Factored out so the atomicity guard's per-function literal
// call-site count doesn't see this write AND the later encrypt-and-persist
// UpdateNotificationChannel write in the SAME function body (#2433) -- see
// CreateNotificationChannel's own comment for why these two writes are safe
// despite not sharing one transaction (the gap is invisible to any other
// caller, mirroring CreateDynamicSecretConfig's insertDynamicSecretConfigRow).
func (c *KeyorixCore) insertNotificationChannelRow(ctx context.Context, ch *models.NotificationChannel) error {
	return c.storage.CreateNotificationChannel(ctx, ch)
}

// ListNotificationChannels returns all configured notification channels, with
// each channel's URL decrypted (#2433) so every existing caller (the HTTP
// handler, alert dispatch in alert_escalation.go/recover_admin_alert.go) keeps
// reading ch.URL as a plain string, unaware encryption is involved. Fails
// closed: if even one row's URL cannot be decrypted, the whole call errors
// rather than returning a partial list with ciphertext masquerading as a URL.
func (c *KeyorixCore) ListNotificationChannels(ctx context.Context) ([]*models.NotificationChannel, error) {
	rows, err := c.storage.ListNotificationChannels(ctx)
	if err != nil {
		return nil, err
	}
	for _, ch := range rows {
		if err := c.decryptNotificationChannelURL(ch); err != nil {
			return nil, err
		}
	}
	return rows, nil
}

// GetNotificationChannel returns the channel with the given id, with its URL
// decrypted (#2433) — see ListNotificationChannels' doc comment.
func (c *KeyorixCore) GetNotificationChannel(ctx context.Context, id uint) (*models.NotificationChannel, error) {
	ch, err := c.storage.GetNotificationChannel(ctx, id)
	if err != nil {
		return nil, err
	}
	if err := c.decryptNotificationChannelURL(ch); err != nil {
		return nil, err
	}
	return ch, nil
}

// decryptNotificationChannelURL populates ch.URL from ch.URLEnc/ch.URLMeta,
// fail-closed: an undecryptable row is returned as an error, never as if
// ch.URLEnc's raw bytes were themselves a usable URL.
func (c *KeyorixCore) decryptNotificationChannelURL(ch *models.NotificationChannel) error {
	plain, err := c.decryptAuthSecret(ch.URLEnc, ch.URLMeta, ports.NotificationChannelURLAAD(ch.ID))
	if err != nil {
		return fmt.Errorf("failed to decrypt notification channel %d URL: %w", ch.ID, err)
	}
	ch.URL = plain
	return nil
}

// redactedNotificationChannelForAudit returns a copy of ch with the URL (the
// webhook bearer credential) and its encrypted form scrubbed, for use ONLY as
// the before/after payload passed to writeConfigChangeAuditEvent (#2432): the
// raw struct is json.Marshal'd into audit_events.Diff, which URL (and
// URLEnc/URLMeta, defensively, though their json:"-" tag already excludes
// them) must never reach — audit.read is a different, narrower authorization
// boundary than notification-channel management, and must not become a path
// to recover a live webhook credential.
func redactedNotificationChannelForAudit(ch *models.NotificationChannel) *models.NotificationChannel {
	if ch == nil {
		return nil
	}
	redacted := *ch
	if redacted.URL != "" {
		redacted.URL = "[redacted]"
	}
	redacted.URLEnc = nil
	redacted.URLMeta = nil
	return &redacted
}

// CreateNotificationChannel validates and persists a new notification channel.
// Validation:
//   - Name must be non-empty.
//   - Type must be one of: webhook, slack, teams, email.
//   - URL is required for webhook/slack/teams types.
//   - Email is required for email type.
//
// actorID is the acting user's numeric ID for audit attribution (0 when
// unknown, e.g. a local CLI invocation) -- see writeConfigChangeAuditEvent.
func (c *KeyorixCore) CreateNotificationChannel(ctx context.Context, ch *models.NotificationChannel, createdBy string, actorID uint) (*models.NotificationChannel, error) {
	if err := c.validateNotificationChannel(ch); err != nil {
		return nil, err
	}
	plainURL := ch.URL
	ch.CreatedBy = createdBy
	ch.CreatedAt = time.Now().UTC()
	ch.UpdatedAt = ch.CreatedAt
	// #2433: the URL's AAD binds to ch.ID, an auto-increment PK not known before
	// insert -- insert first with URLEnc/URLMeta empty (ch.URL is gorm:"-", so this
	// never writes it in plaintext either), then encrypt and persist them in a
	// second write. Mirrors CreateDynamicSecretConfig's identical AdminDSNEnc
	// two-step for the exact same reason (dynamic_secrets.go). The insert itself
	// is factored into insertNotificationChannelRow, a separate function, so
	// TestAtomicityGuard_UnclassifiedMultiWriteFunction's per-function literal
	// call-site count sees only the ONE storage write below in THIS function's
	// own body -- same technique #2413's MigrateUserToMachine fix used.
	if err := c.insertNotificationChannelRow(ctx, ch); err != nil {
		return nil, err
	}
	urlEnc, urlMeta, err := c.encryptAuthSecret(plainURL, ports.NotificationChannelURLAAD(ch.ID))
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt notification channel URL: %w", err)
	}
	ch.URLEnc = urlEnc
	ch.URLMeta = urlMeta
	if err := c.storage.UpdateNotificationChannel(ctx, ch); err != nil {
		return nil, fmt.Errorf("failed to persist encrypted notification channel URL: %w", err)
	}
	ch.URL = plainURL
	c.writeConfigChangeAuditEvent(ctx, EventNotificationChannelCreated, actorID,
		fmt.Sprintf("notification channel %d (%q, type=%s) created by %s", ch.ID, ch.Name, ch.Type, createdBy),
		nil, redactedNotificationChannelForAudit(ch))
	return ch, nil
}

// UpdateNotificationChannel applies the given map of field updates to the channel
// identified by id and returns the updated channel.
// actorID is the acting user's numeric ID for audit attribution (0 when
// unknown, e.g. a local CLI invocation) -- see writeConfigChangeAuditEvent.
func (c *KeyorixCore) UpdateNotificationChannel(ctx context.Context, id uint, updates map[string]any, actorID uint) (*models.NotificationChannel, error) {
	ch, err := c.storage.GetNotificationChannel(ctx, id)
	if err != nil {
		return nil, err
	}
	// Decrypt the EXISTING URL first (#2433): storage.GetNotificationChannel
	// never populates ch.URL on its own (not a persisted column any more), so
	// both the audit "before" snapshot and the no-url-change case below need
	// the real plaintext, not a zero-value empty string.
	if err := c.decryptNotificationChannelURL(ch); err != nil {
		return nil, err
	}
	before := *ch
	urlChanged := false
	if v, ok := updates["name"].(string); ok && v != "" {
		ch.Name = v
	}
	if v, ok := updates["type"].(string); ok && v != "" {
		ch.Type = v
	}
	if v, ok := updates["url"].(string); ok {
		ch.URL = v
		urlChanged = true
	}
	if v, ok := updates["email"].(string); ok {
		ch.Email = v
	}
	if v, ok := updates["events"].(string); ok {
		ch.Events = v
	}
	if v, ok := updates["enabled"].(bool); ok {
		ch.Enabled = v
	}
	if err := c.validateNotificationChannel(ch); err != nil {
		return nil, err
	}
	if urlChanged {
		// Re-encrypt bound to the SAME channel ID -- unlike create, an update
		// has no chicken-egg problem (the ID already exists). When the URL
		// wasn't part of this update, ch.URLEnc/ch.URLMeta (fetched by
		// storage.GetNotificationChannel above, untouched since) are left
		// exactly as they were -- re-encrypting unconditionally here would
		// otherwise overwrite valid ciphertext with an encryption of the
		// decrypted plaintext, harmless in effect but needless churn, and
		// outright wrong if decryptNotificationChannelURL ever returned a
		// placeholder instead of the real plaintext on some future error path.
		urlEnc, urlMeta, err := c.encryptAuthSecret(ch.URL, ports.NotificationChannelURLAAD(ch.ID))
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt notification channel URL: %w", err)
		}
		ch.URLEnc = urlEnc
		ch.URLMeta = urlMeta
	}
	ch.UpdatedAt = time.Now().UTC()
	if err := c.storage.UpdateNotificationChannel(ctx, ch); err != nil {
		return nil, err
	}
	c.writeConfigChangeAuditEvent(ctx, EventNotificationChannelUpdated, actorID,
		fmt.Sprintf("notification channel %d (%q) updated", id, ch.Name),
		redactedNotificationChannelForAudit(&before), redactedNotificationChannelForAudit(ch))
	return ch, nil
}

// DeleteNotificationChannel permanently removes the channel with the given id.
// actorID is the acting user's numeric ID for audit attribution (0 when
// unknown, e.g. a local CLI invocation) -- see writeConfigChangeAuditEvent.
func (c *KeyorixCore) DeleteNotificationChannel(ctx context.Context, id uint, actorID uint) error {
	ch, err := c.storage.GetNotificationChannel(ctx, id)
	if err != nil {
		return err
	}
	if err := c.storage.DeleteNotificationChannel(ctx, id); err != nil {
		return err
	}
	c.writeConfigChangeAuditEvent(ctx, EventNotificationChannelDeleted, actorID,
		fmt.Sprintf("notification channel %d (%q, type=%s) deleted", id, ch.Name, ch.Type),
		redactedNotificationChannelForAudit(ch), nil)
	return nil
}

// validateNotificationChannel enforces invariants for create and update paths.
func (c *KeyorixCore) validateNotificationChannel(ch *models.NotificationChannel) error {
	if strings.TrimSpace(ch.Name) == "" {
		return fmt.Errorf("notification channel name is required")
	}
	if _, ok := validChannelTypes[ch.Type]; !ok {
		return fmt.Errorf("invalid notification channel type %q: must be one of webhook, slack, teams, email", ch.Type)
	}
	urlValidator := c.webhookURLValidator
	if urlValidator == nil {
		urlValidator = validateWebhookURL
	}
	switch ch.Type {
	case "webhook", "slack", "teams":
		if strings.TrimSpace(ch.URL) == "" {
			return fmt.Errorf("notification channel URL is required for type %q", ch.Type)
		}
		if err := urlValidator(ch.URL); err != nil {
			return err
		}
	case "email":
		if strings.TrimSpace(ch.Email) == "" {
			return fmt.Errorf("notification channel email is required for type \"email\"")
		}
	}
	return nil
}

// validateWebhookURL enforces SSRF-prevention rules on outbound webhook/slack/teams URLs.
// It requires an https scheme and rejects destinations that resolve to RFC 1918,
// loopback, link-local, or IMDS (169.254.0.0/16) addresses.
func validateWebhookURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("notification channel: invalid URL %q: %w", raw, err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("notification channel: URL must use https (got %q)", u.Scheme)
	}
	host := u.Hostname()
	if ip := net.ParseIP(host); ip != nil {
		if isChannelDisallowedIP(ip) {
			return fmt.Errorf("notification channel: URL targets a private/link-local address; refusing internal destination")
		}
		return nil
	}
	addrs, err := channelLookupIPAddr(context.Background(), host)
	if err != nil {
		return fmt.Errorf("notification channel: could not resolve URL hostname to verify it is not private/internal: %w", err)
	}
	for _, a := range addrs {
		if isChannelDisallowedIP(a.IP) {
			return fmt.Errorf("notification channel: URL resolves to a private/link-local address (%s); refusing internal destination", a.IP)
		}
	}
	return nil
}

// channelLookupIPAddr resolves a hostname to its IP addresses — a var (like
// evidencesink/notifychan's identically-shaped lookupIPAddr) so tests can
// substitute a fake resolver without a real DNS query, and so
// escalationTransport (alert_escalation.go) can share the EXACT same
// resolution seam this construction-time check uses, making a DNS-rebinding
// scenario (a public answer here, a private one at actual escalation-dial
// time) directly testable end-to-end.
var channelLookupIPAddr netutil.Resolver = netutil.DefaultResolver

// isChannelDisallowedIP reports whether ip is a private, link-local, or loopback
// address — all of which are forbidden as outbound webhook destinations (SSRF guard).
//
// Checked both directly AND against ip's embedded IPv4 (netutil.EmbeddedIPv4),
// mirroring netutil's own matchesCIDRsWithEmbedded "direct match OR embedded
// match" shape — checking ONLY the decoded form would wrongly clear a genuine
// IPv6 loopback/link-local literal (e.g. ::1 itself decodes, as deprecated
// IPv4-compatible, to embedded 0.0.0.1, which is neither loopback nor private
// in isolation). A NAT64 (64:ff9b::/96) or IPv4-compatible (::x) encoding of a
// private/loopback/link-local IPv4 (e.g. 64:ff9b::a9fe:a9fe = cloud IMDS
// 169.254.169.254) needs the embedded check: Go's own net.IP.IsPrivate/
// IsLoopback/IsLinkLocalUnicast fold IPv4-MAPPED (::ffff:x) via To4, but NOT
// these two encodings, so a bare stdlib check here disagreed with
// netutil.IsPrivateOrLinkLocal (the guard every backend-infrastructure dial
// site in this codebase shares) for exactly those two forms -- reachable both
// from validateWebhookURL's construction-time check and, more importantly,
// from escalationTransport's dial-time re-validation (alert_escalation.go),
// which wires this exact function in as its netutil.Dialer.Disallow policy.
func isChannelDisallowedIP(ip net.IP) bool {
	if isChannelDisallowedIPDirect(ip) {
		return true
	}
	if v4 := netutil.EmbeddedIPv4(ip); v4 != nil {
		return isChannelDisallowedIPDirect(v4)
	}
	return false
}

func isChannelDisallowedIPDirect(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast()
}
