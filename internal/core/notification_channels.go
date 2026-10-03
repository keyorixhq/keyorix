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

// ListNotificationChannels returns all configured notification channels, with
// each channel's URL decrypted back into ch.URL (#2433).
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
// decrypted back into ch.URL (#2433).
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
	ch.CreatedBy = createdBy
	ch.CreatedAt = time.Now().UTC()
	ch.UpdatedAt = ch.CreatedAt
	if err := c.insertNotificationChannelRow(ctx, ch); err != nil {
		return nil, err
	}
	// #2433: the URL is encrypted bound to NotificationChannelURLAAD(ch.ID), so
	// it must be encrypted AFTER the row exists (ch.ID is an auto-increment PK,
	// not known beforehand) -- insert first with url_enc/url_meta empty, then
	// encrypt and persist them in a second write, mirroring
	// CreateDynamicSecretConfig's identical two-phase admin-DSN encryption
	// (dynamic_secrets.go). The gap is invisible to any other caller: ch.ID
	// isn't returned to the requester until this function returns.
	if err := c.encryptNotificationChannelURL(ch); err != nil {
		return nil, err
	}
	if err := c.storage.UpdateNotificationChannel(ctx, ch); err != nil {
		return nil, fmt.Errorf("failed to persist encrypted notification channel URL: %w", err)
	}
	after := notificationChannelAuditViewOf(*ch)
	c.writeConfigChangeAuditEvent(ctx, EventNotificationChannelCreated, actorID,
		fmt.Sprintf("notification channel %d (%q, type=%s) created by %s", ch.ID, ch.Name, ch.Type, createdBy),
		nil, after)
	return ch, nil
}

// insertNotificationChannelRow performs CreateNotificationChannel's first
// storage write in isolation -- mirrors insertDynamicSecretConfigRow
// (dynamic_secrets.go)'s identical reason for existing as its own named
// helper rather than an inline call: it keeps this one write, and the
// later encrypt-and-persist write, in two clearly separate steps of the
// same two-phase insert-then-encrypt shape the atomicity guard
// (atomicity_guard_test.go) already recognizes for DynamicSecretConfig.
func (c *KeyorixCore) insertNotificationChannelRow(ctx context.Context, ch *models.NotificationChannel) error {
	return c.storage.CreateNotificationChannel(ctx, ch)
}

// UpdateNotificationChannel applies the given map of field updates to the channel
// identified by id and returns the updated channel.
// actorID is the acting user's numeric ID for audit attribution (0 when
// unknown, e.g. a local CLI invocation) -- see writeConfigChangeAuditEvent.
func (c *KeyorixCore) UpdateNotificationChannel(ctx context.Context, id uint, updates map[string]any, actorID uint) (*models.NotificationChannel, error) {
	ch, err := c.GetNotificationChannel(ctx, id) // decrypts ch.URL (#2433)
	if err != nil {
		return nil, err
	}
	before := notificationChannelAuditViewOf(*ch)
	if v, ok := updates["name"].(string); ok && v != "" {
		ch.Name = v
	}
	if v, ok := updates["type"].(string); ok && v != "" {
		ch.Type = v
	}
	if v, ok := updates["url"].(string); ok {
		ch.URL = v
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
	ch.UpdatedAt = time.Now().UTC()
	if err := c.encryptNotificationChannelURL(ch); err != nil {
		return nil, err
	}
	if err := c.storage.UpdateNotificationChannel(ctx, ch); err != nil {
		return nil, err
	}
	after := notificationChannelAuditViewOf(*ch)
	c.writeConfigChangeAuditEvent(ctx, EventNotificationChannelUpdated, actorID,
		fmt.Sprintf("notification channel %d (%q) updated", id, ch.Name),
		before, after)
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
	before := notificationChannelAuditViewOf(*ch)
	c.writeConfigChangeAuditEvent(ctx, EventNotificationChannelDeleted, actorID,
		fmt.Sprintf("notification channel %d (%q, type=%s) deleted", id, ch.Name, ch.Type),
		before, nil)
	return nil
}

// notificationChannelAuditView mirrors models.NotificationChannel's audit-relevant
// fields WITHOUT its credential-bearing URL (#2432): the raw destination URL
// (the webhook/Slack/Teams bearer credential -- internal/notifychan/delivery.go's
// own doc comment) must never be marshaled into audit_events.Diff, which any
// audit.read holder can read regardless of whether they manage notification
// channels at all. URLConfigured records only WHETHER a destination is set,
// never its value -- enough for an incident investigation to see a webhook
// destination was added/changed/removed, never to recover it.
type notificationChannelAuditView struct {
	ID             uint   `json:"id"`
	Name           string `json:"name"`
	Type           string `json:"type"`
	Enabled        bool   `json:"enabled"`
	URLConfigured  bool   `json:"url_configured,omitempty"`
	Email          string `json:"email,omitempty"`
	Events         string `json:"events,omitempty"`
	MaxRetries     int    `json:"max_retries,omitempty"`
	RetryBackoffMs int    `json:"retry_backoff_ms,omitempty"`
	CreatedBy      string `json:"created_by,omitempty"`
}

// notificationChannelAuditViewOf redacts ch's URL for the audit trail. Checks
// both ch.URL (set on the create/update path, before encryption) and
// ch.URLEnc (set whenever ch came from a bare, non-decrypting storage read,
// e.g. DeleteNotificationChannel) so URLConfigured is accurate regardless of
// which form the caller happened to have in hand.
func notificationChannelAuditViewOf(ch models.NotificationChannel) notificationChannelAuditView {
	return notificationChannelAuditView{
		ID: ch.ID, Name: ch.Name, Type: ch.Type, Enabled: ch.Enabled,
		URLConfigured:  ch.URL != "" || len(ch.URLEnc) != 0,
		Email:          ch.Email,
		Events:         ch.Events,
		MaxRetries:     ch.MaxRetries,
		RetryBackoffMs: ch.RetryBackoffMs,
		CreatedBy:      ch.CreatedBy,
	}
}

// encryptNotificationChannelURL sets ch.URLEnc/ch.URLMeta from ch.URL's
// current plaintext value, bound to NotificationChannelURLAAD(ch.ID) -- the
// same envelope scheme (and the same encryptAuthSecret helper,
// internal/core/service.go) already used for the dynamic-secret admin DSN
// and the MFA TOTP seed. ch.ID must already be assigned (the row must
// already exist; see CreateNotificationChannel's two-phase insert-then-encrypt).
func (c *KeyorixCore) encryptNotificationChannelURL(ch *models.NotificationChannel) error {
	urlEnc, urlMeta, err := c.encryptAuthSecret(ch.URL, ports.NotificationChannelURLAAD(ch.ID))
	if err != nil {
		return fmt.Errorf("failed to encrypt notification channel URL: %w", err)
	}
	ch.URLEnc = urlEnc
	ch.URLMeta = urlMeta
	return nil
}

// decryptNotificationChannelURL populates ch.URL from ch.URLEnc/ch.URLMeta,
// reversing encryptNotificationChannelURL. Called by every read path
// (GetNotificationChannel/ListNotificationChannels) so every other call site
// in the codebase -- dispatchToChannel (alert_escalation.go), validation, the
// CRUD HTTP response (server/http/handlers/notification_channels.go) -- keeps
// reading ch.URL exactly as before #2433, with no ripple. Fails closed: a
// decrypt error is returned rather than silently handing back ciphertext or
// an empty URL as if no destination were configured.
func (c *KeyorixCore) decryptNotificationChannelURL(ch *models.NotificationChannel) error {
	// Nothing to decrypt -- URL stays whatever it already was. ch.URL carries
	// gorm:"-" (never populated by a real storage read), so after a genuine
	// GetNotificationChannel/ListNotificationChannels fetch it is already ""
	// here; this branch only matters for a channel that genuinely has no URL
	// (type "email"), and is also what lets a hand-built *models.NotificationChannel{URL: "..."}
	// test fixture (constructed without ever going through encryptNotificationChannelURL)
	// pass through unchanged.
	if len(ch.URLEnc) == 0 {
		return nil
	}
	plain, err := c.decryptAuthSecret(ch.URLEnc, ch.URLMeta, ports.NotificationChannelURLAAD(ch.ID))
	if err != nil {
		return fmt.Errorf("failed to decrypt notification channel URL: %w", err)
	}
	ch.URL = plain
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
