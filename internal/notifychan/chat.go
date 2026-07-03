// chat.go — Slack / Microsoft Teams notification channels. Both accept an incoming
// webhook URL that carries its own secret token; the only per-platform difference is
// the JSON payload shape (Slack: {text}; Teams: a MessageCard). Delivery, retry, and
// metrics are handled by the shared engine (delivery.go); the channel label is the
// platform (slack|teams).
package notifychan

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/keyorixhq/keyorix/internal/core"
)

const (
	chatTimeout   = 10 * time.Second
	chatQueueSize = 256
)

// ChatKind selects the payload format for the chat webhook.
type ChatKind string

const (
	ChatSlack ChatKind = "slack"
	ChatTeams ChatKind = "teams"
)

// ChatConfig configures a Slack/Teams channel: the platform and its incoming-webhook
// URL (which embeds the platform's secret token).
type ChatConfig struct {
	Kind       ChatKind
	WebhookURL string
}

// ChatSink delivers notifications to a Slack or Teams incoming webhook.
type ChatSink struct {
	cfg    ChatConfig
	client *http.Client
	d      *deliverer
}

// NewChat builds a chat sink and starts its worker. The kind must be slack|teams and
// the webhook URL is required. Close() drains in-flight events at shutdown.
func NewChat(cfg ChatConfig) (*ChatSink, error) {
	return newChat(cfg, deliveryBaseBackoff)
}

// newChat is the constructor with an injectable retry backoff for tests.
func newChat(cfg ChatConfig, baseBackoff time.Duration) (*ChatSink, error) {
	switch cfg.Kind {
	case ChatSlack, ChatTeams:
	default:
		return nil, fmt.Errorf("notifychan: unknown chat kind %q (want slack|teams)", cfg.Kind)
	}
	if cfg.WebhookURL == "" {
		return nil, fmt.Errorf("notifychan: chat webhook_url is required")
	}
	if err := validateEndpoint(cfg.WebhookURL, false); err != nil {
		return nil, err
	}
	s := &ChatSink{
		cfg:    cfg,
		client: &http.Client{Timeout: chatTimeout, CheckRedirect: refuseRedirectDowngrade},
	}
	s.d = newDeliverer(string(cfg.Kind), chatQueueSize, baseBackoff, s.send)
	return s, nil
}

// Deliver enqueues the event. Non-blocking; a full queue drops and counts it.
func (s *ChatSink) Deliver(ev core.NotificationEvent) {
	if s == nil {
		return
	}
	s.d.enqueue(ev)
}

// send POSTs the platform payload once. retryable reports whether a non-nil err is
// transient (5xx/429/transport) versus permanent (4xx / marshalling).
func (s *ChatSink) send(ctx context.Context, ev core.NotificationEvent) (retryable bool, err error) {
	body, err := json.Marshal(chatPayload(s.cfg.Kind, ev))
	if err != nil {
		return false, fmt.Errorf("marshal %s payload: %w", s.cfg.Kind, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.WebhookURL, bytes.NewReader(body))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return true, err // transport / timeout — transient
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return false, nil
	}
	retryable = resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests
	return retryable, fmt.Errorf("%s webhook returned %s", s.cfg.Kind, strings.TrimSpace(resp.Status))
}

// mrkdwnEscaper neutralizes Slack/Teams mrkdwn control syntax before a
// user-controllable string (secret name, project name, or anything else that
// ultimately traces back to a Title/Message an ordinary, non-admin user can choose —
// e.g. by naming a secret they own and sharing it, ADR-024) is interpolated into a
// chat payload. Slack's incoming-webhook `text` field is rendered as mrkdwn by
// default, where `<...>` is parsed as a link/mention token: `<!channel>`/`<!here>`/
// `<!everyone>` trigger a mass ping, `<@USERID>` mentions a specific user, and
// `<https://evil.example|label>` renders as a clickable link with an
// attacker-chosen label. Escaping `<`/`>` (per Slack's own escaping rules, along
// with `&` so the escape sequences themselves can't be re-interpreted) turns any
// such sequence back into inert literal text — this is Slack's documented escaping
// convention, and Teams' MessageCard fields share the same HTML-ish convention, so
// the same replacer is safe for both platforms.
var mrkdwnEscaper = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")

// escapeMrkdwn applies mrkdwnEscaper to a single string.
func escapeMrkdwn(s string) string {
	return mrkdwnEscaper.Replace(s)
}

// chatText renders the notification as a single plain-text message (no remote
// resources), shared by both platforms. Title/Message may embed user-controllable
// values (secret/project names), so both are mrkdwn-escaped before interpolation —
// this is the single choke point every caller's text passes through, so escaping
// here (rather than at each notification call site) covers every current and
// future producer of a NotificationEvent.
func chatText(ev core.NotificationEvent) string {
	var b strings.Builder
	if ev.Title != "" {
		fmt.Fprintf(&b, "*%s*\n", escapeMrkdwn(ev.Title))
	}
	b.WriteString(escapeMrkdwn(ev.Message))
	if ev.Link != "" {
		fmt.Fprintf(&b, "\n%s", ev.Link)
	}
	return b.String()
}

// chatPayload builds the platform-specific JSON body. Slack incoming webhooks take
// {text}; Teams connectors take a MessageCard. Every field sourced from
// user-controllable data (Title, Message) is mrkdwn-escaped (via chatText/
// escapeMrkdwn) before it reaches either payload shape — Link is excluded because it
// is always a server-generated path (e.g. "/secrets/%d"), never user input.
func chatPayload(kind ChatKind, ev core.NotificationEvent) interface{} {
	text := chatText(ev)
	if kind == ChatTeams {
		title := ev.Title
		if title == "" {
			title = "Keyorix notification"
		}
		return map[string]interface{}{
			"@type":    "MessageCard",
			"@context": "https://schema.org/extensions",
			"summary":  escapeMrkdwn(title),
			"title":    escapeMrkdwn(title),
			"text":     escapeMrkdwn(ev.Message),
		}
	}
	return map[string]string{"text": text}
}

// Close stops the worker after draining queued events. Idempotent.
func (s *ChatSink) Close() {
	if s == nil {
		return
	}
	s.d.close()
}
