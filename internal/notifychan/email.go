// email.go — the SMTP notification channel. Like the credential-delivery mailer
// (ADR-028) it delegates TLS correctness to wneessen/go-mail rather than hand-
// rolling net/smtp. Delivery, retry, and metrics are handled by the shared engine
// (delivery.go).
//
// A per-user event (ev.Email resolved by the caller, e.g. dispatchNotification)
// always has somewhere to go. A BROADCAST event (SendComplianceDigest,
// notifyRotationFailures) has no such per-user address — a broadcast is meant for
// whoever is configured to receive it, not one specific mailbox — so it is routed
// to cfg.BroadcastTo, the operator-configured digest/admin destination, exactly the
// way the webhook/chat channels always route a broadcast to their one fixed
// endpoint. With neither an event Email nor a configured BroadcastTo there is
// nowhere to send it; that drop is counted and logged like any other channel
// failure rather than silently discarded (#221).
package notifychan

import (
	"context"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	mail "github.com/wneessen/go-mail"

	"github.com/keyorixhq/keyorix/internal/core"
)

const (
	emailTimeout   = 10 * time.Second
	emailQueueSize = 256
)

// envAllowInsecureSMTP gates tls=none for the notification-email channel, mirroring
// the same opt-in required for credential-delivery SMTP (internal/delivery) and the
// explicit-opt-in convention used for other insecure toggles in this codebase (e.g.
// insecure_skip_verify): cleartext SMTP is never enabled by default.
const envAllowInsecureSMTP = "KEYORIX_ALLOW_INSECURE_SMTP"

// envFlagEnabled reports whether the named environment variable is set to a truthy
// value. Unset or unparsable = false (fail closed).
func envFlagEnabled(name string) bool {
	v, ok := os.LookupEnv(name)
	if !ok {
		return false
	}
	b, err := strconv.ParseBool(v)
	return err == nil && b
}

// EmailConfig configures the SMTP notification channel.
type EmailConfig struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
	TLS      string // starttls | implicit | none(dev-only)
	// BroadcastTo is the destination address for BROADCAST notifications (the
	// scheduled compliance digest, auto-rotation-failure alerts) — the address a
	// deployment-wide alert goes to when email is the channel handling it. Optional:
	// leave empty when a non-email channel (Slack/Teams/webhook) already receives
	// broadcasts, or when email-only broadcast alerting isn't wanted. Without it, a
	// broadcast event has no recipient to route to and is dropped (counted/logged,
	// not silently, #221).
	BroadcastTo string
}

// EmailSink delivers notifications as plaintext email via the operator's SMTP relay.
type EmailSink struct {
	cfg EmailConfig
	d   *deliverer
}

// NewEmail validates the SMTP settings and starts the delivery worker. Host and
// From are required. Close() drains in-flight events at shutdown.
func NewEmail(cfg EmailConfig) (*EmailSink, error) {
	return newEmail(cfg, deliveryBaseBackoff)
}

// newEmail is the constructor with an injectable retry backoff for tests.
func newEmail(cfg EmailConfig, baseBackoff time.Duration) (*EmailSink, error) {
	if cfg.Host == "" {
		return nil, fmt.Errorf("notifychan: email smtp host is required")
	}
	if cfg.From == "" {
		return nil, fmt.Errorf("notifychan: email smtp from address is required")
	}
	switch strings.ToLower(cfg.TLS) {
	case "", "starttls", "implicit":
	case "none":
		if !envFlagEnabled(envAllowInsecureSMTP) {
			return nil, fmt.Errorf("notifychan: email smtp tls=none sends mail (and any relay credentials) in cleartext; refusing unless the operator explicitly opts in by setting %s=true", envAllowInsecureSMTP)
		}
		log.Printf("notifychan: WARNING email smtp tls=none is ACTIVE — notification email will be sent over CLEARTEXT SMTP; dev/test only, never use in production")
	default:
		return nil, fmt.Errorf("notifychan: unknown smtp tls mode %q (want starttls|implicit|none)", cfg.TLS)
	}
	s := &EmailSink{cfg: cfg}
	s.d = newDeliverer("email", emailQueueSize, baseBackoff, s.send)
	return s, nil
}

// Deliver enqueues the event and reports whether it was actually handed off for
// sending. Non-blocking; a full queue drops and counts it (see delivery.go).
//
// An event with no per-user Email is a BROADCAST (compliance digest, rotation-
// failure alert): it is routed to the configured BroadcastTo address rather than
// being dropped for lacking a per-user recipient (#221). With no Email and no
// BroadcastTo configured there is genuinely nowhere to send it — that is still
// counted and logged as a dropped delivery, not silently discarded, so an operator
// running email-only can see a broadcast channel that never has anywhere to go.
func (s *EmailSink) Deliver(ev core.NotificationEvent) bool {
	if s == nil {
		return false
	}
	if ev.Email == "" {
		if s.cfg.BroadcastTo == "" {
			notifyDeliveries.WithLabelValues(s.d.channel, outcomeDropped).Inc()
			log.Printf("notifychan: email dropped a broadcast notification (type=%q) — no recipient and no email.broadcast_to destination configured", ev.Type)
			return false
		}
		ev.Email = s.cfg.BroadcastTo
	}
	s.d.enqueue(ev)
	return true
}

// send mails the event once. retryable reports whether a non-nil err is transient: a
// bad from/to address or misconfiguration is permanent; an SMTP dial/relay error is
// transient and worth retrying.
func (s *EmailSink) send(ctx context.Context, ev core.NotificationEvent) (retryable bool, err error) {
	subject, body := renderEmail(ev)
	msg := mail.NewMsg()
	if ferr := msg.From(s.cfg.From); ferr != nil {
		return false, fmt.Errorf("invalid from address %q: %w", s.cfg.From, ferr)
	}
	if terr := msg.To(ev.Email); terr != nil {
		return false, fmt.Errorf("invalid recipient %q: %w", ev.Email, terr)
	}
	msg.Subject(subject)
	msg.SetBodyString(mail.TypeTextPlain, body)

	client, err := s.newClient()
	if err != nil {
		return false, err // misconfiguration — permanent
	}
	if err := client.DialAndSendWithContext(ctx, msg); err != nil {
		return true, err // SMTP relay / network error — transient
	}
	return false, nil
}

// newClient builds a go-mail client from the SMTP settings, selecting the TLS
// policy and enabling auth only when a username is configured (an internal relay
// may authenticate by network).
func (s *EmailSink) newClient() (*mail.Client, error) {
	opts := []mail.Option{mail.WithTimeout(emailTimeout)}
	if s.cfg.Port > 0 {
		opts = append(opts, mail.WithPort(s.cfg.Port))
	}
	switch strings.ToLower(s.cfg.TLS) {
	case "implicit":
		opts = append(opts, mail.WithSSL())
	case "none":
		opts = append(opts, mail.WithTLSPolicy(mail.NoTLS))
	default: // "" or starttls
		opts = append(opts, mail.WithTLSPolicy(mail.TLSMandatory))
	}
	if s.cfg.Username != "" {
		opts = append(opts,
			mail.WithSMTPAuth(mail.SMTPAuthAutoDiscover),
			mail.WithUsername(s.cfg.Username),
			mail.WithPassword(s.cfg.Password),
		)
	}
	return mail.NewClient(s.cfg.Host, opts...)
}

// renderEmail produces the subject and plaintext body for a notification. No remote
// resources or tracking — just the title, message, and an optional in-app link.
func renderEmail(ev core.NotificationEvent) (subject, body string) {
	subject = ev.Title
	if subject == "" {
		subject = "Keyorix notification"
	}
	var b strings.Builder
	if ev.Message != "" {
		b.WriteString(ev.Message)
		b.WriteString("\n")
	}
	if ev.Link != "" {
		fmt.Fprintf(&b, "\nOpen in Keyorix: %s\n", ev.Link)
	}
	b.WriteString("\n— Keyorix\n")
	return subject, b.String()
}

// Close stops the worker after draining queued events. Idempotent.
func (s *EmailSink) Close() {
	if s == nil {
		return
	}
	s.d.close()
}
