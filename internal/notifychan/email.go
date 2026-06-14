// email.go — the SMTP notification channel. Like the credential-delivery mailer
// (ADR-028) it delegates TLS correctness to wneessen/go-mail rather than hand-
// rolling net/smtp. Sending is asynchronous (a bounded queue drained by a worker)
// so Deliver never blocks the triggering action; events without a recipient email
// are skipped.
package notifychan

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	mail "github.com/wneessen/go-mail"

	"github.com/keyorixhq/keyorix/internal/core"
)

const (
	emailTimeout   = 10 * time.Second
	emailQueueSize = 256
)

// EmailConfig configures the SMTP notification channel.
type EmailConfig struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
	TLS      string // starttls | implicit | none(dev-only)
}

// EmailSink delivers notifications as plaintext email via the operator's SMTP relay.
type EmailSink struct {
	cfg     EmailConfig
	queue   chan core.NotificationEvent
	wg      sync.WaitGroup
	mu      sync.Mutex
	dropped int
}

// NewEmail validates the SMTP settings and starts the delivery worker. Host and
// From are required. Close() drains in-flight events at shutdown.
func NewEmail(cfg EmailConfig) (*EmailSink, error) {
	if cfg.Host == "" {
		return nil, fmt.Errorf("notifychan: email smtp host is required")
	}
	if cfg.From == "" {
		return nil, fmt.Errorf("notifychan: email smtp from address is required")
	}
	switch strings.ToLower(cfg.TLS) {
	case "", "starttls", "implicit", "none":
	default:
		return nil, fmt.Errorf("notifychan: unknown smtp tls mode %q (want starttls|implicit|none)", cfg.TLS)
	}
	s := &EmailSink{cfg: cfg, queue: make(chan core.NotificationEvent, emailQueueSize)}
	s.wg.Add(1)
	go s.worker()
	return s, nil
}

// Deliver enqueues the event. Non-blocking; drops (and counts) when the queue is
// full so a wedged relay never stalls the caller.
func (s *EmailSink) Deliver(ev core.NotificationEvent) {
	if s == nil {
		return
	}
	select {
	case s.queue <- ev:
	default:
		s.mu.Lock()
		s.dropped++
		dropped := s.dropped
		s.mu.Unlock()
		log.Printf("notifychan: email queue full, dropped notification (total dropped: %d)", dropped)
	}
}

func (s *EmailSink) worker() {
	defer s.wg.Done()
	for ev := range s.queue {
		if ev.Email == "" {
			continue // no address to send to
		}
		if err := s.send(context.Background(), ev); err != nil {
			log.Printf("notifychan: email delivery to %s failed: %v", ev.Email, err)
		}
	}
}

func (s *EmailSink) send(ctx context.Context, ev core.NotificationEvent) error {
	subject, body := renderEmail(ev)
	msg := mail.NewMsg()
	if err := msg.From(s.cfg.From); err != nil {
		return fmt.Errorf("invalid from address %q: %w", s.cfg.From, err)
	}
	if err := msg.To(ev.Email); err != nil {
		return fmt.Errorf("invalid recipient %q: %w", ev.Email, err)
	}
	msg.Subject(subject)
	msg.SetBodyString(mail.TypeTextPlain, body)

	client, err := s.newClient()
	if err != nil {
		return err
	}
	return client.DialAndSendWithContext(ctx, msg)
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

// Close stops the worker after draining queued events.
func (s *EmailSink) Close() {
	if s == nil {
		return
	}
	close(s.queue)
	s.wg.Wait()
}
