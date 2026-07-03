// smtp.go — SMTP credential delivery (ADR-028).
//
// SMTPDelivery sends a new principal's single-use setup link via the operator's own
// mail relay. TLS correctness (implicit TLS on 465, STARTTLS on 587, auth
// negotiation) is delegated to wneessen/go-mail rather than hand-rolled on top of
// stdlib net/smtp — getting TLS wrong in a security product is not worth the saved
// dependency.
//
// The email carries ONLY the single-use, short-TTL link plus context (inviter,
// install name, optional note, assignment summary). It never contains a password, a
// reusable token, or any remote resource (image/CSS/JS/tracking pixel): regulated
// buyers' mail gateways flag those and they are a privacy/exfil surface.
//
// Send failures degrade gracefully to out-of-band: DeliverSetupLink returns a result
// with Delivered=false and the link in LinkForAdmin (and logs the cause) rather than
// failing closed, so the admin can always relay the link manually.
package delivery

import (
	"context"
	"fmt"
	"html"
	"log"
	"strings"
	"time"

	mail "github.com/wneessen/go-mail"
)

// smtpDialTimeout bounds a single send so a wedged relay cannot stall the request.
const smtpDialTimeout = 10 * time.Second

// TLS modes (credential_delivery.smtp.tls).
const (
	smtpTLSStartTLS = "starttls"
	smtpTLSImplicit = "implicit"
	smtpTLSNone     = "none"
)

// EnvAllowInsecureSMTP gates credential_delivery.smtp.tls=none. Cleartext SMTP sends
// the setup-link email (and, if the relay requires auth, the relay credentials) over
// the wire unencrypted — mirroring the explicit-opt-in convention used for other
// insecure toggles in this codebase (e.g. insecure_skip_verify), tls=none refuses to
// activate unless this env var is set to a truthy value.
const EnvAllowInsecureSMTP = "KEYORIX_ALLOW_INSECURE_SMTP"

// SMTPDelivery sends setup links via the operator's configured SMTP relay.
type SMTPDelivery struct {
	cfg SMTPSettings
}

// newSMTPDelivery validates the SMTP settings and returns a ready sender. It does
// not dial — connection is per-send so a relay outage never blocks startup.
func newSMTPDelivery(cfg SMTPSettings) (*SMTPDelivery, error) {
	if cfg.Host == "" {
		return nil, fmt.Errorf("delivery: smtp host is required")
	}
	if cfg.From == "" {
		return nil, fmt.Errorf("delivery: smtp from address is required")
	}
	switch strings.ToLower(cfg.TLS) {
	case "", smtpTLSStartTLS, smtpTLSImplicit:
	case smtpTLSNone:
		if !envFlagEnabled(EnvAllowInsecureSMTP) {
			return nil, fmt.Errorf("delivery: smtp.tls=none sends mail (and any relay credentials) in cleartext; refusing unless the operator explicitly opts in by setting %s=true", EnvAllowInsecureSMTP)
		}
		log.Printf("delivery: WARNING smtp.tls=none is ACTIVE — setup-link email will be sent over CLEARTEXT SMTP; dev/test only, never use in production")
	default:
		return nil, fmt.Errorf("delivery: unknown smtp tls mode %q (want starttls|implicit|none)", cfg.TLS)
	}
	return &SMTPDelivery{cfg: cfg}, nil
}

func (d *SMTPDelivery) Name() string { return ChannelSMTP }

// DeliverSetupLink builds and sends the setup-link email. On any failure it returns
// a non-delivered result carrying the link for manual relay (graceful degradation),
// never an error — a setup link must always have a recourse path.
func (d *SMTPDelivery) DeliverSetupLink(ctx context.Context, req SetupLinkRequest) (DeliveryResult, error) {
	if req.Link == "" {
		return DeliveryResult{}, fmt.Errorf("delivery: setup link is empty")
	}
	if req.RecipientEmail == "" {
		return DeliveryResult{}, fmt.Errorf("delivery: recipient email is empty")
	}

	msg, err := d.buildMessage(req)
	if err != nil {
		// A malformed from/to is a config error, not a transient outage — still
		// degrade to manual relay rather than dropping the principal's only link.
		log.Printf("delivery: smtp message build failed for %s, degrading to manual relay: %v", req.RecipientEmail, err)
		return DeliveryResult{Channel: ChannelSMTP, Delivered: false, LinkForAdmin: req.Link}, nil
	}

	client, err := d.newClient()
	if err != nil {
		log.Printf("delivery: smtp client init failed, degrading to manual relay: %v", err)
		return DeliveryResult{Channel: ChannelSMTP, Delivered: false, LinkForAdmin: req.Link}, nil
	}

	if err := client.DialAndSendWithContext(ctx, msg); err != nil {
		log.Printf("delivery: smtp send to %s failed, degrading to manual relay: %v", req.RecipientEmail, err)
		return DeliveryResult{Channel: ChannelSMTP, Delivered: false, LinkForAdmin: req.Link}, nil
	}
	return DeliveryResult{Channel: ChannelSMTP, Delivered: true}, nil
}

// newClient builds a go-mail client from the SMTP settings, selecting the TLS policy
// and auth mechanism. Auth is auto-discovered when credentials are present and
// disabled otherwise (e.g. an internal relay that authenticates by network).
func (d *SMTPDelivery) newClient() (*mail.Client, error) {
	opts := []mail.Option{
		mail.WithTimeout(smtpDialTimeout),
	}
	if d.cfg.Port > 0 {
		opts = append(opts, mail.WithPort(d.cfg.Port))
	}
	switch strings.ToLower(d.cfg.TLS) {
	case smtpTLSImplicit:
		opts = append(opts, mail.WithSSL())
	case smtpTLSNone:
		opts = append(opts, mail.WithTLSPolicy(mail.NoTLS))
	default: // "" or starttls — require STARTTLS.
		opts = append(opts, mail.WithTLSPolicy(mail.TLSMandatory))
	}
	if d.cfg.Username != "" {
		opts = append(opts,
			mail.WithSMTPAuth(mail.SMTPAuthAutoDiscover),
			mail.WithUsername(d.cfg.Username),
			mail.WithPassword(d.cfg.Password),
		)
	}
	return mail.NewClient(d.cfg.Host, opts...)
}

// buildMessage renders the setup-link email. Exposed-for-test via buildMessage; the
// plaintext and HTML parts are produced by renderBody so their content can be
// asserted (no remote resources, link present) without a live SMTP server.
func (d *SMTPDelivery) buildMessage(req SetupLinkRequest) (*mail.Msg, error) {
	msg := mail.NewMsg()
	if err := msg.From(d.cfg.From); err != nil {
		return nil, fmt.Errorf("invalid from address %q: %w", d.cfg.From, err)
	}
	if err := msg.To(req.RecipientEmail); err != nil {
		return nil, fmt.Errorf("invalid recipient %q: %w", req.RecipientEmail, err)
	}
	plain, htmlBody := renderBody(req)
	msg.Subject(subjectFor(req))
	msg.SetBodyString(mail.TypeTextPlain, plain)
	msg.AddAlternativeString(mail.TypeTextHTML, htmlBody)
	return msg, nil
}

// subjectFor returns the email subject, scoped to the install name when present.
func subjectFor(req SetupLinkRequest) string {
	install := req.InstallName
	if install == "" {
		install = "Keyorix"
	}
	return fmt.Sprintf("Set up your %s access", install)
}

// renderBody produces the plaintext and minimal-inline-HTML bodies. No remote
// resources, no tracking — text plus one anchor for the single call to action.
func renderBody(req SetupLinkRequest) (plain, htmlBody string) {
	install := req.InstallName
	if install == "" {
		install = "Keyorix"
	}
	greetName := req.DisplayName
	if greetName == "" {
		greetName = "there"
	}

	var p strings.Builder
	fmt.Fprintf(&p, "Hi %s,\n\n", greetName)
	fmt.Fprintf(&p, "You've been given access to %s.\n\n", install)
	if req.AssignmentSummary != "" {
		fmt.Fprintf(&p, "Your access: %s\n\n", req.AssignmentSummary)
	}
	if req.Message != "" {
		fmt.Fprintf(&p, "Note from the sender:\n%s\n\n", req.Message)
	}
	p.WriteString("To set your password and finish setup, open this single-use link:\n")
	fmt.Fprintf(&p, "%s\n\n", req.Link)
	p.WriteString("The link can be used once and expires soon. If you weren't expecting this, you can ignore this email.\n")

	var h strings.Builder
	h.WriteString("<div style=\"font-family:sans-serif;font-size:14px;line-height:1.5;color:#1a1a1a\">")
	fmt.Fprintf(&h, "<p>Hi %s,</p>", html.EscapeString(greetName))
	fmt.Fprintf(&h, "<p>You've been given access to <strong>%s</strong>.</p>", html.EscapeString(install))
	if req.AssignmentSummary != "" {
		fmt.Fprintf(&h, "<p><strong>Your access:</strong> %s</p>", html.EscapeString(req.AssignmentSummary))
	}
	if req.Message != "" {
		fmt.Fprintf(&h, "<p><strong>Note from the sender:</strong><br>%s</p>", html.EscapeString(req.Message))
	}
	h.WriteString("<p>To set your password and finish setup, use this single-use link:</p>")
	// The href and visible text are the same trusted setup URL; no redirect, no tracking.
	fmt.Fprintf(&h, "<p><a href=\"%s\">%s</a></p>", html.EscapeString(req.Link), html.EscapeString(req.Link))
	h.WriteString("<p style=\"color:#666\">The link can be used once and expires soon. If you weren't expecting this, you can ignore this email.</p>")
	h.WriteString("</div>")

	return p.String(), h.String()
}
