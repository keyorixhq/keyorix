// Package delivery transports a new principal's first-credential setup link to
// them (ADR-028). It sits behind one CredentialDelivery interface with two
// interchangeable channels — operator-configured SMTP email and admin out-of-band
// display (the link is returned to the admin to relay manually) — selected by
// config, mirroring the SIEM-connector pattern in internal/audit/siem.
//
// SECURITY: an implementation never sees a password or any reusable credential. It
// transports only the single-use, short-TTL, hashed-at-rest setup link (or, for the
// out-of-band one-time-password path, a value the caller forces to be reset on first
// login). No email carries a password or a reusable token.
package delivery

import (
	"context"
	"fmt"
	"log"

	"github.com/keyorixhq/keyorix/internal/envflag"
)

// EnvAllowInsecureLogDelivery gates credential_delivery.mode=log (ADR-028). Writing a
// live, usable password-reset / setup link to the application log is a real credential
// disclosure — anyone with log read access gets a working account-takeover link. Unlike
// the other delivery modes it is dev/test-only, so — mirroring how other insecure
// toggles in this codebase (e.g. insecure_skip_verify) require an explicit operator
// opt-in rather than defaulting on — mode=log refuses to activate unless this env var is
// set to a truthy value.
const EnvAllowInsecureLogDelivery = "KEYORIX_ALLOW_INSECURE_LOG_DELIVERY"

// Delivery modes (credential_delivery.mode).
const (
	// ModeAuto uses SMTP when configured, else out-of-band. Safe zero-config default.
	ModeAuto = "auto"
	// ModeSMTP always sends via SMTP, degrading to a returned link if sending fails.
	ModeSMTP = "smtp"
	// ModeOutOfBand never attempts SMTP; always returns the link to the admin.
	// Correct default for air-gapped installs.
	ModeOutOfBand = "out_of_band"
	// ModeLog writes the link to the server log with a loud warning (dev/test only).
	ModeLog = "log"
)

// Channel identifiers reported on a DeliveryResult.
const (
	ChannelSMTP      = "smtp"
	ChannelOutOfBand = "out_of_band"
	ChannelLog       = "log"
)

// SetupLinkRequest is the transport-agnostic payload for delivering a setup link.
type SetupLinkRequest struct {
	RecipientEmail    string
	DisplayName       string
	Link              string // fully-formed https URL containing the single-use token
	Purpose           string
	InstallName       string // e.g. "Acme Corporation Keyorix"
	Message           string // optional inviter note
	AssignmentSummary string // e.g. "developer on mobile-app, viewer on payment-svc"
}

// DeliveryResult reports how a setup link was delivered.
type DeliveryResult struct {
	Channel      string // ChannelSMTP | ChannelOutOfBand | ChannelLog
	Delivered    bool   // true if actually sent; false if returned for manual relay
	LinkForAdmin string // populated for out-of-band — the link to show the admin once
}

// CredentialDelivery delivers a setup link (or one-time secret) to a new principal.
// Implementations never see the password; they transport the single-use link only.
type CredentialDelivery interface {
	// DeliverSetupLink delivers the link to the recipient. For out-of-band mode it
	// returns the link to the caller (for the admin to relay) instead of sending.
	DeliverSetupLink(ctx context.Context, req SetupLinkRequest) (DeliveryResult, error)
	// Name identifies the channel for logging/audit.
	Name() string
}

// SMTPSettings configures the operator's own mail relay. The password is resolved
// from KEYORIX_SMTP_PASSWORD by the config layer and passed in here; it is never
// written to the config file. SMTP transport is implemented in smtp.go
// (newSMTPDelivery) and selected by New below.
type SMTPSettings struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
	TLS      string // starttls | implicit | none(dev-only)
}

// Configured reports whether an SMTP relay has been set up.
func (s SMTPSettings) Configured() bool {
	return s.Host != ""
}

// Config selects and parameterizes the delivery channel.
type Config struct {
	Mode    string // ModeAuto | ModeSMTP | ModeOutOfBand | ModeLog ("" = ModeAuto)
	BaseURL string // used by the caller to build absolute setup links
	SMTP    SMTPSettings
}

// New selects a CredentialDelivery implementation from cfg, mirroring siem.New.
//
//   - out_of_band — always return the link to the admin (air-gapped installs).
//   - log         — write the link to the server log (dev/test only).
//   - smtp        — send via the operator's relay; send failures degrade to
//     out-of-band rather than failing closed.
//   - auto ("")   — smtp when an SMTP relay is configured, else out_of_band, so a
//     zero-config install still works without any mail infrastructure.
func New(cfg Config) (CredentialDelivery, error) {
	mode := cfg.Mode
	if mode == "" {
		mode = ModeAuto
	}
	switch mode {
	case ModeOutOfBand:
		return &OutOfBandDelivery{}, nil
	case ModeLog:
		if !envflag.Enabled(EnvAllowInsecureLogDelivery) {
			return nil, fmt.Errorf("delivery: credential_delivery.mode=log writes a live, usable setup link to the log; refusing unless the operator explicitly opts in by setting %s=true", EnvAllowInsecureLogDelivery)
		}
		log.Printf("delivery: WARNING credential_delivery.mode=log is ACTIVE — setup links (live, usable credentials) will be written to the application log; dev/test only, never use in production")
		return &LogDelivery{}, nil
	case ModeSMTP:
		return newSMTPDelivery(cfg.SMTP)
	case ModeAuto:
		if cfg.SMTP.Configured() {
			return newSMTPDelivery(cfg.SMTP)
		}
		return &OutOfBandDelivery{}, nil
	default:
		return nil, fmt.Errorf("delivery: unknown mode %q (want auto|smtp|out_of_band|log)", cfg.Mode)
	}
}

// OutOfBandDelivery sends nothing; it returns the link in DeliveryResult.LinkForAdmin
// so the create-user / invite response carries it back to the admin UI/CLI, which
// displays it once for the admin to relay over their own secure channel. This is the
// only path that works on an air-gapped install.
type OutOfBandDelivery struct{}

func (d *OutOfBandDelivery) DeliverSetupLink(_ context.Context, req SetupLinkRequest) (DeliveryResult, error) {
	if req.Link == "" {
		return DeliveryResult{}, fmt.Errorf("delivery: setup link is empty")
	}
	return DeliveryResult{
		Channel:      ChannelOutOfBand,
		Delivered:    false,
		LinkForAdmin: req.Link,
	}, nil
}

func (d *OutOfBandDelivery) Name() string { return ChannelOutOfBand }

// LogDelivery writes the setup link to the server log with a loud warning. Dev/test
// only — it puts a credential-bearing link in the logs, so it is never selected
// unless the operator explicitly sets mode=log.
type LogDelivery struct{}

func (d *LogDelivery) DeliverSetupLink(_ context.Context, req SetupLinkRequest) (DeliveryResult, error) {
	if req.Link == "" {
		return DeliveryResult{}, fmt.Errorf("delivery: setup link is empty")
	}
	log.Printf("delivery: [DEV LOG MODE] setup link for %s (purpose=%s): %s",
		req.RecipientEmail, req.Purpose, req.Link)
	return DeliveryResult{Channel: ChannelLog, Delivered: true}, nil
}

func (d *LogDelivery) Name() string { return ChannelLog }
