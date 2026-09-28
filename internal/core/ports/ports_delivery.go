// ports_delivery.go — the CredentialDelivery seam (ADR-109 "last decoupling",
// B5). SetupLinkRequest/DeliveryResult are plain data structs with no methods
// of their own (unlike RotationPartialError/NotaryReceipt), so — like step
// 1's NotaryReceipt/SAMLAssertion — the canonical declaration lives here, and
// internal/delivery's own SetupLinkRequest/DeliveryResult/ChannelOutOfBand
// become bare aliases, so every existing implementation (SMTPDelivery,
// OutOfBandDelivery, LogDelivery) satisfies CredentialDelivery with no
// adapter, and every existing caller/test that builds a
// delivery.SetupLinkRequest/delivery.DeliveryResult literal keeps compiling
// unchanged.
package ports

import "context"

// ChannelOutOfBand identifies the out-of-band delivery channel (the setup
// link is returned to the caller/admin instead of actually being sent) —
// internal/core/setup_delivery.go constructs a DeliveryResult with this
// channel directly when no CredentialDelivery is wired (SetCredentialDelivery
// never called), the SAME fallback behavior internal/delivery.OutOfBandDelivery
// itself implements when it IS wired; unwired and wired-to-OutOfBandDelivery
// must report an identical channel.
const ChannelOutOfBand = "out_of_band"

// SetupLinkRequest is the transport-agnostic payload for delivering a setup
// link (mirrors internal/delivery.SetupLinkRequest).
type SetupLinkRequest struct {
	RecipientEmail    string
	DisplayName       string
	Link              string // fully-formed https URL containing the single-use token
	Purpose           string
	InstallName       string // e.g. "Acme Corporation Keyorix"
	Message           string // optional inviter note
	AssignmentSummary string // e.g. "developer on mobile-app, viewer on payment-svc"
}

// DeliveryResult is the outcome of a CredentialDelivery.DeliverSetupLink call
// (mirrors internal/delivery.DeliveryResult).
type DeliveryResult struct {
	Channel      string // internal/delivery.ChannelSMTP | ChannelOutOfBand | ChannelLog
	Delivered    bool   // true if actually sent; false if returned for manual relay
	LinkForAdmin string // populated for out-of-band — the link to show the admin once
}

// CredentialDelivery delivers a setup link (or one-time secret) to a new
// principal. Structurally identical to internal/delivery.CredentialDelivery
// (not a type alias of it — see internal/delivery's own doc comment on why
// no alias is needed once SetupLinkRequest/DeliveryResult are the same type
// on both sides) — every existing implementation (SMTPDelivery,
// OutOfBandDelivery, LogDelivery) already satisfies this with no adapter.
//
// nil (SetCredentialDelivery never called) means out-of-band: internal/core's
// own fallback in provisionSetupLink returns the link to the caller directly,
// without needing an internal/delivery import to construct that fallback
// DeliveryResult (see ChannelOutOfBand above) — unlike LicenseGate, this was
// already internal/core's existing behavior before this port existed (the nil
// case was never a "feature unavailable" error), so no behavior changes here.
type CredentialDelivery interface {
	// DeliverSetupLink delivers the link to the recipient. For out-of-band
	// mode it returns the link to the caller (for the admin to relay)
	// instead of sending.
	DeliverSetupLink(ctx context.Context, req SetupLinkRequest) (DeliveryResult, error)
	// Name identifies the channel for logging/audit.
	Name() string
}
