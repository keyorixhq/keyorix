package license

import (
	"time"

	"github.com/keyorixhq/keyorix/internal/trust"
)

// Gate is the server-side feature gate built from an installed license token. It evaluates
// the token freshly on every call (Evaluate is cheap — one ed25519 verify), so the reported
// state always reflects the current time without any cached-state or background-timer
// lifecycle: a license that lapses while the server runs is observed on the next call.
//
// A nil *Gate is valid and behaves as "no license installed" (community baseline) — so a
// server with no license configured needs no special-casing at call sites.
type Gate struct {
	token        string
	reg          *trust.KeyRegistry
	deploymentID string
	grace        time.Duration
	now          func() time.Time // injectable for tests; defaults to time.Now
}

// NewGate builds a gate over an installed token. A nil registry or empty token still yields
// a usable gate that simply evaluates to the baseline (fail-safe).
func NewGate(token string, reg *trust.KeyRegistry, deploymentID string, grace time.Duration) *Gate {
	if grace <= 0 {
		grace = 14 * 24 * time.Hour
	}
	return &Gate{token: token, reg: reg, deploymentID: deploymentID, grace: grace, now: time.Now}
}

// Status evaluates the license against the current time. It never errors — a degraded
// license returns a baseline Status with a Reason. A nil gate reports StateNone.
func (g *Gate) Status() Status {
	if g == nil {
		return Status{State: StateNone, Reason: "no license configured — running the community baseline"}
	}
	reg := g.reg
	if reg == nil {
		reg = trust.NewRegistry()
	}
	now := time.Now
	if g.now != nil {
		now = g.now
	}
	return Evaluate(g.token, reg, g.deploymentID, now(), g.grace)
}

// HasFeature reports whether commercial feature f is currently granted. This is the single
// gate the rest of the server calls before enabling a commercial-only capability; it is
// false for every feature under a degraded, expired, missing, or unconfigured license.
func (g *Gate) HasFeature(f string) bool {
	return g.Status().HasFeature(f)
}
