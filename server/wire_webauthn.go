package main

import (
	"fmt"
	"log"

	"github.com/keyorixhq/keyorix/internal/webauthnrp"
)

// cmpOr returns a if non-empty, else b (a tiny local helper to avoid a new import).
func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// wireWebAuthn is a core wiring step (coreWiringSteps in main.go).
func wireWebAuthn(cw *coreWiring) error {
	cfg, coreService := cw.cfg, cw.core
	// Wire WebAuthn / passkeys (ADR-036) when configured. A bad RP config (no
	// origins / invalid RP ID) fails loud rather than silently disabling passkeys.
	// The relying party is internal/webauthnrp (the go-webauthn library stays out
	// of internal/core, CORE-DECOUPLE-WEBAUTHN-1).
	if wa := cfg.WebAuthn; wa.Enabled {
		rp, werr := webauthnrp.New(webauthnrp.Config{
			RPID:          wa.RPID,
			RPDisplayName: cmpOr(wa.RPDisplayName, "Keyorix"),
			RPOrigins:     wa.RPOrigins,
		})
		if werr != nil {
			return fmt.Errorf("failed to init WebAuthn: %w", werr)
		}
		coreService.SetWebAuthn(rp)
		log.Printf("WebAuthn enabled (RP ID %q, %d origin(s))", wa.RPID, len(wa.RPOrigins))
	}
	return nil
}
