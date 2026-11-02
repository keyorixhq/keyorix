package handlers

import (
	"errors"
	"net/http"

	"github.com/keyorixhq/keyorix/internal/core"
)

// errTOTPUnavailableInFIPSMode is the client text for core.ErrTOTPUnavailableInFIPSMode.
// Core returns it before any code is evaluated, so it confirms nothing about the
// code; it only says this server cannot do TOTP and what still works.
const errTOTPUnavailableInFIPSMode = "TOTP is not available in FIPS mode; use a recovery code or a passkey"

// writeTOTPUnavailable answers core.ErrTOTPUnavailableInFIPSMode with 503 and
// reports whether it did. Every handler that can reach a TOTP check calls it
// first in its error mapping.
func writeTOTPUnavailable(w http.ResponseWriter, err error) bool {
	if !errors.Is(err, core.ErrTOTPUnavailableInFIPSMode) {
		return false
	}
	sendError(w, "TOTPUnavailable", errTOTPUnavailableInFIPSMode, http.StatusServiceUnavailable, nil)
	return true
}
