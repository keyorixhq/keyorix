// Package envflag provides the shared helper for environment-variable-gated
// insecure-mode opt-ins used throughout this codebase (e.g. insecure_skip_verify):
// unset or unparsable means disabled (fail closed).
//
// Extracted from two independent copies (internal/delivery, internal/notifychan)
// that had each grown their own identical envFlagEnabled implementation — see
// keyorix-private/adversarial-review/IMPLEMENTATION-ASYMMETRY-SCAN-2026-09-05.md,
// finding F6: the duplicated copies also duplicated AllowInsecureSMTP itself
// under two different names, which is exactly the kind of duplication that
// silently diverges when one copy's gate is tightened and the other isn't.
package envflag

import (
	"os"
	"strconv"
)

// AllowInsecureSMTP gates tls=none for every SMTP-sending channel in this
// codebase (credential-delivery setup-link mail, ADR-028; the notification
// email channel). Cleartext SMTP sends the message — and, if the relay
// requires auth, the relay credentials — over the wire unencrypted, so
// tls=none refuses to activate unless this is set to a truthy value.
const AllowInsecureSMTP = "KEYORIX_ALLOW_INSECURE_SMTP"

// Enabled reports whether the named environment variable is set to a truthy
// value (accepts anything strconv.ParseBool accepts: "1", "t", "true", etc.,
// case sensitive per ParseBool). Unset or unparsable = false (fail closed).
func Enabled(name string) bool {
	v, ok := os.LookupEnv(name)
	if !ok {
		return false
	}
	b, err := strconv.ParseBool(v)
	return err == nil && b
}
