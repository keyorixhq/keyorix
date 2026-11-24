package dsn

import "fmt"

// StoredSQLTransportGrace is the #4374 soft period, as one switch. The operator's
// transport policy (dynamic_secrets.insecure_allow_plaintext_dynamic_secret_transport)
// now covers postgres and mysql admin_dsns: without the flag only a connection that
// verifies the server certificate is accepted. A NEW or EDITED admin_dsn that does
// not verify is refused when it is saved, whatever this constant says. While it is
// true, an admin_dsn that was already stored keeps issuing, with a WARNING and an
// audit event on every issue, so an upgrade does not stop existing configs at once.
// Set it to false in the next release to refuse those at issue time too.
const StoredSQLTransportGrace = true

// TransportPolicyKey is the operator setting that allows a dynamic-secret admin_dsn
// whose connection does not verify the server certificate.
const TransportPolicyKey = "dynamic_secrets.insecure_allow_plaintext_dynamic_secret_transport"

// TransportWeakness says that a postgres or mysql admin_dsn connects without
// verifying the server certificate (or without TLS). The engine decides it from
// the parsed driver config (internal/dynamic, sql_transport.go); this package only
// holds the vocabulary, so it stays a stdlib-only leaf. Option names the setting
// as the driver resolved it (for example "sslmode=prefer" when sslmode is not
// set): it is built from the parsed config, never copied from the DSN, so it is
// safe to log and to show to the API caller.
type TransportWeakness struct {
	Backend string
	Option  string
	// Plaintext is true when some connection attempt is without TLS.
	Plaintext bool
}

// Refusal is the error for an admin_dsn the policy refuses.
func (w *TransportWeakness) Refusal() *ForbiddenOptionError {
	return &ForbiddenOptionError{Backend: w.Backend, Option: w.Option, Reason: w.fix()}
}

// Effect says what the weakness does, for a log line or an audit event.
func (w *TransportWeakness) Effect() string {
	if w.Plaintext {
		return "the connection may be plaintext (no TLS)"
	}
	return "the server certificate is not verified"
}

func (w *TransportWeakness) fix() string {
	what := "it does not verify the server certificate"
	if w.Plaintext {
		what = "it can connect without TLS"
	}
	use := "sslmode=verify-full (or verify-ca)"
	if w.Backend == "mysql" {
		use = "tls=true"
	}
	return fmt.Sprintf("%s; use %s, or the operator can set %s", what, use, TransportPolicyKey)
}

// Warning is the log line for an admin_dsn the policy lets through: allowed says
// the operator flag is set; otherwise the admin_dsn is a stored one in the
// StoredSQLTransportGrace soft period. It names the backend and option only.
func (w *TransportWeakness) Warning(allowed bool) string {
	what := w.Effect()
	if allowed {
		return fmt.Sprintf("WARNING: %s admin_dsn has %s: %s; %s is explicitly enabled", w.Backend, w.Option, what, TransportPolicyKey)
	}
	return fmt.Sprintf("WARNING: %s admin_dsn has %s: %s; this stored admin_dsn is accepted only during the upgrade grace period and will be refused in the next release (set %s, or edit the admin_dsn: %s)", w.Backend, w.Option, what, TransportPolicyKey, w.fix())
}
