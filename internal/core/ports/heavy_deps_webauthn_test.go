package ports

// CORE-DECOUPLE-WEBAUTHN-1: go-webauthn left internal/core's closure. Core talks
// to the relying party through WebAuthnRelyingParty (ports_webauthn.go); the
// library is in internal/webauthnrp, wired from server/wire_webauthn.go. go-tpm,
// cbor and msgp came in only through go-webauthn (its protocol and webauthncose
// packages), so they are forbidden by name too: a second route back in would
// otherwise go unnoticed.
func init() {
	const why = "CORE-DECOUPLE-WEBAUTHN-1: the WebAuthn relying party lives in internal/webauthnrp behind ports.WebAuthnRelyingParty"
	registerForbiddenHeavyDep("github.com/go-webauthn/", why)
	registerForbiddenHeavyDep("github.com/google/go-tpm", why+" (go-tpm came in only through go-webauthn)")
	registerForbiddenHeavyDep("github.com/fxamacker/cbor", why+" (cbor came in only through go-webauthn)")
	registerForbiddenHeavyDep("github.com/tinylib/msgp", why+" (msgp came in only through go-webauthn)")
}
