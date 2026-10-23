package webauthnrp

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/keyorixhq/keyorix/internal/core/ports"
)

// --- (d) the constructor never hands core a typed nil -----------------------

// TestNew_BadConfigIsAnErrorAndANilInterface: a relying-party config the
// library refuses (no origins) is an error, and the value returned with it is a
// nil interface, so a caller that ignored the error would still see passkeys as
// disabled rather than call methods on a nil pointer. Wrap(nil) is the same.
func TestNew_BadConfigIsAnErrorAndANilInterface(t *testing.T) {
	rp, err := New(Config{RPID: "example.org", RPDisplayName: "Keyorix"})
	if err == nil {
		t.Fatal("a config without origins must be refused")
	}
	if rp != nil {
		t.Fatalf("New returned a non-nil %T with its error", rp)
	}
	if got := Wrap(nil); got != nil {
		t.Fatalf("Wrap(nil) = %T, want a nil interface", got)
	}
	if got := Wrap(&webauthn.WebAuthn{}); got == nil {
		t.Fatal("Wrap of a real relying party must not be nil")
	}
}

// --- (b) user verification REQUIRED on every assertion ---------------------

func sessionUV(t *testing.T, s ports.WebAuthnSession) protocol.UserVerificationRequirement {
	t.Helper()
	sd, ok := s.(*webauthn.SessionData)
	if !ok {
		t.Fatalf("session is %T", s)
	}
	return sd.UserVerification
}

func optionsUV(t *testing.T, raw json.RawMessage) protocol.UserVerificationRequirement {
	t.Helper()
	var o protocol.PublicKeyCredentialRequestOptions
	if err := json.Unmarshal(raw, &o); err != nil {
		t.Fatal(err)
	}
	return o.UserVerification
}

// TestAssertionCeremonies_RequireUserVerification pins UV=required on both
// assertion kinds the adapter begins (BeginLogin serves the second-factor login
// AND step-up reauth). It checks the session the library enforces from (not
// only the options the browser sees): validateLogin verifies UV only when the
// stored session says "required".
func TestAssertionCeremonies_RequireUserVerification(t *testing.T) {
	if assertionUserVerification != protocol.VerificationRequired {
		t.Fatalf("assertionUserVerification = %q, want %q", assertionUserVerification, protocol.VerificationRequired)
	}
	rp := specRP(t)
	opts, sess, err := rp.BeginLogin(specUser(t, rp, 0))
	if err != nil {
		t.Fatal(err)
	}
	if got := sessionUV(t, sess); got != protocol.VerificationRequired {
		t.Errorf("BeginLogin session UV = %q", got)
	}
	if got := optionsUV(t, opts); got != protocol.VerificationRequired {
		t.Errorf("BeginLogin options UV = %q", got)
	}
	opts, sess, err = rp.BeginPasskeyLogin()
	if err != nil {
		t.Fatal(err)
	}
	if got := sessionUV(t, sess); got != protocol.VerificationRequired {
		t.Errorf("BeginPasskeyLogin session UV = %q", got)
	}
	if got := optionsUV(t, opts); got != protocol.VerificationRequired {
		t.Errorf("BeginPasskeyLogin options UV = %q", got)
	}
}

// uvOutcome runs the real NoneES256 assertion (UV flag NOT set) against a
// session the adapter began, for the second-factor and the passwordless path.
func uvOutcome(t *testing.T) (loginErr, passkeyErr error) {
	t.Helper()
	rp := specRP(t)
	user := specUser(t, rp, 0)
	_, sess, err := rp.BeginLogin(user)
	if err != nil {
		t.Fatal(err)
	}
	_, loginErr = rp.ValidateLogin(user, withSpecChallenge(t, sess), specAssertion(t, nil))

	_, sess, err = rp.BeginPasskeyLogin()
	if err != nil {
		t.Fatal(err)
	}
	resolve := func(_, _ []byte) (ports.WebAuthnUser, error) { return user, nil }
	_, passkeyErr = rp.ValidatePasskeyLogin(resolve, withSpecChallenge(t, sess), specAssertion(t, specUserID(1)))
	return loginErr, passkeyErr
}

// TestAssertionWithoutUV_IsRejected_RedWhenPreferred is the behavioural half of
// the pin: a cryptographically valid assertion whose authenticator did not
// verify the user is refused on a session this adapter began. The mutation
// subtest sets the option to "preferred" and requires the same assertion to be
// ACCEPTED, so the pin is shown to be what refuses it (red when preferred).
func TestAssertionWithoutUV_IsRejected_RedWhenPreferred(t *testing.T) {
	loginErr, passkeyErr := uvOutcome(t)
	for name, err := range map[string]error{"login": loginErr, "passkey": passkeyErr} {
		if err == nil {
			t.Errorf("%s: an assertion without user verification was accepted", name)
		} else if !strings.Contains(errDevInfo(err), "User verification required") {
			t.Errorf("%s: refused for the wrong reason: %v (%s)", name, err, errDevInfo(err))
		}
	}

	t.Run("mutation: preferred lets it through", func(t *testing.T) {
		saved := assertionUserVerification
		assertionUserVerification = protocol.VerificationPreferred
		t.Cleanup(func() { assertionUserVerification = saved })
		loginErr, passkeyErr := uvOutcome(t)
		if loginErr != nil || passkeyErr != nil {
			t.Fatalf("with UV preferred the same assertion must pass (else this test does not exercise UV): login=%v passkey=%v", loginErr, passkeyErr)
		}
	})
}

func errDevInfo(err error) string {
	if perr, ok := errors.AsType[*protocol.Error](err); ok {
		return perr.DevInfo
	}
	return ""
}

// TestRegistration_ExcludesAndPrefersResidentKey pins the registration options
// core used to pass: every usable credential is excluded, resident key
// "preferred".
func TestRegistration_ExcludesAndPrefersResidentKey(t *testing.T) {
	rp := specRP(t)
	opts, sess, err := rp.BeginRegistration(specUser(t, rp, 0))
	if err != nil {
		t.Fatal(err)
	}
	var o protocol.PublicKeyCredentialCreationOptions
	if err := json.Unmarshal(opts, &o); err != nil {
		t.Fatal(err)
	}
	if o.AuthenticatorSelection.ResidentKey != protocol.ResidentKeyRequirementPreferred {
		t.Errorf("residentKey = %q, want preferred", o.AuthenticatorSelection.ResidentKey)
	}
	if len(o.CredentialExcludeList) != 1 || !bytes.Equal(o.CredentialExcludeList[0].CredentialID, specHex(t, specCredentialIDHex)) {
		t.Errorf("excludeCredentials = %+v, want the user's one credential", o.CredentialExcludeList)
	}
	if sd, ok := sess.(*webauthn.SessionData); !ok || !bytes.Equal(sd.UserID, specUserID(1)) {
		t.Errorf("registration session not bound to the user: %#v", sess)
	}
}

// --- (a) the clone signal survives the adapter ------------------------------

// TestValidate_RegressedCounterSurfacesCloneWarning drives a real assertion
// (counter 0) against a credential whose stored counter is 5: the library's
// clone signal must come out as WebAuthnVerified.CloneWarning on both login
// paths; with a stored counter of 0 (the one waived case) it must not.
func TestValidate_RegressedCounterSurfacesCloneWarning(t *testing.T) {
	for _, tc := range []struct {
		stored    uint32
		wantClone bool
	}{{stored: 5, wantClone: true}, {stored: 0, wantClone: false}} {
		rp := specRP(t)
		user := specUser(t, rp, tc.stored)
		// The session must not require UV here: the vector has no UV flag and this
		// test is about the counter, so use the library's own default session.
		sess := &webauthn.SessionData{UserID: specUserID(1)}
		v, err := rp.ValidateLogin(user, withSpecChallenge(t, sess), specAssertion(t, nil))
		if err != nil {
			t.Fatalf("stored=%d: %v", tc.stored, err)
		}
		checkVerified(t, "login", tc.stored, tc.wantClone, v)

		resolve := func(_, _ []byte) (ports.WebAuthnUser, error) { return specUser(t, rp, tc.stored), nil }
		v, err = rp.ValidatePasskeyLogin(resolve, withSpecChallenge(t, &webauthn.SessionData{}), specAssertion(t, specUserID(1)))
		if err != nil {
			t.Fatalf("passkey stored=%d: %v", tc.stored, err)
		}
		checkVerified(t, "passkey", tc.stored, tc.wantClone, v)
	}
}

func checkVerified(t *testing.T, path string, stored uint32, wantClone bool, v ports.WebAuthnVerified) {
	t.Helper()
	if v.CloneWarning != wantClone {
		t.Errorf("%s stored=%d: CloneWarning = %v, want %v", path, stored, v.CloneWarning, wantClone)
	}
	if !bytes.Equal(v.ID, specHex(t, specCredentialIDHex)) {
		t.Errorf("%s: ID = %x", path, v.ID)
	}
	cred, ok := v.Credential.(*webauthn.Credential)
	if !ok {
		t.Fatalf("%s: Credential is %T", path, v.Credential)
	}
	if cred.Authenticator.CloneWarning != v.CloneWarning || cred.Authenticator.SignCount != v.SignCount {
		t.Errorf("%s: flattened fields disagree with the credential that will be persisted: %+v vs %+v", path, v, cred.Authenticator)
	}
}

// --- error chains and fail-closed input handling ----------------------------

// TestErrors_LibraryErrorAndResolveErrorKeptInChain: the adapter adds no
// wrapper of its own, so core's "assertion verification failed: %w" chain
// still reaches the library's *protocol.Error, and the passwordless resolve
// callback's error is still inside what ValidatePasskeyLogin returns.
func TestErrors_LibraryErrorAndResolveErrorKeptInChain(t *testing.T) {
	rp := specRP(t)
	user := specUser(t, rp, 0)
	bad := specAssertion(t, nil)
	bad.Response.Signature = []byte("not-the-real-signature")
	_, err := rp.ValidateLogin(user, withSpecChallenge(t, &webauthn.SessionData{UserID: specUserID(1)}), bad)
	if _, ok := errors.AsType[*protocol.Error](err); !ok {
		t.Fatalf("a failed assertion must surface the library's *protocol.Error, got %T %v", err, err)
	}

	sentinel := errors.New("storage down (sentinel)")
	resolve := func(_, _ []byte) (ports.WebAuthnUser, error) { return ports.WebAuthnUser{}, sentinel }
	_, err = rp.ValidatePasskeyLogin(resolve, withSpecChallenge(t, &webauthn.SessionData{}), specAssertion(t, specUserID(1)))
	if !errors.Is(err, sentinel) || !strings.Contains(err.Error(), sentinel.Error()) {
		t.Fatalf("resolve's error must stay in the chain and the text: %v", err)
	}
}

// TestWrongValueTypes_FailClosed: a parsed response, credential or session of
// the wrong type is an error, never a panic and never a pass.
func TestWrongValueTypes_FailClosed(t *testing.T) {
	rp := specRP(t)
	user := specUser(t, rp, 0)
	sess := withSpecChallenge(t, &webauthn.SessionData{UserID: specUserID(1)})
	creation := &protocol.ParsedCredentialCreationData{}
	if _, err := rp.ValidateLogin(user, sess, nil); err == nil {
		t.Error("nil parsed response accepted")
	}
	if _, err := rp.ValidateLogin(user, sess, creation); err == nil {
		t.Error("a creation response accepted as an assertion")
	}
	if _, err := rp.FinishRegistration(user, sess, specAssertion(t, nil)); err == nil {
		t.Error("an assertion accepted as a creation response")
	}
	if _, err := rp.ValidateLogin(user, "not a session", specAssertion(t, nil)); err == nil {
		t.Error("a foreign session value accepted")
	}
	foreign := ports.WebAuthnUser{ID: specUserID(1), Credentials: []ports.WebAuthnCredential{webauthn.Credential{}}}
	if _, err := rp.ValidateLogin(foreign, sess, specAssertion(t, nil)); err == nil {
		t.Error("a credential DecodeCredential did not produce accepted")
	}
}

// --- (c) golden: rows written by main decode and re-encode byte-identically --

const goldenDir = "testdata/main-277e33568"

// TestGolden_MainRowsRoundTripByteIdentical: every credential blob and ceremony
// row in testdata was written by main 277e33568 (before this package existed)
// through its real Begin*/Finish* paths. Decoding each through the adapter and
// encoding it the way core now stores it (json.Marshal of the opaque value)
// must give the same bytes, so rows written before and after a rolling deploy
// read the same in both directions.
func TestGolden_MainRowsRoundTripByteIdentical(t *testing.T) {
	rp := specRP(t)
	files, err := filepath.Glob(filepath.Join(goldenDir, "*.json"))
	if err != nil || len(files) < 6 {
		t.Fatalf("golden fixtures missing (%d found): %v", len(files), err)
	}
	for _, f := range files {
		want, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var v any
		if strings.HasPrefix(filepath.Base(f), "credential-") {
			v, err = rp.DecodeCredential(want)
		} else {
			v, err = rp.DecodeSession(want)
		}
		if err != nil {
			t.Fatalf("%s: decode: %v", f, err)
		}
		got, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s: re-encoded bytes differ\n got: %s\nwant: %s", f, got, want)
		}
	}
}

// TestGolden_NewRowsHaveMainsShape: rows this adapter writes now carry exactly
// the JSON members main's rows carry (values differ: challenges are random).
func TestGolden_NewRowsHaveMainsShape(t *testing.T) {
	rp := specRP(t)
	user := specUser(t, rp, 0)
	_, reg, err := rp.BeginRegistration(user)
	if err != nil {
		t.Fatal(err)
	}
	_, login, err := rp.BeginLogin(user)
	if err != nil {
		t.Fatal(err)
	}
	_, pwl, err := rp.BeginPasskeyLogin()
	if err != nil {
		t.Fatal(err)
	}
	for file, sess := range map[string]ports.WebAuthnSession{
		"session-register.json": reg, "session-login.json": login, "session-reauth.json": login, "session-passwordless.json": pwl,
	} {
		got, err := json.Marshal(sess)
		if err != nil {
			t.Fatal(err)
		}
		want, err := os.ReadFile(filepath.Join(goldenDir, file))
		if err != nil {
			t.Fatal(err)
		}
		if g, w := jsonKeys(t, got), jsonKeys(t, want); !slices.Equal(g, w) {
			t.Errorf("%s: members %v, main wrote %v", file, g, w)
		}
	}
}

func jsonKeys(t *testing.T, b []byte) []string {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// TestOptionsJSON_SameBytesInAResponse: the handlers now put the options JSON
// in their response where they used to put the library struct.
// handlers.encodeJSONResponse (json.NewEncoder, HTML escaping on) must produce
// the same bytes either way, including for a user name that needs escaping.
func TestOptionsJSON_SameBytesInAResponse(t *testing.T) {
	r := specRP(t).(*relyingParty)
	wu := &user{id: specUserID(1), name: `a<b>&"c`, displayName: `a<b>&"c`}
	creation, _, err := r.rp.BeginRegistration(wu)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(creation.Response)
	if err != nil {
		t.Fatal(err)
	}
	encode := func(v any) []byte {
		var buf bytes.Buffer
		if err := json.NewEncoder(&buf).Encode(map[string]any{"data": map[string]any{"publicKey": v, "webauthn_session": "t"}}); err != nil {
			t.Fatal(err)
		}
		return buf.Bytes()
	}
	if a, b := encode(creation.Response), encode(json.RawMessage(raw)); !bytes.Equal(a, b) {
		t.Fatalf("response bytes differ\nstruct: %s\n   raw: %s", a, b)
	}
}
