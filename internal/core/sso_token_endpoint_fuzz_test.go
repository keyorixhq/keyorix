package core

// LIB-FUZZ-2 target 3: golang.org/x/oauth2 behind KeyorixCore.CompleteSSO, against
// a hostile or compromised IdP token endpoint.
//
// Inventory. The browser returns to /auth/sso/<provider>/callback?code=&state=;
// CompleteSSO consumes the stored login state, then p.OAuth.Exchange(ctx, code)
// POSTs to the IdP's token_endpoint and oauth2 parses whatever comes back: JSON
// or form-encoded depending on the response Content-Type (mime-sniffed by the
// library), an HTTP status that may be an error with an error body, extra fields
// ("id_token" is read with tok.Extra), numeric/string confusions in expires_in.
// The id_token string then goes to verifyIDToken. The state row is the CSRF and
// replay defence: provider-bound, expiring, single-use. A compromised IdP (or any
// MITM of a misconfigured http token_endpoint) chooses every byte of that response.
// The id_token CLAIM semantics are already fuzzed by FuzzVerifyIDTokenClaims and the
// raw token by FuzzVerifyIDToken; this target is the layer in between:
// oauth2's response parsing and CompleteSSO's use of it.
//
// Observable "accepted": verifyIDToken passed, which is the one point after which
// CompleteSSO asks storage who the subject is. The storage mock records the
// external id it was asked about and then fails, so no deeper mock is needed and
// the login is never completed.
//
// Oracle. The harness holds the only signing key and has exactly one valid
// id_token, ssoFuzzValidToken (subject okta|55, the stored nonce, exp in the
// future of the harness clock). Reaching the
// subject lookup therefore implies, independently of anything oauth2 or
// verifyIDToken decided:
//   - the callback named the provider, the state row belongs to it, and the row
//     had not expired (a mismatch must be refused even when the IdP answers);
//   - the callback carried exactly the state the harness issued;
//   - the IdP answered 2xx (an error status with a valid token in its body is not
//     a login);
//   - the response body carries the valid token, raw or in the form/JSON
//     encoding oauth2 decodes (no other string verifies);
//   - the subject looked up is the signed token's own, "sso:okta:okta|55".
//
// Replay. The key is derived from a fixed label, the core's clock is fixed at
// ssoFuzzNow and the valid token is a literal, so a saved crasher (whose body
// carries the token bytes the finding process saw) verifies the same way in any
// later process: TestSSOTokenEndpointSeed_Replayable pins that.

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/mock"
	"golang.org/x/oauth2"

	"github.com/keyorixhq/keyorix/internal/fuzzutil"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

const (
	ssoFuzzIssuer   = "https://idp.test"
	ssoFuzzClientID = "client-1"
	ssoFuzzNonce    = "nonce-issued"
	ssoFuzzState    = "state-issued"
	ssoFuzzSubject  = "okta|55"
)

var errSSOFuzzStop = errors.New("harness: identity lookup reached")

// ssoFuzzNow is the clock of every core the harness builds: token expiry and the
// state row's expiry are judged against it, never against the wall clock.
var ssoFuzzNow = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

// ssoFuzzValidToken is ssoFuzzMint(nil) output under ssoFuzzKey, pasted in: the
// one id_token that verifies (ES256, exp = ssoFuzzNow + 1h). ECDSA signatures
// are randomised, so a freshly minted token would differ in every process; a
// literal keeps the oracle's notion of "the valid token" the same bytes a saved
// crasher carries. Regenerate it with ssoFuzzMint if the claims change.
const ssoFuzzValidToken = "eyJhbGciOiJFUzI1NiIsImtpZCI6ImtpZC0xIiwidHlwIjoiSldUIn0." +
	"eyJhdWQiOiJjbGllbnQtMSIsImVtYWlsIjoiYWRhQHguaW8iLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiZXhwIjoxNzY3MjI5MjAwLCJpc3MiOiJodHRwczovL2lkcC50ZXN0Iiwibm9uY2UiOiJub25jZS1pc3N1ZWQiLCJzdWIiOiJva3RhfDU1In0." +
	"QE9XnCHztP1MuD6_B0Oqg1TXykevLpenopE1rD6lOLzQAHb7maVmoGLHDQPWpiaid-JqD672l8w25X1EjYGWAg"

// ssoFuzzKey is the harness's only signing key, derived from a fixed label so
// every process holds the same one.
func ssoFuzzKey(tb testing.TB) *ecdsa.PrivateKey {
	tb.Helper()
	d := sha256.Sum256([]byte("keyorix sso fuzz key"))
	k, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), d[:])
	if err != nil {
		tb.Fatal(err)
	}
	return k
}

// ssoFuzzMint signs the harness claims (mutated by mut) with method and signKey.
func ssoFuzzMint(tb testing.TB, mut func(jwt.MapClaims), method jwt.SigningMethod, signKey any) string {
	tb.Helper()
	claims := jwt.MapClaims{
		"iss": ssoFuzzIssuer, "aud": ssoFuzzClientID, "sub": ssoFuzzSubject, "email": "ada@x.io",
		"email_verified": true, "nonce": ssoFuzzNonce, "exp": ssoFuzzNow.Add(time.Hour).Unix(),
	}
	if mut != nil {
		mut(claims)
	}
	tok := jwt.NewWithClaims(method, claims)
	tok.Header["kid"] = "kid-1"
	s, err := tok.SignedString(signKey)
	if err != nil {
		tb.Fatal(err)
	}
	return s
}

// newSSOFuzzCore builds a core whose only provider exchanges codes at tokenURL,
// whose storage resolves only the issued state (once) to a row of rowProvider
// expiring rowExpiresIn seconds after ssoFuzzNow, and whose subject lookup
// records the external id in *reached and then fails.
func newSSOFuzzCore(key *ecdsa.PrivateKey, tokenURL, rowProvider string, rowExpiresIn int64, reached *string) *KeyorixCore {
	st := new(MockStorage)
	row := &models.SSOLoginState{Provider: rowProvider, Nonce: ssoFuzzNonce, ReturnTo: "/dash",
		ExpiresAt: ssoFuzzNow.Add(time.Duration(rowExpiresIn) * time.Second)}
	// Single use, exact match: only the issued state resolves, and only once.
	st.On("ConsumeSSOLoginState", mock.Anything, ssoFuzzState).Return(row, nil).Once()
	st.On("ConsumeSSOLoginState", mock.Anything, mock.Anything).Return((*models.SSOLoginState)(nil), errors.New("not found"))
	st.On("GetUserByExternalID", mock.Anything, mock.Anything).Run(func(a mock.Arguments) {
		*reached = a.String(1)
	}).Return((*models.User)(nil), errSSOFuzzStop)
	p := &SSOProvider{
		Name: "okta", Issuer: ssoFuzzIssuer, ClientID: ssoFuzzClientID,
		OAuth: &oauth2.Config{
			ClientID: ssoFuzzClientID, ClientSecret: "s3cret",
			Endpoint:    oauth2.Endpoint{AuthURL: ssoFuzzIssuer + "/authorize", TokenURL: tokenURL},
			RedirectURL: "https://keyorix.test/auth/sso/okta/callback", Scopes: []string{"openid", "email"},
		},
	}
	return &KeyorixCore{
		storage: st, now: func() time.Time { return ssoFuzzNow },
		ssoJWKS:      staticResolver{kid: "kid-1", key: &key.PublicKey},
		ssoProviders: map[string]*SSOProvider{"okta": p},
	}
}

// ssoFuzzProbe runs one issued-state callback against an IdP answering 200 with
// ctype and body, and returns the external id the subject lookup was asked for.
func ssoFuzzProbe(key *ecdsa.PrivateKey, idp *ssoFuzzIdP, tokenURL, ctype string, body []byte) string {
	idp.set(200, ctype, body)
	var reached string
	_, _, _, _ = newSSOFuzzCore(key, tokenURL, "okta", 300, &reached).CompleteSSO(context.Background(), "okta", "auth-code", ssoFuzzState, "ua", "203.0.113.9")
	return reached
}

func ssoFuzzJSON(id string) []byte {
	return fmt.Appendf(nil, `{"access_token":"at","token_type":"Bearer","expires_in":3600,"id_token":%q}`, id)
}

func ssoFuzzForm(id string) []byte {
	return []byte("access_token=at&token_type=Bearer&expires_in=3600&id_token=" + url.QueryEscape(id))
}

// ssoSameToken reports whether got is the signed token: the same string, or the
// same header, payload and signature bytes. A base64url signature has unused
// trailing bits (86 characters for a 64-byte ES256 signature carry 4 spare bits),
// which a non-strict decoder ignores, so another spelling of the same signature
// verifies. That is no forgery: the signature bytes and every claim are unchanged.
func ssoSameToken(got, token string) bool {
	if got == token {
		return true
	}
	g, w := strings.Split(got, "."), strings.Split(token, ".")
	if len(g) != 3 || len(w) != 3 || g[0] != w[0] || g[1] != w[1] {
		return false
	}
	gs, err1 := base64.RawURLEncoding.DecodeString(g[2])
	ws, err2 := base64.RawURLEncoding.DecodeString(w[2])
	return err1 == nil && err2 == nil && bytes.Equal(gs, ws)
}

// ssoBodyCarries reports whether body carries token: as raw bytes, as a
// form-encoded id_token value (%2E for "."), or as a top-level JSON id_token
// string (\u002e for "."), the encodings oauth2 decodes a token response from.
// The form and JSON values are compared with ssoSameToken, so a non-canonical
// spelling of the signature does not read as a foreign token.
func ssoBodyCarries(body []byte, token string) bool {
	if bytes.Contains(body, []byte(token)) {
		return true
	}
	if q, _ := url.ParseQuery(string(body)); slices.ContainsFunc(q["id_token"], func(v string) bool { return ssoSameToken(v, token) }) {
		return true
	}
	var m map[string]json.RawMessage
	var s string
	return json.Unmarshal(body, &m) == nil && json.Unmarshal(m["id_token"], &s) == nil && ssoSameToken(s, token)
}

type ssoFuzzIdP struct {
	mu     sync.Mutex
	status int
	ctype  string
	body   []byte
}

func (i *ssoFuzzIdP) set(status int, ctype string, body []byte) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.status, i.ctype, i.body = status, ctype, body
}

func (i *ssoFuzzIdP) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	i.mu.Lock()
	status, ctype, body := i.status, i.ctype, i.body
	i.mu.Unlock()
	if ctype != "" {
		w.Header().Set("Content-Type", ctype)
	}
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

// ssoFuzzCtype keeps a fuzzed Content-Type a legal header value: the target is
// oauth2's reading of it, not net/http's header validation.
func ssoFuzzCtype(s string) string {
	if len(s) > 120 {
		s = s[:120]
	}
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || r > 0x7e {
			return ' '
		}
		return r
	}, s)
}

// ssoReachedSubject is the oracle: "" means no violation. reached is the external
// id passed to the subject lookup ("" if CompleteSSO never got there).
func ssoReachedSubject(reached, validToken string, in ssoFuzzInput) string {
	if reached == "" {
		return ""
	}
	switch {
	case in.callbackProvider != "okta":
		return fmt.Sprintf("accepted a login for callback provider %q", in.callbackProvider)
	case in.rowProvider != "okta":
		return fmt.Sprintf("accepted a login whose state row belongs to provider %q", in.rowProvider)
	case in.rowExpiresIn <= 0:
		return fmt.Sprintf("accepted a login whose state expired %ds ago", -in.rowExpiresIn)
	case in.state != ssoFuzzState:
		return fmt.Sprintf("accepted a callback with state %q, the issued one is %q", in.state, ssoFuzzState)
	case in.status < 200 || in.status > 299:
		return fmt.Sprintf("accepted a token response with HTTP status %d", in.status)
	case !ssoBodyCarries(in.body, validToken):
		return "accepted an id_token that is not the one the harness signed"
	case reached != "sso:okta:"+ssoFuzzSubject:
		return fmt.Sprintf("looked up subject %q, the signed token says %q", reached, "sso:okta:"+ssoFuzzSubject)
	}
	return ""
}

type ssoFuzzInput struct {
	callbackProvider, rowProvider, state string
	rowExpiresIn                         int64 // seconds after ssoFuzzNow, as stored
	status                               int
	body                                 []byte
}

func FuzzCompleteSSOTokenEndpoint(f *testing.F) {
	key := ssoFuzzKey(f)
	valid := ssoFuzzValidToken
	expired := ssoFuzzMint(f, func(c jwt.MapClaims) { c["exp"] = ssoFuzzNow.Add(-time.Hour).Unix() }, jwt.SigningMethodES256, key)
	wrongNonce := ssoFuzzMint(f, func(c jwt.MapClaims) { c["nonce"] = "other" }, jwt.SigningMethodES256, key)
	algNone := ssoFuzzMint(f, nil, jwt.SigningMethodNone, jwt.UnsafeAllowNoneSignatureType)
	b64 := base64.RawURLEncoding.EncodeToString
	hs256 := b64([]byte(`{"alg":"HS256","kid":"kid-1","typ":"JWT"}`)) + "." + strings.SplitN(valid, ".", 3)[1] + ".c2ln"

	idp := &ssoFuzzIdP{}
	srv := httptest.NewServer(idp)
	f.Cleanup(srv.Close)

	js, form := ssoFuzzJSON, ssoFuzzForm
	type seed struct {
		prov, rowProv, state string
		exp                  int64
		status               uint16
		ctype                string
		body                 []byte
	}
	for _, s := range []seed{
		{"okta", "okta", ssoFuzzState, 300, 0, "application/json", js(valid)},
		{"okta", "okta", ssoFuzzState, 300, 0, "application/x-www-form-urlencoded", form(valid)},
		{"okta", "okta", ssoFuzzState, 300, 0, "text/plain; charset=UTF-8", form(valid)},
		{"okta", "okta", ssoFuzzState, 300, 0, "", js(valid)},
		{"okta", "okta", ssoFuzzState, 300, 200, "application/json", js(valid)}, // 400 with a valid token
		{"okta", "okta", ssoFuzzState, 300, 0, "application/json", js(expired)},
		{"okta", "okta", ssoFuzzState, 300, 0, "application/json", js(wrongNonce)},
		{"okta", "okta", ssoFuzzState, 300, 0, "application/json", js(algNone)},
		{"okta", "okta", ssoFuzzState, 300, 0, "application/json", js(hs256)},
		{"okta", "okta", ssoFuzzState, 300, 0, "application/json", []byte(`{"access_token":"at","id_token":"` + wrongNonce + `","id_token":"` + valid + `"}`)},
		{"okta", "okta", ssoFuzzState, 300, 0, "application/json", []byte(`{"error":"invalid_grant","error_description":"x","id_token":"` + valid + `"}`)},
		{"okta", "okta", ssoFuzzState, 300, 0, "application/json", []byte(`{"access_token":"at","id_token":123}`)},
		{"okta", "okta", ssoFuzzState, 300, 0, "application/json", []byte(`{"access_token":"at","expires_in":"3600","id_token":"` + valid + `"}`)},
		{"okta", "okta", ssoFuzzState, 300, 0, "application/json", []byte(`{"access_token":"at","expires_in":1e400,"id_token":"` + valid + `"}`)},
		{"okta", "saml", ssoFuzzState, 300, 0, "application/json", js(valid)},  // row of another provider
		{"okta", "okta", ssoFuzzState, -300, 0, "application/json", js(valid)}, // expired state row
		{"other", "okta", ssoFuzzState, 300, 0, "application/json", js(valid)}, // unknown callback provider
		{"okta", "okta", "state-other", 300, 0, "application/json", js(valid)}, // state not issued
		{"okta", "okta", ssoFuzzState, 300, 0, "application/json", nil},        // empty body
		{"okta", "okta", ssoFuzzState, 300, 0, "application/json; charset=\x01", js(valid)},
	} {
		f.Add(s.prov, s.rowProv, s.state, s.exp, s.status, s.ctype, s.body)
	}

	// Liveness: the seeds start where they claim. The valid token, JSON or form
	// encoded, reaches the subject lookup; every flawed one stops before it.
	probe := func(ctype string, body []byte) string { return ssoFuzzProbe(key, idp, srv.URL, ctype, body) }
	for name, c := range map[string]struct {
		ctype string
		body  []byte
		want  string
	}{
		"valid json": {"application/json", js(valid), "sso:okta:" + ssoFuzzSubject},
		"valid form": {"application/x-www-form-urlencoded", form(valid), "sso:okta:" + ssoFuzzSubject},
		"expired":    {"application/json", js(expired), ""},
		"nonce":      {"application/json", js(wrongNonce), ""},
		"alg none":   {"application/json", js(algNone), ""},
		"hs256":      {"application/json", js(hs256), ""},
	} {
		if got := probe(c.ctype, c.body); got != c.want {
			f.Fatalf("seed %q: subject lookup %q, want %q", name, got, c.want)
		}
	}

	f.Fuzz(func(t *testing.T, callbackProvider, rowProvider, state string, rowExpiresIn int64, status uint16, ctype string, body []byte) {
		if rowExpiresIn > 1_000_000 {
			rowExpiresIn = 1_000_000
		}
		if rowExpiresIn < -1_000_000 {
			rowExpiresIn = -1_000_000
		}
		in := ssoFuzzInput{callbackProvider, rowProvider, state, rowExpiresIn, 200 + int(status)%400, body}
		idp.set(in.status, ssoFuzzCtype(ctype), body)
		var reached string
		c := newSSOFuzzCore(key, srv.URL, rowProvider, rowExpiresIn, &reached)
		var session any
		fuzzutil.Guard(t.Fatalf, "CompleteSSO", func() {
			s, _, _, _ := c.CompleteSSO(context.Background(), callbackProvider, "auth-code", state, "ua", "203.0.113.9")
			if s != nil {
				session = s
			}
		})
		if session != nil {
			t.Fatal("CompleteSSO minted a session although the storage mock refuses every subject")
		}
		if msg := ssoReachedSubject(reached, valid, in); msg != "" {
			t.Fatal(msg)
		}
	})
}

// TestSSOTokenEndpointOracle_RedProof: the oracle names each planted acceptance and
// is silent on the one correct login and on every rejection.
func TestSSOTokenEndpointOracle_RedProof(t *testing.T) {
	const valid = "VALID.TOKEN.BYTES"
	ok := ssoFuzzInput{"okta", "okta", ssoFuzzState, 300, 200, []byte(`{"id_token":"` + valid + `"}`)}
	subj := "sso:okta:" + ssoFuzzSubject
	if msg := ssoReachedSubject(subj, valid, ok); msg != "" {
		t.Fatalf("oracle rejects the correct login: %s", msg)
	}
	if msg := ssoReachedSubject("", valid, ssoFuzzInput{}); msg != "" {
		t.Fatalf("oracle flags a refused login: %s", msg)
	}
	for name, mut := range map[string]func(*ssoFuzzInput) string{
		"wrong callback provider": func(in *ssoFuzzInput) string { in.callbackProvider = "x"; return subj },
		"state row of another provider": func(in *ssoFuzzInput) string {
			in.rowProvider = "saml"
			return subj
		},
		"expired state row":      func(in *ssoFuzzInput) string { in.rowExpiresIn = -1; return subj },
		"state not issued":       func(in *ssoFuzzInput) string { in.state = "x"; return subj },
		"error status accepted":  func(in *ssoFuzzInput) string { in.status = 400; return subj },
		"foreign id_token":       func(in *ssoFuzzInput) string { in.body = []byte(`{"id_token":"OTHER"}`); return subj },
		"subject from elsewhere": func(*ssoFuzzInput) string { return "sso:okta:admin" },
	} {
		in := ok
		reached := mut(&in)
		if ssoReachedSubject(reached, valid, in) == "" {
			t.Errorf("oracle missed planted acceptance: %s", name)
		}
	}
	// The valid token in an encoding oauth2 decodes is still the valid token: an
	// escaped "." must not read as a foreign id_token.
	for name, body := range map[string][]byte{
		"form, %2E escapes":     []byte("id_token=" + strings.ReplaceAll(valid, ".", "%2E")),
		"json, \\u002e escapes": []byte(`{"id_token":"` + strings.ReplaceAll(valid, ".", `\u002e`) + `"}`),
	} {
		in := ok
		in.body = body
		if msg := ssoReachedSubject(subj, valid, in); msg != "" {
			t.Errorf("oracle rejects the valid token sent as %s: %s", name, msg)
		}
	}
}

// TestSSOTokenEndpointSeed_Replayable: the valid token is a literal and still
// reaches the subject lookup, so the key and the clock are the same in every
// process and a saved crasher carrying it replays the path that found it. With a
// per-process key (or a wall-clock exp) this fails.
func TestSSOTokenEndpointSeed_Replayable(t *testing.T) {
	idp := &ssoFuzzIdP{}
	srv := httptest.NewServer(idp)
	t.Cleanup(srv.Close)
	key := ssoFuzzKey(t)
	for name, c := range map[string]struct {
		ctype string
		body  []byte
	}{
		"json": {"application/json", ssoFuzzJSON(ssoFuzzValidToken)},
		"form": {"application/x-www-form-urlencoded", ssoFuzzForm(ssoFuzzValidToken)},
	} {
		if got, want := ssoFuzzProbe(key, idp, srv.URL, c.ctype, c.body), "sso:okta:"+ssoFuzzSubject; got != want {
			t.Errorf("%s: the literal valid token reached subject lookup %q, want %q", name, got, want)
		}
	}
}

// TestSSOBodyCarries_NonCanonicalSignature pins the oracle decision behind the
// finding on a saved crasher: the valid token with the spare trailing bits of its
// signature set differently is still the valid token, while any change to the
// header, the payload or the signature bytes is a foreign one.
func TestSSOBodyCarries_NonCanonicalSignature(t *testing.T) {
	valid := ssoFuzzValidToken
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	last := strings.IndexByte(alphabet, valid[len(valid)-1])
	respell := valid[:len(valid)-1] + string(alphabet[last^1]) // flips the lowest of the 4 spare bits
	if respell == valid {
		t.Fatal("test setup: respelled token equals the original")
	}
	flipSig := valid[:len(valid)-6] + string(alphabet[strings.IndexByte(alphabet, valid[len(valid)-6])^32]) + valid[len(valid)-5:]
	parts := strings.Split(valid, ".")
	flipPayload := parts[0] + "." + string(alphabet[strings.IndexByte(alphabet, parts[1][0])^1]) + parts[1][1:] + "." + parts[2]
	for name, c := range map[string]struct {
		body []byte
		want bool
	}{
		"form, respelled signature": {ssoFuzzForm(respell), true},
		"json, respelled signature": {ssoFuzzJSON(respell), true},
		"form, one signature bit":   {ssoFuzzForm(flipSig), false},
		"form, payload changed":     {ssoFuzzForm(flipPayload), false},
		"json, payload changed":     {ssoFuzzJSON(flipPayload), false},
		"form, token cut short":     {ssoFuzzForm(valid[:len(valid)-2]), false},
	} {
		if got := ssoBodyCarries(c.body, valid); got != c.want {
			t.Errorf("%s: ssoBodyCarries = %v, want %v", name, got, c.want)
		}
	}
}
