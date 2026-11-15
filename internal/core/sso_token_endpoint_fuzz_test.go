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
// Oracle. The harness holds the only signing key and mints exactly one valid
// id_token (subject okta|55, the stored nonce, exp in the future). Reaching the
// subject lookup therefore implies, independently of anything oauth2 or
// verifyIDToken decided:
//   - the callback named the provider, the state row belongs to it, and the row
//     had not expired (a mismatch must be refused even when the IdP answers);
//   - the callback carried exactly the state the harness issued;
//   - the IdP answered 2xx (an error status with a valid token in its body is not
//     a login);
//   - the valid token's bytes are in the response body (no other string verifies);
//   - the subject looked up is the signed token's own, "sso:okta:okta|55".

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
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
	case !bytes.Contains(in.body, []byte(validToken)):
		return "accepted an id_token that is not the one the harness signed"
	case reached != "sso:okta:"+ssoFuzzSubject:
		return fmt.Sprintf("looked up subject %q, the signed token says %q", reached, "sso:okta:"+ssoFuzzSubject)
	}
	return ""
}

type ssoFuzzInput struct {
	callbackProvider, rowProvider, state string
	rowExpiresIn                         int64 // seconds from now, as stored
	status                               int
	body                                 []byte
}

func FuzzCompleteSSOTokenEndpoint(f *testing.F) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		f.Fatal(err)
	}
	mint := func(mut func(jwt.MapClaims), method jwt.SigningMethod, signKey any) string {
		claims := jwt.MapClaims{
			"iss": ssoFuzzIssuer, "aud": ssoFuzzClientID, "sub": ssoFuzzSubject, "email": "ada@x.io",
			"email_verified": true, "nonce": ssoFuzzNonce, "exp": time.Now().Add(time.Hour).Unix(),
		}
		if mut != nil {
			mut(claims)
		}
		tok := jwt.NewWithClaims(method, claims)
		tok.Header["kid"] = "kid-1"
		s, err := tok.SignedString(signKey)
		if err != nil {
			f.Fatal(err)
		}
		return s
	}
	valid := mint(nil, jwt.SigningMethodRS256, key)
	expired := mint(func(c jwt.MapClaims) { c["exp"] = time.Now().Add(-time.Hour).Unix() }, jwt.SigningMethodRS256, key)
	wrongNonce := mint(func(c jwt.MapClaims) { c["nonce"] = "other" }, jwt.SigningMethodRS256, key)
	algNone := mint(nil, jwt.SigningMethodNone, jwt.UnsafeAllowNoneSignatureType)
	b64 := base64.RawURLEncoding.EncodeToString
	hs256 := b64([]byte(`{"alg":"HS256","kid":"kid-1","typ":"JWT"}`)) + "." + strings.SplitN(valid, ".", 3)[1] + ".c2ln"

	idp := &ssoFuzzIdP{}
	srv := httptest.NewServer(idp)
	f.Cleanup(srv.Close)

	js := func(id string) []byte {
		return fmt.Appendf(nil, `{"access_token":"at","token_type":"Bearer","expires_in":3600,"id_token":%q}`, id)
	}
	form := func(id string) []byte {
		return []byte("access_token=at&token_type=Bearer&expires_in=3600&id_token=" + url.QueryEscape(id))
	}
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

	newCore := func(rowProvider string, rowExpiresIn int64, reached *string) *KeyorixCore {
		st := new(MockStorage)
		row := &models.SSOLoginState{Provider: rowProvider, Nonce: ssoFuzzNonce, ReturnTo: "/dash",
			ExpiresAt: time.Now().Add(time.Duration(rowExpiresIn) * time.Second)}
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
				Endpoint:    oauth2.Endpoint{AuthURL: ssoFuzzIssuer + "/authorize", TokenURL: srv.URL},
				RedirectURL: "https://keyorix.test/auth/sso/okta/callback", Scopes: []string{"openid", "email"},
			},
		}
		return &KeyorixCore{
			storage: st, now: time.Now,
			ssoJWKS:      staticResolver{kid: "kid-1", key: &key.PublicKey},
			ssoProviders: map[string]*SSOProvider{"okta": p},
		}
	}

	// Liveness: the seeds start where they claim. The valid token, JSON or form
	// encoded, reaches the subject lookup; every flawed one stops before it.
	probe := func(ctype string, body []byte) string {
		idp.set(200, ctype, body)
		var reached string
		_, _, _, _ = newCore("okta", 300, &reached).CompleteSSO(context.Background(), "okta", "auth-code", ssoFuzzState, "ua", "203.0.113.9")
		return reached
	}
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
		c := newCore(rowProvider, rowExpiresIn, &reached)
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
}
