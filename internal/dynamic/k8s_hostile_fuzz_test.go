package dynamic

// k8s_hostile_fuzz_test.go: FuzzK8sTokenRequestHostileAPI is the hostile-backend
// record-and-mutate target for the Kubernetes dynamic-secrets engine (rules:
// internal/fuzzutil/hostile/RULES.md). The "API server" is a local TLS httptest
// server that serves a valid bound-Secret create, TokenRequest and Secret
// delete, and a mutation program corrupts one of them. KubernetesEngine.Issue
// builds its real minter (newRealK8sMinter) from the CA PEM, exactly as
// production does, so the production TLS and redirect policy is what is tested.
//
// Strict decoders follow the Kubernetes API: TokenRequest.status.token is a
// non-empty string and status.expirationTimestamp an RFC 3339 time; a created
// Secret has metadata.uid. Credentials are the synthetic strings below.

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/fuzzutil/hostile"
)

const (
	hostileK8sBearer = "kx-hostile-k8s-bearer-5d2e"
	hostileK8sToken  = "kx.hostile.sa-token"
	hostileK8sExpiry = "2031-01-02T03:04:05Z"
)

func k8sHostileRoutes() []hostile.Route {
	js := func(s string) hostile.Resp {
		return hostile.Resp{Status: 200, CT: "application/json", Body: []byte(s)}
	}
	created := func(s string) hostile.Resp { // the real API answers create/TokenRequest with 201
		r := js(s)
		r.Status = 201
		return r
	}
	return []hostile.Route{
		{Name: "token", Method: "POST", Prefix: "/api/v1/namespaces/ns/serviceaccounts/", Valid: func(int, *http.Request) hostile.Resp {
			return created(`{"kind":"TokenRequest","apiVersion":"authentication.k8s.io/v1","status":{"token":"` + hostileK8sToken + `","expirationTimestamp":"` + hostileK8sExpiry + `"}}`)
		}},
		{Name: "secret", Method: "POST", Prefix: "/api/v1/namespaces/ns/secrets", Valid: func(int, *http.Request) hostile.Resp {
			return created(`{"kind":"Secret","apiVersion":"v1","metadata":{"name":"x","uid":"1b2c3d4e-0000-4000-8000-000000000001"}}`)
		}},
		{Name: "secretdel", Method: "DELETE", Prefix: "/api/v1/namespaces/ns/secrets/", Valid: func(int, *http.Request) hostile.Resp {
			return js(`{"kind":"Status","apiVersion":"v1","status":"Success"}`)
		}},
	}
}

func strictK8sToken(b []byte) (tok string, exp time.Time, expOK, ok bool) {
	var d struct {
		Status *struct {
			Token *string `json:"token"`
			Exp   *string `json:"expirationTimestamp"`
		} `json:"status"`
	}
	if json.Unmarshal(b, &d) != nil || d.Status == nil || d.Status.Token == nil || *d.Status.Token == "" {
		return "", time.Time{}, false, false
	}
	if d.Status.Exp != nil {
		if t, err := time.Parse(time.RFC3339, *d.Status.Exp); err == nil {
			return *d.Status.Token, t, true, true
		}
	}
	return *d.Status.Token, time.Time{}, false, true
}

func strictK8sUID(b []byte) bool {
	var d struct {
		Metadata *struct {
			UID *string `json:"uid"`
		} `json:"metadata"`
	}
	return json.Unmarshal(b, &d) == nil && d.Metadata != nil && d.Metadata.UID != nil && *d.Metadata.UID != ""
}

func FuzzK8sTokenRequestHostileAPI(f *testing.F) {
	f.Add([]byte{})
	for _, p := range []hostile.Program{
		{Route: 0, Ops: []hostile.Op{{Code: 0, A: 2}}},       // status -> null
		{Route: 0, Ops: []hostile.Op{{Code: 1, A: 3}}},       // token removed
		{Route: 0, Ops: []hostile.Op{{Code: 11, A: 3}}},      // token -> ""
		{Route: 0, Ops: []hostile.Op{{Code: 1, A: 4}}},       // expiry removed
		{Route: 0, Ops: []hostile.Op{{Code: 6, A: 4, B: 2}}}, // expiry -> "null"
		{Route: 0, Ops: []hostile.Op{{Code: 12, A: 3}}},      // token -> canary
		{Route: 1, Ops: []hostile.Op{{Code: 1, A: 2}}},       // uid removed
		{Route: 0, Redir: 2}, {Route: 1, Redir: 1}, {Route: 0, Redir: 5},
		{Route: 0, Fault: 7}, {Route: 0, Fault: 2}, {Route: 0, Enc: 2},
		{Route: 2, Status: 10}, {Route: 2, Redir: 3},
	} {
		f.Add(hostile.Encode(p))
	}

	f.Fuzz(func(t *testing.T, prog []byte) {
		h := runK8sHostile(hostile.Decode(prog), k8sKnown)
		defer h.Close()
		h.Finish(t.Fatalf)
	})
}

// k8sKnown lists this target's triaged, still-open findings (hostile.Known;
// issue-ready text in the m32 report). Each has a reproducer test below.
var k8sKnown = []hostile.Known{{
	// EXPECTED-DIFFERENCE: isK8sSuccess (kubernetes.go) deliberately accepts
	// any 2xx; the API server answers create/TokenRequest with 201. Only the
	// sub-tag is suppressed: the exchange was complete and every value check
	// (uid, token, expiry) agreed with the strict decoders.
	ID:     "HK-K8S-ANY-2XX",
	Class:  "EXPECTED-DIFFERENCE",
	Prefix: "O5/bad-status-accepted/2xx-valid-body: Issue",
	// Input fa27efe2ea8f6ef4: route=token status=206.
	Repro: hostile.Program{Route: 0, Status: 5},
}, {
	// EXPECTED-DIFFERENCE: Revoke uses the same any-2xx rule for the Secret
	// DELETE; the API server answers 200 or 202. A server that answers 2xx
	// without deleting can do so with 200 as well, so 204 adds nothing.
	ID:     "HK-K8S-REVOKE-ANY-2XX",
	Class:  "EXPECTED-DIFFERENCE",
	Prefix: "O5/revoke-status: Revoke reported success on final HTTP status ",
	When: func(h *hostile.Harness) bool {
		recs := h.Served("secretdel")
		return len(recs) > 0 && recs[len(recs)-1].Status >= 200 && recs[len(recs)-1].Status < 300
	},
	// Input 36084bde8e5e5c64: route=secretdel status=204.
	Repro: hostile.Program{Route: 2, Status: 4},
}, {
	// HARDENING: the bound-Secret create and the TokenRequest decode ONE JSON
	// value (kubernetes.go, json.NewDecoder(...).Decode) and drainAndClose
	// discards the rest, so a transport/integrity error after the complete
	// value is never seen. Same class as HK-FETCHER/HK-JWKS-TRAILING-*.
	ID:     "HK-K8S-TRAILING-TRANSPORT-ERROR",
	Class:  "HARDENING",
	Prefix: "O5/transport-error-ignored: Issue succeeded",
	// Input 5848f4454dc550cb: route=token frame=cl-too-long.
	Repro: hostile.Program{Route: 0, Frame: 1},
}}

// TestK8sHostileKnownFindingsReproduce replays every k8sKnown entry with the
// entry NOT applied; it goes red when a finding is fixed.
func TestK8sHostileKnownFindingsReproduce(t *testing.T) {
	for _, k := range k8sKnown {
		t.Run(k.ID, func(t *testing.T) {
			h := runK8sHostile(k.Repro, nil)
			defer h.Close()
			hostile.RequireKnownReproduces(t, k, h)
		})
	}
}

// runK8sHostile runs one program against KubernetesEngine.Issue/Revoke and
// applies the target's oracles; the caller calls Finish or Evaluate.
func runK8sHostile(p hostile.Program, known []hostile.Known) *hostile.Harness {
	h := hostile.New(hostile.Config{
		Routes: k8sHostileRoutes(), Program: p, TLS: true,
		Credentials: []string{hostileK8sBearer}, RequestCeiling: 5,
		Known: known,
	})
	dsn, _ := json.Marshal(map[string]any{
		"namespace": "ns", "service_account": "sa", "revocable": true,
		"api_server": h.URL(), "ca_cert": h.CAPEM(), "token": hostileK8sBearer,
	})
	var e KubernetesEngine

	var cred Credential
	var label string
	err := h.Run("KubernetesEngine.Issue", func(ctx context.Context) error {
		var ie error
		cred, label, ie = e.Issue(ctx, string(dsn), "", 10*time.Minute)
		return ie
	})
	if p.Pristine() && (err != nil || cred.Fields["token"] != hostileK8sToken) {
		h.Violate("O6 LIVENESS: pristine Issue returned %v %v (unmatched: %v)", cred.Fields, err, h.Unmatched())
	}
	if err == nil {
		tokContent := func(b []byte) bool { _, _, _, ok := strictK8sToken(b); return ok }
		uidSeen, uk := h.Delivery("secret", strictK8sUID, 200, 201)
		tokSeen, tk := h.Delivery("token", tokContent, 200, 201)
		// A final 2xx other than 200/201 is still O5/bad-status-accepted; when
		// both exchanges are otherwise complete and every value check below
		// passes it carries the /2xx-valid-body sub-tag (isK8sSuccess accepts
		// any 2xx by design), so a known entry can name exactly that.
		other2xx := false
		if uk == "status" || tk == "status" {
			u2, uk2 := h.Delivery("secret", strictK8sUID, hostile.Status2xx...)
			t2, tk2 := h.Delivery("token", tokContent, hostile.Status2xx...)
			if uk2 != "status" && uk2 != "bad" && tk2 != "status" && tk2 != "bad" {
				uidSeen, uk, tokSeen, tk, other2xx = u2, uk2, t2, tk2, true
			}
		}
		tok, exp, expOK, tokOK := strictK8sToken(tokSeen)
		valueOK := false
		switch {
		case uk == "status" || tk == "status":
			h.Violate("O5/bad-status-accepted: Issue succeeded on a bound-Secret/TokenRequest response whose final HTTP status was not 200/201 (secret=%q token=%q)", uk, tk)
		case uk == "bad" || tk == "bad":
			h.Violate("O5/incomplete: Issue succeeded although the bound-Secret or TokenRequest exchange was incomplete, redirected or had a non-200 status")
		case hostile.HasDuplicateKeys(tokSeen) || hostile.HasDuplicateKeys(uidSeen):
			// duplicate member names: no single correct reading (RFC 8259)
			// not a value disagreement, so the 2xx-valid-body sub-tag below still applies
			valueOK = true
		case !strictK8sUID(uidSeen):
			h.Violate("O5/uid: Issue succeeded with a bound-Secret response that has no uid")
		case !tokOK:
			h.Violate("O5/empty-token: Issue succeeded but the delivered TokenRequest has no token (credential %q)", cred.Fields["token"])
		case cred.Fields["token"] != tok:
			h.Violate("O5/token-value: Issue returned token %q, strict decoder %q", cred.Fields["token"], tok)
		case !expOK && cred.Fields["expiration"] == "":
			h.Violate("O5/expiry-dropped: Issue succeeded with a token that carries no usable expirationTimestamp; the credential is returned with no expiration")
		case expOK && cred.Fields["expiration"] != exp.UTC().Format(time.RFC3339):
			h.Violate("O5/expiry-value: expiration %q vs strict %q", cred.Fields["expiration"], exp)
		default:
			valueOK = true
		}
		if other2xx {
			if valueOK && (uk == "" || uk == "transport") && (tk == "" || tk == "transport") {
				h.Violate("O5/bad-status-accepted/2xx-valid-body: Issue succeeded on a final 2xx other than 200/201 with complete bodies the strict decoders agree with")
			} else {
				h.Violate("O5/bad-status-accepted: Issue succeeded on a bound-Secret/TokenRequest response whose final HTTP status was not 200/201 (secret=%q token=%q)", uk, tk)
			}
		}
		if uk == "transport" || tk == "transport" {
			h.Violate("O5/transport-error-ignored: Issue succeeded although a response ended in a transport/framing/gzip error after the full JSON value")
		}
	}
	if label != "" {
		rerr := h.Run("KubernetesEngine.Revoke", func(ctx context.Context) error {
			return e.Revoke(ctx, string(dsn), label)
		})
		if rerr == nil {
			recs := h.Served("secretdel")
			if len(recs) == 0 {
				h.Violate("O5/revoke-no-request: Revoke reported success without contacting the API server")
			} else if last := recs[len(recs)-1]; last.Status != 200 && last.Status != 202 && last.Status != 404 {
				h.Violate("O5/revoke-status: Revoke reported success on final HTTP status %d", last.Status)
			}
		}
	}
	return h
}
