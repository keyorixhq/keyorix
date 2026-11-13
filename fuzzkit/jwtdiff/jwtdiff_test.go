package jwtdiff

import (
	"context"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/keyorixhq/keyorix/fuzzkit/diffkit"
)

func inputFor(k knobs) *input { return &input{token: buildToken(k), cfg: configFor(k)} }

// agree asserts golang-jwt and the reference verifier reach the same decision.
func agree(t *testing.T, k knobs) {
	t.Helper()
	c := NewComparator()
	diverged, d := c.Compare(context.Background(), inputFor(k))
	if diverged {
		t.Fatalf("unexpected divergence for %+v:\n%v", k, d)
	}
}

func TestKnownCasesAgree(t *testing.T) {
	cases := []struct {
		name string
		k    knobs
	}{
		{"genuine RS256 accepted", knobs{expectedAlg: algRS256, tokenAlg: algRS256, audKind: 0, expKind: 0}},
		{"genuine ES256 accepted", knobs{expectedAlg: algES256, tokenAlg: algES256, audKind: 0, expKind: 0}},
		{"genuine HS256 accepted", knobs{expectedAlg: algHS256, tokenAlg: algHS256, audKind: 0, expKind: 0}},
		{"genuine RS256 aud in array", knobs{expectedAlg: algRS256, tokenAlg: algRS256, audKind: 1}},
		{"alg none rejected", knobs{expectedAlg: algRS256, tokenAlg: algNone}},
		{"RS/HS confusion rejected", knobs{expectedAlg: algRS256, tokenAlg: algHS256, rsPubAsHMAC: true}},
		{"wrong RS key rejected", knobs{expectedAlg: algRS256, tokenAlg: algRS256, wrongKey: true}},
		{"tampered signature rejected", knobs{expectedAlg: algRS256, tokenAlg: algRS256, tamperSig: true}},
		{"expired rejected", knobs{expectedAlg: algRS256, tokenAlg: algRS256, expKind: 1}},
		{"missing exp rejected", knobs{expectedAlg: algRS256, tokenAlg: algRS256, expKind: 2}},
		{"nbf future rejected", knobs{expectedAlg: algRS256, tokenAlg: algRS256, nbfKind: 2}},
		{"aud wrong rejected", knobs{expectedAlg: algRS256, tokenAlg: algRS256, audKind: 2}},
		{"aud missing rejected", knobs{expectedAlg: algRS256, tokenAlg: algRS256, audKind: 3}},
		{"aud array without expected rejected", knobs{expectedAlg: algRS256, tokenAlg: algRS256, audKind: 4}},
		{"alg mismatch ES for RS rejected", knobs{expectedAlg: algRS256, tokenAlg: algES256}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { agree(t, tc.k) })
	}
}

// --- Red proof --------------------------------------------------------------
//
// The Keyorix-side analogue is internal/core/sso.go verifyIDToken, which pins the
// accepted algorithms to the asymmetric family via jwt.WithValidMethods and so
// rejects alg:none. keyorixVerify models that. A SCRATCH copy with a single
// planted relaxation — dropping the method allowlist and honouring alg:none —
// accepts an unsigned token the reference verifier rejects, which the oracle
// reports. No production code is touched.

type keyorixVerify struct {
	name      string
	allowNone bool // the planted relaxation
}

func (k keyorixVerify) Name() string { return k.name }

func (k keyorixVerify) Run(_ context.Context, in *input) (string, error) {
	methods := []string{"RS256"}
	keyfunc := func(t *jwt.Token) (any, error) { return in.cfg.rsaPub, nil }
	if k.allowNone {
		methods = []string{"RS256", "none"}
		keyfunc = func(t *jwt.Token) (any, error) {
			if t.Method.Alg() == "none" {
				return jwt.UnsafeAllowNoneSignatureType, nil
			}
			return in.cfg.rsaPub, nil
		}
	}
	tok, err := jwt.Parse(in.token, keyfunc,
		jwt.WithValidMethods(methods),
		jwt.WithExpirationRequired(),
		jwt.WithAudience(in.cfg.aud),
		jwt.WithTimeFunc(func() time.Time { return in.cfg.now }),
	)
	if err != nil {
		return "", err
	}
	claims := tok.Claims.(jwt.MapClaims)
	sub, _ := claims["sub"].(string)
	return sub, nil
}

func TestRedProof_AllowNoneDiverges(t *testing.T) {
	// A well-formed alg:none token with otherwise-valid claims.
	noneTok := inputFor(knobs{expectedAlg: algRS256, tokenAlg: algNone, expKind: 0, audKind: 0})

	green := diffkit.Comparator[*input, string]{
		Impls:   []diffkit.Impl[*input, string]{keyorixVerify{name: "keyorix-strict"}, refImpl{}},
		Timeout: perImplTimeout, Decide: decide,
	}
	if diverged, d := green.Compare(context.Background(), noneTok); diverged {
		t.Fatalf("strict wrapper should agree with reference on alg:none, got:\n%v", d)
	}

	red := diffkit.Comparator[*input, string]{
		Impls:   []diffkit.Impl[*input, string]{keyorixVerify{name: "keyorix-relaxed", allowNone: true}, refImpl{}},
		Timeout: perImplTimeout, Decide: decide,
	}
	diverged, d := red.Compare(context.Background(), noneTok)
	if !diverged {
		t.Fatal("planted relaxation (accepts alg:none) was NOT caught by the differential oracle")
	}
	t.Logf("red proof fired as expected:\n%v", d)
}
