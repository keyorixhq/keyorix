package verifierflip_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/oidcverify"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/internal/testutil/fuzzworld"
	"github.com/keyorixhq/keyorix/internal/testutil/sqlitetest"
	"github.com/keyorixhq/keyorix/pkg/bundleverify"
	"github.com/keyorixhq/keyorix/pkg/trust"
)

type staticJWKS struct{ pub *rsa.PublicKey }

func (s staticJWKS) Key(_ context.Context, _, kid string) (any, error) {
	if kid == "k1" {
		return s.pub, nil
	}
	return nil, fmt.Errorf("no key %q", kid)
}

func oidcTarget(t testing.TB) tgt {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
	v, err := oidcverify.NewOIDCVerifier([]oidcverify.OIDCTrustedIssuer{{Issuer: "https://idp.example", Audiences: []string{"keyorix"}}}, staticJWKS{&priv.PublicKey})
	if err != nil {
		t.Fatal(err)
	}
	v.SetClockForTesting(func() time.Time { return now })
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": "https://idp.example", "aud": "keyorix", "sub": "ci-job-42",
		"iat": now.Add(-time.Minute).Unix(), "exp": now.Add(time.Hour).Unix(),
	})
	tok.Header["kid"] = "k1"
	raw, err := tok.SignedString(priv)
	if err != nil {
		t.Fatal(err)
	}
	dot := strings.LastIndexByte(raw, '.')
	return tgt{
		Name: "oidc-jwt-rs256", Artifact: []byte(raw),
		Verify: func(b []byte) bool {
			_, _, _, err := v.VerifyWithExpiry(context.Background(), string(b))
			return err == nil
		},
		Canon: func(b []byte) string {
			iss, sub, exp, _ := v.VerifyWithExpiry(context.Background(), string(b))
			segs := strings.Split(string(b), ".")
			sig, _ := base64.RawURLEncoding.DecodeString(segs[len(segs)-1])
			return fmt.Sprintf("%s|%s|%d|%s", iss, sub, exp.Unix(), hex.EncodeToString(sig))
		},
		Seps: [][]byte{{'.'}},
		Region: func(off int) string {
			switch d1 := strings.IndexByte(raw, '.'); {
			case off <= d1:
				return "header"
			case off <= dot:
				return "payload"
			default:
				return "signature"
			}
		},
		MACStart: dot + 1, MACEnd: len(raw),
	}
}

// tokenWorld builds a real core over SQLite and returns validators for the
// three opaque credential types. These are DB lookups by SHA-256, so the
// verifier property is: no token other than the issued one authenticates.
func tokenTargets(t testing.TB) []tgt {
	if err := i18n.InitializeForTesting(); err != nil {
		t.Fatal(err)
	}
	db := fuzzworld.OpenSQLite(t, sqlitetest.DSN("vflip_"), 1)
	fuzzworld.Bootstrap(t, db)
	c := core.NewKeyorixCore(store.NewLocalStorage(db))
	ls := store.NewLocalStorage(db)
	ctx := context.Background()
	c.SetBootstrapToken("bootstrap-token")
	if _, err := c.BootstrapSystem(ctx, &core.BootstrapRequest{Username: "admin", Email: "admin@example.com", Password: "TestPassword123!", Token: "bootstrap-token"}); err != nil {
		t.Logf("bootstrap: %v", err)
	}
	sess, _, err := c.Login(ctx, &core.LoginRequest{Username: "admin", Password: "TestPassword123!"})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	admin, err := ls.GetUserByUsername(ctx, "admin")
	if err != nil {
		t.Fatal(err)
	}
	var out []tgt
	out = append(out, tgt{
		Name: "session-token", Artifact: []byte(sess.SessionToken),
		Verify: func(b []byte) bool {
			u, _, err := c.ValidateSessionToken(ctx, string(b))
			return err == nil && u != nil
		},
		Canon: func(b []byte) string {
			u, _, _ := c.ValidateSessionToken(ctx, string(b))
			return fmt.Sprint(u.ID)
		},
	})
	pat, err := c.CreateOwnPAT(ctx, admin.ID, "vflip", nil, []string{"secrets.read"}, 0, 0, nil)
	if err != nil {
		t.Fatalf("pat: %v", err)
	}
	out = append(out, tgt{
		Name: "personal-access-token", Artifact: []byte(pat.PlainToken),
		Verify: func(b []byte) bool {
			u, _, _, _, err := c.ValidatePATToken(ctx, string(b))
			return err == nil && u != nil
		},
		Canon: func(b []byte) string {
			u, _, _, _, _ := c.ValidatePATToken(ctx, string(b))
			return fmt.Sprint(u.ID)
		},
	})
	p, err := ls.CreateProject(ctx, &models.Project{Name: "vflip-proj"})
	if err != nil {
		t.Fatal(err)
	}
	if m, err := c.CreateMachineIdentity(ctx, p.ID, "vflip-machine", "service", "d", "", admin.ID, 0); err != nil {
		t.Logf("machine identity skipped: %v", err)
	} else if res, err := c.IssueMachineToken(ctx, p.ID, m.ID, admin.ID, core.IssueMachineTokenParams{Name: "vflip"}); err != nil {
		t.Logf("machine token skipped: %v", err)
	} else {
		tokenStr := res.PlainToken
		out = append(out, tgt{
			Name: "machine-token", Artifact: []byte(tokenStr),
			Verify: func(b []byte) bool {
				mi, _, _, _, err := c.ValidateMachineToken(ctx, string(b))
				return err == nil && mi != nil
			},
			Canon: func(b []byte) string {
				mi, _, _, _, _ := c.ValidateMachineToken(ctx, string(b))
				return fmt.Sprint(mi.ID)
			},
		})
	}
	return out
}

// bundleTarget: pkg/bundleverify's signed air-gap update bundle (gzip+tar,
// ed25519-signed manifest pinning every component by sha256). Verify streams
// every component through its pinned hash, so an accepted mutation means the
// manifest AND all components are intact; Canon is therefore the manifest.
func bundleTarget(t testing.TB) tgt {
	pub, priv, err := ed25519.GenerateKey(bytes.NewReader(bytes.Repeat([]byte{9}, 64)))
	if err != nil {
		t.Fatal(err)
	}
	reg := trust.NewRegistry()
	if err := reg.Add(trust.PurposeUpdate, "upd-1", pub); err != nil {
		t.Fatal(err)
	}
	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "a.bin"), bytes.Repeat([]byte("component-a-"), 20), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "b.yaml"), []byte("kind: Thing\nname: b\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	m, err := bundleverify.BuildManifest(src, "1.2.3", "upd-1", "", time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	sig, err := bundleverify.Sign(m, priv)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := bundleverify.WriteBundle(&buf, src, m, sig); err != nil {
		t.Fatal(err)
	}
	return tgt{
		Name: "update-bundle-ed25519-manifest", Artifact: buf.Bytes(),
		Verify: func(b []byte) bool { _, err := bundleverify.Verify(bytes.NewReader(b), reg); return err == nil },
		Canon: func(b []byte) string {
			mm, _ := bundleverify.Verify(bytes.NewReader(b), reg)
			o, _ := mm.MarshalCanonical()
			return string(o)
		},
	}
}

func extraTargets(t testing.TB) []tgt {
	out := []tgt{oidcTarget(t), bundleTarget(t)}
	out = append(out, tokenTargets(t)...)
	return out
}
