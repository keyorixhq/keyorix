// session_cache_chokepoint_test.go — proves the session-liveness chokepoint
// (core.SessionLiveForToken, wired into serveAuthCacheHit) catches a stale
// positive auth-cache entry regardless of WHICH revocation call site deleted
// the session row, even when that specific call site's own cache-invalidation
// never runs. Covers every "list session hashes, then delete, then invalidate"
// call site enumerated in the session-revoke-cache-race investigation:
// RevokeUserSessions, DeleteSessionsForUserExcept, ChangePassword, ActivateMFA,
// DisableMFA, FinishWebAuthnRegistration's first-enrollment purge,
// DeleteWebAuthnCredential's last-passkey purge, and both setup-token-consume
// paths (MFA-required and auto-login). See
// docs/findings/2026-09-20-FINDING-session-revoke-cache-race.md.
//
// Each case uses TWO *core.KeyorixCore instances sharing one DB: cRouter (has
// SetTokenCacheInvalidator wired; used only to log the victim in, build the
// router, and read) and cShadow (does NOT have it wired — "this call site's own
// eviction never ran," standing in for the multi-replica gap and for a
// hypothetical future call site that forgets to wire eviction). Both share the
// same package-level server/middleware auth cache (it is a process global), so
// cShadow's writes are invisible to that cache exactly the way a second, unaware
// replica's would be. If the fix is doing its job, a cache hit served by
// cRouter's router still denies the request, because SessionLiveForToken
// re-reads the session row directly from the (shared) DB rather than trusting
// the stale cache snapshot.
package http

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/pquerna/otp/totp"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	sqlite "github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	customMiddleware "github.com/keyorixhq/keyorix/server/middleware"
)

// Spec test vector constants (NoneES256), reproduced verbatim from
// internal/core/webauthn_spec_vectors_test.go (unexported there, and this
// package cannot reach across that boundary) so
// FinishWebAuthnRegistration's real attestation-verification success path is
// exercised for real — a hand-rolled fixture cannot fake a valid signature
// over a real challenge/clientData/authenticatorData.
const (
	sccCredentialIDHex         = "f91f391db4c9b2fde0ea70189cba3fb63f579ba6122b33ad94ff3ec330084be4" //nolint:gosec
	sccCredentialPubKeyHex     = "a5010203262001215820afefa16f97ca9b2d23eb86ccb64098d20db90856062eb249c33a9b672f26df61225820930a56b87a2fca66334b03458abf879717c12cc68ed73290af2e2664796b9220"
	sccRegAttestationObjectHex = "a363666d74646e6f6e656761747453746d74a068617574684461746158a4bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b559000000008446ccb9ab1db374750b2367ff6f3a1f0020f91f391db4c9b2fde0ea70189cba3fb63f579ba6122b33ad94ff3ec330084be4a5010203262001215820afefa16f97ca9b2d23eb86ccb64098d20db90856062eb249c33a9b672f26df61225820930a56b87a2fca66334b03458abf879717c12cc68ed73290af2e2664796b9220"
	sccRegClientDataJSONHex    = "7b2274797065223a22776562617574686e2e637265617465222c226368616c6c656e6765223a22414d4d507434557878475453746e63647134313759447742466938767049612d7077386f4f755657345441222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a66616c73652c22657874726144617461223a22636c69656e74446174614a534f4e206d617920626520657874656e6465642077697468206164646974696f6e616c206669656c647320696e20746865206675747572652c207375636820617320746869733a20426b5165446a646354427258426941774a544c453551227d"
	sccRegChallengeHex         = "00c30fb78531c464d2b6771dab8d7b603c01162f2fa486bea70f283ae556e130"
)

func sccHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decode hex: %v", err)
	}
	return b
}

func sccSHA256Hex(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// sccWebAuthnID mirrors webauthnUser.WebAuthnID()'s 8-byte big-endian encoding
// (internal/core/webauthn.go), needed to hand-build SessionData the library
// will accept as belonging to userID.
func sccWebAuthnID(userID uint) []byte {
	b := make([]byte, 8)
	id := uint64(userID)
	for i := 7; i >= 0; i-- {
		b[i] = byte(id)
		id >>= 8
	}
	return b
}

// sccWorld is the shared fixture for every chokepoint case: two cores over one
// DB, plus a project/secret/role/permission the victim is granted so
// srrAuthedRead exercises a real authenticated, authorized request.
type sccWorld struct {
	db      *gorm.DB
	ls      *store.LocalStorage
	cRouter *core.KeyorixCore // invalidator wired; login + router only
	cShadow *core.KeyorixCore // invalidator NOT wired; performs every operation under test
	router  http.Handler
	admin   *models.User
	ref     string
}

func sccSetupWorld(t *testing.T) *sccWorld {
	t.Helper()
	if err := i18n.InitializeForTesting(); err != nil {
		t.Fatalf("i18n: %v", err)
	}
	t.Cleanup(i18n.ResetForTesting)

	dbPath := filepath.Join(t.TempDir(), "scc.db")
	db, err := gorm.Open(sqlite.Open(dbPath+"?_foreign_keys=1&_busy_timeout=10000&_journal_mode=WAL&_txlock=immediate"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(models.AllTestModels()...); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	// Not part of AllTestModels() (see internal/core/webauthn_test.go's identical
	// explicit inclusion) -- needed for DeleteWebAuthnCredential's reauth-gate case.
	if err := db.AutoMigrate(&models.MFAStepUpGrant{}); err != nil {
		t.Fatalf("migrate MFAStepUpGrant: %v", err)
	}
	ls := store.NewLocalStorage(db)

	cRouter := core.NewKeyorixCore(store.NewLocalStorage(db))
	cRouter.SetTokenCacheInvalidator(customMiddleware.InvalidateTokenCacheByHash)

	cShadow := core.NewKeyorixCore(store.NewLocalStorage(db))
	// Deliberately NOT calling cShadow.SetTokenCacheInvalidator: every operation
	// in this file runs through cShadow, so its own cache-eviction step is
	// always a silent no-op — exactly the condition requirement (c) asks for.
	enc := encryption.NewService(&config.EncryptionConfig{Enabled: true, DEKPath: "scc-dek.key", SaltPath: "scc-kek.salt"}, t.TempDir())
	if err := enc.Initialize("scc-test-passphrase"); err != nil {
		t.Fatalf("initialize encryptor: %v", err)
	}
	cShadow.SetAuthEncryptor(enc)
	rp, err := webauthn.New(&webauthn.Config{
		RPID: "example.org", RPDisplayName: "Keyorix", RPOrigins: []string{"https://example.org"},
	})
	if err != nil {
		t.Fatalf("webauthn RP: %v", err)
	}
	cShadow.SetWebAuthn(rp)

	ctx := context.Background()
	cShadow.SetBootstrapToken("scc-bootstrap-token")
	if _, err := cShadow.BootstrapSystem(ctx, &core.BootstrapRequest{
		Username: "sccadmin", Email: "sccadmin@example.com",
		Password: "TestPassword123!", Token: "scc-bootstrap-token",
	}); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	admin, err := ls.GetUserByUsername(ctx, "sccadmin")
	if err != nil || admin == nil {
		t.Fatalf("admin lookup: %v", err)
	}

	proj, err := ls.CreateProject(ctx, &models.Project{Name: "scc"})
	if err != nil {
		t.Fatalf("create project: %v", err)
	}
	env, err := ls.CreateEnvironment(ctx, &models.Environment{Name: "prod", ProjectID: proj.ID})
	if err != nil {
		t.Fatalf("create env: %v", err)
	}
	sec, err := cShadow.CreateSecret(ctx, &core.CreateSecretRequest{
		Name: "s", Value: []byte("init"), ProjectID: proj.ID, EnvironmentID: env.ID,
		Type: "password", CreatedBy: "sccadmin", OwnerID: admin.ID,
	})
	if err != nil || sec == nil {
		t.Fatalf("create secret: %v", err)
	}
	ref := "scc/prod/s"
	var perm models.Permission
	if e := db.Where("name = ?", "secrets.read").First(&perm).Error; e != nil {
		perm = models.Permission{Name: "secrets.read", Resource: "secrets", Action: "read"}
		if e2 := db.Create(&perm).Error; e2 != nil {
			t.Fatalf("seed permission: %v", e2)
		}
	}
	role := models.Role{Name: "scc-reader", NameFolded: "scc-reader"}
	if err := db.Create(&role).Error; err != nil {
		t.Fatalf("seed role: %v", err)
	}
	if err := db.Create(&models.RolePermission{RoleID: role.ID, PermissionID: perm.ID}).Error; err != nil {
		t.Fatalf("seed role-permission: %v", err)
	}

	r, err := NewRouter(&config.Config{}, cRouter)
	if err != nil {
		t.Fatalf("router: %v", err)
	}

	return &sccWorld{db: db, ls: ls, cRouter: cRouter, cShadow: cShadow, router: r, admin: admin, ref: ref}
}

// newVictimWithPrimedCache creates a fresh victim, grants them the read-access
// role, logs in via cRouter, and primes the auth cache with a real cold-path
// read (the positive control every case needs) — returns the victim and their
// session token.
func (w *sccWorld) newVictimWithPrimedCache(t *testing.T, username, password string) (*models.User, string) {
	t.Helper()
	ctx := context.Background()
	victim, err := w.cRouter.CreateUser(ctx, &core.CreateUserRequest{
		Username: username, Email: username + "@x.io", Password: password,
	})
	if err != nil || victim == nil {
		t.Fatalf("create victim %s: %v", username, err)
	}
	var role models.Role
	if err := w.db.Where("name = ?", "scc-reader").First(&role).Error; err != nil {
		t.Fatalf("lookup role: %v", err)
	}
	var proj models.Project
	if err := w.db.Where("name = ?", "scc").First(&proj).Error; err != nil {
		t.Fatalf("lookup project: %v", err)
	}
	if err := w.cRouter.AssignUserRole(ctx, 0, victim.ID, role.ID, core.Scope{ProjectID: proj.ID}, false); err != nil {
		t.Fatalf("grant victim %s: %v", username, err)
	}
	sess, _, err := w.cRouter.Login(ctx, &core.LoginRequest{Username: username, Password: password})
	if err != nil || sess == nil {
		t.Fatalf("login victim %s: %v", username, err)
	}
	if !srrAuthedRead(w.router, w.ref, sess.SessionToken) {
		t.Fatalf("positive control: victim %s's own fresh session did not authenticate", username)
	}
	return victim, sess.SessionToken
}

// assertDenied re-checks the primed token and fails the test if it still
// authenticates — the chokepoint's whole job.
func (w *sccWorld) assertDenied(t *testing.T, token string) {
	t.Helper()
	if srrAuthedRead(w.router, w.ref, token) {
		t.Error("cache hit still authenticated after the operation ran with the invalidator disabled — the session chokepoint did not catch it")
	}
}

// TestSessionCacheChokepoint_CoversEveryVulnerableCallSite is the requirement
// (c) table test: for every "list session hashes, then delete, then
// invalidate" call site the investigation enumerated, warm the cache, run the
// operation through a core with no cache invalidator wired, and confirm the
// session-liveness chokepoint (not that site's own eviction) is what denies
// the next cache hit.
func TestSessionCacheChokepoint_CoversEveryVulnerableCallSite(t *testing.T) {
	w := sccSetupWorld(t)
	ctx := context.Background()

	t.Run("RevokeUserSessions", func(t *testing.T) {
		victim, token := w.newVictimWithPrimedCache(t, "scc-revoke", "Xk7#Qp2$Rn5@Wv9!")
		if _, err := w.cShadow.RevokeUserSessions(ctx, w.admin.ID, victim.ID); err != nil {
			t.Fatalf("RevokeUserSessions: %v", err)
		}
		w.assertDenied(t, token)
	})

	t.Run("DeleteSessionsForUserExcept", func(t *testing.T) {
		victim, token := w.newVictimWithPrimedCache(t, "scc-delsess", "Xk7#Qp2$Rn5@Wv9!")
		if err := w.cShadow.DeleteSessionsForUserExcept(ctx, core.ActorTypeUser, w.admin.ID, victim.ID, 0); err != nil {
			t.Fatalf("DeleteSessionsForUserExcept: %v", err)
		}
		w.assertDenied(t, token)
	})

	t.Run("ChangePassword", func(t *testing.T) {
		victim, token := w.newVictimWithPrimedCache(t, "scc-chpwd", "Xk7#Qp2$Rn5@Wv9!")
		if err := w.cShadow.ChangePassword(ctx, victim.ID, "Xk7#Qp2$Rn5@Wv9!", "Zz9!Rp2$Xk7#Wv5@", ""); err != nil {
			t.Fatalf("ChangePassword: %v", err)
		}
		w.assertDenied(t, token)
	})

	t.Run("ActivateMFA", func(t *testing.T) {
		victim, token := w.newVictimWithPrimedCache(t, "scc-actmfa", "Xk7#Qp2$Rn5@Wv9!")
		_, secret, err := w.cShadow.BeginMFAEnrollment(ctx, victim.ID)
		if err != nil {
			t.Fatalf("BeginMFAEnrollment: %v", err)
		}
		code, err := totp.GenerateCode(secret, time.Now())
		if err != nil {
			t.Fatalf("generate totp: %v", err)
		}
		if _, err := w.cShadow.ActivateMFA(ctx, victim.ID, code, "Xk7#Qp2$Rn5@Wv9!"); err != nil {
			t.Fatalf("ActivateMFA: %v", err)
		}
		w.assertDenied(t, token)
	})

	t.Run("DisableMFA", func(t *testing.T) {
		victim, _ := w.newVictimWithPrimedCache(t, "scc-dismfa", "Xk7#Qp2$Rn5@Wv9!")
		// Precondition: enable MFA first (not the operation under test) via a
		// throwaway session, then re-login for a FRESH token to prime and check
		// against DisableMFA itself.
		_, secret, err := w.cShadow.BeginMFAEnrollment(ctx, victim.ID)
		if err != nil {
			t.Fatalf("BeginMFAEnrollment: %v", err)
		}
		code, err := totp.GenerateCode(secret, time.Now())
		if err != nil {
			t.Fatalf("generate totp: %v", err)
		}
		if _, err := w.cShadow.ActivateMFA(ctx, victim.ID, code, "Xk7#Qp2$Rn5@Wv9!"); err != nil {
			t.Fatalf("ActivateMFA precondition: %v", err)
		}
		sess, _, err := w.cRouter.Login(ctx, &core.LoginRequest{Username: "scc-dismfa", Password: "Xk7#Qp2$Rn5@Wv9!"})
		// MFA is enabled, so Login now demands a second factor -- mint the session
		// directly instead of driving the challenge/verify dance, which is not
		// what this test is about.
		if err != nil && sess == nil {
			expiresAt := time.Now().Add(time.Hour)
			s2, cerr := w.cShadow.Storage().CreateSession(ctx, &models.Session{
				UserID: victim.ID, SessionToken: mustRandomToken(t), ExpiresAt: &expiresAt,
			})
			if cerr != nil {
				t.Fatalf("mint post-mfa session: %v", cerr)
			}
			sess = s2
		}
		if !srrAuthedRead(w.router, w.ref, sess.SessionToken) {
			t.Fatalf("positive control: post-MFA session did not authenticate")
		}
		// +30s (one TOTP step) from the ActivateMFA precondition's code above so
		// the anti-replay MarkTOTPStepUsed check (same step -> rejected as reused)
		// does not collide with it -- validateTOTPStep's +-1 step skew still
		// accepts this at call time, moments later.
		freshCode, err := totp.GenerateCode(secret, time.Now().Add(30*time.Second))
		if err != nil {
			t.Fatalf("generate totp: %v", err)
		}
		if err := w.cShadow.DisableMFA(ctx, victim.ID, freshCode); err != nil {
			t.Fatalf("DisableMFA: %v", err)
		}
		w.assertDenied(t, sess.SessionToken)
	})

	t.Run("FinishWebAuthnRegistration_FirstEnrollment", func(t *testing.T) {
		victim, token := w.newVictimWithPrimedCache(t, "scc-webauthn-reg", "Xk7#Qp2$Rn5@Wv9!")

		id := base64URLEncode(sccHex(t, sccCredentialIDHex))
		body := map[string]any{
			"id": id, "rawId": id, "type": "public-key",
			"response": map[string]any{
				"attestationObject": base64URLEncode(sccHex(t, sccRegAttestationObjectHex)),
				"clientDataJSON":    base64URLEncode(sccHex(t, sccRegClientDataJSONHex)),
			},
		}
		data, err := jsonMarshal(body)
		if err != nil {
			t.Fatalf("marshal attestation body: %v", err)
		}
		parsed, err := protocol.ParseCredentialCreationResponseBytes(data)
		if err != nil {
			t.Fatalf("parse attestation: %v", err)
		}
		challenge := base64URLEncode(sccHex(t, sccRegChallengeHex))

		sd := &webauthn.SessionData{
			Challenge:  challenge,
			UserID:     sccWebAuthnID(victim.ID),
			CredParams: []protocol.CredentialParameter{{Type: protocol.PublicKeyCredentialType, Algorithm: webauthncose.AlgES256}},
		}
		sdJSON, err := jsonMarshal(sd)
		if err != nil {
			t.Fatalf("marshal session data: %v", err)
		}
		regToken := mustRandomToken(t)
		if err := w.cShadow.Storage().CreateWebAuthnSession(ctx, &models.WebAuthnSession{
			UserID: victim.ID, TokenHash: sccSHA256Hex(regToken), Purpose: "register",
			Data: sdJSON, ExpiresAt: time.Now().Add(5 * time.Minute), CreatedAt: time.Now(),
		}); err != nil {
			t.Fatalf("seed webauthn session: %v", err)
		}

		if _, err := w.cShadow.FinishWebAuthnRegistration(ctx, victim.ID, regToken, "laptop", "Xk7#Qp2$Rn5@Wv9!", parsed); err != nil {
			t.Fatalf("FinishWebAuthnRegistration: %v", err)
		}
		w.assertDenied(t, token)
	})

	t.Run("DeleteWebAuthnCredential_LastPasskey", func(t *testing.T) {
		victim, token := w.newVictimWithPrimedCache(t, "scc-webauthn-del", "Xk7#Qp2$Rn5@Wv9!")
		blob, err := jsonMarshal(webauthn.Credential{ID: []byte("scc-cred")})
		if err != nil {
			t.Fatalf("marshal credential: %v", err)
		}
		cred := &models.WebAuthnCredential{UserID: victim.ID, CredentialID: []byte("scc-cred"), Name: "key", CredentialBlob: blob}
		if err := w.db.Create(cred).Error; err != nil {
			t.Fatalf("seed credential: %v", err)
		}
		if err := w.cShadow.Storage().SetUserWebAuthnEnabled(ctx, victim.ID, true); err != nil {
			t.Fatalf("enable webauthn: %v", err)
		}
		// requireReauth's account-security-factor-change gate does not accept a
		// bare password once a second factor is enrolled (WebAuthnEnabled=true
		// here) -- it also needs a fresh reauth-purpose step-up grant, exactly
		// like internal/core/webauthn_test.go's own seedStepUpGrant.
		if err := w.db.Create(&models.MFAStepUpGrant{UserID: victim.ID, Purpose: models.MFAStepUpPurposeReauth, ExpiresAt: time.Now().Add(15 * time.Minute)}).Error; err != nil {
			t.Fatalf("seed step-up grant: %v", err)
		}
		if err := w.cShadow.DeleteWebAuthnCredential(ctx, victim.ID, cred.ID, "Xk7#Qp2$Rn5@Wv9!"); err != nil {
			t.Fatalf("DeleteWebAuthnCredential: %v", err)
		}
		w.assertDenied(t, token)
	})

	t.Run("SetupConsume_MFARequiredBranch", func(t *testing.T) {
		victim, token := w.newVictimWithPrimedCache(t, "scc-setup-mfa", "Xk7#Qp2$Rn5@Wv9!")
		_, secret, err := w.cShadow.BeginMFAEnrollment(ctx, victim.ID)
		if err != nil {
			t.Fatalf("BeginMFAEnrollment: %v", err)
		}
		code, err := totp.GenerateCode(secret, time.Now())
		if err != nil {
			t.Fatalf("generate totp: %v", err)
		}
		if _, err := w.cShadow.ActivateMFA(ctx, victim.ID, code, "Xk7#Qp2$Rn5@Wv9!"); err != nil {
			t.Fatalf("ActivateMFA precondition: %v", err)
		}
		// The precondition itself deleted the primed session (ActivateMFA purges
		// sessions too) -- re-prime with a directly-minted session so THIS case
		// isolates the setup-consume path's own effect, not ActivateMFA's.
		expiresAt := time.Now().Add(time.Hour)
		sess, err := w.cShadow.Storage().CreateSession(ctx, &models.Session{
			UserID: victim.ID, SessionToken: mustRandomToken(t), ExpiresAt: &expiresAt,
		})
		if err != nil {
			t.Fatalf("mint session: %v", err)
		}
		if !srrAuthedRead(w.router, w.ref, sess.SessionToken) {
			t.Fatalf("positive control: re-primed session did not authenticate")
		}
		res, err := w.cShadow.IssueSetupToken(ctx, core.IssueSetupTokenRequest{
			Purpose: core.SetupPurposePasswordResetLink, SubjectEmail: victim.Email, SubjectUserID: &victim.ID,
		})
		if err != nil {
			t.Fatalf("IssueSetupToken: %v", err)
		}
		if _, err := w.cShadow.CompleteSetup(ctx, res.PlainToken, "Zz9!Rp2$Xk7#Wv5@", "ua", "1.2.3.4"); err == nil || err != core.ErrMFARequired {
			t.Fatalf("CompleteSetup: expected ErrMFARequired, got %v", err)
		}
		w.assertDenied(t, sess.SessionToken)
		_ = token // the original priming token was already superseded by the re-primed one above
	})

	t.Run("SetupConsume_AutoLoginBranch", func(t *testing.T) {
		victim, token := w.newVictimWithPrimedCache(t, "scc-setup-auto", "Xk7#Qp2$Rn5@Wv9!")
		res, err := w.cShadow.IssueSetupToken(ctx, core.IssueSetupTokenRequest{
			Purpose: core.SetupPurposePasswordResetLink, SubjectEmail: victim.Email, SubjectUserID: &victim.ID,
		})
		if err != nil {
			t.Fatalf("IssueSetupToken: %v", err)
		}
		if _, err := w.cShadow.CompleteSetup(ctx, res.PlainToken, "Zz9!Rp2$Xk7#Wv5@", "ua", "1.2.3.4"); err != nil {
			t.Fatalf("CompleteSetup: %v", err)
		}
		w.assertDenied(t, token)
	})
}

func base64URLEncode(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

func jsonMarshal(v any) ([]byte, error) {
	return json.Marshal(v)
}

// mustRandomToken returns a fresh random hex token for directly-minted test
// sessions/webauthn-ceremony tokens where the real generator isn't reachable.
func mustRandomToken(t *testing.T) string {
	t.Helper()
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatalf("random token: %v", err)
	}
	return hex.EncodeToString(b[:])
}
