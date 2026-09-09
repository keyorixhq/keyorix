// remote_storage_conformance_tranche4_auth_security_test.go — issue #1808,
// tranche 4: the authentication/second-factor cluster tranche 3 explicitly
// flagged as HIGH priority and deliberately deferred (WebAuthn, TOTP MFA, MFA
// step-up grants, SSO login state, the password/MFA login-verification proxy,
// and the cluster-wide login-attempt rate limiter).
//
// Two methods here have NO LocalStorage equivalent to compare against:
// VerifyLoginCredentials (remote_login_verify.go) and VerifyMFALoginCredentials
// (remote_mfa.go) both implement a core.RemoteLoginVerifier/RemoteMFAVerifier
// interface that LocalStorage never needs to satisfy — a LocalStorage-backed
// core does the ENTIRE check in-process (core.Login/core.VerifyPasswordCredentials,
// core.VerifyMFACredentials) and never proxies anything. For these two, the
// "local" side of the differential is the core-level function the upstream
// server's OWN handler calls for the real HTTP request (confirmed against
// server/http/handlers/users_crud.go's VerifyCredentials/VerifyMFACredentials
// doc comments), exercised directly against h.upstreamCore — not h.ls. Every
// other method in this file has a real LocalStorage primitive and follows the
// established h.ls vs h.rs shape.
//
// MFA enrolment fixtures use the SAME real path internal/core/mfa_test.go's own
// TestMFA_FullFlow uses: h.upstreamCore.BeginMFAEnrollment + ActivateMFA against
// a real bcrypt password and a real (encryption-enabled) TOTP secret, with
// codes generated via github.com/pquerna/otp/totp against the wall clock
// (validateTOTPStep tolerates the adjacent +-1 step, i.e. a ~90s window, so
// generating a code immediately before use is not flaky in practice) — not a
// shortcut, per the task brief's explicit instruction to use the codebase's own
// enrollment patterns rather than inventing one.
//
// GetMFASecret's comparison deliberately does NOT run SecretEnc/SecretMeta
// through assertFieldExhaustiveEqual (whose failure path prints %#v of both
// structs): even though this is ciphertext, not the raw TOTP secret, targeted
// bytes.Equal/len comparisons prove the same wire fidelity without ever
// printing the ciphertext bytes into a test failure message.
package http

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// conformanceSHA256Hex mirrors core's own (unexported) sha256Hex — MFA/WebAuthn
// challenge and session tokens are stored only as a hash, and this file needs
// to resolve a plaintext token it minted back to its stored row via LocalStorage
// read primitives that key on the hash, exactly like the real callers do.
func conformanceSHA256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// enableMFAEncryption wires a real, enabled encryption.Service onto
// h.upstreamCore — BeginMFAEnrollment refuses outright ("requires at-rest
// encryption to be enabled") without one, and newConformanceHarness's own
// newTestCore never wires one (no test up to this tranche has needed MFA
// enrolment). Mirrors internal/core/mfa_test.go's newMFATestCore setup exactly.
func enableMFAEncryption(t *testing.T, h *conformanceHarness) {
	t.Helper()
	enc := encryption.NewService(&config.EncryptionConfig{
		Enabled: true, DEKPath: "conformance-dek.key", SaltPath: "conformance-kek.salt",
	}, t.TempDir())
	require.NoError(t, enc.Initialize("conformance-test-passphrase"))
	h.upstreamCore.SetAuthEncryptor(enc)
}

// Deliberately unrelated to any username/email/display-name word used by this
// file's fixtures: internal/core/password_policy.go's containsPersonalInfo
// rejects a password containing ANY 3+ char word of the display name
// case-insensitively, and every fixture in this file names its user
// "Conformance <Method> <suffix>" -- a password built from those same words
// (e.g. containing "conformance") fails CreateUser with a validation error.
// ensureMFAStepUpGrantTable AutoMigrates models.MFAStepUpGrant onto the
// harness's underlying DB. models.AllTestModels() (internal/storage/models/all_models.go,
// the single source of truth newConformanceHarness's newTestCore AutoMigrates)
// does not include MFAStepUpGrant -- no test up to this tranche has needed the
// table, so the omission was never exercised. Fixed here, scoped to this file's
// own tests only, rather than editing that shared list (out of scope for this
// task's "one new file" constraint); the real fix belongs in all_models.go.
func ensureMFAStepUpGrantTable(t *testing.T, h *conformanceHarness) {
	t.Helper()
	require.NoError(t, h.ls.DB().AutoMigrate(&models.MFAStepUpGrant{}))
}

const conformanceMFAPassword = "Xk9#Tq2Lm7@Wp4Rb!"

// enrollMFA creates a real user and fully enrolls + activates real TOTP MFA for
// them via h.upstreamCore (in-process, real bcrypt password, real encrypted
// secret) — the exact BeginMFAEnrollment/ActivateMFA sequence
// internal/core/mfa_test.go's TestMFA_FullFlow uses. Returns the user and the
// base32 TOTP secret (needed to generate valid codes in tests).
func enrollMFA(t *testing.T, h *conformanceHarness, ctx context.Context, username string) (*models.User, string) {
	t.Helper()
	user, err := h.upstreamCore.CreateUser(ctx, &core.CreateUserRequest{
		Username: username, Email: username + "@example.com", DisplayName: "Conformance MFA " + username,
		Password: conformanceMFAPassword,
	})
	require.NoError(t, err)
	_, secret, err := h.upstreamCore.BeginMFAEnrollment(ctx, user.ID)
	require.NoError(t, err)
	// Activate using the PREVIOUS time-step (mirrors internal/core/mfa_test.go's
	// TestMFA_FullFlow exactly): validateTOTPStep's anti-replay (MarkTOTPStepUsed)
	// burns whichever step the activation code resolves to, so activating with the
	// CURRENT step would leave a caller-generated login code for "now" looking like
	// a replay of the very code that just activated MFA, a few milliseconds later
	// in the same 30s window.
	code, err := totp.GenerateCode(secret, time.Now().Add(-30*time.Second))
	require.NoError(t, err)
	_, err = h.upstreamCore.ActivateMFA(ctx, user.ID, code, conformanceMFAPassword)
	require.NoError(t, err)
	return user, secret
}

// --- CreateWebAuthnSession ---

func TestConformance_CreateWebAuthnSession(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	newUser := func(suffix string) *models.User {
		user, err := h.ls.CreateUser(ctx, &models.User{
			Username: "conformance-cwas-" + suffix, Email: "conformance-cwas-" + suffix + "@example.com",
			DisplayName: "Conformance CreateWebAuthnSession " + suffix, IsActive: true,
		})
		require.NoError(t, err)
		return user
	}

	expiresAt := time.Now().Add(5 * time.Minute).UTC().Truncate(time.Second)

	localUser := newUser("local")
	localSession := &models.WebAuthnSession{
		UserID: localUser.ID, TokenHash: "conformance-cwas-hash-local", Purpose: "login",
		Data: []byte(`{"challenge":"local"}`), ExpiresAt: expiresAt, CreatedAt: time.Now().UTC().Truncate(time.Second),
	}
	require.NoError(t, h.ls.CreateWebAuthnSession(ctx, localSession))
	require.NotZero(t, localSession.ID, "sanity: LocalStorage.CreateWebAuthnSession must assign an ID")

	remoteUser := newUser("remote")
	remoteSession := &models.WebAuthnSession{
		UserID: remoteUser.ID, TokenHash: "conformance-cwas-hash-remote", Purpose: "login",
		Data: []byte(`{"challenge":"remote"}`), ExpiresAt: expiresAt, CreatedAt: time.Now().UTC().Truncate(time.Second),
	}
	require.NoError(t, h.rs.CreateWebAuthnSession(ctx, remoteSession), "RemoteStorage.CreateWebAuthnSession must succeed")
	require.NotZero(t, remoteSession.ID, "the server-assigned ID must be copied back onto the caller's struct, not left zero")

	// Read back through the SAME LocalStorage instance the router wraps -- proves the
	// session actually landed server-side, not just that the client-side struct was
	// echoed back unmodified. ConsumeWebAuthnSession is the only read primitive
	// available (there is no non-consuming getter), so this necessarily also
	// exercises the single-use consume -- fine, since this fixture is dedicated to it.
	now := time.Now().UTC()
	localConsumed, err := h.ls.ConsumeWebAuthnSession(ctx, "conformance-cwas-hash-local", now)
	require.NoError(t, err, "sanity: the local session must be consumable")
	remoteConsumed, err := h.ls.ConsumeWebAuthnSession(ctx, "conformance-cwas-hash-remote", now)
	require.NoError(t, err,
		"the session created via RemoteStorage must actually exist server-side with a valid, unexpired, unused "+
			"row -- not just report success")

	exclude := map[string]bool{"UsedAt": true} // stamped by the consume READ itself, not by Create
	assertFieldExhaustiveEqual(t, "LocalStorage.CreateWebAuthnSession (sanity baseline)", localSession, localConsumed, exclude)
	assertFieldExhaustiveEqual(t, "RemoteStorage.CreateWebAuthnSession (wire round trip)", remoteSession, remoteConsumed, exclude)
}

// --- ConsumeWebAuthnSession ---

func TestConformance_ConsumeWebAuthnSession(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	newUser := func(suffix string) *models.User {
		user, err := h.ls.CreateUser(ctx, &models.User{
			Username: "conformance-cws-" + suffix, Email: "conformance-cws-" + suffix + "@example.com",
			DisplayName: "Conformance ConsumeWebAuthnSession " + suffix, IsActive: true,
		})
		require.NoError(t, err)
		return user
	}
	newSession := func(userID uint, suffix string, expiresAt time.Time) string {
		tokenHash := "conformance-cws-hash-" + suffix
		require.NoError(t, h.ls.CreateWebAuthnSession(ctx, &models.WebAuthnSession{
			UserID: userID, TokenHash: tokenHash, Purpose: "login",
			Data: []byte(`{"challenge":"x"}`), ExpiresAt: expiresAt, CreatedAt: time.Now().UTC(),
		}))
		return tokenHash
	}

	now := time.Now().UTC()

	localUser := newUser("local")
	localHash := newSession(localUser.ID, "local", now.Add(5*time.Minute))
	localConsumed, err := h.ls.ConsumeWebAuthnSession(ctx, localHash, now)
	require.NoError(t, err)
	assert.Equal(t, localUser.ID, localConsumed.UserID)
	assert.NotNil(t, localConsumed.UsedAt)
	_, err = h.ls.ConsumeWebAuthnSession(ctx, localHash, now)
	assert.Error(t, err, "sanity: a consumed session must not be consumable twice")

	remoteUser := newUser("remote")
	remoteHash := newSession(remoteUser.ID, "remote", now.Add(5*time.Minute))
	remoteConsumed, err := h.rs.ConsumeWebAuthnSession(ctx, remoteHash, now)
	require.NoError(t, err, "RemoteStorage.ConsumeWebAuthnSession must succeed for a valid, unexpired, unused session")
	assert.Equal(t, remoteUser.ID, remoteConsumed.UserID)
	assert.NotNil(t, remoteConsumed.UsedAt, "the session must actually be marked used server-side")
	_, err = h.rs.ConsumeWebAuthnSession(ctx, remoteHash, now)
	assert.Error(t, err, "RemoteStorage.ConsumeWebAuthnSession must refuse a second consume of an already-used "+
		"session -- single-use must hold across the wire too")

	expiredUser := newUser("expired")
	expiredHash := newSession(expiredUser.ID, "expired", now.Add(-time.Minute))
	_, err = h.rs.ConsumeWebAuthnSession(ctx, expiredHash, now)
	assert.Error(t, err, "RemoteStorage.ConsumeWebAuthnSession must refuse an expired session, even though it was never consumed")
}

// --- ListWebAuthnCredentials ---

func TestConformance_ListWebAuthnCredentials(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	newUser := func(suffix string) *models.User {
		user, err := h.ls.CreateUser(ctx, &models.User{
			Username: "conformance-lwac-" + suffix, Email: "conformance-lwac-" + suffix + "@example.com",
			DisplayName: "Conformance ListWebAuthnCredentials " + suffix, IsActive: true,
		})
		require.NoError(t, err)
		return user
	}
	newCred := func(userID uint, suffix string) *models.WebAuthnCredential {
		cred := &models.WebAuthnCredential{
			UserID: userID, CredentialID: []byte("conformance-lwac-credid-" + suffix),
			Name: "cred-" + suffix, CredentialBlob: []byte(`{"id":"` + suffix + `"}`), CreatedAt: time.Now().UTC(),
		}
		require.NoError(t, h.ls.CreateWebAuthnCredential(ctx, cred))
		return cred
	}

	localUser := newUser("local")
	newCred(localUser.ID, "local-1")
	newCred(localUser.ID, "local-2")
	localList, err := h.ls.ListWebAuthnCredentials(ctx, localUser.ID)
	require.NoError(t, err)
	assert.Len(t, localList, 2, "sanity: both of the local user's credentials must be listed")

	remoteUser := newUser("remote")
	newCred(remoteUser.ID, "remote-1")
	newCred(remoteUser.ID, "remote-2")
	bystander := newUser("bystander")
	newCred(bystander.ID, "bystander")

	remoteList, err := h.rs.ListWebAuthnCredentials(ctx, remoteUser.ID)
	require.NoError(t, err, "RemoteStorage.ListWebAuthnCredentials must succeed")
	require.Len(t, remoteList, 2, "must return exactly the caller's own two credentials -- a bystander's credential "+
		"leaking in (or the caller's own being dropped) would both be scope-drop defects")

	for _, got := range remoteList {
		want, err := h.ls.GetWebAuthnCredentialByCredID(ctx, got.CredentialID, remoteUser.ID)
		require.NoError(t, err)
		assertFieldExhaustiveEqual(t, "RemoteStorage.ListWebAuthnCredentials (wire fidelity)", want, got, nil)
	}
}

// --- GetWebAuthnCredentialByCredID ---

func TestConformance_GetWebAuthnCredentialByCredID(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	newUser := func(suffix string) *models.User {
		user, err := h.ls.CreateUser(ctx, &models.User{
			Username: "conformance-gwaci-" + suffix, Email: "conformance-gwaci-" + suffix + "@example.com",
			DisplayName: "Conformance GetWebAuthnCredentialByCredID " + suffix, IsActive: true,
		})
		require.NoError(t, err)
		return user
	}
	newCred := func(userID uint, suffix string) *models.WebAuthnCredential {
		cred := &models.WebAuthnCredential{
			UserID: userID, CredentialID: []byte("conformance-gwaci-credid-" + suffix),
			Name: "cred-" + suffix, CredentialBlob: []byte(`{"id":"` + suffix + `"}`), CreatedAt: time.Now().UTC(),
		}
		require.NoError(t, h.ls.CreateWebAuthnCredential(ctx, cred))
		return cred
	}

	localUser := newUser("local")
	localCred := newCred(localUser.ID, "local")
	localGot, err := h.ls.GetWebAuthnCredentialByCredID(ctx, localCred.CredentialID, localUser.ID)
	require.NoError(t, err)
	assertFieldExhaustiveEqual(t, "LocalStorage.GetWebAuthnCredentialByCredID (sanity baseline)", localCred, localGot, nil)

	remoteUser := newUser("remote")
	remoteCred := newCred(remoteUser.ID, "remote")
	remoteGot, err := h.rs.GetWebAuthnCredentialByCredID(ctx, remoteCred.CredentialID, remoteUser.ID)
	require.NoError(t, err, "RemoteStorage.GetWebAuthnCredentialByCredID must find a genuinely owned credential")
	assertFieldExhaustiveEqual(t, "RemoteStorage.GetWebAuthnCredentialByCredID (wire round trip)", remoteCred, remoteGot, nil)

	// #307 ownership scoping: a DIFFERENT user's userID must not resolve this credential.
	otherUser := newUser("other")
	_, err = h.rs.GetWebAuthnCredentialByCredID(ctx, remoteCred.CredentialID, otherUser.ID)
	assert.Error(t, err, "RemoteStorage.GetWebAuthnCredentialByCredID must not let a caller fetch another user's "+
		"credential blob by supplying a different user_id")
}

// --- LockWebAuthnCredentialForUpdate ---

func TestConformance_LockWebAuthnCredentialForUpdate(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	newUser := func(suffix string) *models.User {
		user, err := h.ls.CreateUser(ctx, &models.User{
			Username: "conformance-lwcfu-" + suffix, Email: "conformance-lwcfu-" + suffix + "@example.com",
			DisplayName: "Conformance LockWebAuthnCredentialForUpdate " + suffix, IsActive: true,
		})
		require.NoError(t, err)
		return user
	}
	newCred := func(userID uint, suffix string) *models.WebAuthnCredential {
		cred := &models.WebAuthnCredential{
			UserID: userID, CredentialID: []byte("conformance-lwcfu-credid-" + suffix),
			Name: "cred-" + suffix, CredentialBlob: []byte(`{"id":"` + suffix + `"}`), CreatedAt: time.Now().UTC(),
		}
		require.NoError(t, h.ls.CreateWebAuthnCredential(ctx, cred))
		return cred
	}

	localUser := newUser("local")
	localCred := newCred(localUser.ID, "local")
	localLocked, err := h.ls.LockWebAuthnCredentialForUpdate(ctx, localCred.CredentialID, localUser.ID)
	require.NoError(t, err)
	assertFieldExhaustiveEqual(t, "LocalStorage.LockWebAuthnCredentialForUpdate (sanity baseline)", localCred, localLocked, nil)

	remoteUser := newUser("remote")
	remoteCred := newCred(remoteUser.ID, "remote")
	remoteLocked, err := h.rs.LockWebAuthnCredentialForUpdate(ctx, remoteCred.CredentialID, remoteUser.ID)
	require.NoError(t, err, "RemoteStorage.LockWebAuthnCredentialForUpdate must find a genuinely owned credential")
	assertFieldExhaustiveEqual(t, "RemoteStorage.LockWebAuthnCredentialForUpdate (wire round trip)", remoteCred, remoteLocked, nil)

	otherUser := newUser("other")
	_, err = h.rs.LockWebAuthnCredentialForUpdate(ctx, remoteCred.CredentialID, otherUser.ID)
	assert.Error(t, err, "RemoteStorage.LockWebAuthnCredentialForUpdate must preserve the same ownership scoping as "+
		"GetWebAuthnCredentialByCredID -- a different user_id must not resolve the row")
}

// --- UpdateWebAuthnCredential ---

func TestConformance_UpdateWebAuthnCredential(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	newUser := func(suffix string) *models.User {
		user, err := h.ls.CreateUser(ctx, &models.User{
			Username: "conformance-uwac-" + suffix, Email: "conformance-uwac-" + suffix + "@example.com",
			DisplayName: "Conformance UpdateWebAuthnCredential " + suffix, IsActive: true,
		})
		require.NoError(t, err)
		return user
	}
	newCred := func(userID uint, suffix string) *models.WebAuthnCredential {
		cred := &models.WebAuthnCredential{
			UserID: userID, CredentialID: []byte("conformance-uwac-credid-" + suffix),
			Name: "cred-" + suffix, CredentialBlob: []byte(`{"id":"` + suffix + `"}`), CreatedAt: time.Now().UTC(),
		}
		require.NoError(t, h.ls.CreateWebAuthnCredential(ctx, cred))
		return cred
	}

	// LocalStorage's own primitive (local_webauthn.go) is an unconditional full-row
	// Save with no restriction -- the ceiling exercised below is a server/handler-
	// level narrowing (#1714), not a storage-layer one, so the LOCAL sanity
	// baseline exercises a full mutation exactly like tranche2/3's other
	// full-row-Save conformance tests (e.g. TransitionMachineIdentityState).
	localCred := newCred(newUser("local").ID, "local")
	localCred.Name = "updated-local"
	localCred.Disabled = true
	now := time.Now().UTC().Truncate(time.Second)
	localCred.LastUsedAt = &now
	require.NoError(t, h.ls.UpdateWebAuthnCredential(ctx, localCred))
	localAfter, err := h.ls.GetWebAuthnCredentialByCredID(ctx, localCred.CredentialID, localCred.UserID)
	require.NoError(t, err)
	assertFieldExhaustiveEqual(t, "LocalStorage.UpdateWebAuthnCredential (sanity baseline)", localCred, localAfter, nil)

	// RemoteStorage.UpdateWebAuthnCredential's OWN doc comment (remote_webauthn.go)
	// still describes this as "an unconditional full-row Save, matching
	// LocalStorage's own semantics exactly" -- but #1714
	// (server/http/handlers/webauthn_proxy.go's UpdateWebAuthnCredentialProxy doc)
	// narrowed the SERVER-SIDE handler to exactly rejectIfCloned's disable-on-clone
	// write: identify the row by (credential_id, user_id) -- which scopes ownership
	// by construction -- require disabled == true, and ignore every other field.
	// The prior unconditional Save let a system.write holder reassign a
	// credential's ownership or silently re-enable a clone-disabled credential
	// (contradicting the model's own "never auto-re-enabled" invariant), neither
	// requiring any real WebAuthn ceremony. That RemoteStorage-side doc comment is
	// now stale relative to the real wire contract -- this test's fair comparison
	// is against what the route actually does, not what its client-side comment
	// claims (found while writing this conformance test; not a pre-existing
	// finding this task set out to look for).
	remoteCred := newCred(newUser("remote").ID, "remote")
	remoteCred.Name = "updated-remote"
	remoteCred.Disabled = true
	remoteCred.LastUsedAt = &now
	require.NoError(t, h.rs.UpdateWebAuthnCredential(ctx, remoteCred),
		"RemoteStorage.UpdateWebAuthnCredential must succeed for the disable-on-clone write rejectIfCloned performs")
	remoteAfter, err := h.ls.GetWebAuthnCredentialByCredID(ctx, remoteCred.CredentialID, remoteCred.UserID)
	require.NoError(t, err)
	assert.True(t, remoteAfter.Disabled, "the credential must actually be disabled server-side")
	assert.NotEqual(t, "updated-remote", remoteAfter.Name,
		"#1714: every field besides the disable flag must be IGNORED by this narrowed route, not silently "+
			"applied -- confirms the server-side ceiling is real, not merely documented as a full-row Save")
	assert.Nil(t, remoteAfter.LastUsedAt, "LastUsedAt must also be ignored by this route")

	// Re-enabling (disabled: false) must be rejected outright, never silently
	// applied nor silently ignored-but-reported-success.
	remoteCred.Disabled = false
	err = h.rs.UpdateWebAuthnCredential(ctx, remoteCred)
	assert.Error(t, err, "RemoteStorage.UpdateWebAuthnCredential must reject an attempt to re-enable a credential "+
		"-- #1714 narrowed this route to disable-on-clone only, never re-enable")
	stillDisabled, err := h.ls.GetWebAuthnCredentialByCredID(ctx, remoteCred.CredentialID, remoteCred.UserID)
	require.NoError(t, err)
	assert.True(t, stillDisabled.Disabled, "a rejected re-enable attempt must not have actually re-enabled the credential")
}

// --- CountWebAuthnCredentials ---

func TestConformance_CountWebAuthnCredentials(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	newUser := func(suffix string) *models.User {
		user, err := h.ls.CreateUser(ctx, &models.User{
			Username: "conformance-cwac-" + suffix, Email: "conformance-cwac-" + suffix + "@example.com",
			DisplayName: "Conformance CountWebAuthnCredentials " + suffix, IsActive: true,
		})
		require.NoError(t, err)
		return user
	}
	newCred := func(userID uint, suffix string) {
		require.NoError(t, h.ls.CreateWebAuthnCredential(ctx, &models.WebAuthnCredential{
			UserID: userID, CredentialID: []byte("conformance-cwac-credid-" + suffix),
			Name: "cred-" + suffix, CredentialBlob: []byte(`{}`), CreatedAt: time.Now().UTC(),
		}))
	}

	localUser := newUser("local")
	newCred(localUser.ID, "local-1")
	newCred(localUser.ID, "local-2")
	localCount, err := h.ls.CountWebAuthnCredentials(ctx, localUser.ID)
	require.NoError(t, err)
	assert.Equal(t, int64(2), localCount)

	remoteUser := newUser("remote")
	newCred(remoteUser.ID, "remote-1")
	remoteCount, err := h.rs.CountWebAuthnCredentials(ctx, remoteUser.ID)
	require.NoError(t, err, "RemoteStorage.CountWebAuthnCredentials must succeed")
	assert.Equal(t, int64(1), remoteCount, "must count exactly this user's own credentials")
}

// --- AdvanceWebAuthnCredentialCounter ---

func TestConformance_AdvanceWebAuthnCredentialCounter(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	newUser := func(suffix string) *models.User {
		user, err := h.ls.CreateUser(ctx, &models.User{
			Username: "conformance-awcc-" + suffix, Email: "conformance-awcc-" + suffix + "@example.com",
			DisplayName: "Conformance AdvanceWebAuthnCredentialCounter " + suffix, IsActive: true,
		})
		require.NoError(t, err)
		return user
	}
	newCredWithCounter := func(userID uint, suffix string, signCount uint32) *models.WebAuthnCredential {
		cred := &models.WebAuthnCredential{
			UserID: userID, CredentialID: []byte("conformance-awcc-credid-" + suffix), Name: "cred",
			CredentialBlob: []byte(fmt.Sprintf(`{"authenticator":{"signCount":%d}}`, signCount)), CreatedAt: time.Now().UTC(),
		}
		require.NoError(t, h.ls.CreateWebAuthnCredential(ctx, cred))
		return cred
	}
	lastUsed := time.Now().UTC().Truncate(time.Second)

	localUser := newUser("local")
	localCred := newCredWithCounter(localUser.ID, "local", 5)
	newBlobLocal := []byte(`{"authenticator":{"signCount":10}}`)
	advancedLocal, err := h.ls.AdvanceWebAuthnCredentialCounter(ctx, localCred.CredentialID, localUser.ID, newBlobLocal, 10, lastUsed)
	require.NoError(t, err)
	assert.True(t, advancedLocal, "sanity: a strictly greater counter must advance")
	afterLocal, err := h.ls.GetWebAuthnCredentialByCredID(ctx, localCred.CredentialID, localUser.ID)
	require.NoError(t, err)
	assert.Equal(t, newBlobLocal, []byte(afterLocal.CredentialBlob))

	remoteUser := newUser("remote")
	remoteCred := newCredWithCounter(remoteUser.ID, "remote", 5)
	newBlobRemote := []byte(`{"authenticator":{"signCount":10}}`)
	advancedRemote, err := h.rs.AdvanceWebAuthnCredentialCounter(ctx, remoteCred.CredentialID, remoteUser.ID, newBlobRemote, 10, lastUsed)
	require.NoError(t, err, "RemoteStorage.AdvanceWebAuthnCredentialCounter must succeed")
	assert.True(t, advancedRemote, "must report Advanced=true for a strictly greater counter")
	afterRemote, err := h.ls.GetWebAuthnCredentialByCredID(ctx, remoteCred.CredentialID, remoteUser.ID)
	require.NoError(t, err)
	assert.Equal(t, newBlobRemote, []byte(afterRemote.CredentialBlob), "the new blob must actually be persisted server-side")
	assert.NotNil(t, afterRemote.LastUsedAt)

	// Stale counter must be a no-op on both -- the #306/#517 CAS guarantee this
	// method exists to preserve across the wire.
	staleBlob := []byte(`{"authenticator":{"signCount":3}}`)
	staleLocal, err := h.ls.AdvanceWebAuthnCredentialCounter(ctx, localCred.CredentialID, localUser.ID, staleBlob, 3, time.Now().UTC())
	require.NoError(t, err)
	assert.False(t, staleLocal, "sanity: a stale counter must not advance")

	staleRemote, err := h.rs.AdvanceWebAuthnCredentialCounter(ctx, remoteCred.CredentialID, remoteUser.ID, staleBlob, 3, time.Now().UTC())
	require.NoError(t, err)
	assert.False(t, staleRemote, "RemoteStorage.AdvanceWebAuthnCredentialCounter must report Advanced=false for a "+
		"stale counter, not silently apply it and regress the persisted counter (defeats clone detection)")
	stillFreshRemote, err := h.ls.GetWebAuthnCredentialByCredID(ctx, remoteCred.CredentialID, remoteUser.ID)
	require.NoError(t, err)
	assert.Equal(t, newBlobRemote, []byte(stillFreshRemote.CredentialBlob),
		"a stale-counter attempt must not have overwritten the already-persisted newer blob")
}

// --- GetMFASecret ---

func TestConformance_GetMFASecret(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()
	enableMFAEncryption(t, h)

	localUser, _ := enrollMFA(t, h, ctx, "conformance-gms-local")
	localSecret, err := h.ls.GetMFASecret(ctx, localUser.ID)
	require.NoError(t, err)
	assert.True(t, localSecret.Activated)

	remoteUser, _ := enrollMFA(t, h, ctx, "conformance-gms-remote")
	remoteSecret, err := h.rs.GetMFASecret(ctx, remoteUser.ID)
	require.NoError(t, err, "RemoteStorage.GetMFASecret must find a genuinely enrolled user's secret row")

	wantRemote, err := h.ls.GetMFASecret(ctx, remoteUser.ID)
	require.NoError(t, err)
	assert.Equal(t, wantRemote.ID, remoteSecret.ID)
	assert.Equal(t, wantRemote.UserID, remoteSecret.UserID)
	assert.Equal(t, wantRemote.Activated, remoteSecret.Activated)
	assert.Equal(t, wantRemote.LastUsedStep, remoteSecret.LastUsedStep)
	assert.True(t, wantRemote.CreatedAt.Equal(remoteSecret.CreatedAt))
	// Deliberately targeted, non-printing assertions for the ciphertext fields
	// (see this file's package doc) -- bytes.Equal never prints the actual bytes
	// into a testify failure message, unlike assertFieldExhaustiveEqual's %#v dump.
	assert.True(t, bytes.Equal(wantRemote.SecretEnc, remoteSecret.SecretEnc),
		"SecretEnc ciphertext must round-trip over the wire unchanged")
	assert.True(t, bytes.Equal(wantRemote.SecretMeta, remoteSecret.SecretMeta),
		"SecretMeta must round-trip over the wire unchanged")

	bystander, err := h.ls.CreateUser(ctx, &models.User{
		Username: "conformance-gms-none", Email: "conformance-gms-none@example.com", DisplayName: "no mfa", IsActive: true,
	})
	require.NoError(t, err)
	_, err = h.ls.GetMFASecret(ctx, bystander.ID)
	assert.Error(t, err, "sanity: no MFA secret row exists yet")
	_, err = h.rs.GetMFASecret(ctx, bystander.ID)
	assert.Error(t, err, "RemoteStorage.GetMFASecret must also fail for a user with no MFA secret row, not silently succeed")
}

// --- MarkTOTPStepUsed ---

func TestConformance_MarkTOTPStepUsed(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()
	enableMFAEncryption(t, h)

	// ActivateMFA (inside enrollMFA) already calls MarkTOTPStepUsed once, for the
	// REAL current wall-clock TOTP step (unix-time/30, tens of millions today) --
	// an arbitrary small constant like 12345 would be "older" than that already-
	// persisted step and get rejected as stale, not accepted as fresh. Derive the
	// baseline from the row enrollMFA actually left behind instead of guessing.
	localUser, _ := enrollMFA(t, h, ctx, "conformance-mtsu-local")
	localSecretRow, err := h.ls.GetMFASecret(ctx, localUser.ID)
	require.NoError(t, err)
	require.NotNil(t, localSecretRow.LastUsedStep, "sanity: ActivateMFA must have already recorded a last-used step")
	localFreshStep := *localSecretRow.LastUsedStep + 100
	freshLocal, err := h.ls.MarkTOTPStepUsed(ctx, localUser.ID, localFreshStep)
	require.NoError(t, err)
	assert.True(t, freshLocal, "sanity: a strictly greater step must be accepted as fresh")
	replayLocal, err := h.ls.MarkTOTPStepUsed(ctx, localUser.ID, localFreshStep)
	require.NoError(t, err)
	assert.False(t, replayLocal, "sanity: the SAME step replayed must be rejected")

	remoteUser, _ := enrollMFA(t, h, ctx, "conformance-mtsu-remote")
	remoteSecretRow, err := h.ls.GetMFASecret(ctx, remoteUser.ID)
	require.NoError(t, err)
	require.NotNil(t, remoteSecretRow.LastUsedStep)
	remoteFreshStep := *remoteSecretRow.LastUsedStep + 100
	freshRemote, err := h.rs.MarkTOTPStepUsed(ctx, remoteUser.ID, remoteFreshStep)
	require.NoError(t, err)
	assert.True(t, freshRemote, "RemoteStorage.MarkTOTPStepUsed must report fresh=true for a strictly greater step")
	replayRemote, err := h.rs.MarkTOTPStepUsed(ctx, remoteUser.ID, remoteFreshStep)
	require.NoError(t, err)
	assert.False(t, replayRemote, "RemoteStorage.MarkTOTPStepUsed must reject a replayed step server-side, not "+
		"silently accept it twice")

	// An older step than what's now persisted must also be rejected -- confirms the
	// advance really landed server-side, not merely that a duplicate call happened
	// to also return false.
	olderRemote, err := h.rs.MarkTOTPStepUsed(ctx, remoteUser.ID, remoteFreshStep-1)
	require.NoError(t, err)
	assert.False(t, olderRemote, "an older step than the persisted last-used-step must be rejected")
}

// --- CountUnusedMFARecoveryCodes ---

func TestConformance_CountUnusedMFARecoveryCodes(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	newUser := func(suffix string) *models.User {
		user, err := h.ls.CreateUser(ctx, &models.User{
			Username: "conformance-cumrc-" + suffix, Email: "conformance-cumrc-" + suffix + "@example.com",
			DisplayName: "Conformance CountUnusedMFARecoveryCodes " + suffix, IsActive: true,
		})
		require.NoError(t, err)
		return user
	}

	localUser := newUser("local")
	require.NoError(t, h.ls.CreateMFARecoveryCodes(ctx, localUser.ID, []string{"h1", "h2", "h3"}))
	consumedLocal, err := h.ls.ConsumeMFARecoveryCode(ctx, localUser.ID, "h1", time.Now().UTC())
	require.NoError(t, err)
	require.True(t, consumedLocal)
	localCount, err := h.ls.CountUnusedMFARecoveryCodes(ctx, localUser.ID)
	require.NoError(t, err)
	assert.Equal(t, 2, localCount)

	remoteUser := newUser("remote")
	require.NoError(t, h.ls.CreateMFARecoveryCodes(ctx, remoteUser.ID, []string{"r1", "r2", "r3", "r4"}))
	consumedRemote, err := h.ls.ConsumeMFARecoveryCode(ctx, remoteUser.ID, "r1", time.Now().UTC())
	require.NoError(t, err)
	require.True(t, consumedRemote)
	remoteCount, err := h.rs.CountUnusedMFARecoveryCodes(ctx, remoteUser.ID)
	require.NoError(t, err, "RemoteStorage.CountUnusedMFARecoveryCodes must succeed")
	assert.Equal(t, 3, remoteCount, "must count only the still-unused codes server-side")
}

// --- IssueMFAChallenge ---

func TestConformance_IssueMFAChallenge(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	newUser := func(suffix string) *models.User {
		user, err := h.ls.CreateUser(ctx, &models.User{
			Username: "conformance-imc-" + suffix, Email: "conformance-imc-" + suffix + "@example.com",
			DisplayName: "Conformance IssueMFAChallenge " + suffix, IsActive: true,
		})
		require.NoError(t, err)
		return user
	}

	// "Local" baseline: h.upstreamCore.CreateMFAChallenge is what IssueMFAChallenge's
	// wire handler itself calls server-side (see remote_mfa.go's doc and
	// users_crud.go's IssueMFAChallenge) -- IssueMFAChallenge has no separate
	// LocalStorage primitive of its own to compare against (LocalStorage.CreateMFAChallenge
	// takes a full pre-built *models.MFAChallenge, not a bare userID).
	localUser := newUser("local")
	localToken, err := h.upstreamCore.CreateMFAChallenge(ctx, localUser.ID)
	require.NoError(t, err)
	require.NotEmpty(t, localToken)
	localCh, err := h.ls.GetActiveMFAChallenge(ctx, conformanceSHA256Hex(localToken), time.Now())
	require.NoError(t, err, "sanity: the locally issued challenge token must resolve back to an active challenge row")
	assert.Equal(t, localUser.ID, localCh.UserID)

	remoteUser := newUser("remote")
	remoteToken, err := h.rs.IssueMFAChallenge(ctx, remoteUser.ID)
	require.NoError(t, err, "RemoteStorage.IssueMFAChallenge must succeed")
	assert.NotEmpty(t, remoteToken)
	remoteCh, err := h.ls.GetActiveMFAChallenge(ctx, conformanceSHA256Hex(remoteToken), time.Now())
	require.NoError(t, err, "the challenge minted via RemoteStorage.IssueMFAChallenge must actually be persisted "+
		"server-side, resolvable through the SAME LocalStorage instance the router wraps -- not just an opaque "+
		"token that goes nowhere")
	assert.Equal(t, remoteUser.ID, remoteCh.UserID, "the challenge must be bound to the caller-supplied user_id")
}

// --- GetActiveMFAChallenge ---

func TestConformance_GetActiveMFAChallenge(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	newUser := func(suffix string) *models.User {
		user, err := h.ls.CreateUser(ctx, &models.User{
			Username: "conformance-gamc-" + suffix, Email: "conformance-gamc-" + suffix + "@example.com",
			DisplayName: "Conformance GetActiveMFAChallenge " + suffix, IsActive: true,
		})
		require.NoError(t, err)
		return user
	}

	localUser := newUser("local")
	localToken, err := h.upstreamCore.CreateMFAChallenge(ctx, localUser.ID)
	require.NoError(t, err)
	localCh, err := h.ls.GetActiveMFAChallenge(ctx, conformanceSHA256Hex(localToken), time.Now())
	require.NoError(t, err)
	assert.Nil(t, localCh.UsedAt, "sanity: a fresh challenge is not yet consumed")

	remoteUser := newUser("remote")
	remoteToken, err := h.upstreamCore.CreateMFAChallenge(ctx, remoteUser.ID)
	require.NoError(t, err)
	remoteCh, err := h.rs.GetActiveMFAChallenge(ctx, conformanceSHA256Hex(remoteToken), time.Now())
	require.NoError(t, err, "RemoteStorage.GetActiveMFAChallenge must find a genuinely active challenge")
	assert.Nil(t, remoteCh.UsedAt, "a not-yet-consumed challenge must not appear used")
	assert.Equal(t, remoteUser.ID, remoteCh.UserID)

	// Consuming it must make it no longer "active".
	_, err = h.ls.ConsumeMFAChallenge(ctx, conformanceSHA256Hex(remoteToken), time.Now())
	require.NoError(t, err)
	_, err = h.rs.GetActiveMFAChallenge(ctx, conformanceSHA256Hex(remoteToken), time.Now())
	assert.Error(t, err, "RemoteStorage.GetActiveMFAChallenge must refuse an already-consumed challenge, not report "+
		"it as still active")
}

// --- ConsumeMFAChallenge ---

func TestConformance_ConsumeMFAChallenge(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	newUser := func(suffix string) *models.User {
		user, err := h.ls.CreateUser(ctx, &models.User{
			Username: "conformance-cmc-" + suffix, Email: "conformance-cmc-" + suffix + "@example.com",
			DisplayName: "Conformance ConsumeMFAChallenge " + suffix, IsActive: true,
		})
		require.NoError(t, err)
		return user
	}

	localUser := newUser("local")
	localToken, err := h.upstreamCore.CreateMFAChallenge(ctx, localUser.ID)
	require.NoError(t, err)
	localConsumed, err := h.ls.ConsumeMFAChallenge(ctx, conformanceSHA256Hex(localToken), time.Now())
	require.NoError(t, err)
	assert.NotNil(t, localConsumed.UsedAt)
	_, err = h.ls.ConsumeMFAChallenge(ctx, conformanceSHA256Hex(localToken), time.Now())
	assert.Error(t, err, "sanity: a challenge is single-use")

	remoteUser := newUser("remote")
	remoteToken, err := h.upstreamCore.CreateMFAChallenge(ctx, remoteUser.ID)
	require.NoError(t, err)
	remoteConsumed, err := h.rs.ConsumeMFAChallenge(ctx, conformanceSHA256Hex(remoteToken), time.Now())
	require.NoError(t, err, "RemoteStorage.ConsumeMFAChallenge must succeed for a valid, active challenge")
	assert.NotNil(t, remoteConsumed.UsedAt, "the challenge must actually be marked used server-side")
	_, err = h.rs.ConsumeMFAChallenge(ctx, conformanceSHA256Hex(remoteToken), time.Now())
	assert.Error(t, err, "RemoteStorage.ConsumeMFAChallenge must refuse a second consume -- single-use must hold "+
		"across the wire")
}

// --- VerifyMFALoginCredentials ---

func TestConformance_VerifyMFALoginCredentials(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()
	enableMFAEncryption(t, h)

	// "Local" baseline: core.VerifyMFACredentials is the SAME function the
	// upstream's own POST /api/v1/users/verify-mfa handler calls
	// (server/http/handlers/users_crud.go's VerifyMFACredentials doc comment) --
	// VerifyMFALoginCredentials has no LocalStorage equivalent of its own to
	// proxy to (it implements core.RemoteMFAVerifier, an interface only
	// RemoteStorage needs to satisfy).
	localUser, localSecret := enrollMFA(t, h, ctx, "conformance-vmlc-local")
	localChallenge, err := h.upstreamCore.CreateMFAChallenge(ctx, localUser.ID)
	require.NoError(t, err)
	localCode, err := totp.GenerateCode(localSecret, time.Now())
	require.NoError(t, err)
	verifiedLocal, localUsedRecovery, err := h.upstreamCore.VerifyMFACredentials(ctx, localChallenge, localCode)
	require.NoError(t, err, "sanity: a correct TOTP code against a fresh challenge must verify")
	assert.False(t, localUsedRecovery)
	assert.Equal(t, localUser.ID, verifiedLocal.ID)

	// Remote: the identical shape, through RemoteStorage.VerifyMFALoginCredentials.
	remoteUser, remoteSecret := enrollMFA(t, h, ctx, "conformance-vmlc-remote")
	remoteChallenge, err := h.upstreamCore.CreateMFAChallenge(ctx, remoteUser.ID)
	require.NoError(t, err)
	remoteCode, err := totp.GenerateCode(remoteSecret, time.Now())
	require.NoError(t, err)
	remoteVerified, remoteUsedRecovery, err := h.rs.VerifyMFALoginCredentials(ctx, remoteChallenge, remoteCode)
	require.NoError(t, err, "RemoteStorage.VerifyMFALoginCredentials must succeed for a correct TOTP code against a fresh challenge")
	assert.False(t, remoteUsedRecovery)

	// Field fidelity: verifyMFAWireResponse deliberately narrows the returned User to
	// ID/Username/PasswordChangedAt/CreatedAt (remote_mfa.go's doc) specifically
	// because enforcePasswordExpiryGate (ADR-025) reads PasswordChangedAt -- a
	// dropped field here would silently defeat that gate under storage.type: remote.
	wantUser, err := h.ls.GetUser(ctx, remoteUser.ID)
	require.NoError(t, err)
	assert.Equal(t, wantUser.ID, remoteVerified.ID)
	assert.Equal(t, wantUser.Username, remoteVerified.Username)
	require.NotNil(t, remoteVerified.PasswordChangedAt,
		"PasswordChangedAt must not be dropped on the wire -- ADR-025's password-expiry gate silently no-ops without it")
	assert.True(t, wantUser.PasswordChangedAt.Equal(*remoteVerified.PasswordChangedAt))
	assert.True(t, wantUser.CreatedAt.Equal(remoteVerified.CreatedAt), "CreatedAt must not be dropped either")

	// Negative: a wrong code must fail, AND the challenge must be burned by that
	// FIRST attempt regardless of correctness (core.VerifyMFACredentials consumes
	// the challenge before ever checking the code) -- a subsequent, CORRECT code
	// against the same challenge must also fail.
	wrongUser, wrongSecret := enrollMFA(t, h, ctx, "conformance-vmlc-wrongcode")
	wrongChallenge, err := h.upstreamCore.CreateMFAChallenge(ctx, wrongUser.ID)
	require.NoError(t, err)
	_, _, err = h.rs.VerifyMFALoginCredentials(ctx, wrongChallenge, "000000")
	assert.Error(t, err, "RemoteStorage.VerifyMFALoginCredentials must reject an incorrect TOTP code")
	rightCode, err := totp.GenerateCode(wrongSecret, time.Now())
	require.NoError(t, err)
	_, _, err = h.rs.VerifyMFALoginCredentials(ctx, wrongChallenge, rightCode)
	assert.Error(t, err, "a challenge must be single-use regardless of whether the first attempt's code was "+
		"correct -- a wrong-code attempt still burns it")

	// Unknown/garbage challenge must be rejected too.
	_, _, err = h.rs.VerifyMFALoginCredentials(ctx, "not-a-real-challenge-token", "123456")
	assert.Error(t, err, "an unknown challenge token must be rejected")
}

// --- GetActiveMFAStepUpGrant ---

func TestConformance_GetActiveMFAStepUpGrant(t *testing.T) {
	h := newConformanceHarness(t)
	ensureMFAStepUpGrantTable(t, h)
	ctx := context.Background()

	newUser := func(suffix string) *models.User {
		user, err := h.ls.CreateUser(ctx, &models.User{
			Username: "conformance-gamsug-" + suffix, Email: "conformance-gamsug-" + suffix + "@example.com",
			DisplayName: "Conformance GetActiveMFAStepUpGrant " + suffix, IsActive: true,
		})
		require.NoError(t, err)
		return user
	}

	localUser := newUser("local")
	localSeed := &models.MFAStepUpGrant{
		UserID: localUser.ID, Purpose: models.MFAStepUpPurposeReauth,
		ExpiresAt: time.Now().Add(15 * time.Minute).UTC().Truncate(time.Second), CreatedAt: time.Now().UTC().Truncate(time.Second),
	}
	require.NoError(t, h.ls.CreateMFAStepUpGrant(ctx, localSeed))
	localGrant, err := h.ls.GetActiveMFAStepUpGrant(ctx, localUser.ID, models.MFAStepUpPurposeReauth, time.Now())
	require.NoError(t, err)
	require.NotNil(t, localGrant)
	assertFieldExhaustiveEqual(t, "LocalStorage.GetActiveMFAStepUpGrant (sanity baseline)", localSeed, localGrant, nil)

	remoteUser := newUser("remote")
	remoteSeed := &models.MFAStepUpGrant{
		UserID: remoteUser.ID, Purpose: models.MFAStepUpPurposeReauth,
		ExpiresAt: time.Now().Add(15 * time.Minute).UTC().Truncate(time.Second), CreatedAt: time.Now().UTC().Truncate(time.Second),
	}
	require.NoError(t, h.ls.CreateMFAStepUpGrant(ctx, remoteSeed))
	remoteGrant, err := h.rs.GetActiveMFAStepUpGrant(ctx, remoteUser.ID, models.MFAStepUpPurposeReauth, time.Now())
	require.NoError(t, err, "RemoteStorage.GetActiveMFAStepUpGrant must find a genuinely active grant")
	require.NotNil(t, remoteGrant)
	// mfaStepUpGrantWire never carries ConsumedAt (remote_mfa_stepup_grant.go) -- both
	// sides are nil here anyway (the grant was never consumed), so no exclusion needed.
	assertFieldExhaustiveEqual(t, "RemoteStorage.GetActiveMFAStepUpGrant (wire round trip)", remoteSeed, remoteGrant, nil)

	noGrantUser := newUser("nogrant")
	gotNil, err := h.rs.GetActiveMFAStepUpGrant(ctx, noGrantUser.ID, models.MFAStepUpPurposeReauth, time.Now())
	require.NoError(t, err, "RemoteStorage.GetActiveMFAStepUpGrant must return (nil, nil) for no active grant, not an error")
	assert.Nil(t, gotNil)

	expiredUser := newUser("expired")
	require.NoError(t, h.ls.CreateMFAStepUpGrant(ctx, &models.MFAStepUpGrant{
		UserID: expiredUser.ID, Purpose: models.MFAStepUpPurposeReauth,
		ExpiresAt: time.Now().Add(-time.Minute).UTC(), CreatedAt: time.Now().UTC(),
	}))
	gotExpired, err := h.rs.GetActiveMFAStepUpGrant(ctx, expiredUser.ID, models.MFAStepUpPurposeReauth, time.Now())
	require.NoError(t, err)
	assert.Nil(t, gotExpired, "an expired grant must not be reported as active")
}

// --- PruneMFAStepUpGrants ---

func TestConformance_PruneMFAStepUpGrants(t *testing.T) {
	h := newConformanceHarness(t)
	ensureMFAStepUpGrantTable(t, h)
	ctx := context.Background()

	newUser := func(suffix string) *models.User {
		user, err := h.ls.CreateUser(ctx, &models.User{
			Username: "conformance-pmsug-" + suffix, Email: "conformance-pmsug-" + suffix + "@example.com",
			DisplayName: "Conformance PruneMFAStepUpGrants " + suffix, IsActive: true,
		})
		require.NoError(t, err)
		return user
	}

	// PruneMFAStepUpGrantsProxy (CORE-RATE-003, mirroring PruneLoginAttemptsProxy)
	// deliberately does NOT trust the wire `before` verbatim: it routes through
	// core.KeyorixCore.PruneMFAStepUpGrants, which clamps the effective cutoff to
	// max(30 days ago, before) -- a caller can only NARROW the deletion window,
	// never widen it past the 30-day floor. A `before` of "1 hour ago" (fine for
	// LocalStorage's own unclamped primitive) would silently clamp to "30 days
	// ago" over the wire, and a grant merely 1 hour past its expiry would survive
	// the remote call even though it wouldn't survive the local one -- so `past`
	// here must be older than that 30-day floor for the remote and local
	// comparisons to agree on what gets purged.
	past := time.Now().Add(-31 * 24 * time.Hour).UTC()
	future := time.Now().Add(time.Hour).UTC()
	cutoff := time.Now().UTC()

	localExpired := newUser("local-expired")
	require.NoError(t, h.ls.CreateMFAStepUpGrant(ctx, &models.MFAStepUpGrant{
		UserID: localExpired.ID, Purpose: models.MFAStepUpPurposeReauth, ExpiresAt: past, CreatedAt: time.Now().UTC(),
	}))
	localFuture := newUser("local-future")
	require.NoError(t, h.ls.CreateMFAStepUpGrant(ctx, &models.MFAStepUpGrant{
		UserID: localFuture.ID, Purpose: models.MFAStepUpPurposeReauth, ExpiresAt: future, CreatedAt: time.Now().UTC(),
	}))
	localRemoved, err := h.ls.PruneMFAStepUpGrants(ctx, cutoff)
	require.NoError(t, err)
	assert.Equal(t, int64(1), localRemoved, "sanity: exactly the expired grant must be purged")

	remoteExpired := newUser("remote-expired")
	require.NoError(t, h.ls.CreateMFAStepUpGrant(ctx, &models.MFAStepUpGrant{
		UserID: remoteExpired.ID, Purpose: models.MFAStepUpPurposeReauth, ExpiresAt: past, CreatedAt: time.Now().UTC(),
	}))
	remoteFuture := newUser("remote-future")
	require.NoError(t, h.ls.CreateMFAStepUpGrant(ctx, &models.MFAStepUpGrant{
		UserID: remoteFuture.ID, Purpose: models.MFAStepUpPurposeReauth, ExpiresAt: future, CreatedAt: time.Now().UTC(),
	}))
	remoteRemoved, err := h.rs.PruneMFAStepUpGrants(ctx, cutoff)
	require.NoError(t, err, "RemoteStorage.PruneMFAStepUpGrants must succeed")
	assert.Equal(t, int64(1), remoteRemoved, "RemoteStorage.PruneMFAStepUpGrants must report exactly the one "+
		"expired grant it purged this call, not the earlier local one too and not zero (silent no-op)")

	stillActive, err := h.ls.GetActiveMFAStepUpGrant(ctx, remoteFuture.ID, models.MFAStepUpPurposeReauth, time.Now())
	require.NoError(t, err)
	assert.NotNil(t, stillActive, "PruneMFAStepUpGrants must not touch a grant that has not yet expired")
}

// --- CreateSSOLoginState ---

func TestConformance_CreateSSOLoginState(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	localState := &models.SSOLoginState{
		State: "conformance-csls-state-local", Nonce: "nonce-local", Provider: "oidc", ReturnTo: "/dashboard",
		ExpiresAt: time.Now().Add(10 * time.Minute).UTC().Truncate(time.Second), CreatedAt: time.Now().UTC().Truncate(time.Second),
	}
	require.NoError(t, h.ls.CreateSSOLoginState(ctx, localState))
	require.NotZero(t, localState.ID)

	remoteState := &models.SSOLoginState{
		State: "conformance-csls-state-remote", Nonce: "nonce-remote", Provider: "saml", ReturnTo: "/settings",
		ExpiresAt: time.Now().Add(10 * time.Minute).UTC().Truncate(time.Second), CreatedAt: time.Now().UTC().Truncate(time.Second),
	}
	require.NoError(t, h.rs.CreateSSOLoginState(ctx, remoteState), "RemoteStorage.CreateSSOLoginState must succeed")
	require.NotZero(t, remoteState.ID, "the server-assigned ID must be copied back onto the caller's struct")

	// ConsumeSSOLoginState is the only read primitive (no non-consuming getter),
	// so reading back necessarily also exercises the single-use consume --
	// acceptable, this fixture is dedicated to this one read.
	localConsumed, err := h.ls.ConsumeSSOLoginState(ctx, "conformance-csls-state-local")
	require.NoError(t, err)
	remoteConsumed, err := h.ls.ConsumeSSOLoginState(ctx, "conformance-csls-state-remote")
	require.NoError(t, err, "the state created via RemoteStorage must actually exist server-side")

	assertFieldExhaustiveEqual(t, "LocalStorage.CreateSSOLoginState (sanity baseline)", localState, localConsumed, nil)
	assertFieldExhaustiveEqual(t, "RemoteStorage.CreateSSOLoginState (wire round trip)", remoteState, remoteConsumed, nil)
}

// --- ConsumeSSOLoginState ---

func TestConformance_ConsumeSSOLoginState(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	newState := func(suffix string) string {
		state := "conformance-cssls-" + suffix
		require.NoError(t, h.ls.CreateSSOLoginState(ctx, &models.SSOLoginState{
			State: state, Nonce: "nonce-" + suffix, Provider: "oidc",
			ExpiresAt: time.Now().Add(10 * time.Minute).UTC(), CreatedAt: time.Now().UTC(),
		}))
		return state
	}

	localState := newState("local")
	localConsumed, err := h.ls.ConsumeSSOLoginState(ctx, localState)
	require.NoError(t, err)
	assert.Equal(t, localState, localConsumed.State)
	_, err = h.ls.ConsumeSSOLoginState(ctx, localState)
	assert.Error(t, err, "sanity: a state is single-use")

	remoteState := newState("remote")
	remoteConsumed, err := h.rs.ConsumeSSOLoginState(ctx, remoteState)
	require.NoError(t, err, "RemoteStorage.ConsumeSSOLoginState must succeed for a genuinely pending state")
	assert.Equal(t, remoteState, remoteConsumed.State)
	_, err = h.rs.ConsumeSSOLoginState(ctx, remoteState)
	assert.Error(t, err, "RemoteStorage.ConsumeSSOLoginState must refuse a REPLAYED state/RelayState -- single-use "+
		"must hold across the wire, closing exactly the TOCTOU the atomic read-then-conditional-delete exists to prevent")

	_, err = h.rs.ConsumeSSOLoginState(ctx, "conformance-cssls-never-existed")
	assert.Error(t, err, "an unknown state must be rejected")
}

// --- VerifyLoginCredentials ---

func TestConformance_VerifyLoginCredentials(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	// See conformanceMFAPassword's doc for why this must not overlap with any
	// word this file's usernames/display names use.
	const password = "Zp4Rn8Ky3@Tw6Hf!"

	newUser := func(suffix string) *models.User {
		user, err := h.upstreamCore.CreateUser(ctx, &core.CreateUserRequest{
			Username: "conformance-vlc-" + suffix, Email: "conformance-vlc-" + suffix + "@example.com",
			DisplayName: "Conformance VerifyLoginCredentials " + suffix, Password: password,
		})
		require.NoError(t, err)
		return user
	}

	// "Local" baseline: core.Login exercised in-process -- the same function the
	// upstream's own VerifyCredentials handler calls server-side for the remote
	// path below (server/http/handlers/users_crud.go's doc comment). RemoteStorage
	// has no local equivalent (VerifyLoginCredentials implements
	// core.RemoteLoginVerifier, an interface only RemoteStorage needs).
	localUser := newUser("local")
	localSession, loggedInLocal, err := h.upstreamCore.Login(ctx, &core.LoginRequest{
		Username: localUser.Username, Password: password, UserAgent: "conformance-ua", IPAddress: "10.0.0.1",
	})
	require.NoError(t, err, "sanity: a correct password must log in")
	require.NotNil(t, localSession)
	assert.Equal(t, localUser.ID, loggedInLocal.ID)

	remoteUser := newUser("remote")
	remoteModelUser, remoteSession, err := h.rs.VerifyLoginCredentials(ctx, remoteUser.Username, password, "conformance-ua", "10.0.0.2")
	require.NoError(t, err, "RemoteStorage.VerifyLoginCredentials must succeed for the correct password")
	require.NotNil(t, remoteSession, "a session must be minted atomically with verification (#508) when no second factor is required")
	assert.Equal(t, remoteUser.ID, remoteModelUser.ID)
	assert.Equal(t, remoteUser.Username, remoteModelUser.Username)
	assert.Equal(t, remoteUser.Email, remoteModelUser.Email)
	assert.Equal(t, remoteUser.DisplayName, remoteModelUser.DisplayName)
	assert.True(t, remoteModelUser.IsActive)
	assert.False(t, remoteModelUser.MFAEnabled)
	assert.False(t, remoteModelUser.WebAuthnEnabled)

	// The session minted server-side must actually be usable -- read it back through
	// the SAME LocalStorage instance the router wraps, not just trust the wire response.
	persistedSession, err := h.ls.GetSession(ctx, remoteSession.SessionToken)
	require.NoError(t, err, "the session minted via RemoteStorage.VerifyLoginCredentials must actually exist server-side")
	assert.Equal(t, remoteUser.ID, persistedSession.UserID)

	// Wrong password must fail identically on both paths, without minting a session.
	_, _, err = h.upstreamCore.Login(ctx, &core.LoginRequest{Username: localUser.Username, Password: "wrong-password", UserAgent: "ua", IPAddress: "10.0.0.1"})
	assert.Error(t, err, "sanity: a wrong password must be rejected")
	_, wrongSession, err := h.rs.VerifyLoginCredentials(ctx, remoteUser.Username, "wrong-password", "conformance-ua", "10.0.0.2")
	assert.Error(t, err, "RemoteStorage.VerifyLoginCredentials must reject an incorrect password")
	assert.Nil(t, wrongSession)

	// Unknown username must fail the same generic way (no user-enumeration oracle).
	_, _, err = h.rs.VerifyLoginCredentials(ctx, "conformance-vlc-does-not-exist", password, "ua", "1.2.3.4")
	assert.Error(t, err)
}

// --- RecordLoginAttempt ---

func TestConformance_RecordLoginAttempt(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	before := time.Now().UTC().Add(-time.Minute)

	localIP := "203.0.113.10"
	require.NoError(t, h.ls.RecordLoginAttempt(ctx, localIP, time.Now().UTC()))
	localCount, err := h.ls.CountRecentLoginAttempts(ctx, localIP, before)
	require.NoError(t, err)
	assert.Equal(t, int64(1), localCount, "sanity: the local attempt must be counted")

	// The exact defect class CLAUDE.md documents this codebase having hit before: a
	// RemoteStorage login-attempt no-op that reported success but never actually
	// recorded the row server-side. A success return value alone would not
	// distinguish "it happened" from "it silently didn't" -- observe the effect via
	// BOTH RemoteStorage's own count AND LocalStorage's count against the SAME
	// backing store, independently of each other.
	remoteIP := "203.0.113.20"
	require.NoError(t, h.rs.RecordLoginAttempt(ctx, remoteIP, time.Now().UTC()), "RemoteStorage.RecordLoginAttempt must succeed")

	remoteCountViaRemote, err := h.rs.CountRecentLoginAttempts(ctx, remoteIP, before)
	require.NoError(t, err)
	assert.Equal(t, int64(1), remoteCountViaRemote,
		"RemoteStorage.CountRecentLoginAttempts must see the attempt RecordLoginAttempt just recorded")

	remoteCountViaLocal, err := h.ls.CountRecentLoginAttempts(ctx, remoteIP, before)
	require.NoError(t, err)
	assert.Equal(t, int64(1), remoteCountViaLocal,
		"the attempt recorded via RemoteStorage.RecordLoginAttempt must exist as a REAL row in the SAME "+
			"LocalStorage-backed table the router wraps -- read back through LocalStorage directly, independent of "+
			"RemoteStorage's own count call, to rule out a client-side-only echo masquerading as a real write "+
			"(the historical no-op defect this method's own doc comment names)")

	bystanderCount, err := h.ls.CountRecentLoginAttempts(ctx, "203.0.113.30", before)
	require.NoError(t, err)
	assert.Zero(t, bystanderCount, "a bystander IP's count must be unaffected")
}

// --- CountRecentLoginAttempts ---

func TestConformance_CountRecentLoginAttempts(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	now := time.Now().UTC()
	since := now.Add(-time.Hour)

	localIP := "198.51.100.10"
	require.NoError(t, h.ls.RecordLoginAttempt(ctx, localIP, now.Add(-30*time.Minute)))
	require.NoError(t, h.ls.RecordLoginAttempt(ctx, localIP, now.Add(-2*time.Hour))) // outside the window
	localCount, err := h.ls.CountRecentLoginAttempts(ctx, localIP, since)
	require.NoError(t, err)
	assert.Equal(t, int64(1), localCount, "sanity: only the in-window attempt counts")

	remoteIP := "198.51.100.20"
	require.NoError(t, h.ls.RecordLoginAttempt(ctx, remoteIP, now.Add(-30*time.Minute)))
	require.NoError(t, h.ls.RecordLoginAttempt(ctx, remoteIP, now.Add(-2*time.Hour)))
	remoteCount, err := h.rs.CountRecentLoginAttempts(ctx, remoteIP, since)
	require.NoError(t, err, "RemoteStorage.CountRecentLoginAttempts must succeed")
	assert.Equal(t, int64(1), remoteCount, "must count only attempts strictly after `since`, matching "+
		"LocalStorage's own windowing exactly -- a dropped/widened since-bound on the wire would over- or under-count")

	otherIPCount, err := h.rs.CountRecentLoginAttempts(ctx, "198.51.100.30", since)
	require.NoError(t, err)
	assert.Zero(t, otherIPCount, "a different IP must not be conflated into this count")
}

// --- PruneLoginAttempts ---

func TestConformance_PruneLoginAttempts(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	now := time.Now().UTC()
	past := now.Add(-24 * time.Hour)
	recent := now.Add(-time.Minute)
	cutoff := now.Add(-time.Hour)

	localIP := "192.0.2.10"
	require.NoError(t, h.ls.RecordLoginAttempt(ctx, localIP, past))
	require.NoError(t, h.ls.RecordLoginAttempt(ctx, localIP, recent))
	localRemoved, err := h.ls.PruneLoginAttempts(ctx, cutoff)
	require.NoError(t, err)
	assert.Equal(t, int64(1), localRemoved, "sanity: only the stale attempt must be purged")
	localAfter, err := h.ls.CountRecentLoginAttempts(ctx, localIP, now.Add(-25*time.Hour))
	require.NoError(t, err)
	assert.Equal(t, int64(1), localAfter, "the recent attempt must survive")

	remoteIP := "192.0.2.20"
	require.NoError(t, h.ls.RecordLoginAttempt(ctx, remoteIP, past))
	require.NoError(t, h.ls.RecordLoginAttempt(ctx, remoteIP, recent))
	remoteRemoved, err := h.rs.PruneLoginAttempts(ctx, cutoff)
	require.NoError(t, err, "RemoteStorage.PruneLoginAttempts must succeed")
	assert.Equal(t, int64(1), remoteRemoved, "RemoteStorage.PruneLoginAttempts must report exactly the one stale "+
		"attempt it purged this call -- not the earlier local IP's row too (cross-IP leakage) and not zero (silent no-op)")
	remoteAfter, err := h.ls.CountRecentLoginAttempts(ctx, remoteIP, now.Add(-25*time.Hour))
	require.NoError(t, err)
	assert.Equal(t, int64(1), remoteAfter, "the recent attempt must survive the prune, verified by reading back "+
		"through LocalStorage directly, not just trusting the reported delete count")
}
