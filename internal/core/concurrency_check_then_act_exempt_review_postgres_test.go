// concurrency_check_then_act_exempt_review_postgres_test.go — C-GUARD2-EXEMPT-REVIEW
// (#2564): the independent second review of docs/check-then-act-lock-exempt.tsv.
// Every test here pins ONE concrete two-replica interleaving that a TSV row's
// "safe" classification did not hold up against, on real Postgres, with each
// replica on its own *gorm.DB connection pool (own LocalStorage, own
// KeyorixCore), exactly like the #1646/#2581 SoD race tests.
//
// How the interleaving is forced (and what that does and does NOT prove):
// rather than looping raceReplicas until a millisecond window happens to line
// up, each test registers a one-shot GORM callback on replica A's OWN
// *gorm.DB (callbacks are per-*gorm.DB, so replica B's connection is never
// hooked) that runs replica B's real, complete core operation — on B's own
// connection, committing on its own — immediately before A's specific write
// statement executes. That is a legal interleaving under Postgres READ
// COMMITTED with no shared lock between the two calls: nothing here reaches
// into either replica's code path, it only chooses WHEN B runs. It proves
// the end state is reachable; it says nothing about how often an unforced
// race hits the window. The precedent for this technique is
// internal/storage/store/concurrency_purge_restore_race_test.go.
//
// Each test is t.Skip'd with its tracking issue: they demonstrate an OPEN
// gap and fail by design until the locking fix lands (locking fixes need
// coordinator review, so this file is test-only). Remove the Skip in the
// fixing PR; the test then goes green.
package core

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core/ports"
	"github.com/keyorixhq/keyorix/internal/dynamic"
	"github.com/keyorixhq/keyorix/internal/dynamic/dynamictest"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/i18n"
	kxstorage "github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	localstore "github.com/keyorixhq/keyorix/internal/storage/store"
)

// ctaReview is one test's two-replica Postgres fixture: a bootstrapped admin
// (global admin, ID adminID), one project with one environment, and two
// independent replicas A and B on their own connections into the same schema.
type ctaReview struct {
	t         *testing.T
	ctx       context.Context
	setupDB   *gorm.DB
	setup     *KeyorixCore
	dbA       *gorm.DB
	coreA     *KeyorixCore
	coreB     *KeyorixCore
	enc       ports.EncryptionProvider
	adminID   uint
	projectID uint
	envID     uint
}

func newCTAReview(t *testing.T) *ctaReview {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	dsn := pgIsolatedSchemaDSN(t, pgTestDSN(t))
	ctx := context.Background()

	setupDB := pgOpen(t, dsn)
	require.NoError(t, setupDB.AutoMigrate(kxstorage.AllModels()...))

	// One shared key set for every replica: replicas of one install share key
	// material, and the MFA/dynamic-secret tests need B to encrypt what A decrypts.
	enc := encryption.NewService(&config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}, t.TempDir())
	require.NoError(t, enc.Initialize("cta-review-passphrase"))

	newCore := func(db *gorm.DB) *KeyorixCore {
		c := NewKeyorixCore(localstore.NewLocalStorage(db))
		c.SetAuthEncryptor(enc)
		return c
	}
	setup := newCore(setupDB)
	setup.SetBootstrapToken("cta-review-token")
	boot, err := setup.BootstrapSystem(ctx, &BootstrapRequest{
		Username: "admin", Email: "admin@example.com", Password: "BootstrapPass123!",
		DisplayName: "Admin", Token: "cta-review-token",
	})
	require.NoError(t, err)

	proj, err := setup.CreateProject(ctx, "cta-review-project", "")
	require.NoError(t, err)
	env, err := setup.CreateEnvironment(ctx, proj.ID, "cta-review-env")
	require.NoError(t, err)

	dbA := pgOpen(t, dsn)
	return &ctaReview{
		t: t, ctx: ctx, setupDB: setupDB, setup: setup,
		dbA: dbA, coreA: newCore(dbA), coreB: newCore(pgOpen(t, dsn)),
		enc: enc, adminID: boot.User.ID, projectID: proj.ID, envID: env.ID,
	}
}

// user creates an active user with a real password hash and, when
// projectRole != "", a direct grant of that role at the fixture project.
func (f *ctaReview) user(name, projectRole string) *models.User {
	f.t.Helper()
	u, err := f.setup.CreateUser(f.ctx, &CreateUserRequest{
		Username: name, Email: name + "@example.com", DisplayName: name, Password: "UserPass123!xyz-long-enough",
	})
	require.NoError(f.t, err)
	if projectRole != "" {
		role, err := f.setup.Storage().GetRoleByName(f.ctx, projectRole)
		require.NoError(f.t, err)
		require.NoError(f.t, f.setup.Storage().AssignRole(f.ctx, u.ID, role.ID, Scope{ProjectID: f.projectID}))
	}
	return u
}

// secret seeds a live secret owned by ownerID in the fixture project/env.
func (f *ctaReview) secret(name string, ownerID uint) *models.SecretNode {
	f.t.Helper()
	s := &models.SecretNode{Name: name, ProjectID: f.projectID, EnvironmentID: f.envID, IsSecret: true, OwnerID: ownerID}
	require.NoError(f.t, f.setupDB.Create(s).Error)
	return s
}

// beforeA registers a one-shot hook on replica A's own *gorm.DB: immediately
// before A's first `kind` statement ("create" or "update") against `table`
// executes, run `concurrent` (replica B's operation, on B's own connection) to
// completion. Returns a func reporting whether the hook fired, so a test can
// fail loudly if A never reached the write it meant to interleave against
// (a hook that silently never fires would make the test vacuous).
func (f *ctaReview) beforeA(kind, table string, concurrent func()) (fired func() bool) {
	f.t.Helper()
	var once sync.Once
	hit := false
	fn := func(tx *gorm.DB) {
		if tx.Statement.Table != table {
			return
		}
		once.Do(func() {
			hit = true
			concurrent()
		})
	}
	name := "cta-review:before-" + kind + "-" + table
	switch kind {
	case "create":
		require.NoError(f.t, f.dbA.Callback().Create().Before("gorm:create").Register(name, fn))
	case "update":
		require.NoError(f.t, f.dbA.Callback().Update().Before("gorm:update").Register(name, fn))
	default:
		f.t.Fatalf("beforeA: unknown kind %q", kind)
	}
	return func() bool { return hit }
}

func (f *ctaReview) countLive(model interface{}, where string, args ...interface{}) int64 {
	f.t.Helper()
	var n int64
	require.NoError(f.t, f.setupDB.Unscoped().Model(model).Where(where, args...).Count(&n).Error)
	return n
}

// TestCTAReview_ShareSecret_vs_DeleteSecret_CrossReplicaPostgres: a share
// created while the secret is concurrently deleted must not survive as a live
// grant on the deleted secret (#370: "delete means gone for sharing too" —
// a surviving share silently reactivates on RestoreSecret).
func TestCTAReview_ShareSecret_vs_DeleteSecret_CrossReplicaPostgres(t *testing.T) {
	t.Skip("open gap #2646: ShareSecret vs DeleteSecret leaves a live share on a deleted secret; un-skip in the fixing PR")
	t.Parallel()
	f := newCTAReview(t)
	owner := f.user("cta-owner", "project_admin")
	recipient := f.user("cta-recipient", "project_viewer")
	s := f.secret("cta-share-secret", owner.ID)

	var errB error
	fired := f.beforeA("create", "share_records", func() { errB = f.coreB.DeleteSecret(f.ctx, s.ID) })
	_, errA := f.coreA.ShareSecret(f.ctx, &ShareSecretRequest{
		SecretID: s.ID, RecipientID: recipient.ID, Permission: "read", SharedBy: owner.ID,
	})
	t.Logf("ShareSecret (A) err=%v, DeleteSecret (B) err=%v", errA, errB)
	require.True(t, fired(), "the hook must have interleaved B's DeleteSecret before A's share INSERT")
	require.NoError(t, errB)

	assert.EqualValues(t, 1, f.countLive(&models.SecretNode{}, "id = ? AND deleted_at IS NOT NULL", s.ID), "secret must be deleted")
	assert.Zero(t, f.countLive(&models.ShareRecord{}, "secret_id = ? AND deleted_at IS NULL", s.ID),
		"#370 violated: a live share exists on a soft-deleted secret (it reactivates on RestoreSecret)")
}

// TestCTAReview_ShareSecretWithGroup_vs_DeleteSecret_CrossReplicaPostgres: the
// group-recipient sibling of the test above, through the same CreateShareRecord.
func TestCTAReview_ShareSecretWithGroup_vs_DeleteSecret_CrossReplicaPostgres(t *testing.T) {
	t.Skip("open gap #2647: ShareSecretWithGroup vs DeleteSecret leaves a live group share on a deleted secret; un-skip in the fixing PR")
	t.Parallel()
	f := newCTAReview(t)
	owner := f.user("cta-gowner", "project_admin")
	s := f.secret("cta-gshare-secret", owner.ID)
	g := &models.Group{Name: "cta-group", NameFolded: "cta-group"}
	require.NoError(t, f.setupDB.Create(g).Error)
	viewer, err := f.setup.Storage().GetRoleByName(f.ctx, "project_viewer")
	require.NoError(t, err)
	require.NoError(t, f.setup.Storage().AssignRoleToGroup(f.ctx, g.ID, viewer.ID, Scope{ProjectID: f.projectID}))

	var errB error
	fired := f.beforeA("create", "share_records", func() { errB = f.coreB.DeleteSecret(f.ctx, s.ID) })
	_, errA := f.coreA.ShareSecretWithGroup(f.ctx, &GroupShareSecretRequest{
		SecretID: s.ID, GroupID: g.ID, Permission: "read", SharedBy: owner.ID,
	})
	t.Logf("ShareSecretWithGroup (A) err=%v, DeleteSecret (B) err=%v", errA, errB)
	require.True(t, fired(), "the hook must have interleaved B's DeleteSecret before A's share INSERT")
	require.NoError(t, errB)

	assert.Zero(t, f.countLive(&models.ShareRecord{}, "secret_id = ? AND deleted_at IS NULL", s.ID),
		"#370 violated: a live group share exists on a soft-deleted secret")
}

// TestCTAReview_UpdateSharePermission_vs_RevokeShare_CrossReplicaPostgres: a
// share revoked while a permission update is in flight must stay revoked.
// UpdateShareRecord's Save(struct) matches 0 rows on the soft-deleted share
// and GORM falls back to INSERT ... ON CONFLICT (id) DO UPDATE SET <all
// columns>, deleted_at included — resurrecting the revoked grant.
//
// Bug origin (#2648):
//
//	Introduced-by: LocalStorage.UpdateShareRecord's GORM Save(existing)
//	Detected-by:   C-GUARD2-EXEMPT-REVIEW #2662
//	Class:         cross-replica check-then-act
//	Severity:      high (a revoked share is live again)
//	Guard:         this test (pg-gated) + TestUpdateSharePermission_IsColumnScoped
//	Fix:           UpdateShareRecord is a column-scoped UPDATE scoped to
//	               deleted_at IS NULL; matching no row fails closed
func TestCTAReview_UpdateSharePermission_vs_RevokeShare_CrossReplicaPostgres(t *testing.T) {
	t.Parallel()
	f := newCTAReview(t)
	owner := f.user("cta-uowner", "project_admin")
	recipient := f.user("cta-urecipient", "project_viewer")
	s := f.secret("cta-ushare-secret", owner.ID)
	share, err := f.setup.ShareSecret(f.ctx, &ShareSecretRequest{
		SecretID: s.ID, RecipientID: recipient.ID, Permission: "read", SharedBy: owner.ID,
	})
	require.NoError(t, err)

	var errB error
	fired := f.beforeA("update", "share_records", func() { errB = f.coreB.RevokeShare(f.ctx, share.ID, owner.ID) })
	_, errA := f.coreA.UpdateSharePermission(f.ctx, &UpdateShareRequest{
		ShareID: share.ID, Permission: "write", UpdatedBy: owner.ID,
	})
	t.Logf("UpdateSharePermission (A) err=%v, RevokeShare (B) err=%v", errA, errB)
	require.True(t, fired(), "the hook must have interleaved B's RevokeShare before A's share UPDATE")
	require.NoError(t, errB, "the revoke itself reported success")

	assert.Zero(t, f.countLive(&models.ShareRecord{}, "id = ? AND deleted_at IS NULL", share.ID),
		"a share whose revocation reported success is live again")
}

// TestCTAReview_GrantSecretACL_vs_DeleteSecret_CrossReplicaPostgres: an ACL
// grant racing DeleteSecret must not leave an ACL row on the deleted secret
// (DeleteSecret's own CWE-284 cascade exists so ACLs cannot reactivate on
// restore).
func TestCTAReview_GrantSecretACL_vs_DeleteSecret_CrossReplicaPostgres(t *testing.T) {
	t.Skip("open gap #2649: GrantSecretACL vs DeleteSecret leaves an ACL grant on a deleted secret; un-skip in the fixing PR")
	t.Parallel()
	f := newCTAReview(t)
	grantee := f.user("cta-aclgrantee", "project_viewer")
	s := f.secret("cta-acl-secret", f.adminID)

	var errB error
	fired := f.beforeA("create", "secret_acls", func() { errB = f.coreB.DeleteSecret(f.ctx, s.ID) })
	errA := f.coreA.GrantSecretACL(f.ctx, f.adminID, s.ID, grantee.ID, []string{"secrets.read"})
	t.Logf("GrantSecretACL (A) err=%v, DeleteSecret (B) err=%v", errA, errB)
	require.True(t, fired(), "the hook must have interleaved B's DeleteSecret before A's ACL upsert")
	require.NoError(t, errB)

	assert.Zero(t, f.countLive(&models.SecretACL{}, "secret_id = ?", s.ID),
		"CWE-284 cascade violated: an ACL grant exists on a soft-deleted secret (it reactivates on RestoreSecret)")
}

// TestCTAReview_SetSecretAutoRotate_vs_DeleteSecret_CrossReplicaPostgres:
// SetSecretAutoRotate persists its pre-check snapshot with UpdateSecret's
// full-row Save(struct). Against a concurrently deleted secret that Save's
// UPDATE matches 0 rows and GORM's upsert fallback writes deleted_at = NULL —
// undeleting the secret with no RestoreSecret call, no secret.restored audit
// event, and no RestoreSecret parent-liveness check. (The same stale Save
// also overwrites a concurrent admin's rotation-backend binding and a
// concurrent ClearProjectSecretOwnership — see the issue.)
func TestCTAReview_SetSecretAutoRotate_vs_DeleteSecret_CrossReplicaPostgres(t *testing.T) {
	t.Skip("open gap #2650: SetSecretAutoRotate's stale full-row Save undeletes/overwrites concurrent secret changes; un-skip in the fixing PR")
	t.Parallel()
	f := newCTAReview(t)
	s := f.secret("cta-rotate-secret", f.adminID)

	var errB error
	fired := f.beforeA("update", "secret_nodes", func() { errB = f.coreB.DeleteSecret(f.ctx, s.ID) })
	errA := f.coreA.SetSecretAutoRotate(f.ctx, s.ID, AutoRotateSpec{Enabled: true, Length: 32}, f.adminID)
	t.Logf("SetSecretAutoRotate (A) err=%v, DeleteSecret (B) err=%v", errA, errB)
	require.True(t, fired(), "the hook must have interleaved B's DeleteSecret before A's secret UPDATE")
	require.NoError(t, errB, "the delete itself reported success")

	assert.Zero(t, f.countLive(&models.SecretNode{}, "id = ? AND deleted_at IS NULL", s.ID),
		"a secret whose deletion reported success is live again, without RestoreSecret")
}

// TestCTAReview_CreateDynamicSecretConfig_vs_DeleteProject_CrossReplicaPostgres:
// CreateDynamicSecretConfig's insert commits on its own (the row IS visible to
// other callers, contrary to its in-code comment), then a second full-row
// Save writes the encrypted DSN. DeleteProject landing in between disables
// the config (#369); the stale Save writes disabled=false back. RestoreProject
// deliberately does not re-enable configs (#369), so this leaves a config
// that can mint credentials as soon as the project is restored.
func TestCTAReview_CreateDynamicSecretConfig_vs_DeleteProject_CrossReplicaPostgres(t *testing.T) {
	t.Skip("open gap #2651: CreateDynamicSecretConfig's second Save re-enables a config disabled by a concurrent DeleteProject; un-skip in the fixing PR")
	t.Parallel()
	f := newCTAReview(t)
	fake := &dynamictest.FakeEngine{NativeExpiry: true}
	f.coreA.SetDynamicEngineFactory(func(string) (dynamic.CredentialEngine, error) { return fake, nil })
	f.coreB.SetDynamicEngineFactory(func(string) (dynamic.CredentialEngine, error) { return fake, nil })

	var errB error
	fired := f.beforeA("update", "dynamic_secret_configs", func() { errB = f.coreB.DeleteProject(f.ctx, f.projectID, true) })
	cfg, errA := f.coreA.CreateDynamicSecretConfig(f.ctx, &CreateDynamicSecretConfigRequest{
		Name: "cta-dyn", ProjectID: f.projectID, EnvironmentID: f.envID, BackendType: "postgres",
		AdminDSN:          "postgres://admin:s3cr3t@db.internal:5432/app",
		CreationTemplate:  "GRANT SELECT ON ALL TABLES IN SCHEMA public TO {{name}};",
		DefaultTTLSeconds: 3600, CreatedBy: "admin", ActorID: f.adminID,
	})
	t.Logf("CreateDynamicSecretConfig (A) err=%v, DeleteProject (B) err=%v", errA, errB)
	require.True(t, fired(), "the hook must have interleaved B's DeleteProject before A's config re-Save")
	require.NoError(t, errA)
	require.NoError(t, errB)

	var got models.DynamicSecretConfig
	require.NoError(t, f.setupDB.First(&got, cfg.ID).Error)
	assert.True(t, got.Disabled, "#369 violated: a config in a deleted project is enabled (it mints again the moment the project is restored)")
}

// TestCTAReview_IssueLease_vs_DeleteProject_CrossReplicaPostgres: a lease
// issued while the project is concurrently deleted must not survive as an
// active, never-revoked credential. DeleteProject's lease revocation lists
// leases BEFORE A's lease row exists, and nothing re-checks afterwards.
func TestCTAReview_IssueLease_vs_DeleteProject_CrossReplicaPostgres(t *testing.T) {
	t.Skip("open gap #2652: IssueLease vs DeleteProject leaves an active, unrevoked credential under a deleted project; un-skip in the fixing PR")
	t.Parallel()
	f := newCTAReview(t)
	fake := &dynamictest.FakeEngine{NativeExpiry: true}
	for _, c := range []*KeyorixCore{f.setup, f.coreA, f.coreB} {
		c.SetDynamicEngineFactory(func(string) (dynamic.CredentialEngine, error) { return fake, nil })
	}
	cfg, err := f.setup.CreateDynamicSecretConfig(f.ctx, &CreateDynamicSecretConfigRequest{
		Name: "cta-lease", ProjectID: f.projectID, EnvironmentID: f.envID, BackendType: "postgres",
		AdminDSN:          "postgres://admin:s3cr3t@db.internal:5432/app",
		CreationTemplate:  "GRANT SELECT ON ALL TABLES IN SCHEMA public TO {{name}};",
		DefaultTTLSeconds: 3600, CreatedBy: "admin", ActorID: f.adminID,
	})
	require.NoError(t, err)

	var errB error
	fired := f.beforeA("create", "dynamic_secret_leases", func() { errB = f.coreB.DeleteProject(f.ctx, f.projectID, true) })
	lease, errA := f.coreA.IssueLease(f.ctx, cfg.ID, 0, f.adminID)
	t.Logf("IssueLease (A) err=%v, DeleteProject (B) err=%v", errA, errB)
	require.True(t, fired(), "the hook must have interleaved B's DeleteProject before A's lease INSERT")
	require.NoError(t, errB)

	active := f.countLive(&models.DynamicSecretLease{}, "config_id = ? AND status = ?", cfg.ID, "active")
	if errA == nil {
		t.Logf("issued lease %s; backend revocations: %v", lease.LeaseID, fake.Revoked)
	}
	assert.Zero(t, active,
		"#369 violated: an active, never-revoked dynamic-secret lease exists under a deleted project and a disabled config")
}

// TestCTAReview_UpdateUser_vs_SuspendUser_CrossReplicaPostgres: an admin's
// display-name edit in flight must not undo another admin's concurrent
// suspension. UpdateUser's default branch writes the full pre-read row
// (Select("*")) gated only on is_active, and SuspendUser changes
// account_state, not is_active — so the stale account_state='active' wins.
func TestCTAReview_UpdateUser_vs_SuspendUser_CrossReplicaPostgres(t *testing.T) {
	t.Skip("open gap #2653: UpdateUser's full-row conditional write reverts a concurrent SuspendUser; un-skip in the fixing PR")
	t.Parallel()
	f := newCTAReview(t)
	target := f.user("cta-suspendee", "project_viewer")

	var errB error
	fired := f.beforeA("update", "users", func() { errB = f.coreB.SuspendUser(f.ctx, f.adminID, target.ID) })
	_, errA := f.coreA.UpdateUser(f.ctx, &UpdateUserRequest{ID: target.ID, ActorID: f.adminID, DisplayName: "renamed"})
	t.Logf("UpdateUser (A) err=%v, SuspendUser (B) err=%v", errA, errB)
	require.True(t, fired(), "the hook must have interleaved B's SuspendUser before A's user UPDATE")
	require.NoError(t, errB, "the suspension itself reported success")

	var got models.User
	require.NoError(t, f.setupDB.First(&got, target.ID).Error)
	assert.Equal(t, AccountSuspended, got.AccountState, "a suspension that reported success was silently reverted")
}

// TestCTAReview_UpdateOwnProfile_vs_ChangePassword_CrossReplicaPostgres: the
// self-service sibling of the test above, reachable with only a session. A
// display-name-only profile update (no re-auth) in flight while the account
// holder changes their password writes the OLD password hash back.
func TestCTAReview_UpdateOwnProfile_vs_ChangePassword_CrossReplicaPostgres(t *testing.T) {
	t.Skip("open gap #2654: UpdateOwnProfile's full-row write reverts a concurrent password change; un-skip in the fixing PR")
	t.Parallel()
	f := newCTAReview(t)
	victim := f.user("cta-victim", "project_viewer")
	var before models.User
	require.NoError(t, f.setupDB.First(&before, victim.ID).Error)

	var errB error
	fired := f.beforeA("update", "users", func() {
		errB = f.coreB.ChangePassword(f.ctx, victim.ID, "UserPass123!xyz-long-enough", "NewUserPass456!abc-long-enough", "")
	})
	_, errA := f.coreA.UpdateOwnProfile(f.ctx, victim.ID, "stale-session-rename", "", "")
	t.Logf("UpdateOwnProfile (A) err=%v, ChangePassword (B) err=%v", errA, errB)
	require.True(t, fired(), "the hook must have interleaved B's ChangePassword before A's user UPDATE")
	require.NoError(t, errB, "the password change itself reported success")

	var got models.User
	require.NoError(t, f.setupDB.First(&got, victim.ID).Error)
	assert.NotEqual(t, before.PasswordHash, got.PasswordHash, "the OLD password hash is live again after a successful password change")
}

// TestCTAReview_ActivateMFA_vs_BeginMFAEnrollment_CrossReplicaPostgres: the
// TOTP secret ActivateMFA activates must be the one the submitted code was
// validated against. ActivateMFASecret was UPDATE ... WHERE user_id = ?, with
// nothing pinning the secret; a re-enrolment (e.g. from a stolen session)
// landing between validation and activation got activated instead. Fixed by
// pinning the conditional write to the validated ciphertext: under the forced
// interleaving activation must now fail closed, leaving MFA off and the
// replacement secret unactivated.
//
// Bug origin
//
//	Introduced-by: #G08 (activation moved into one transaction, but the
//	               activating UPDATE never re-asserted which secret it activates)
//	Detected-by:   C-GUARD2-EXEMPT-REVIEW #2662
//	Class:         cross-replica check-then-act
//	Severity:      high (MFA bound to a secret an attacker controls)
//	Guard:         this test + TestActivateMFA_SecretSwappedAfterValidation_FailsClosed
func TestCTAReview_ActivateMFA_vs_BeginMFAEnrollment_CrossReplicaPostgres(t *testing.T) {
	t.Parallel()
	f := newCTAReview(t)
	victim := f.user("cta-mfa", "")
	_, s1, err := f.setup.BeginMFAEnrollment(f.ctx, victim.ID)
	require.NoError(t, err)
	code, err := totp.GenerateCode(s1, time.Now())
	require.NoError(t, err)

	var errB error
	fired := f.beforeA("update", "mfa_secrets", func() { _, _, errB = f.coreB.BeginMFAEnrollment(f.ctx, victim.ID) })
	_, errA := f.coreA.ActivateMFA(f.ctx, victim.ID, code, "UserPass123!xyz-long-enough", "")
	t.Logf("ActivateMFA (A) err=%v, BeginMFAEnrollment (B) err=%v", errA, errB)
	require.True(t, fired(), "the hook must have interleaved B's BeginMFAEnrollment before A's activation UPDATE")
	require.NoError(t, errB)
	assertActivationNeverBindsUnvalidatedSecret(t, f.setup, victim.ID, s1, errA)
}

// assertActivationNeverBindsUnvalidatedSecret: either ActivateMFA failed closed
// (ErrMFAEnrollmentChanged, MFA off, stored secret not activated), or it
// succeeded and the activated secret is the one the code was validated
// against. With the swap forced before activation, only the first is legal.
func assertActivationNeverBindsUnvalidatedSecret(t *testing.T, c *KeyorixCore, userID uint, validated string, activateErr error) {
	t.Helper()
	ctx := context.Background()
	active, err := c.loadTOTPSecret(ctx, userID)
	require.NoError(t, err)
	row, err := c.Storage().GetMFASecret(ctx, userID)
	require.NoError(t, err)
	user, err := c.Storage().GetUser(ctx, userID)
	require.NoError(t, err)
	t.Logf("activate err=%v, secret swapped=%v, activated=%v, MFAEnabled=%v", activateErr, active != validated, row.Activated, user.MFAEnabled)
	assert.False(t, row.Activated && active != validated,
		"MFA was activated with a TOTP secret the account holder never validated a code against")
	require.ErrorIs(t, activateErr, ErrMFAEnrollmentChanged, "the secret was swapped before activation: it must fail closed")
	assert.False(t, user.MFAEnabled, "a failed activation must roll back MFAEnabled")
	assert.False(t, row.Activated)
}

// TestCTAReview_RestoreEnvironment_vs_DeleteProject_CrossReplicaPostgres:
// LocalStorage.RestoreEnvironment checks project liveness in one autocommit
// SELECT and un-deletes in a separate UPDATE; a DeleteProject committing in
// between (its cascade skips the already-deleted environment) leaves a live
// environment under a deleted project — the exact state RestoreEnvironment's
// own doc comment says it refuses to create.
func TestCTAReview_RestoreEnvironment_vs_DeleteProject_CrossReplicaPostgres(t *testing.T) {
	t.Skip("open gap #2656: RestoreEnvironment vs DeleteProject leaves a live environment under a deleted project; un-skip in the fixing PR")
	t.Parallel()
	f := newCTAReview(t)
	require.NoError(t, f.setup.DeleteEnvironment(f.ctx, f.envID))

	var errB error
	fired := f.beforeA("update", "environments", func() { errB = f.coreB.DeleteProject(f.ctx, f.projectID, true) })
	errA := f.coreA.RestoreEnvironment(f.ctx, f.adminID, f.projectID, f.envID)
	t.Logf("RestoreEnvironment (A) err=%v, DeleteProject (B) err=%v", errA, errB)
	require.True(t, fired(), "the hook must have interleaved B's DeleteProject before A's environment UPDATE")
	require.NoError(t, errB)

	assert.EqualValues(t, 1, f.countLive(&models.Project{}, "id = ? AND deleted_at IS NOT NULL", f.projectID), "project must be deleted")
	assert.Zero(t, f.countLive(&models.Environment{}, "project_id = ? AND deleted_at IS NULL", f.projectID),
		"a live environment exists under a soft-deleted project")
}

// TestCTAReview_TransitionMembership_ActivateVsRevoke_CrossReplicaPostgres: a
// membership revoked while its activation is in flight must not end up
// `revoked` with the role grant live. Activation commits the provisioned→
// active CAS, THEN grants; a revoke landing between finds no grant
// (ErrNotProjectMember, deliberately ignored) and reports success; the
// activation's grant then lands.
func TestCTAReview_TransitionMembership_ActivateVsRevoke_CrossReplicaPostgres(t *testing.T) {
	t.Skip("open gap #2657: TransitionMembership activate vs revoke leaves a revoked membership with a live role grant; un-skip in the fixing PR")
	t.Parallel()
	f := newCTAReview(t)
	u := f.user("cta-member", "")
	m, err := f.setup.Storage().CreateProjectMembership(f.ctx, &models.ProjectMembership{
		ProjectID: f.projectID, UserID: u.ID, Role: "project_viewer", State: MembershipProvisioned,
	})
	require.NoError(t, err)

	var errB error
	fired := f.beforeA("create", "user_roles", func() {
		_, errB = f.coreB.TransitionMembership(f.ctx, f.projectID, m.ID, MembershipRevoked, f.adminID, false)
	})
	_, errA := f.coreA.TransitionMembership(f.ctx, f.projectID, m.ID, MembershipActive, f.adminID, false)
	t.Logf("activate (A) err=%v, revoke (B) err=%v", errA, errB)
	require.True(t, fired(), "the hook must have interleaved B's revoke before A's role-grant INSERT")
	require.NoError(t, errB, "the revoke itself reported success")

	got, err := f.setup.Storage().GetProjectMembership(f.ctx, m.ID)
	require.NoError(t, err)
	member, err := f.setup.Storage().IsProjectMember(f.ctx, u.ID, f.projectID)
	require.NoError(t, err)
	t.Logf("final membership state=%s, holds project grant=%v", got.State, member)
	assert.False(t, got.State == MembershipRevoked && member,
		"membership is `revoked` (terminal) yet the user still holds the project role grant")
}

// TestCTAReview_InviteMemberOpenMode_vs_Revoke_CrossReplicaPostgres: the
// invite-path sibling of the test above. In `open` validation mode
// inviteMemberWithMode commits the membership straight as `active`, THEN
// grants the role; a revoke landing between finds no grant and reports
// success, and the invite's grant then lands.
func TestCTAReview_InviteMemberOpenMode_vs_Revoke_CrossReplicaPostgres(t *testing.T) {
	t.Skip("open gap #2659: open-mode InviteMember vs revoke leaves a revoked membership with a live role grant; un-skip in the fixing PR")
	t.Parallel()
	f := newCTAReview(t)
	f.coreA.SetMembershipValidationMode(ValidationModeOpen)
	u := f.user("cta-invitee", "")

	var errB error
	fired := f.beforeA("create", "user_roles", func() {
		m, err := f.coreB.Storage().GetActiveProjectMembership(f.ctx, f.projectID, u.ID)
		if err != nil {
			errB = err
			return
		}
		_, errB = f.coreB.TransitionMembership(f.ctx, f.projectID, m.ID, MembershipRevoked, f.adminID, false)
	})
	created, errA := f.coreA.InviteMember(f.ctx, f.projectID, u.ID, "project_viewer", f.adminID, 0, false)
	t.Logf("invite (A) err=%v, revoke (B) err=%v", errA, errB)
	require.True(t, fired(), "the hook must have interleaved B's revoke before A's role-grant INSERT")
	require.NoError(t, errA)
	require.NoError(t, errB, "the revoke itself reported success")

	got, err := f.setup.Storage().GetProjectMembership(f.ctx, created.ID)
	require.NoError(t, err)
	member, err := f.setup.Storage().IsProjectMember(f.ctx, u.ID, f.projectID)
	require.NoError(t, err)
	t.Logf("final membership state=%s, holds project grant=%v", got.State, member)
	assert.False(t, got.State == MembershipRevoked && member,
		"membership is `revoked` (terminal) yet the user still holds the project role grant")
}

// TestCTAReview_AddSecretDependency_CrossReplicaCycle_Postgres: INV-CORE-31
// says the dependency graph stays acyclic "including under concurrent adds".
// Its existing guard (TestAddSecretDependency_ConcurrentRaceCannotPersistACycle)
// races two goroutines through ONE KeyorixCore on SQLite, so it is serialized
// by that core's own secretDependencyMu and never exercises two replicas.
// Cross-replica, CreateSecretDependencyExclusive's SELECT ... FOR UPDATE locks
// only edges that already exist: B's locking read blocks on A's locks, and
// under READ COMMITTED it then returns its statement-start snapshot — WITHOUT
// A's just-committed edge — so B's cycle check passes and both edges commit.
//
// Unlike the tests above, B cannot run to completion inside A's hook (it
// blocks on A's own row locks), so the hook starts B in a goroutine, waits
// until Postgres reports a backend waiting on a lock, and only then lets A's
// INSERT and COMMIT proceed. With the #2660 fix B blocks on the per-project
// named lock A holds instead, and runs its cycle check after A commits.
//
// Bug origin
//
//	Introduced-by: #260 (CreateSecretDependencyExclusive relied on FOR UPDATE of
//	               existing edges, which does not block phantom inserts)
//	Detected-by:   C-GUARD2-EXEMPT-REVIEW #2662
//	Class:         cross-replica check-then-act
//	Severity:      medium (INV-CORE-31 integrity: a persisted dependency cycle)
//	Guard:         this test; fixed by secretDependencyGraphLockKey
func TestCTAReview_AddSecretDependency_CrossReplicaCycle_Postgres(t *testing.T) {
	t.Parallel()
	f := newCTAReview(t)
	s1 := f.secret("cta-dep-1", f.adminID)
	s2 := f.secret("cta-dep-2", f.adminID)
	s3 := f.secret("cta-dep-3", f.adminID)
	// One pre-existing edge, so the project has a row for FOR UPDATE to lock
	// (with zero edges there is nothing to lock at all).
	_, err := f.setup.AddSecretDependency(f.ctx, ActorTypeUser, f.adminID, s3.ID, s1.ID, "", 0)
	require.NoError(t, err)

	var errB error
	done := make(chan struct{})
	fired := f.beforeA("create", "secret_dependencies", func() {
		go func() {
			defer close(done)
			_, errB = f.coreB.AddSecretDependency(f.ctx, ActorTypeUser, f.adminID, s2.ID, s1.ID, "", 0)
		}()
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			select {
			case <-done:
				return
			default:
			}
			var waiting int64
			require.NoError(t, f.setupDB.Raw(
				"SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() AND wait_event_type = 'Lock'").
				Scan(&waiting).Error)
			if waiting > 0 {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	})
	_, errA := f.coreA.AddSecretDependency(f.ctx, ActorTypeUser, f.adminID, s1.ID, s2.ID, "", 0)
	require.True(t, fired(), "the hook must have started B's add before A's edge INSERT")
	<-done
	t.Logf("add s1->s2 (A) err=%v, add s2->s1 (B) err=%v", errA, errB)

	both := f.countLive(&models.SecretDependency{},
		"(dependent_secret_id = ? AND depends_on_secret_id = ?) OR (dependent_secret_id = ? AND depends_on_secret_id = ?)",
		s1.ID, s2.ID, s2.ID, s1.ID)
	assert.Less(t, both, int64(2), "INV-CORE-31 violated: both s1->s2 and s2->s1 committed — a dependency cycle")
	assert.NoError(t, errA, "A held the graph lock first, so its edge commits")
	assert.ErrorContains(t, errB, "cycle", "B's cycle check must run after A commits and refuse s2->s1")
}
