package core

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/rotation"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func rotationExecCore(t *testing.T) (*KeyorixCore, *gorm.DB, time.Time) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.SecretNode{}, &models.SecretVersion{}, &models.RotationPolicy{}, &models.AuditEvent{},
		&models.Project{}, &models.Environment{}, &models.Role{}, &models.UserRole{},
	))
	// ListSecrets(ProjectID) JOINs environments, so the scope needs a real env row.
	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "proj"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 1, ProjectID: 1, Name: "prod"}).Error)
	c := &KeyorixCore{storage: store.NewLocalStorage(db)}
	fixed := time.Date(2026, 6, 16, 12, 0, 0, 0, time.UTC)
	c.now = func() time.Time { return fixed }
	return c, db, fixed
}

func seedRotatableSecret(t *testing.T, db *gorm.DB, id uint, name string, autoRotate bool, lastRotated time.Time) {
	t.Helper()
	lr := lastRotated
	require.NoError(t, db.Create(&models.SecretNode{
		ID: id, Name: name, ProjectID: 1, EnvironmentID: 1, IsSecret: true,
		Status: "active", AutoRotate: autoRotate, LastRotatedAt: &lr, CreatedAt: lastRotated,
	}).Error)
	require.NoError(t, db.Create(&models.SecretVersion{
		SecretNodeID: id, VersionNumber: 1, EncryptedValue: []byte("original-" + name),
		EncryptionMetadata: []byte("{}"), CreatedAt: lastRotated,
	}).Error)
}

func latestVersion(t *testing.T, db *gorm.DB, secretID uint) *models.SecretVersion {
	t.Helper()
	var v models.SecretVersion
	require.NoError(t, db.Where("secret_node_id = ?", secretID).Order("version_number desc").First(&v).Error)
	return &v
}

func TestRunAutoRotation_RotatesOverdueOptedInOnly(t *testing.T) {
	c, db, fixed := rotationExecCore(t)
	pid := uint(1)
	require.NoError(t, db.Create(&models.RotationPolicy{
		ID: 1, Name: "30-day", Scope: "project", ProjectID: &pid, IntervalDays: 30,
		IsActive: true, CreatedBy: "admin",
	}).Error)

	seedRotatableSecret(t, db, 1, "due-managed", true, fixed.Add(-60*24*time.Hour))   // overdue + opted-in → rotate
	seedRotatableSecret(t, db, 2, "fresh-managed", true, fixed.Add(-5*24*time.Hour))  // opted-in but not due → skip
	seedRotatableSecret(t, db, 3, "due-external", false, fixed.Add(-60*24*time.Hour)) // overdue but not opted-in → skip

	n, err := c.RunAutoRotation(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 1, n, "only the overdue, opted-in secret rotates")

	// s1: new version with a freshly generated (different) value; LastRotatedAt advanced.
	v1 := latestVersion(t, db, 1)
	assert.Equal(t, 2, v1.VersionNumber, "due-managed secret gained a new version")
	assert.NotEqual(t, "original-due-managed", string(v1.EncryptedValue))
	assert.Len(t, string(v1.EncryptedValue), rotatedValueLength)
	var s1 models.SecretNode
	require.NoError(t, db.First(&s1, 1).Error)
	require.NotNil(t, s1.LastRotatedAt)
	assert.True(t, s1.LastRotatedAt.After(fixed.Add(-time.Minute)), "LastRotatedAt advanced to now")

	// s2 and s3 are untouched (still on version 1).
	assert.Equal(t, 1, latestVersion(t, db, 2).VersionNumber, "not-due secret unchanged")
	assert.Equal(t, 1, latestVersion(t, db, 3).VersionNumber, "non-opted-in secret unchanged")
}

func TestRunAutoRotation_InactivePolicyIgnored(t *testing.T) {
	c, db, fixed := rotationExecCore(t)
	pid := uint(1)
	require.NoError(t, db.Create(&models.RotationPolicy{
		ID: 1, Name: "off", Scope: "project", ProjectID: &pid, IntervalDays: 30,
		IsActive: true, CreatedBy: "admin",
	}).Error)
	// GORM applies the column default (is_active=true) for a zero-value bool on Create,
	// so force it false explicitly to model an inactive policy.
	require.NoError(t, db.Model(&models.RotationPolicy{}).Where("id = ?", 1).Update("is_active", false).Error)
	seedRotatableSecret(t, db, 1, "due-managed", true, fixed.Add(-60*24*time.Hour))

	n, err := c.RunAutoRotation(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 0, n, "no rotation under an inactive policy")
	assert.Equal(t, 1, latestVersion(t, db, 1).VersionNumber)
}

func TestSetSecretAutoRotate_TogglesAndPersists(t *testing.T) {
	c, db, fixed := rotationExecCore(t)
	seedRotatableSecret(t, db, 1, "key", false, fixed.Add(-24*time.Hour))

	// Enable with a generator spec.
	require.NoError(t, c.SetSecretAutoRotate(context.Background(), 1, AutoRotateSpec{Enabled: true, Length: 48, Charset: "hex"}, 9))
	var s models.SecretNode
	require.NoError(t, db.First(&s, 1).Error)
	assert.True(t, s.AutoRotate)
	assert.Equal(t, 48, s.RotationLength)
	assert.Equal(t, "hex", s.RotationCharset)

	require.NoError(t, c.SetSecretAutoRotate(context.Background(), 1, AutoRotateSpec{Enabled: false}, 9))
	require.NoError(t, db.First(&s, 1).Error)
	assert.False(t, s.AutoRotate)
}

func TestSetSecretAutoRotate_ValidatesSpec(t *testing.T) {
	c, db, fixed := rotationExecCore(t)
	seedRotatableSecret(t, db, 1, "key", false, fixed.Add(-24*time.Hour))
	ctx := context.Background()

	err := c.SetSecretAutoRotate(ctx, 1, AutoRotateSpec{Enabled: true, Charset: "klingon"}, 9)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown rotation charset")

	err = c.SetSecretAutoRotate(ctx, 1, AutoRotateSpec{Enabled: true, Length: 5000}, 9)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "out of range")
}

func TestGenerateRotatedValueSpec_LengthAndCharset(t *testing.T) {
	// hex charset, custom length.
	v, err := generateRotatedValueSpec(48, "hex")
	require.NoError(t, err)
	assert.Len(t, v, 48)
	for _, ch := range v {
		assert.Contains(t, charsetHex, string(ch))
	}
	// length 0 → default; unknown charset → alphanumeric (fail-safe, never empty).
	v, err = generateRotatedValueSpec(0, "bogus")
	require.NoError(t, err)
	assert.Len(t, v, rotatedValueLength)
	for _, ch := range v {
		assert.Contains(t, charsetAlphanumeric, string(ch))
	}
	// below-min length clamps up, not to zero-length.
	v, err = generateRotatedValueSpec(2, "")
	require.NoError(t, err)
	assert.Len(t, v, rotatedValueMinLength)
}

// The executor honors a secret's generator spec.
func TestRunAutoRotation_UsesSecretSpec(t *testing.T) {
	c, db, fixed := rotationExecCore(t)
	pid := uint(1)
	require.NoError(t, db.Create(&models.RotationPolicy{
		ID: 1, Name: "30-day", Scope: "project", ProjectID: &pid, IntervalDays: 30,
		IsActive: true, CreatedBy: "admin",
	}).Error)
	// Overdue, opted-in, hex/16.
	lr := fixed.Add(-60 * 24 * time.Hour)
	require.NoError(t, db.Create(&models.SecretNode{
		ID: 1, Name: "hex-key", ProjectID: 1, EnvironmentID: 1, IsSecret: true, Status: "active",
		AutoRotate: true, RotationLength: 16, RotationCharset: "hex", LastRotatedAt: &lr, CreatedAt: lr,
	}).Error)
	require.NoError(t, db.Create(&models.SecretVersion{
		SecretNodeID: 1, VersionNumber: 1, EncryptedValue: []byte("orig"), EncryptionMetadata: []byte("{}"), CreatedAt: lr,
	}).Error)

	n, err := c.RunAutoRotation(context.Background())
	require.NoError(t, err)
	require.Equal(t, 1, n)

	v := latestVersion(t, db, 1)
	assert.Equal(t, 2, v.VersionNumber)
	assert.Len(t, string(v.EncryptedValue), 16)
	for _, ch := range string(v.EncryptedValue) {
		assert.Contains(t, charsetHex, string(ch))
	}
}

func TestGenerateRotatedValue_UniqueAndCharset(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		v, err := generateRotatedValue()
		require.NoError(t, err)
		assert.Len(t, v, rotatedValueLength)
		for _, ch := range v {
			assert.Contains(t, rotatedValueCharset, string(ch))
		}
		assert.False(t, seen[v], "values must not repeat")
		seen[v] = true
	}
}

// fakeExecutor records the (ref, value) it was asked to rotate and can fail on demand.
type fakeExecutor struct {
	name   string
	gotRef string
	gotVal string
	called bool
	err    error
}

func (f *fakeExecutor) Name() string { return f.name }
func (f *fakeExecutor) Type() string { return "fake" }
func (f *fakeExecutor) Rotate(_ context.Context, ref, val string) error {
	f.called = true
	f.gotRef, f.gotVal = ref, val
	return f.err
}

func seedBackendSecret(t *testing.T, db *gorm.DB, id uint, backend, ref string, lastRotated time.Time) {
	t.Helper()
	lr := lastRotated
	require.NoError(t, db.Create(&models.SecretNode{
		ID: id, Name: "upstream-cred", ProjectID: 1, EnvironmentID: 1, IsSecret: true, Status: "active",
		AutoRotate: true, RotationBackend: backend, RotationRef: ref, LastRotatedAt: &lr, CreatedAt: lastRotated,
	}).Error)
	require.NoError(t, db.Create(&models.SecretVersion{
		SecretNodeID: id, VersionNumber: 1, EncryptedValue: []byte("orig"), EncryptionMetadata: []byte("{}"), CreatedAt: lastRotated,
	}).Error)
}

func backendPolicyCore(t *testing.T, fake *fakeExecutor) (*KeyorixCore, *gorm.DB, time.Time) {
	c, db, fixed := rotationExecCore(t)
	pid := uint(1)
	require.NoError(t, db.Create(&models.RotationPolicy{
		ID: 1, Name: "30-day", Scope: "project", ProjectID: &pid, IntervalDays: 30, IsActive: true, CreatedBy: "admin",
	}).Error)
	c.SetRotationManager(rotation.NewManager([]rotation.Executor{fake}))
	return c, db, fixed
}

// Backend rotation: the executor applies the new value upstream, then it's stored.
func TestRunAutoRotation_BackendApplied(t *testing.T) {
	fake := &fakeExecutor{name: "pg"}
	c, db, fixed := backendPolicyCore(t, fake)
	seedBackendSecret(t, db, 1, "pg", "app_svc", fixed.Add(-60*24*time.Hour))

	n, err := c.RunAutoRotation(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 1, n)

	require.True(t, fake.called, "the upstream executor was invoked")
	assert.Equal(t, "app_svc", fake.gotRef)
	v := latestVersion(t, db, 1)
	assert.Equal(t, 2, v.VersionNumber, "new value stored after upstream success")
	assert.Equal(t, fake.gotVal, string(v.EncryptedValue), "stored value matches what was applied upstream")
}

// If the upstream apply fails, the value is NOT stored (no drift between Keyorix and upstream).
func TestRunAutoRotation_BackendFailureNotStored(t *testing.T) {
	fake := &fakeExecutor{name: "pg", err: errors.New("connection refused")}
	c, db, fixed := backendPolicyCore(t, fake)
	seedBackendSecret(t, db, 1, "pg", "app_svc", fixed.Add(-60*24*time.Hour))

	n, err := c.RunAutoRotation(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 0, n, "a failed upstream apply rotates nothing")
	assert.True(t, fake.called)
	assert.Equal(t, 1, latestVersion(t, db, 1).VersionNumber, "value not stored on upstream failure")
}

// An unknown backend name (no executor registered) is skipped, not stored.
func TestRunAutoRotation_UnknownBackendSkipped(t *testing.T) {
	fake := &fakeExecutor{name: "pg"}
	c, db, fixed := backendPolicyCore(t, fake)
	seedBackendSecret(t, db, 1, "nope", "app_svc", fixed.Add(-60*24*time.Hour))

	n, err := c.RunAutoRotation(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 0, n)
	assert.False(t, fake.called, "the registered executor is not invoked for a different backend name")
	assert.Equal(t, 1, latestVersion(t, db, 1).VersionNumber)
}

func TestSetSecretAutoRotate_BackendRefBothOrNeither(t *testing.T) {
	c, db, fixed := rotationExecCore(t)
	seedRotatableSecret(t, db, 1, "key", false, fixed.Add(-24*time.Hour))
	c.SetRotationManager(rotation.NewManager([]rotation.Executor{&fakeExecutor{name: "pg"}}))
	ctx := context.Background()
	require.NoError(t, db.Create(&models.Role{ID: 1, Name: "project_admin"}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 9, RoleID: 1, ProjectID: 1}).Error)

	// backend without ref → error
	err := c.SetSecretAutoRotate(ctx, 1, AutoRotateSpec{Enabled: true, Backend: "pg"}, 9)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must be set together")

	// both set, backend exists, actor holds project_admin → ok
	require.NoError(t, c.SetSecretAutoRotate(ctx, 1, AutoRotateSpec{Enabled: true, Backend: "pg", Ref: "app_svc"}, 9))
	var s models.SecretNode
	require.NoError(t, db.First(&s, 1).Error)
	assert.Equal(t, "pg", s.RotationBackend)
	assert.Equal(t, "app_svc", s.RotationRef)
}

func TestSetSecretAutoRotate_RejectsUnknownBackend(t *testing.T) {
	c, db, fixed := rotationExecCore(t)
	seedRotatableSecret(t, db, 1, "key", false, fixed.Add(-24*time.Hour))
	ctx := context.Background()

	// No manager configured → backend reference rejected.
	err := c.SetSecretAutoRotate(ctx, 1, AutoRotateSpec{Enabled: true, Backend: "pg", Ref: "app_svc"}, 9)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no rotation backends")

	// Manager present but the named backend is not registered → rejected.
	c.SetRotationManager(rotation.NewManager([]rotation.Executor{&fakeExecutor{name: "other"}}))
	err = c.SetSecretAutoRotate(ctx, 1, AutoRotateSpec{Enabled: true, Backend: "pg", Ref: "app_svc"}, 9)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown rotation backend")
}

// TestSetSecretAutoRotate_BindingBackendRequiresAdminAuthority pins #90: binding a
// rotation backend to a secret is gated only by scoped secrets.write on the secret,
// so any project editor could point an org-wide-credentialed backend (AWS/GCP/Azure
// IAM, a shared DB superuser) at a ref they can influence and have the next
// scheduler run mint that credential into their own readable secret. A non-admin
// actor must be refused.
func TestSetSecretAutoRotate_BindingBackendRequiresAdminAuthority(t *testing.T) {
	c, db, fixed := rotationExecCore(t)
	seedRotatableSecret(t, db, 1, "key", false, fixed.Add(-24*time.Hour))
	c.SetRotationManager(rotation.NewManager([]rotation.Executor{&fakeExecutor{name: "pg"}}))
	ctx := context.Background()
	// actor 9 has secrets.write on the secret (enforced by the transport layer,
	// out of scope here) but NO role at all — the realistic "project editor" persona.

	err := c.SetSecretAutoRotate(ctx, 1, AutoRotateSpec{Enabled: true, Backend: "pg", Ref: "app_svc"}, 9)
	require.Error(t, err, "a non-admin actor must not be able to bind a rotation backend")
	assert.Contains(t, err.Error(), "admin authority")

	var s models.SecretNode
	require.NoError(t, db.First(&s, 1).Error)
	assert.Empty(t, s.RotationBackend, "the secret must not end up bound to the backend")
}

// TestSetSecretAutoRotate_InKeyorixRotationNoAdminRequired is the positive control:
// the common case (no external backend — Keyorix regenerates the value itself) has
// no cross-scope credential-minting risk and is unaffected by the new ceiling.
func TestSetSecretAutoRotate_InKeyorixRotationNoAdminRequired(t *testing.T) {
	c, db, fixed := rotationExecCore(t)
	seedRotatableSecret(t, db, 1, "key", false, fixed.Add(-24*time.Hour))
	ctx := context.Background()

	require.NoError(t, c.SetSecretAutoRotate(ctx, 1, AutoRotateSpec{Enabled: true}, 9),
		"enabling in-Keyorix rotation (no backend) needs no elevated authority")
}

// fakeGenExecutor is a generate-upstream backend: GenerateUpstream mints the value.
type fakeGenExecutor struct {
	name   string
	value  string
	gotRef string
	err    error
}

func (f *fakeGenExecutor) Name() string { return f.name }
func (f *fakeGenExecutor) Type() string { return "fakegen" }
func (f *fakeGenExecutor) Rotate(context.Context, string, string) error {
	return errors.New("use GenerateUpstream")
}
func (f *fakeGenExecutor) GenerateUpstream(_ context.Context, ref string) (string, error) {
	f.gotRef = ref
	return f.value, f.err
}

// For a generate-upstream backend the STORED value is what the upstream minted, not the
// Keyorix-generated candidate.
func TestRunAutoRotation_GenerateUpstreamStored(t *testing.T) {
	c, db, fixed := rotationExecCore(t)
	pid := uint(1)
	require.NoError(t, db.Create(&models.RotationPolicy{
		ID: 1, Name: "30-day", Scope: "project", ProjectID: &pid, IntervalDays: 30, IsActive: true, CreatedBy: "admin",
	}).Error)
	fake := &fakeGenExecutor{name: "cloud", value: `{"access_key_id":"AKIANEW","secret_access_key":"s"}`}
	c.SetRotationManager(rotation.NewManager([]rotation.Executor{fake}))
	seedBackendSecret(t, db, 1, "cloud", "svc-app", fixed.Add(-60*24*time.Hour))

	n, err := c.RunAutoRotation(context.Background())
	require.NoError(t, err)
	require.Equal(t, 1, n)
	assert.Equal(t, "svc-app", fake.gotRef)
	v := latestVersion(t, db, 1)
	assert.Equal(t, 2, v.VersionNumber)
	assert.Equal(t, fake.value, string(v.EncryptedValue), "stored value is the upstream-minted one, not a generated candidate")
}

// A generate-upstream failure stores nothing.
func TestRunAutoRotation_GenerateUpstreamFailureNotStored(t *testing.T) {
	c, db, fixed := rotationExecCore(t)
	pid := uint(1)
	require.NoError(t, db.Create(&models.RotationPolicy{
		ID: 1, Name: "30-day", Scope: "project", ProjectID: &pid, IntervalDays: 30, IsActive: true, CreatedBy: "admin",
	}).Error)
	fake := &fakeGenExecutor{name: "cloud", err: errors.New("LimitExceeded")}
	c.SetRotationManager(rotation.NewManager([]rotation.Executor{fake}))
	seedBackendSecret(t, db, 1, "cloud", "svc-app", fixed.Add(-60*24*time.Hour))

	n, err := c.RunAutoRotation(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 0, n)
	assert.Equal(t, 1, latestVersion(t, db, 1).VersionNumber)
}

// A rotation failure broadcasts a single summary notification (fakeSink is defined in
// notification_dispatch_test.go).
func TestRunAutoRotation_NotifiesFailures(t *testing.T) {
	fake := &fakeExecutor{name: "pg", err: errors.New("connection refused")}
	c, db, fixed := backendPolicyCore(t, fake)
	sink := &fakeSink{}
	c.SetNotificationSink(sink)
	seedBackendSecret(t, db, 1, "pg", "app_svc", fixed.Add(-60*24*time.Hour)) // name "upstream-cred"

	_, err := c.RunAutoRotation(context.Background())
	require.NoError(t, err)
	require.Len(t, sink.events, 1)
	assert.Equal(t, "rotation.failed", sink.events[0].Type)
	assert.Contains(t, sink.events[0].Title, "1 secret")
	assert.Contains(t, sink.events[0].Message, "upstream-cred")
	assert.Contains(t, sink.events[0].Message, "connection refused")
}

// A clean run (no failures) sends nothing.
func TestRunAutoRotation_NoFailuresNoNotify(t *testing.T) {
	c, db, fixed := rotationExecCore(t)
	pid := uint(1)
	require.NoError(t, db.Create(&models.RotationPolicy{
		ID: 1, Name: "30-day", Scope: "project", ProjectID: &pid, IntervalDays: 30, IsActive: true, CreatedBy: "admin",
	}).Error)
	sink := &fakeSink{}
	c.SetNotificationSink(sink)
	seedRotatableSecret(t, db, 1, "k", true, fixed.Add(-60*24*time.Hour)) // generated → succeeds

	_, err := c.RunAutoRotation(context.Background())
	require.NoError(t, err)
	assert.Empty(t, sink.events)
}

// rotationDriftStore wraps LocalStorage and fails UpdateSecret, so RotateSecret errors AFTER
// the backend executor has already applied the new credential upstream — the split-brain /
// drift case.
type rotationDriftStore struct {
	*store.LocalStorage
}

func (s *rotationDriftStore) UpdateSecret(_ context.Context, _ *models.SecretNode) (*models.SecretNode, error) {
	return nil, errors.New("simulated storage failure after upstream rotation")
}

// TestRunAutoRotation_BackendSucceedsStoreFails_AuditsDrift pins that the most dangerous
// rotation outcome — the upstream credential is rotated but storing the new value in Keyorix
// fails — is audited distinctly. Before the fix this path only logged + reported a generic
// failure; the live credential could drift from Keyorix's record with no audit trail. The
// backend-apply-FAILURE path was already audited; this closes the asymmetry.
func TestRunAutoRotation_BackendSucceedsStoreFails_AuditsDrift(t *testing.T) {
	fake := &fakeExecutor{name: "pg"}
	c, db, fixed := backendPolicyCore(t, fake)
	// Make the post-backend store fail: RotateSecret's final UpdateSecret errors.
	c.storage = &rotationDriftStore{LocalStorage: c.storage.(*store.LocalStorage)}
	seedBackendSecret(t, db, 1, "pg", "app_svc", fixed.Add(-60*24*time.Hour))

	n, err := c.RunAutoRotation(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 0, n, "the rotation did not complete — the store failed")
	require.True(t, fake.called, "the upstream backend WAS rotated (so the credential changed)")

	// Exactly one auto-rotation audit event, and it flags the drift distinctly.
	var events []models.AuditEvent
	require.NoError(t, db.Where("event_type = ?", EventSecretAutoRotated).Find(&events).Error)
	require.Len(t, events, 1)
	assert.Contains(t, events[0].Description, "DRIFT", "the backend-succeeded-store-failed case must be audited as drift")
	assert.Contains(t, events[0].Description, "app_svc", "the audit must name the upstream ref to reconcile")
}
