package core_test

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/testhelper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Wave 6 core-sod finding #3: a "sod"-category risk exception's reference must
// name a violation DetectSoDViolations is CURRENTLY reporting — otherwise two
// system.write holders could create-and-approve an exception for a
// (policy, principal) pair that has never violated anything (pre-emptively
// suppressing a future violation before it exists) or that has already been
// resolved, defeating dual control's whole point of governing acceptance of a
// KNOWN, currently-real gap.

// A reference that does not correspond to any currently-detected SoD
// violation must be refused at creation time.
func TestCreateRiskException_RejectsNonExistentSoDReference(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	require.NoError(t, h.DB.AutoMigrate(&models.SoDPolicy{}, &models.AuditEvent{}, &models.RiskException{}))

	ctx := context.Background()
	// A policy exists, but NOBODY currently violates it — no user/machine holds
	// both sides. The reference format is fully guessable/deterministic
	// (sod:policy:<id>:<principalType>:<principalID>) from public policy/user
	// IDs, which is exactly the exploit: a bogus or future-looking reference
	// naming a (policy, principal) pair that has no live violation yet.
	_, err := h.CoreService.CreateSoDPolicy(ctx, 1, "write-vs-useradmin", "", "secrets.write", "users.read")
	require.NoError(t, err)

	sod, err := h.CoreService.DetectSoDViolations(ctx)
	require.NoError(t, err)
	require.Empty(t, sod.Violations, "no one holds both sides yet")

	bogusRef := "sod:policy:1:user:9999" // matches the reference format, but no such violation exists
	_, err = h.CoreService.CreateRiskException(ctx, 1, "pre-authorize future SoD gap", "sod", bogusRef, "just in case", time.Now().Add(30*24*time.Hour))
	require.Error(t, err, "a reference that names no live SoD violation must be refused")
	assert.Contains(t, err.Error(), "does not match any currently-detected SoD violation")
}

// A reference naming a violation that IS currently live must still succeed —
// the fix must not break the legitimate flow.
func TestCreateRiskException_AcceptsLiveSoDReference(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	require.NoError(t, h.DB.AutoMigrate(&models.SoDPolicy{}, &models.AuditEvent{}, &models.RiskException{}))

	ctx := context.Background()
	h.CreateTestUser(t, "alice", 10)
	h.AssignUserRole(t, 10, 3, nil) // editor → secrets.write + users.read
	_, err := h.CoreService.CreateSoDPolicy(ctx, 1, "write-vs-useradmin", "", "secrets.write", "users.read")
	require.NoError(t, err)

	sod, err := h.CoreService.DetectSoDViolations(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, sod.Violations)
	ref := sod.Violations[0].Reference

	exc, err := h.CoreService.CreateRiskException(ctx, 1, "accept for Q3 migration", "sod", ref, "temporary", time.Now().Add(30*24*time.Hour))
	require.NoError(t, err, "a reference matching a live violation must be accepted")
	assert.Equal(t, ref, exc.Reference)
}

// Re-validation at approval time: if the violation the exception referenced
// gets resolved (the principal's offending role is revoked) between creation
// and approval, approval must be refused too — a stale reference cannot be
// rubber-stamped just because it was live at creation time.
func TestApproveRiskException_RejectsSoDReferenceThatWentStale(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	require.NoError(t, h.DB.AutoMigrate(&models.SoDPolicy{}, &models.AuditEvent{}, &models.RiskException{}))

	ctx := context.Background()
	h.CreateTestUser(t, "alice", 10)
	h.AssignUserRole(t, 10, 3, nil) // editor → secrets.write + users.read
	_, err := h.CoreService.CreateSoDPolicy(ctx, 1, "write-vs-useradmin", "", "secrets.write", "users.read")
	require.NoError(t, err)

	sod, err := h.CoreService.DetectSoDViolations(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, sod.Violations)
	ref := sod.Violations[0].Reference

	exc, err := h.CoreService.CreateRiskException(ctx, 1, "accept for Q3 migration", "sod", ref, "temporary", time.Now().Add(30*24*time.Hour))
	require.NoError(t, err)

	// The violation resolves before anyone approves the exception (e.g. alice's
	// editor role is revoked) — deleted directly via storage, mirroring how
	// AssignUserRole above seeded it, so this exercises only the SoD
	// re-validation under test rather than any unrelated RBAC authority check.
	require.NoError(t, h.DB.Where("user_id = ? AND role_id = ?", 10, 3).Delete(&models.UserRole{}).Error)

	sodAfter, err := h.CoreService.DetectSoDViolations(ctx)
	require.NoError(t, err)
	require.Empty(t, sodAfter.Violations, "the violation must be gone")

	err = h.CoreService.ApproveRiskException(ctx, 2, exc.ID)
	require.Error(t, err, "approval must re-validate against a fresh scan and refuse a now-stale reference")
	assert.Contains(t, err.Error(), "does not match any currently-detected SoD violation")
}
