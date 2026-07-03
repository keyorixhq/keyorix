package core

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// compliancePostureCore builds a bare KeyorixCore against a real (empty) sqlite DB —
// only models.Project is migrated, since accessGovernancePosture's ListProjects is the
// one call GetCompliancePosture treats as fatal; every other sub-rollup query errors
// (e.g. from a missing table) are expected to soft-fail into Degraded, not abort.
func compliancePostureCore(t *testing.T) *KeyorixCore {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.Project{}))
	c := &KeyorixCore{storage: store.NewLocalStorage(db)}
	c.now = func() time.Time { return time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC) }
	return c
}

// failingLegalHoldStore wraps LocalStorage and fails GetActiveLegalHold, simulating a DB
// error on that one sub-rollup while every other posture query still runs for real.
type failingLegalHoldStore struct {
	*store.LocalStorage
}

func (s *failingLegalHoldStore) GetActiveLegalHold(_ context.Context) (*models.LegalHold, error) {
	return nil, errors.New("simulated db failure")
}

// #136: before the fix, a failed legal-hold query left LegalHold.Active=false —
// byte-identical to "queried, no hold in effect". That's the most dangerous instance of
// the fail-open pattern: it's the signal purge jobs would otherwise trust to preserve
// records under hold, and it feeds an HMAC-signed evidence pack an auditor trusts. A query
// failure must surface as Degraded, not as a silently-clean zero value.
func TestGetCompliancePosture_DegradedOnLegalHoldQueryError(t *testing.T) {
	c := compliancePostureCore(t)
	c.storage = &failingLegalHoldStore{LocalStorage: c.storage.(*store.LocalStorage)}

	p, err := c.GetCompliancePosture(context.Background())
	require.NoError(t, err, "a single failed sub-rollup must not abort the whole snapshot")

	assert.False(t, p.LegalHold.Active, "the field itself still reads as its zero value")
	assert.True(t, p.Degraded, "a failed legal-hold query must flip Degraded — the zero value above is UNKNOWN, not verified-clean")
	assert.True(t, containsSubstring(p.DegradedReasons, "legal_hold"), "expected a legal_hold entry in DegradedReasons, got %v", p.DegradedReasons)

	controls, err := c.GetComplianceControls(context.Background())
	require.NoError(t, err)
	lh := findControl(t, controls.Controls, "legal-hold")
	assert.Equal(t, ControlStatusUnknown, lh.Status, "the legal-hold CONTROL must surface as unknown, not silently pass, when its posture signal is degraded")
}

// failingRiskExceptionsStore wraps LocalStorage and fails ListRiskExceptions, simulating
// a DB error on the risk-exception sub-rollup.
type failingRiskExceptionsStore struct {
	*store.LocalStorage
}

func (s *failingRiskExceptionsStore) ListRiskExceptions(_ context.Context, _ bool) ([]*models.RiskException, error) {
	return nil, errors.New("simulated db failure")
}

// #136: empirically, dropping the risk_exceptions table flipped a real active exception
// from count=1 to count=0 — a query failure must surface as Degraded, not a silently-clean
// zero count.
func TestGetCompliancePosture_DegradedOnRiskExceptionQueryError(t *testing.T) {
	c := compliancePostureCore(t)
	c.storage = &failingRiskExceptionsStore{LocalStorage: c.storage.(*store.LocalStorage)}

	p, err := c.GetCompliancePosture(context.Background())
	require.NoError(t, err, "a single failed sub-rollup must not abort the whole snapshot")

	assert.Equal(t, 0, p.Risk.ActiveExceptions, "the field itself still reads as its zero value")
	assert.True(t, p.Degraded, "a failed risk-exception query must flip Degraded")
	assert.True(t, containsSubstring(p.DegradedReasons, "risk"), "expected a risk entry in DegradedReasons, got %v", p.DegradedReasons)
}

// failingSoDPoliciesStore wraps LocalStorage and fails ListSoDPolicies, simulating a DB
// error on the SoD sub-rollup.
type failingSoDPoliciesStore struct {
	*store.LocalStorage
}

func (s *failingSoDPoliciesStore) ListSoDPolicies(_ context.Context) ([]*models.SoDPolicy, error) {
	return nil, errors.New("simulated db failure")
}

// #136: empirically, dropping the sod_policies table flipped a real toxic-combination
// violation from count>=1 to count=0 — a query failure must surface as Degraded, not a
// silently-clean zero count.
func TestGetCompliancePosture_DegradedOnSoDPoliciesQueryError(t *testing.T) {
	c := compliancePostureCore(t)
	c.storage = &failingSoDPoliciesStore{LocalStorage: c.storage.(*store.LocalStorage)}

	p, err := c.GetCompliancePosture(context.Background())
	require.NoError(t, err, "a single failed sub-rollup must not abort the whole snapshot")

	assert.Equal(t, 0, p.AccessGovernance.SoDViolations, "the field itself still reads as its zero value")
	assert.True(t, p.Degraded, "a failed SoD-policy query must flip Degraded")
	assert.True(t, containsSubstring(p.DegradedReasons, "sod_violations"), "expected a sod_violations entry in DegradedReasons, got %v", p.DegradedReasons)

	controls, err := c.GetComplianceControls(context.Background())
	require.NoError(t, err)
	sod := findControl(t, controls.Controls, "separation-of-duties")
	assert.Equal(t, ControlStatusUnknown, sod.Status, "the SoD CONTROL must surface as unknown, not silently pass, when its posture signal is degraded")
}

func containsSubstring(ss []string, sub string) bool {
	for _, s := range ss {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}
