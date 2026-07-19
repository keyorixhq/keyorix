package core

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// ---- helpers ----

func newUsageReportCore(t *testing.T) (*KeyorixCore, *MockStorage) {
	t.Helper()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	return c, ms
}

// ---- tests ----

// TestGetUsageReport_AllProjects verifies that when no projectID is given,
// GetProjectUsageStats is called with a nil slice and both projects appear in
// the returned report.
func TestGetUsageReport_AllProjects(t *testing.T) {
	c, ms := newUsageReportCore(t)

	stats := []storage.ProjectUsageStat{
		{ProjectID: 1, ProjectName: "alpha", SecretCount: 5, ReadsInWindow: 20, UniqueReaders: 3},
		{ProjectID: 2, ProjectName: "beta", SecretCount: 2, ReadsInWindow: 7, UniqueReaders: 1},
	}
	ms.On("GetProjectUsageStats", mock.Anything, []uint(nil), 30).Return(stats, nil)

	report, err := c.GetUsageReport(context.Background(), 30, nil)
	require.NoError(t, err)
	assert.Equal(t, 30, report.WindowDays)
	assert.Len(t, report.Projects, 2)
	assert.Equal(t, uint(1), report.Projects[0].ProjectID)
	assert.Equal(t, uint(2), report.Projects[1].ProjectID)
	ms.AssertExpectations(t)
}

// TestGetUsageReport_SingleProject verifies that a non-nil projectID is
// forwarded as a single-element slice to GetProjectUsageStats.
func TestGetUsageReport_SingleProject(t *testing.T) {
	c, ms := newUsageReportCore(t)

	id := uint(7)
	stats := []storage.ProjectUsageStat{
		{ProjectID: 7, ProjectName: "gamma", SecretCount: 1, ReadsInWindow: 3, UniqueReaders: 1},
	}
	ms.On("GetProjectUsageStats", mock.Anything, []uint{7}, 14).Return(stats, nil)

	report, err := c.GetUsageReport(context.Background(), 14, &id)
	require.NoError(t, err)
	assert.Equal(t, 14, report.WindowDays)
	require.Len(t, report.Projects, 1)
	assert.Equal(t, uint(7), report.Projects[0].ProjectID)
	ms.AssertExpectations(t)
}

// TestGetUsageReport_DefaultsInvalidDays verifies that out-of-range windowDays
// values are clamped to 30 before the storage call.
func TestGetUsageReport_DefaultsInvalidDays(t *testing.T) {
	cases := []struct {
		name string
		days int
	}{
		{"zero", 0},
		{"negative", -5},
		{"too large", 400},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, ms := newUsageReportCore(t)
			ms.On("GetProjectUsageStats", mock.Anything, []uint(nil), 30).Return([]storage.ProjectUsageStat{}, nil)

			report, err := c.GetUsageReport(context.Background(), tc.days, nil)
			require.NoError(t, err)
			assert.Equal(t, 30, report.WindowDays, "invalid days %d should default to 30", tc.days)
			ms.AssertExpectations(t)
		})
	}
}

// TestGetUsageReport_EmptyStats verifies that a nil slice from storage is
// coerced to an empty non-nil slice in the returned report.
func TestGetUsageReport_EmptyStats(t *testing.T) {
	c, ms := newUsageReportCore(t)
	ms.On("GetProjectUsageStats", mock.Anything, []uint(nil), 30).Return(nil, nil)

	report, err := c.GetUsageReport(context.Background(), 30, nil)
	require.NoError(t, err)
	assert.NotNil(t, report.Projects)
	assert.Empty(t, report.Projects)
	ms.AssertExpectations(t)
}
