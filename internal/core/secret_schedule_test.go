package core

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// ── enforceSchedule pure unit tests ─────────────────────────────────────────

func monFridaySched() *models.SecretAccessSchedule {
	return &models.SecretAccessSchedule{
		AllowedDays: "1,2,3,4,5",
		StartHour:   9,
		EndHour:     17,
		Timezone:    "UTC",
	}
}

func TestEnforceSchedule_WithinWindow(t *testing.T) {
	// Wednesday 14:00 UTC — within Mon–Fri 09–17
	now := time.Date(2026, 7, 15, 14, 0, 0, 0, time.UTC) // Wednesday
	assert.NoError(t, enforceSchedule(monFridaySched(), now))
}

func TestEnforceSchedule_BeforeStartHour(t *testing.T) {
	// Wednesday 08:00 UTC — before start hour
	now := time.Date(2026, 7, 15, 8, 0, 0, 0, time.UTC)
	assert.ErrorIs(t, enforceSchedule(monFridaySched(), now), ErrAccessOutsideSchedule)
}

func TestEnforceSchedule_AtEndHour(t *testing.T) {
	// Wednesday 17:00 UTC — end hour is exclusive
	now := time.Date(2026, 7, 15, 17, 0, 0, 0, time.UTC)
	assert.ErrorIs(t, enforceSchedule(monFridaySched(), now), ErrAccessOutsideSchedule)
}

func TestEnforceSchedule_AfterEndHour(t *testing.T) {
	now := time.Date(2026, 7, 15, 20, 0, 0, 0, time.UTC)
	assert.ErrorIs(t, enforceSchedule(monFridaySched(), now), ErrAccessOutsideSchedule)
}

func TestEnforceSchedule_OutsideDays(t *testing.T) {
	// Saturday (ISO 6) — not in Mon–Fri schedule
	now := time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC) // Saturday
	assert.ErrorIs(t, enforceSchedule(monFridaySched(), now), ErrAccessOutsideSchedule)
}

func TestEnforceSchedule_Sunday(t *testing.T) {
	// Sunday is ISO 7 — not in Mon–Fri (1,2,3,4,5)
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC) // Sunday
	assert.ErrorIs(t, enforceSchedule(monFridaySched(), now), ErrAccessOutsideSchedule)
}

func TestEnforceSchedule_StarDaysAlwaysPass(t *testing.T) {
	sched := &models.SecretAccessSchedule{
		AllowedDays: "*",
		StartHour:   0,
		EndHour:     24,
		Timezone:    "UTC",
	}
	// Saturday midnight — days check must pass because AllowedDays == "*"
	now := time.Date(2026, 7, 18, 0, 0, 0, 0, time.UTC)
	assert.NoError(t, enforceSchedule(sched, now))
}

func TestEnforceSchedule_UnknownTimezone_FailOpen(t *testing.T) {
	sched := &models.SecretAccessSchedule{
		AllowedDays: "1,2,3,4,5",
		StartHour:   9,
		EndHour:     17,
		Timezone:    "Galaxy/Andromeda", // invalid IANA name
	}
	now := time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC) // Saturday, would be denied on UTC schedule
	// Fail-open: unrecognised timezone returns nil
	assert.NoError(t, enforceSchedule(sched, now))
}

// ── checkSecretAccessSchedule integration tests ──────────────────────────────

// newScheduleCore creates a KeyorixCore backed by an isolated in-memory SQLite for schedule tests.
func newScheduleCore(t *testing.T) (*KeyorixCore, *gorm.DB) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.SecretNode{},
		&models.SecretAccessSchedule{},
		&models.SecretVersion{},
		&models.AuditEvent{},
		&models.Project{},
		&models.Environment{},
	))
	require.NoError(t, db.Create(&models.Project{ID: 10, Name: "p"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 10, ProjectID: 10, Name: "e"}).Error)
	c := &KeyorixCore{storage: store.NewLocalStorage(db)}
	return c, db
}

func TestCheckSecretAccessSchedule_NoSchedule(t *testing.T) {
	c, _ := newScheduleCore(t)
	// secretNodeID 999 has no schedule row — must return nil (no restriction)
	err := c.checkSecretAccessSchedule(context.Background(), 999)
	assert.NoError(t, err)
}

func TestCheckSecretAccessSchedule_WithSchedule_InWindow(t *testing.T) {
	c, db := newScheduleCore(t)
	s := &models.SecretNode{ProjectID: 10, EnvironmentID: 10, Name: "sched-in", IsSecret: true, Status: "active"}
	require.NoError(t, db.Create(s).Error)

	require.NoError(t, db.Create(&models.SecretAccessSchedule{
		SecretNodeID: s.ID,
		AllowedDays:  "*",
		StartHour:    0,
		EndHour:      24,
		Timezone:     "UTC",
	}).Error)

	// Any time should pass (all-day, all-hours)
	err := c.checkSecretAccessSchedule(context.Background(), s.ID)
	assert.NoError(t, err)
}

func TestCheckSecretAccessSchedule_Denied(t *testing.T) {
	_, db := newScheduleCore(t)
	s := &models.SecretNode{ProjectID: 10, EnvironmentID: 10, Name: "sched-deny", IsSecret: true, Status: "active"}
	require.NoError(t, db.Create(s).Error)

	// Schedule that allows ONLY hour 23 on Sundays (ISO 7)
	require.NoError(t, db.Create(&models.SecretAccessSchedule{
		SecretNodeID: s.ID,
		AllowedDays:  "7",
		StartHour:    23,
		EndHour:      24,
		Timezone:     "UTC",
	}).Error)

	ls := store.NewLocalStorage(db)
	// Swap storage to use a fixed "now" outside the window (Monday 12:00)
	frozenMonday := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC) // Monday

	sched, err := ls.GetSecretAccessSchedule(context.Background(), s.ID)
	require.NoError(t, err)
	require.NotNil(t, sched)
	assert.ErrorIs(t, enforceSchedule(sched, frozenMonday), ErrAccessOutsideSchedule)
}

// ── #G09 regression: value-read paths must honor the access schedule too ────
//
// Before the fix, checkSecretAccessSchedule was wired only into the metadata
// read path (GetSecretWithPermissionCheck), never into GetSecretValue /
// GetSecretValueByVersion — so a secret whose metadata read was correctly
// refused outside its configured window could still have its VALUE read
// through GetSecretValue. These tests pin the value-read paths to the same
// guard, using a schedule that excludes today's ISO weekday (deterministic
// regardless of what hour/day the suite runs).

// allowedDaysExcludingToday returns a comma-separated day list (ISO 1=Mon..7=Sun)
// that excludes today, guaranteeing enforceSchedule denies on the day check
// alone — independent of the current hour.
func allowedDaysExcludingToday() string {
	today := int(time.Now().Weekday())
	if today == 0 {
		today = 7
	}
	var days []string
	for d := 1; d <= 7; d++ {
		if d == today {
			continue
		}
		days = append(days, strconv.Itoa(d))
	}
	return strings.Join(days, ",")
}

func TestGetSecretValue_DeniedOutsideAccessSchedule(t *testing.T) {
	c, db := newScheduleCore(t)
	ctx := context.Background()
	s := &models.SecretNode{ProjectID: 10, EnvironmentID: 10, Name: "sched-value-gate", IsSecret: true, Status: "active", Type: "generic"}
	require.NoError(t, db.Create(s).Error)
	require.NoError(t, db.Create(&models.SecretVersion{SecretNodeID: s.ID, VersionNumber: 1, EncryptedValue: []byte("topsecret")}).Error)

	require.NoError(t, db.Create(&models.SecretAccessSchedule{
		SecretNodeID: s.ID,
		AllowedDays:  allowedDaysExcludingToday(),
		StartHour:    0,
		EndHour:      24,
		Timezone:     "UTC",
	}).Error)

	_, err := c.GetSecretValue(ctx, s.ID)
	assert.ErrorIs(t, err, ErrAccessOutsideSchedule, "GetSecretValue must enforce the same schedule window as metadata reads")
}

func TestGetSecretValueByVersion_DeniedOutsideAccessSchedule(t *testing.T) {
	c, db := newScheduleCore(t)
	ctx := context.Background()
	s := &models.SecretNode{ProjectID: 10, EnvironmentID: 10, Name: "sched-value-byver-gate", IsSecret: true, Status: "active", Type: "generic"}
	require.NoError(t, db.Create(s).Error)
	require.NoError(t, db.Create(&models.SecretVersion{SecretNodeID: s.ID, VersionNumber: 1, EncryptedValue: []byte("topsecret")}).Error)

	require.NoError(t, db.Create(&models.SecretAccessSchedule{
		SecretNodeID: s.ID,
		AllowedDays:  allowedDaysExcludingToday(),
		StartHour:    0,
		EndHour:      24,
		Timezone:     "UTC",
	}).Error)

	_, err := c.GetSecretValueByVersion(ctx, s.ID, 1)
	assert.ErrorIs(t, err, ErrAccessOutsideSchedule, "GetSecretValueByVersion must enforce the same schedule window as metadata reads")
}

func TestGetSecretValue_AllowedWithinSchedule(t *testing.T) {
	c, db := newScheduleCore(t)
	ctx := context.Background()
	s := &models.SecretNode{ProjectID: 10, EnvironmentID: 10, Name: "sched-value-allow", IsSecret: true, Status: "active", Type: "generic"}
	require.NoError(t, db.Create(s).Error)
	require.NoError(t, db.Create(&models.SecretVersion{SecretNodeID: s.ID, VersionNumber: 1, EncryptedValue: []byte("topsecret")}).Error)

	require.NoError(t, db.Create(&models.SecretAccessSchedule{
		SecretNodeID: s.ID,
		AllowedDays:  "*",
		StartHour:    0,
		EndHour:      24,
		Timezone:     "UTC",
	}).Error)

	val, err := c.GetSecretValue(ctx, s.ID)
	require.NoError(t, err)
	assert.Equal(t, "topsecret", string(val))
}

// ── SetSecretSchedule / GetSecretSchedule / DeleteSecretSchedule ─────────────

func TestSetAndGetSecretSchedule(t *testing.T) {
	c, db := newScheduleCore(t)
	s := &models.SecretNode{ProjectID: 10, EnvironmentID: 10, Name: "sched-set", IsSecret: true, Status: "active"}
	require.NoError(t, db.Create(s).Error)

	got, err := c.SetSecretSchedule(context.Background(), s.ID, "1,2,3,4,5", 9, 17, "UTC")
	require.NoError(t, err)
	assert.Equal(t, "1,2,3,4,5", got.AllowedDays)
	assert.Equal(t, 9, got.StartHour)
	assert.Equal(t, 17, got.EndHour)
	assert.Equal(t, "UTC", got.Timezone)

	retrieved, err := c.GetSecretSchedule(context.Background(), s.ID)
	require.NoError(t, err)
	require.NotNil(t, retrieved)
	assert.Equal(t, "1,2,3,4,5", retrieved.AllowedDays)
}

func TestDeleteSecretSchedule(t *testing.T) {
	c, db := newScheduleCore(t)
	s := &models.SecretNode{ProjectID: 10, EnvironmentID: 10, Name: "sched-del", IsSecret: true, Status: "active"}
	require.NoError(t, db.Create(s).Error)

	_, err := c.SetSecretSchedule(context.Background(), s.ID, "*", 0, 24, "UTC")
	require.NoError(t, err)

	require.NoError(t, c.DeleteSecretSchedule(context.Background(), s.ID))

	retrieved, err := c.GetSecretSchedule(context.Background(), s.ID)
	require.NoError(t, err)
	assert.Nil(t, retrieved)
}

func TestSetSecretSchedule_ValidationError(t *testing.T) {
	c, _ := newScheduleCore(t)
	// start_hour > end_hour triggers validateScheduleParams error before storage is reached.
	_, err := c.SetSecretSchedule(context.Background(), 999, "*", 17, 9, "UTC")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "end_hour")
}

func TestSetSecretSchedule_StorageError(t *testing.T) {
	c, db := newScheduleCore(t)
	// Drop the table so storage.SetSecretAccessSchedule returns an error.
	require.NoError(t, db.Exec("DROP TABLE IF EXISTS secret_access_schedules").Error)
	_, err := c.SetSecretSchedule(context.Background(), 999, "*", 0, 24, "UTC")
	require.Error(t, err)
}

// ── validateScheduleParams ───────────────────────────────────────────────────

func TestValidateScheduleParams_Valid(t *testing.T) {
	assert.NoError(t, validateScheduleParams("1,2,3,4,5", 9, 17, "UTC"))
	assert.NoError(t, validateScheduleParams("*", 0, 24, "America/New_York"))
}

func TestValidateScheduleParams_BadStartHour(t *testing.T) {
	assert.Error(t, validateScheduleParams("*", -1, 17, "UTC"))
	assert.Error(t, validateScheduleParams("*", 24, 25, "UTC"))
}

func TestValidateScheduleParams_BadEndHour(t *testing.T) {
	assert.Error(t, validateScheduleParams("*", 9, 0, "UTC"))
	assert.Error(t, validateScheduleParams("*", 9, 25, "UTC"))
}

func TestValidateScheduleParams_EndNotAfterStart(t *testing.T) {
	assert.Error(t, validateScheduleParams("*", 17, 9, "UTC"))
	assert.Error(t, validateScheduleParams("*", 9, 9, "UTC"))
}

func TestValidateScheduleParams_BadTimezone(t *testing.T) {
	assert.Error(t, validateScheduleParams("*", 9, 17, "Not/A/Timezone"))
}

func TestValidateScheduleParams_BadDayValue(t *testing.T) {
	assert.Error(t, validateScheduleParams("0,1,2", 9, 17, "UTC")) // 0 is invalid
	assert.Error(t, validateScheduleParams("1,8", 9, 17, "UTC"))   // 8 is invalid
	assert.Error(t, validateScheduleParams("mon", 9, 17, "UTC"))   // string, not number
}
