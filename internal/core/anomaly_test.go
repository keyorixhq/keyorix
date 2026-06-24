package core

import (
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildBaseline(t *testing.T) {
	now := time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC)
	logs := []models.SecretAccessLog{
		{IPAddress: "10.0.0.1", AccessedBy: "alice", AccessTime: now.Add(-1 * time.Hour)},       // in 7d
		{IPAddress: "10.0.0.2", AccessedBy: "bob", AccessTime: now.Add(-2 * 24 * time.Hour)},    // in 7d
		{IPAddress: "10.0.0.1", AccessedBy: "alice", AccessTime: now.Add(-20 * 24 * time.Hour)}, // older than 7d
	}
	b := buildBaseline(logs, now)
	if !b.knownIPs["10.0.0.1"] || !b.knownIPs["10.0.0.2"] {
		t.Fatalf("expected both IPs learned, got %v", b.knownIPs)
	}
	if !b.knownUsers["alice"] || !b.knownUsers["bob"] {
		t.Fatalf("expected both users learned, got %v", b.knownUsers)
	}
	// 2 of 3 accesses fall in the last 7 days → dailyAvg = 2/7.
	if want := 2.0 / 7.0; b.dailyAvg != want {
		t.Fatalf("dailyAvg = %v, want %v", b.dailyAvg, want)
	}
}

func TestDetectAnomalies(t *testing.T) {
	secret := models.SecretNode{ID: 1, Name: "db"}
	baseline := accessBaseline{
		knownIPs:   map[string]bool{"10.0.0.1": true},
		knownUsers: map[string]bool{"alice": true},
	}

	t.Run("off-hours + new IP + new user all fire", func(t *testing.T) {
		// 03:00 UTC is off-hours; unknown IP + unknown user against a non-empty baseline.
		lg := models.SecretAccessLog{
			IPAddress:  "8.8.8.8",
			AccessedBy: "mallory",
			AccessTime: time.Date(2026, 6, 17, 3, 0, 0, 0, time.UTC),
		}
		got := kindsOf(detectAnomalies(secret, lg, baseline, defaultOffHoursPolicy()))
		for _, want := range []string{"off_hours", "new_ip", "new_user"} {
			if !got[want] {
				t.Errorf("expected %s alert, got %v", want, got)
			}
		}
	})

	t.Run("business-hours known IP+user → no alert", func(t *testing.T) {
		lg := models.SecretAccessLog{
			IPAddress:  "10.0.0.1",
			AccessedBy: "alice",
			AccessTime: time.Date(2026, 6, 17, 14, 0, 0, 0, time.UTC),
		}
		if alerts := detectAnomalies(secret, lg, baseline, defaultOffHoursPolicy()); len(alerts) != 0 {
			t.Fatalf("expected no alerts, got %v", kindsOf(alerts))
		}
	})

	t.Run("empty baseline suppresses new-ip/new-user", func(t *testing.T) {
		// Bootstrapping: with no history, an unknown IP/user must not flag (only off-hours,
		// which is time-based, can fire). Use a business-hours time so nothing fires.
		lg := models.SecretAccessLog{
			IPAddress:  "8.8.8.8",
			AccessedBy: "mallory",
			AccessTime: time.Date(2026, 6, 17, 14, 0, 0, 0, time.UTC),
		}
		empty := accessBaseline{knownIPs: map[string]bool{}, knownUsers: map[string]bool{}}
		if alerts := detectAnomalies(secret, lg, empty, defaultOffHoursPolicy()); len(alerts) != 0 {
			t.Fatalf("expected no alerts against an empty baseline, got %v", kindsOf(alerts))
		}
	})
}

// The off-hours decision must be evaluated in the configured timezone: the same
// instant can be off-hours in UTC but business hours elsewhere. This is the bug the
// hardcoded-UTC rule had on non-UTC deployments.
func TestOffHoursPolicy(t *testing.T) {
	la, err := time.LoadLocation("America/Los_Angeles")
	require.NoError(t, err)

	// 2026-06-17 01:00 UTC == 2026-06-16 18:00 PDT (UTC-7 in summer).
	instant := time.Date(2026, 6, 17, 1, 0, 0, 0, time.UTC)

	if !defaultOffHoursPolicy().isOffHours(instant) {
		t.Errorf("01:00 UTC must be off-hours under the UTC 22–6 default")
	}
	pacific := offHoursPolicy{loc: la, start: 22, end: 6}
	if pacific.isOffHours(instant) {
		t.Errorf("18:00 PDT (same instant) must NOT be off-hours under a Pacific 22–6 band")
	}

	// A non-wrapping band [9,17) is a normal interval.
	day := offHoursPolicy{loc: time.UTC, start: 9, end: 17}
	if !day.isOffHours(time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC)) {
		t.Errorf("12:00 must fall inside a non-wrapping [9,17) band")
	}
	if day.isOffHours(time.Date(2026, 6, 17, 20, 0, 0, 0, time.UTC)) {
		t.Errorf("20:00 must fall outside a non-wrapping [9,17) band")
	}
}

func TestSetBusinessHours(t *testing.T) {
	d := NewAnomalyDetector(nil)

	// Timezone only: the default 22–6 band is kept (both hours 0 = unset).
	require.NoError(t, d.SetBusinessHours("America/New_York", 0, 0))
	assert.Equal(t, "America/New_York", d.offHours.loc.String())
	assert.Equal(t, 22, d.offHours.start)
	assert.Equal(t, 6, d.offHours.end)

	// Custom band applied.
	require.NoError(t, d.SetBusinessHours("UTC", 20, 7))
	assert.Equal(t, 20, d.offHours.start)
	assert.Equal(t, 7, d.offHours.end)

	// Invalid timezone: error, and the prior policy is left unchanged.
	before := d.offHours
	require.Error(t, d.SetBusinessHours("Not/AZone", 1, 2))
	assert.Equal(t, before, d.offHours, "an invalid timezone must not mutate the policy")
}

func TestVolumeSpike(t *testing.T) {
	now := time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC)
	secret := models.SecretNode{ID: 1, Name: "db"}

	// Busy secret: dailyAvg 240 → hourlyAvg 10. Threshold = 3×10 = 30, floor 10.
	busy := accessBaseline{dailyAvg: 240}
	if isVolumeSpike(25, busy) {
		t.Error("25 reads vs a 10/hour baseline should NOT be a spike (≤ 3×)")
	}
	if !isVolumeSpike(40, busy) {
		t.Error("40 reads vs a 10/hour baseline should be a spike (> 3×)")
	}

	// Quiet secret: tiny baseline, but the absolute floor prevents flagging a few reads.
	quiet := accessBaseline{dailyAvg: 1}
	if isVolumeSpike(9, quiet) {
		t.Error("9 reads is below the absolute floor and must not flag")
	}
	if !isVolumeSpike(12, quiet) {
		t.Error("12 reads on a near-zero baseline should flag (floor met, far above 3×)")
	}

	// volumeSpikeAlert wraps the decision and carries no single accessor/IP.
	if a := volumeSpikeAlert(secret, 25, busy, now); a != nil {
		t.Errorf("expected nil alert below threshold, got %+v", a)
	}
	a := volumeSpikeAlert(secret, 40, busy, now)
	if a == nil || a.AlertType != "frequency_spike" || a.SecretNodeID != 1 {
		t.Fatalf("expected a frequency_spike alert for secret 1, got %+v", a)
	}
	if a.AccessedBy != "" || a.IPAddress != "" {
		t.Errorf("aggregate spike alert should carry no accessor/IP, got by=%q ip=%q", a.AccessedBy, a.IPAddress)
	}
}

func TestFilterAlerts(t *testing.T) {
	alerts := []models.AnomalyAlert{
		{AlertType: "off_hours", Severity: "medium"},
		{AlertType: "new_ip", Severity: "high"},
		{AlertType: "frequency_spike", Severity: "medium"},
		{AlertType: "new_user", Severity: "high"},
	}

	// No constraint returns the input unchanged.
	assert.Len(t, FilterAlerts(alerts, "", ""), 4)

	// Severity only.
	high := FilterAlerts(alerts, "high", "")
	assert.Len(t, high, 2)
	for _, a := range high {
		assert.Equal(t, "high", a.Severity)
	}

	// Type only.
	spikes := FilterAlerts(alerts, "", "frequency_spike")
	require.Len(t, spikes, 1)
	assert.Equal(t, "frequency_spike", spikes[0].AlertType)

	// Both must match (AND).
	assert.Empty(t, FilterAlerts(alerts, "high", "frequency_spike"), "high + frequency_spike matches nothing here")
	require.Len(t, FilterAlerts(alerts, "medium", "off_hours"), 1)
}

func kindsOf(alerts []models.AnomalyAlert) map[string]bool {
	m := map[string]bool{}
	for _, a := range alerts {
		m[a.AlertType] = true
	}
	return m
}
