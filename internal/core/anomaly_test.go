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
	windowStart := now.Add(-1 * time.Hour) // the live detection window — excluded from the baseline
	logs := []models.SecretAccessLog{
		{IPAddress: "203.0.113.9", AccessedBy: "mallory", AccessTime: now.Add(-30 * time.Minute)}, // inside window → excluded
		{IPAddress: "10.0.0.2", AccessedBy: "bob", AccessTime: now.Add(-2 * 24 * time.Hour)},       // in 7d, before window
		{IPAddress: "10.0.0.1", AccessedBy: "alice", AccessTime: now.Add(-20 * 24 * time.Hour)},    // older than 7d
	}
	b := buildBaseline(logs, now, windowStart)
	// The in-window read must NOT seed the baseline, else it would mask its own anomaly.
	if b.knownIPs["203.0.113.9"] || b.knownUsers["mallory"] {
		t.Fatalf("in-window read must be excluded from the baseline, got IPs=%v users=%v", b.knownIPs, b.knownUsers)
	}
	if !b.knownIPs["10.0.0.1"] || !b.knownIPs["10.0.0.2"] {
		t.Fatalf("expected historical IPs learned, got %v", b.knownIPs)
	}
	if !b.knownUsers["alice"] || !b.knownUsers["bob"] {
		t.Fatalf("expected historical users learned, got %v", b.knownUsers)
	}
	// Of the pre-window reads, only bob's (-2d) is within the last 7 days → dailyAvg = 1/7.
	if want := 1.0 / 7.0; b.dailyAvg != want {
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
		got := kindsOf(detectAnomalies(secret, lg, baseline))
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
		if alerts := detectAnomalies(secret, lg, baseline); len(alerts) != 0 {
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
		if alerts := detectAnomalies(secret, lg, empty); len(alerts) != 0 {
			t.Fatalf("expected no alerts against an empty baseline, got %v", kindsOf(alerts))
		}
	})
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
