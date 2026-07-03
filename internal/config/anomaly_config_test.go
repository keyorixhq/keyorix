package config

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestAnomalyAlertsConfig_GetBaselineQuarantine(t *testing.T) {
	assert.Equal(t, 24*time.Hour, AnomalyAlertsConfig{}.GetBaselineQuarantine(), "default when unset")
	assert.Equal(t, 24*time.Hour, AnomalyAlertsConfig{BaselineQuarantine: "garbage"}.GetBaselineQuarantine(), "unparseable falls back")
	assert.Equal(t, 6*time.Hour, AnomalyAlertsConfig{BaselineQuarantine: "6h"}.GetBaselineQuarantine())
	// "0"/"0s" is an explicit opt-out, not "unset" — must NOT fall back to the default.
	assert.Equal(t, time.Duration(0), AnomalyAlertsConfig{BaselineQuarantine: "0"}.GetBaselineQuarantine())
	assert.Equal(t, time.Duration(0), AnomalyAlertsConfig{BaselineQuarantine: "0s"}.GetBaselineQuarantine())
}
