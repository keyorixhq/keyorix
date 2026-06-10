package config

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestSoftDeleteConfig_GetRetentionDays(t *testing.T) {
	assert.Equal(t, 30, SoftDeleteConfig{}.GetRetentionDays(), "default when unset")
	assert.Equal(t, 30, SoftDeleteConfig{RetentionDays: 0}.GetRetentionDays())
	assert.Equal(t, 30, SoftDeleteConfig{RetentionDays: -5}.GetRetentionDays(), "negative falls back to default")
	assert.Equal(t, 7, SoftDeleteConfig{RetentionDays: 7}.GetRetentionDays())
}

func TestPurgeConfig_GetInterval(t *testing.T) {
	assert.Equal(t, 24*time.Hour, PurgeConfig{}.GetInterval(), "default when unset")
	assert.Equal(t, 24*time.Hour, PurgeConfig{Schedule: "garbage"}.GetInterval(), "unparseable falls back")
	assert.Equal(t, 6*time.Hour, PurgeConfig{Schedule: "6h"}.GetInterval())
	assert.Equal(t, 90*time.Minute, PurgeConfig{Schedule: "90m"}.GetInterval())
}
