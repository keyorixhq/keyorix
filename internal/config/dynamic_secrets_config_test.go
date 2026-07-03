package config

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestDynamicSecretsConfig_GetMaxLeaseTTL(t *testing.T) {
	assert.Equal(t, 90*24*time.Hour, DynamicSecretsConfig{}.GetMaxLeaseTTL(), "default when unset")
	assert.Equal(t, 90*24*time.Hour, DynamicSecretsConfig{MaxLeaseTTL: "garbage"}.GetMaxLeaseTTL(), "unparseable falls back")
	assert.Equal(t, 720*time.Hour, DynamicSecretsConfig{MaxLeaseTTL: "720h"}.GetMaxLeaseTTL())
}
