package config

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// #222/#435: the gRPC server has no way to detect and reclaim idle/abandoned
// connections without keepalive, a slow-drip goroutine/fd exhaustion surface. These
// accessors are what NewServer wires into grpc.KeepaliveParams / KeepaliveEnforcementPolicy.
func TestGRPCKeepaliveConfig_GetTime(t *testing.T) {
	assert.Equal(t, 5*time.Minute, GRPCKeepaliveConfig{}.GetTime(), "default when unset")
	assert.Equal(t, 5*time.Minute, GRPCKeepaliveConfig{Time: "garbage"}.GetTime(), "unparseable falls back")
	assert.Equal(t, 2*time.Minute, GRPCKeepaliveConfig{Time: "2m"}.GetTime())
}

func TestGRPCKeepaliveConfig_GetTimeout(t *testing.T) {
	assert.Equal(t, 20*time.Second, GRPCKeepaliveConfig{}.GetTimeout(), "default when unset")
	assert.Equal(t, 20*time.Second, GRPCKeepaliveConfig{Timeout: "garbage"}.GetTimeout(), "unparseable falls back")
	assert.Equal(t, 10*time.Second, GRPCKeepaliveConfig{Timeout: "10s"}.GetTimeout())
}

func TestGRPCKeepaliveConfig_GetMinTime(t *testing.T) {
	assert.Equal(t, 5*time.Minute, GRPCKeepaliveConfig{}.GetMinTime(), "default when unset")
	assert.Equal(t, 5*time.Minute, GRPCKeepaliveConfig{MinTime: "garbage"}.GetMinTime(), "unparseable falls back")
	assert.Equal(t, 30*time.Second, GRPCKeepaliveConfig{MinTime: "30s"}.GetMinTime())
}

// GRPC-008: MaxConnectionAge/MaxConnectionAgeGrace force periodic reconnection so a
// stream-slot-holding attacker can't pin audit-stream slots indefinitely.
func TestGRPCKeepaliveConfig_GetMaxConnectionAge(t *testing.T) {
	assert.Equal(t, time.Hour, GRPCKeepaliveConfig{}.GetMaxConnectionAge(), "default when unset")
	assert.Equal(t, time.Hour, GRPCKeepaliveConfig{MaxConnectionAge: "garbage"}.GetMaxConnectionAge(), "unparseable falls back")
	assert.Equal(t, 15*time.Minute, GRPCKeepaliveConfig{MaxConnectionAge: "15m"}.GetMaxConnectionAge())
}

func TestGRPCKeepaliveConfig_GetMaxConnectionAgeGrace(t *testing.T) {
	assert.Equal(t, 30*time.Second, GRPCKeepaliveConfig{}.GetMaxConnectionAgeGrace(), "default when unset")
	assert.Equal(t, 30*time.Second, GRPCKeepaliveConfig{MaxConnectionAgeGrace: "garbage"}.GetMaxConnectionAgeGrace(), "unparseable falls back")
	assert.Equal(t, 5*time.Second, GRPCKeepaliveConfig{MaxConnectionAgeGrace: "5s"}.GetMaxConnectionAgeGrace())
}
