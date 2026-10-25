package cryptoinventory

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var riskNow = time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)

func ptrTime(t time.Time) *time.Time { return &t }

func aes256DEK() Asset {
	return Asset{ID: "dek", Class: ClassDEK, Primitive: "ae", Algorithm: "AES-256-GCM", KeySizeBits: 256}
}

func classical(alg string, bits int, expires *time.Time) Asset {
	return Asset{ID: "x", Class: ClassTLSCertificate, Primitive: "signature", Algorithm: alg,
		KeySizeBits: bits, Asymmetric: true, ExpiresAt: expires}
}

func TestAssess_AES256IsLowRisk(t *testing.T) {
	r := DefaultPolicy().Assess(aes256DEK(), riskNow)
	assert.False(t, r.QuantumVulnerable)
	assert.Equal(t, LevelLow, r.Level)
	assert.Less(t, r.Score, 20)
}

func TestAssess_ClassicalAsymmetricIsFlagged(t *testing.T) {
	for _, tc := range []struct {
		alg  string
		bits int
	}{{"RSA-2048", 2048}, {"ECDSA-P256", 256}, {"Ed25519", 256}, {"ECDSA-P384", 384}} {
		t.Run(tc.alg, func(t *testing.T) {
			r := DefaultPolicy().Assess(classical(tc.alg, tc.bits, ptrTime(riskNow.Add(90*24*time.Hour))), riskNow)
			assert.True(t, r.QuantumVulnerable, "Shor breaks %s regardless of size", tc.alg)
			assert.GreaterOrEqual(t, r.Score, 40, "classical-only asymmetric must not score low")
			assert.NotEqual(t, LevelLow, r.Level)
			assert.NotEmpty(t, r.Reasons)
		})
	}
}

func TestAssess_ClassicalAlwaysAboveAES256(t *testing.T) {
	p := DefaultPolicy()
	aes := p.Assess(aes256DEK(), riskNow).Score
	soon := p.Assess(classical("ECDSA-P256", 256, ptrTime(riskNow.Add(24*time.Hour))), riskNow).Score
	assert.Greater(t, soon, aes)
}

func TestAssess_LongerLivedClassicalKeyScoresHigher(t *testing.T) {
	p := DefaultPolicy()
	short := p.Assess(classical("RSA-2048", 2048, ptrTime(riskNow.Add(30*24*time.Hour))), riskNow)
	noExpiry := p.Assess(classical("RSA-2048", 2048, nil), riskNow)
	assert.Greater(t, noExpiry.Score, short.Score, "a key with no expiry outlives the horizon")
	assert.Equal(t, LevelHigh, noExpiry.Level)
	assert.LessOrEqual(t, noExpiry.Score, 100)
}

func TestAssess_ExpiryBeyondHorizonScoresHigherThanBefore(t *testing.T) {
	p := DefaultPolicy()
	before := p.Assess(classical("ECDSA-P256", 256, ptrTime(p.Horizon.AddDate(-3, 0, 0))), riskNow)
	after := p.Assess(classical("ECDSA-P256", 256, ptrTime(p.Horizon.AddDate(3, 0, 0))), riskNow)
	assert.Greater(t, after.Score, before.Score)
}

func TestAssess_HorizonIsConfigurable(t *testing.T) {
	a := classical("RSA-2048", 2048, ptrTime(riskNow.AddDate(5, 0, 0)))
	near := Policy{Horizon: riskNow.AddDate(2, 0, 0), MigrationYears: 3, UnboundedLifetimeYears: 10}
	far := Policy{Horizon: riskNow.AddDate(40, 0, 0), MigrationYears: 3, UnboundedLifetimeYears: 10}
	assert.Greater(t, near.Assess(a, riskNow).Score, far.Assess(a, riskNow).Score)
}

func TestAssess_HorizonAlreadyPassedIsWorstCase(t *testing.T) {
	p := Policy{Horizon: riskNow.AddDate(-1, 0, 0), MigrationYears: 3, UnboundedLifetimeYears: 10}
	r := p.Assess(classical("RSA-2048", 2048, nil), riskNow)
	assert.Equal(t, LevelHigh, r.Level)
	assert.LessOrEqual(t, r.Score, 100)
}

func TestAssess_AES128IsBetweenAES256AndClassical(t *testing.T) {
	p := DefaultPolicy()
	a128 := Asset{ID: "k", Class: ClassDEK, Primitive: "ae", Algorithm: "AES-128-GCM", KeySizeBits: 128}
	s128 := p.Assess(a128, riskNow)
	assert.False(t, s128.QuantumVulnerable, "Grover halves the exponent; it does not break AES")
	assert.Greater(t, s128.Score, p.Assess(aes256DEK(), riskNow).Score)
	assert.Less(t, s128.Score, p.Assess(classical("RSA-2048", 2048, nil), riskNow).Score)
}

func TestAssess_HybridAndPostQuantumScoreLow(t *testing.T) {
	p := DefaultPolicy()
	hybrid := Asset{ID: "h", Class: ClassDEK, Primitive: "kem", Algorithm: "X25519+ML-KEM-768",
		KeySizeBits: 256, Asymmetric: true, PostQuantum: true}
	r := p.Assess(hybrid, riskNow)
	assert.False(t, r.QuantumVulnerable)
	assert.Equal(t, LevelLow, r.Level)
}

func TestAssess_HashVerifierOfHighEntropySecretIsLow(t *testing.T) {
	a := Asset{ID: "rk", Class: ClassRecoveryKey, Primitive: "hash", Algorithm: "SHA-256", KeySizeBits: 260}
	assert.Equal(t, LevelLow, DefaultPolicy().Assess(a, riskNow).Level)
}

func TestAssess_ScoreAlwaysInRange(t *testing.T) {
	p := DefaultPolicy()
	for _, a := range []Asset{
		aes256DEK(),
		classical("RSA-1024", 1024, nil),
		classical("RSA-4096", 4096, ptrTime(riskNow.AddDate(100, 0, 0))),
		classical("ECDSA-P256", 256, ptrTime(riskNow.AddDate(-1, 0, 0))), // already expired
		{ID: "u", Algorithm: "mystery"},
	} {
		r := p.Assess(a, riskNow)
		assert.GreaterOrEqual(t, r.Score, 0, a.Algorithm)
		assert.LessOrEqual(t, r.Score, 100, a.Algorithm)
	}
}

func TestAssess_UnknownAlgorithmFailsClosedToMedium(t *testing.T) {
	r := DefaultPolicy().Assess(Asset{ID: "u", Algorithm: "mystery"}, riskNow)
	assert.NotEqual(t, LevelLow, r.Level, "an unclassifiable algorithm must not be reported as safe")
}

func TestDefaultPolicy_Documented(t *testing.T) {
	p := DefaultPolicy()
	assert.Equal(t, 2035, p.Horizon.Year(), "default horizon follows NIST IR 8547 (classical public-key disallowed 2035)")
	assert.Equal(t, 3, p.MigrationYears)
	assert.Equal(t, 10, p.UnboundedLifetimeYears)
	require.NoError(t, p.Validate())
}

func TestPolicyValidate(t *testing.T) {
	assert.Error(t, Policy{MigrationYears: 3, UnboundedLifetimeYears: 10}.Validate(), "zero horizon")
	assert.Error(t, Policy{Horizon: riskNow, MigrationYears: -1, UnboundedLifetimeYears: 10}.Validate())
	assert.Error(t, Policy{Horizon: riskNow, MigrationYears: 3, UnboundedLifetimeYears: 0}.Validate())
}
