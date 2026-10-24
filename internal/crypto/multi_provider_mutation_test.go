package crypto

// Tests added for the gremlins survivors in multi_provider.go (#3612,
// MUTANT-CRYPTO-1).

import (
	"bytes"
	"errors"
	"log"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// recProvider records the order in which providers are consulted.
type recProvider struct {
	name  string
	key   []byte
	err   error
	calls *[]string
}

func (p *recProvider) Name() string { return p.name }
func (p *recProvider) KEK() ([]byte, error) {
	*p.calls = append(*p.calls, p.name)
	return p.key, p.err
}

func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prevW, prevF := log.Writer(), log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	t.Cleanup(func() { log.SetOutput(prevW); log.SetFlags(prevF) })
	return &buf
}

func okRec(calls *[]string, name string) *recProvider {
	return &recProvider{name: name, key: testKEK(), calls: calls}
}

func failRec(calls *[]string, name, msg string) *recProvider {
	return &recProvider{name: name, err: errors.New(msg), calls: calls}
}

// multi_provider.go:66 — the "<name> succeeded" line is emitted only when more
// than one provider is configured (a single-provider chain stays quiet; two is
// the smallest chain that logs).
func TestMultiKEK_SucceededLogOnlyForChains(t *testing.T) {
	var calls []string

	buf := captureLog(t)
	single, err := NewMultiKeyProvider([]KeyProvider{okRec(&calls, "password")})
	require.NoError(t, err)
	_, err = single.KEK()
	require.NoError(t, err)
	assert.NotContains(t, buf.String(), "succeeded", "a single provider must not log a chain-success line")

	buf.Reset()
	pair, err := NewMultiKeyProvider([]KeyProvider{okRec(&calls, "password"), okRec(&calls, "file")})
	require.NoError(t, err)
	_, err = pair.KEK()
	require.NoError(t, err)
	assert.Contains(t, buf.String(), "key provider: password succeeded")
}

// Providers are tried strictly in configured order and the first success wins:
// later providers are never consulted.
func TestMultiKEK_OrderAndShortCircuit(t *testing.T) {
	var calls []string
	winner := okRec(&calls, "file")
	m, err := NewMultiKeyProvider([]KeyProvider{
		failRec(&calls, "tpm", "no tpm"),
		failRec(&calls, "aws-kms", "no network"),
		winner,
		okRec(&calls, "password"),
	})
	require.NoError(t, err)

	key, err := m.KEK()
	require.NoError(t, err)
	assert.Equal(t, winner.key, key)
	assert.Equal(t, []string{"tpm", "aws-kms", "file"}, calls, "the provider after the first success must not be tried")
}

func TestMultiKEK_AllFail_ErrorListsEveryProviderInOrder(t *testing.T) {
	var calls []string
	m, err := NewMultiKeyProvider([]KeyProvider{
		failRec(&calls, "tpm", "boom-1"),
		failRec(&calls, "file", "boom-2"),
	})
	require.NoError(t, err)

	key, err := m.KEK()
	require.Error(t, err)
	assert.Nil(t, key)
	assert.EqualError(t, err, "all key providers failed: tpm: boom-1; file: boom-2")
	assert.Equal(t, []string{"tpm", "file"}, calls)
}

// A configuration refusal must stop the chain: falling through would turn it
// into a silent downgrade.
func TestMultiKEK_ContextFallbackRefusalStopsTheChain(t *testing.T) {
	var calls []string
	refuse := &recProvider{name: "aws-kms", err: ErrKMSContextFallbackNotNeeded, calls: &calls}
	m, err := NewMultiKeyProvider([]KeyProvider{refuse, okRec(&calls, "password")})
	require.NoError(t, err)

	key, err := m.KEK()
	require.ErrorIs(t, err, ErrKMSContextFallbackNotNeeded)
	assert.Nil(t, key)
	assert.Equal(t, []string{"aws-kms"}, calls, "the fallback provider must not be consulted after a refusal")
}

// The downgrade log line and hook fire together on a real downgrade and not at
// all on a same-tier fallback.
func TestMultiKEK_DowngradeSignalsOnlyOnRealDowngrade(t *testing.T) {
	var calls []string

	buf := captureLog(t)
	same, err := NewMultiKeyProvider([]KeyProvider{failRec(&calls, "aws-kms", "x"), okRec(&calls, "gcp-kms")})
	require.NoError(t, err)
	hooked := false
	same.SetDowngradeHook(func(FallbackDowngrade) { hooked = true })
	_, err = same.KEK()
	require.NoError(t, err)
	assert.False(t, hooked)
	assert.NotContains(t, buf.String(), "SECURITY:")

	buf.Reset()
	down, err := NewMultiKeyProvider([]KeyProvider{failRec(&calls, "aws-kms", "x"), okRec(&calls, "password")})
	require.NoError(t, err)
	var got FallbackDowngrade
	down.SetDowngradeHook(func(d FallbackDowngrade) { got = d })
	_, err = down.KEK()
	require.NoError(t, err)
	assert.Equal(t, FallbackDowngrade{Index: 1, Provider: "password", FromTier: TierHardware, ToTier: TierSoftware}, got)
	assert.Contains(t, buf.String(), "SECURITY: key provider fallback downgraded KEK strength")

	// A primary that succeeds is never a downgrade, whatever its tier.
	buf.Reset()
	got = FallbackDowngrade{}
	first, err := NewMultiKeyProvider([]KeyProvider{okRec(&calls, "password"), okRec(&calls, "tpm")})
	require.NoError(t, err)
	first.SetDowngradeHook(func(d FallbackDowngrade) { got = d })
	_, err = first.KEK()
	require.NoError(t, err)
	assert.Equal(t, FallbackDowngrade{}, got)
	assert.NotContains(t, buf.String(), "SECURITY:")
}
