package rotation

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type stubExec struct{ name string }

func (s stubExec) Name() string                                 { return s.name }
func (s stubExec) Type() string                                 { return "stub" }
func (s stubExec) Rotate(context.Context, string, string) error { return nil }

func TestManager_RegistryAndNilSkip(t *testing.T) {
	m := NewManager([]Executor{stubExec{name: "a"}, stubExec{name: "b"}, nil})
	a, ok := m.Get("a")
	require.True(t, ok)
	assert.Equal(t, "a", a.Name())
	_, ok = m.Get("missing")
	assert.False(t, ok)
	assert.ElementsMatch(t, []string{"a", "b"}, m.Names())
}

func TestPrefixAllowed(t *testing.T) {
	assert.True(t, prefixAllowed(nil, "anything"))             // empty = unrestricted
	assert.True(t, prefixAllowed([]string{"app_"}, "app_svc")) // prefix match
	assert.False(t, prefixAllowed([]string{"app_"}, "root"))   // no match
	assert.False(t, prefixAllowed([]string{""}, "x"))          // empty prefix never matches
}
