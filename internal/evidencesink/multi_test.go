package evidencesink

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type stubForwarder struct {
	label string
	calls int
	err   error
}

func (s *stubForwarder) ForwardEvidence(_ context.Context, _ string, _ []byte, _ string) error {
	s.calls++
	return s.err
}
func (s *stubForwarder) Target() string { return s.label }

func TestMulti_DeliversToAllTargets(t *testing.T) {
	a := &stubForwarder{label: "webhook"}
	b := &stubForwarder{label: "objectstore:bkt/"}
	m := NewMulti(a, b)

	require.NoError(t, m.ForwardEvidence(context.Background(), "pack.json", []byte(`{}`), "v1:x"))
	assert.Equal(t, 1, a.calls)
	assert.Equal(t, 1, b.calls)
	assert.Equal(t, "webhook+objectstore:bkt/", m.Target())
}

func TestMulti_AttemptsAllAndAggregatesErrors(t *testing.T) {
	a := &stubForwarder{label: "webhook", err: errors.New("boom")}
	b := &stubForwarder{label: "objectstore:bkt/"} // succeeds
	m := NewMulti(a, b)

	err := m.ForwardEvidence(context.Background(), "pack.json", []byte(`{}`), "")
	require.Error(t, err, "any failure surfaces as an error")
	assert.Equal(t, 1, a.calls)
	assert.Equal(t, 1, b.calls, "a failing target does not stop the others")
	assert.Contains(t, err.Error(), "webhook")
}
