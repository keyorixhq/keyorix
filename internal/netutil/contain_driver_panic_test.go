package netutil

import (
	"bytes"
	"context"
	"errors"
	"log"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// containing runs fn under ContainDriverPanic the way a boundary function does.
func containing(op string, fn func()) (err error) {
	defer ContainDriverPanic(op, &err)
	fn()
	return nil
}

func TestContainDriverPanic_PanicBecomesError(t *testing.T) {
	t.Parallel()
	err := containing("test op", func() { panic("sensitive-looking detail") })
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrDriverPanic)
	assert.Contains(t, err.Error(), "test op")
	assert.NotContains(t, err.Error(), "sensitive-looking detail", "panic text must stay in the log, not the returned error")
}

func TestContainDriverPanic_RuntimeErrorIsContained(t *testing.T) {
	t.Parallel()
	var s []int
	idx := 5
	err := containing("test op", func() { _ = s[idx] })
	require.ErrorIs(t, err, ErrDriverPanic)
}

func TestContainDriverPanic_ContextErrorsAreNotSwallowed(t *testing.T) {
	t.Parallel()
	for name, cause := range map[string]error{
		"canceled": context.Canceled,
		"deadline": context.DeadlineExceeded,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			err := containing("test op", func() { panic(cause) })
			require.ErrorIs(t, err, cause)
			assert.NotErrorIs(t, err, ErrDriverPanic)
		})
	}
}

func TestContainDriverPanic_NormalReturnIsUntouched(t *testing.T) {
	t.Parallel()
	assert.NoError(t, containing("test op", func() {}))

	sentinel := errors.New("ordinary failure")
	wantErr := func() (err error) {
		defer ContainDriverPanic("test op", &err)
		return sentinel
	}()
	assert.Same(t, sentinel, wantErr)
}

func TestContainDriverPanic_NilErrorPointerDoesNotPanic(t *testing.T) {
	t.Parallel()
	assert.NotPanics(t, func() {
		func() {
			defer ContainDriverPanic("test op", nil)
			panic("x")
		}()
	})
}

// A panic value can carry text from a remote peer; it must not be able to start
// a second log line of its own, least of all one that looks like a SECURITY: line.
// Not parallel: it swaps the process-wide logger output.
func TestContainDriverPanic_LogCannotBeForged(t *testing.T) {
	var buf bytes.Buffer
	prevW, prevF := log.Writer(), log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	defer func() { log.SetOutput(prevW); log.SetFlags(prevF) }()

	_ = containing("test op", func() { panic("first\nSECURITY: forged line") })

	out := buf.String()
	require.True(t, strings.HasPrefix(out, "SECURITY: panic from a third-party database driver contained during test op: "))
	assert.NotContains(t, out, "\nSECURITY: forged", "the panic text must be quoted onto one line")
	starts := 0
	for line := range strings.SplitSeq(out, "\n") {
		if strings.HasPrefix(line, "SECURITY:") {
			starts++
		}
	}
	assert.Equal(t, 1, starts, "exactly one log line may start with SECURITY:")
}
