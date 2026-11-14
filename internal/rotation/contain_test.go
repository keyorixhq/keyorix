package rotation

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/dynamic"
)

type panicExec struct{}

func (panicExec) Name() string { return "probe" }
func (panicExec) Type() string { return "probe" }
func (panicExec) Rotate(context.Context, string, string) error {
	panic("bad reply from postgres://admin:hunter2@db.internal/app")
}

type panicGenExec struct{ panicExec }

func (panicGenExec) GenerateUpstream(context.Context, string) (string, error) {
	panic("bad reply from postgres://admin:hunter2@db.internal/app")
}

func TestManagerContainsExecutorPanics(t *testing.T) {
	m := NewManager([]Executor{panicExec{}, panicGenExec{}, nil})
	e, ok := m.Get("probe")
	if !ok {
		t.Fatal("executor missing")
	}
	// the later entry (generating) won the name collision
	g, isGen := e.(GeneratingExecutor)
	if !isGen {
		t.Fatal("a generating executor must stay generating after containment")
	}
	err := e.Rotate(context.Background(), "r", "v")
	if !errors.Is(err, dynamic.ErrEngineClientPanic) || strings.Contains(err.Error(), "hunter2") {
		t.Fatalf("Rotate: %v", err)
	}
	_, err = g.GenerateUpstream(context.Background(), "r")
	if !errors.Is(err, dynamic.ErrEngineClientPanic) || strings.Contains(err.Error(), "hunter2") {
		t.Fatalf("GenerateUpstream: %v", err)
	}
}

func TestContainedExecutorDoesNotBecomeGenerating(t *testing.T) {
	e, _ := NewManager([]Executor{panicExec{}}).Get("probe")
	if _, isGen := e.(GeneratingExecutor); isGen {
		t.Fatal("containment must not make a plain executor look like a generating one")
	}
	if containExecutor(e) != e {
		t.Fatal("containExecutor must be idempotent")
	}
}
