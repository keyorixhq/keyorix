package rotation

import (
	"context"

	"github.com/keyorixhq/keyorix/internal/dynamic"
)

const executorComponent = "rotation executor"

// containedExecutor decorates an Executor so a client-library panic in Rotate comes
// back as *dynamic.EngineClientPanicError (errors.Is dynamic.ErrEngineClientPanic),
// the same containment internal/dynamic applies to its engines. NewManager applies it
// to every executor it registers.
type containedExecutor struct {
	inner Executor
}

// containedGenerating additionally exposes GenerateUpstream. It is a separate type so
// an executor that cannot generate upstream never starts to look like one: core
// type-asserts ports.GeneratingRotationExecutor to choose GenerateUpstream over Rotate.
type containedGenerating struct {
	containedExecutor
	gen GeneratingExecutor
}

func containExecutor(e Executor) Executor {
	switch v := e.(type) {
	case *containedExecutor, *containedGenerating:
		return e
	case GeneratingExecutor:
		return &containedGenerating{containedExecutor: containedExecutor{inner: v}, gen: v}
	default:
		return &containedExecutor{inner: e}
	}
}

func (c *containedExecutor) Name() string { return c.inner.Name() }
func (c *containedExecutor) Type() string { return c.inner.Type() }

func (c *containedExecutor) Rotate(ctx context.Context, ref, newValue string) (err error) {
	defer dynamic.RecoverClientPanic(executorComponent, c.inner.Name(), "Rotate", &err)()
	return c.inner.Rotate(ctx, ref, newValue)
}

// GenerateUpstream: a panic after the cloud minted the key loses the key material the
// upstream returns only once; the typed error tells the operator the rotation did not
// complete and the log line names the executor, so the leftover key can be removed.
func (c *containedGenerating) GenerateUpstream(ctx context.Context, ref string) (value string, err error) {
	defer dynamic.RecoverClientPanic(executorComponent, c.inner.Name(), "GenerateUpstream", &err)()
	return c.gen.GenerateUpstream(ctx, ref)
}
