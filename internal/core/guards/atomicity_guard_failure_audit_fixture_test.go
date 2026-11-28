package guards

import (
	"path/filepath"
	"testing"
)

// TestAtomicityGuard_AuditBeforeWrite_DistinguishesFailureEvents plants one
// function per audit writer, each writing its event before a later storage write
// (R1.17, AUDIT-DISCLOSURE-NOV-1). The SUCCESS writers must be reported; the
// failure writers (Success=false: writeAuditEventFailed, writeAuditEventFailedFull)
// and a *Denied writer must not be, because a failure event claims nothing that a
// later write could falsify. Before the fix writeAuditEventFailedFull matched the
// writeAuditEvent prefix and was reported as a success event.
func TestAtomicityGuard_AuditBeforeWrite_DistinguishesFailureEvents(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeTree(t, root, map[string]string{"planted.go": `package core

func (c *KeyorixCore) plantedSuccess() {
	c.writeAuditEvent(ctx, "x.done", nil, nil, "")
	c.storage.CreateThing(ctx)
}

func (c *KeyorixCore) plantedSuccessFull() {
	c.writeAuditEventFull(ctx, "x.done", nil, nil, nil, "", "")
	c.storage.UpdateThing(ctx)
}

func (c *KeyorixCore) plantedLog() {
	c.LogThingCreated(ctx)
	c.storage.DeleteThing(ctx)
}

func (c *KeyorixCore) plantedFailed() {
	c.writeAuditEventFailed(ctx, "x.failed", nil, nil, "", "")
	c.storage.CreateThing(ctx)
}

func (c *KeyorixCore) plantedFailedFull() {
	c.writeAuditEventFailedFull(ctx, "x.failed", nil, nil, nil, "", "")
	c.storage.CreateThing(ctx)
}

func (c *KeyorixCore) plantedDenied() {
	c.LogThingDenied(ctx)
	c.storage.CreateThing(ctx)
}
`})

	got := map[string]bool{}
	for _, h := range scanAuditBeforeWriteHits(t, []string{filepath.Join(root, "planted.go")}) {
		got[h.fn] = true
	}
	for _, fn := range []string{"plantedSuccess", "plantedSuccessFull", "plantedLog"} {
		if !got["(*KeyorixCore)."+fn] {
			t.Errorf("%s writes a SUCCESS audit event before a storage write: the guard must report it", fn)
		}
	}
	for _, fn := range []string{"plantedFailed", "plantedFailedFull", "plantedDenied"} {
		if got["(*KeyorixCore)."+fn] {
			t.Errorf("%s writes a FAILURE/denial event (Success=false): the guard must not treat it as a success claim", fn)
		}
	}
}
