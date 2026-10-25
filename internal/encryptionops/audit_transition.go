// audit_transition.go — rotate-kek and migrate-provider carry the audit
// verification state over to the new checkpoint key
// (docs/design-audit-key-transition.md): prepare the cross-signed key
// transition record before any key file is written, complete it once the new
// key files have committed.
package encryptionops

import (
	"context"
	"fmt"
	"os"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/crypto"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/storage"
)

// auditKeyChange is a core over the deployment's database, keyed with the
// current (old) audit-checkpoint key.
type auditKeyChange struct {
	core *core.KeyorixCore
}

// openAuditKeyChange opens the database the server uses and keys a core with
// svc's current audit-checkpoint key. Failing to open it aborts the key change
// before any key file is written: changing the key without carrying the state
// over would leave a sticky discontinuity.
func openAuditKeyChange(cfg *config.Config, svc *encryption.Service) (*auditKeyChange, error) {
	key, kid, ok := svc.AuditCheckpointKey()
	if !ok {
		return &auditKeyChange{}, nil
	}
	st, err := storage.NewStorageFactory().CreateStorage(cfg)
	if err != nil {
		crypto.WipeBytes(key)
		return nil, fmt.Errorf("open the database to carry the audit verification state over (nothing was changed): %w", err)
	}
	c := core.NewKeyorixCore(st)
	c.SetAuditCheckpointKey(key, kid)
	return &auditKeyChange{core: c}, nil
}

// prepare is the encryption.AuditKeyChangePrepare callback.
func (a *auditKeyChange) prepare(newKey []byte, newKeyVersion string) error {
	if a.core == nil {
		return nil
	}
	fmt.Println("Verifying the audit chain under the current key and recording the key transition...")
	if err := a.core.PrepareAuditKeyTransition(context.Background(), newKey, newKeyVersion); err != nil {
		return fmt.Errorf("prepare the audit key transition: %w", err)
	}
	return nil
}

// complete re-keys the core with the committed new key and completes the
// transition. The key change itself has already happened, so a failure here is
// reported, not returned: the server completes the transition at its next
// start, and fails closed if it cannot.
func (a *auditKeyChange) complete(newSvc *encryption.Service) {
	if a.core == nil {
		return
	}
	key, kid, ok := newSvc.AuditCheckpointKey()
	if !ok {
		return
	}
	a.core.SetAuditCheckpointKey(key, kid)
	if _, err := a.core.CompleteAuditKeyTransition(context.Background()); err != nil {
		fmt.Fprintf(os.Stderr, "WARNING: the key change is complete, but the audit verification state was not carried over yet: %v\n", err)
		fmt.Fprintln(os.Stderr, "The server retries this at its next start; if it still fails, `keyorix audit verify` reports the discontinuity (docs/operator/key-rotation-runbook.md).")
		return
	}
	fmt.Println("Audit verification state, high-water mark and retention anchor carried over to the new key (a fresh checkpoint is signed under it when the chain verified; a recorded break stays recorded).")
}
