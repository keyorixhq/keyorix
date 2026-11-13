// Fixture for TestAuditWalkRacingPurgeGuard_RejectsAPlainWalker: from-the-start
// chain walks that skip walkAuditChainRacingPurge. Never compiled (testdata).
package bad

import "context"

type segment struct{ anchor any }

type verification struct{ Valid bool }

type chainStore interface {
	VerifyAuditChain(ctx context.Context, anchor any) (*verification, error)
}

type KeyorixCore struct{ storage chainStore }

func (c *KeyorixCore) walkAuditChain(ctx context.Context, seg segment) (*verification, error) {
	return nil, nil
}

func (c *KeyorixCore) walkAuditChainGaps(ctx context.Context, seg segment, gaps []int) (*verification, error) {
	return nil, nil
}

// exportChain is a new verifier that forgot the purge race.
func (c *KeyorixCore) exportChain(ctx context.Context) error {
	_, err := c.walkAuditChain(ctx, segment{})
	return err
}

// sealedReport walks with the seal gaps directly.
func (c *KeyorixCore) sealedReport(ctx context.Context) error {
	_, err := c.walkAuditChainGaps(ctx, segment{}, nil)
	return err
}

// pickWalk takes the plain walk as a method value.
func pickWalk(c *KeyorixCore) func(context.Context, segment) (*verification, error) {
	return c.walkAuditChain
}

// rawStoreWalk goes below the seal-aware walk to the storage walk.
func rawStoreWalk(ctx context.Context, s chainStore) error {
	_, err := s.VerifyAuditChain(ctx, nil)
	return err
}
