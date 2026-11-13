// Fixture for TestAuditWalkRacingPurgeGuard_RejectsAPlainWalker: a verifier
// that walks through the racing-purge walk only. Never compiled (testdata).
package good

import "context"

type segment struct{ AfterID uint }

type verification struct{ Valid, LinkBroken bool }

type KeyorixCore struct{}

func (c *KeyorixCore) walkAuditChain(ctx context.Context, seg segment) (*verification, error) {
	return &verification{Valid: true}, nil
}

func (c *KeyorixCore) walkAuditChainRacingPurge(ctx context.Context, seg segment) (*verification, error) {
	return c.walkAuditChain(ctx, seg)
}

// exportChain walks from the chain start through the racing-purge walk.
func (c *KeyorixCore) exportChain(ctx context.Context) error {
	_, err := c.walkAuditChainRacingPurge(ctx, segment{})
	return err
}

func (c *KeyorixCore) VerifyAuditChain(ctx context.Context) (*verification, error) {
	return c.walkAuditChainRacingPurge(ctx, segment{})
}

// status calls the core verifier on its own receiver: not a plain walk.
func (c *KeyorixCore) status(ctx context.Context) error {
	_, err := c.VerifyAuditChain(ctx)
	return err
}
