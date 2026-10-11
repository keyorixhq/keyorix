package core

import (
	"context"
	"time"
)

// SecretTotalReads returns how many times secretID's value has been read: the
// number of its secret_access_logs rows with action "read". Every value
// disclosure writes one (LogSecretReadWithProject, commitStagedSecretRead), and
// the table is append-only, so this is the secret's lifetime read count.
//
// It is NOT SecretNode.ReadCount / SecretVersion.ReadCount, which count only
// reads charged against max_reads and stay 0 for a secret without max_reads
// (#2963). No authorization here: callers have already authorized a read of
// the secret's metadata.
func (c *KeyorixCore) SecretTotalReads(ctx context.Context, secretID uint) (int64, error) {
	counts, err := c.storage.CountSecretReadsBySecretIDs(ctx, []uint{secretID}, time.Time{})
	if err != nil {
		return 0, err
	}
	return int64(counts[secretID]), nil
}
