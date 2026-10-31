// audit_seal_resume_key_change_refuse_test.go — the resume after a key
// change (#3814, audit_seal_key_change.go) accepts nothing on the previous
// key's behalf that the transition record does not name. Every case runs on
// SQLite and, with KEYORIX_TEST_PG_DSN, on PostgreSQL.
package core

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// (5) The resume still refuses what no seal and no key authenticates: after
// the same crash and key change, a latest checkpoint or high-water mark
// garbled before the key change (prepare names only what authenticates under
// a seal binding) or after it (its digest is not the one named) is not the
// acceptance's own half-written artifact, and a transition record whose
// naming was altered fails its new-key MAC.
func TestAuditSeal_ResumeAfterKeyChangeRefusesUnaccounted(t *testing.T) {
	for _, variant := range []string{"checkpoint-garbled-before", "checkpoint-garbled-after", "high-water-garbled-before", "high-water-garbled-after", "transition-forged"} {
		t.Run(variant, func(t *testing.T) {
			t.Parallel()
			fcRun(t, func(t *testing.T, e *fcEnv) {
				ctx := context.Background()
				garble := func() {
					switch {
					case strings.HasPrefix(variant, "checkpoint"):
						cp, err := e.restart().storage.LatestAuditCheckpoint(ctx)
						require.NoError(t, err)
						require.NoError(t, e.db.Model(&models.AuditCheckpoint{}).Where("id = ?", cp.ID).Update("signature", strings.Repeat("0", 64)).Error)
					case strings.HasPrefix(variant, "high-water"):
						v := untrustedMeta(t, e.db, auditHighWaterKey)
						require.NoError(t, e.db.Model(&models.SystemMetadata{}).Where(&models.SystemMetadata{Key: auditHighWaterKey}).Update("value", v[:len(v)-4]+"0000").Error)
					}
				}
				var before func()
				if strings.HasSuffix(variant, "-before") {
					before = garble
				}
				_, _ = sealCrashThenKeyChange(t, e, "record", "", before)
				rec := aktTransitionsValue(t, e.db)
				require.NotEmpty(t, rec, "precondition: a transition record exists")
				switch {
				case strings.HasSuffix(variant, "-after"):
					garble()
				case variant == "transition-forged":
					recs, err := parseAuditKeyTransitions(rec)
					require.NoError(t, err)
					last := recs[len(recs)-1]
					require.NotNil(t, last.Sealing, "precondition: the transition names the unfinished acceptance's artifacts")
					last.Sealing.Before = append(last.Sealing.Before, strings.Repeat("ab", 32))
					last.payload, err = json.Marshal(last)
					require.NoError(t, err)
					require.NoError(t, e.db.Model(&models.SystemMetadata{}).Where(&models.SystemMetadata{Key: auditKeyTransitionsKey}).Update("value", encodeAuditKeyTransitions(recs)).Error)
				}
				c := e.restart()
				c.SetAuditCheckpointKey(aktNewKey, "v2")
				want := map[string]string{
					"checkpoint-garbled-before": "latest checkpoint", "checkpoint-garbled-after": "latest checkpoint",
					"high-water-garbled-before": "high-water mark authenticates neither", "high-water-garbled-after": "high-water mark authenticates neither",
					"transition-forged": "key mismatch",
				}[variant]
				sealRefused(t, c, sealReq(), want)
				assert.NotEqual(t, AuditVerifyStatusSealed, incrVerify(t, c).Status)
			})
		})
	}
}
