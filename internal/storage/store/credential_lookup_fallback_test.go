package store

// #3464 (READPATH-DANGLING-ROLE-1 item 4): GetMachineIdentityCredentialWithIdentityStateByHash
// falls back to its GORM query when the raw path is not available: a
// transaction-scoped store (rawStmts nil) or a prepare that failed. The H3
// differential tests (credential_lookup_raw_test.go) compare the raw path with a
// test-local copy of that query, so nothing ran the production fallback itself.
// This test forces both fallback branches, proves from the statement log that the
// fallback query is what answered, and requires the answer (row and not-found
// error text) to equal the raw path's.

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// credentialFallbackSQLMarker is in the GORM fallback's FROM clause only (the raw
// statement reads `FROM machine_identity_credentials c`).
const credentialFallbackSQLMarker = "machine_identity_credentials AS c"

type credentialLookupResult struct {
	cred  *models.MachineIdentityCredential
	state string
	err   error
}

// credentialLookupDiff lists every difference between two lookups: found vs not
// found, error text, identity state and each credential column.
func credentialLookupDiff(want, got credentialLookupResult) []string {
	var d []string
	if (want.err == nil) != (got.err == nil) {
		return []string{"found vs not found"}
	}
	if want.err != nil {
		// The texts differ ("...: sql: no rows in result set" on the raw path,
		// "...: record not found" on GORM, despite credential_lookup_raw.go's
		// "byte-identical" note); what the caller reads is the class:
		// core.credentialRowGone accepts either sentinel.
		if credentialRowGoneClass(want.err) != credentialRowGoneClass(got.err) {
			d = append(d, "not-found class: "+want.err.Error()+" vs "+got.err.Error())
		}
		return d
	}
	w, g := want.cred, got.cred
	add := func(ok bool, what string) {
		if !ok {
			d = append(d, what)
		}
	}
	add(want.state == got.state, "identity_state")
	add(w.ID == g.ID, "id")
	add(w.MachineIdentityID == g.MachineIdentityID, "machine_identity_id")
	add(w.Name == g.Name, "name")
	add(w.TokenHash == g.TokenHash, "token_hash")
	add(w.TokenPrefix == g.TokenPrefix, "token_prefix")
	add(w.AllowedCIDRs == g.AllowedCIDRs, "allowed_cidrs")
	add(w.Revoked == g.Revoked, "revoked")
	add(w.Classification == g.Classification, "classification")
	add(w.CreatedAt.Equal(g.CreatedAt), "created_at")
	add(sameTimePtr(w.ExpiresAt, g.ExpiresAt), "expires_at")
	add(sameTimePtr(w.LastUsedAt, g.LastUsedAt), "last_used_at")
	return d
}

// credentialRowGoneClass is core.credentialRowGone's test, copied (core imports
// this package's interface, not the reverse).
func credentialRowGoneClass(err error) bool {
	return errors.Is(err, gorm.ErrRecordNotFound) || errors.Is(err, sql.ErrNoRows)
}

func sameTimePtr(a, b *time.Time) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.Equal(*b)
}

func lookupCredential(ctx context.Context, st storage.Storage, hash string) credentialLookupResult {
	c, s, err := st.GetMachineIdentityCredentialWithIdentityStateByHash(ctx, hash)
	return credentialLookupResult{c, s, err}
}

func TestCredentialLookup_GORMFallbackAnswersAsTheRawPath(t *testing.T) {
	for _, backend := range principalPermBackends(t) {
		t.Run(backend, func(t *testing.T) {
			ls, open := newPrincipalPermStorage(t, backend)
			require.NoError(t, ls.db.AutoMigrate(&models.MachineIdentityCredential{}))
			w := ppWorld{t: t, ls: ls}
			ctx := context.Background()
			p := w.project()
			active := w.machine(p)
			suspended := w.machine(p)
			require.NoError(t, ls.db.Model(&models.MachineIdentity{}).Where("id = ?", suspended).Update("state", "suspended").Error)

			now := time.Now().UTC().Truncate(time.Second)
			later := now.Add(24 * time.Hour)
			creds := []models.MachineIdentityCredential{
				{MachineIdentityID: active, Name: "plain", TokenHash: "fb-hash-a", TokenPrefix: "kx_m_a", CreatedAt: now},
				{MachineIdentityID: active, Name: "full", TokenHash: "fb-hash-b", TokenPrefix: "kx_m_b", AllowedCIDRs: `["10.0.0.0/8"]`,
					ExpiresAt: &later, LastUsedAt: &now, Revoked: true, Classification: "confidential", CreatedAt: now},
				{MachineIdentityID: suspended, Name: "suspended", TokenHash: "fb-hash-c", TokenPrefix: "kx_m_c", CreatedAt: now},
			}
			for i := range creds {
				require.NoError(t, ls.db.Create(&creds[i]).Error)
			}
			hashes := []string{"fb-hash-a", "fb-hash-b", "fb-hash-c", "fb-no-such-hash", ""}

			// A second root store on the same database whose prepare "failed": the
			// SQLite raw branch then falls back (prepareRawStatements' error path). It
			// has no native pool, so on Postgres it takes the same branch.
			broken := open()
			broken.nativeReads = nil
			errForced := errors.New("forced prepare failure")
			broken.rawStmts.once.Do(func() { broken.rawStmts.prepErr = errForced })

			counter := ppCountStatements(t, ls.db)
			brokenCounter := ppCountStatements(t, broken.db)
			for _, h := range hashes {
				_, _, handled, _ := ls.getMachineIdentityCredentialWithIdentityStateByHashRaw(ctx, h)
				require.True(t, handled, "control: the root store answers %q on the raw path", h)
				var want credentialLookupResult
				rawStmts := counter.during(func() { want = lookupCredential(ctx, ls, h) })
				for _, s := range rawStmts {
					require.NotContains(t, s, credentialFallbackSQLMarker, "control: the root store did not fall back for %q", h)
				}
				if h == "fb-hash-c" {
					require.NoError(t, want.err)
					require.Equal(t, "suspended", want.state, "control: the identity state is read")
				}

				// Branch 1: transaction-scoped store, rawStmts == nil.
				var inTx credentialLookupResult
				txStmts := counter.during(func() {
					require.NoError(t, ls.WithTransaction(ctx, func(tx storage.Storage) error {
						inTx = lookupCredential(ctx, tx, h)
						return nil
					}))
				})
				require.True(t, containsMarker(txStmts), "hash %q: the transaction-scoped lookup ran the GORM fallback: %v", h, txStmts)
				require.Empty(t, credentialLookupDiff(want, inTx), "hash %q: fallback in a transaction vs raw path", h)

				// Branch 2: root store whose prepare failed.
				var afterPrepFail credentialLookupResult
				prepStmts := brokenCounter.during(func() { afterPrepFail = lookupCredential(ctx, broken, h) })
				require.True(t, containsMarker(prepStmts), "hash %q: the prepare-failed lookup ran the GORM fallback: %v", h, prepStmts)
				require.Empty(t, credentialLookupDiff(want, afterPrepFail), "hash %q: fallback after a prepare failure vs raw path", h)
			}
		})
	}
}

func containsMarker(stmts []string) bool {
	for _, s := range stmts {
		if strings.Contains(s, credentialFallbackSQLMarker) {
			return true
		}
	}
	return false
}

// Mutation check without touching production code: deliberately broken copies of
// the fallback query, through the same comparison, must be told apart from the
// raw path. If credentialLookupDiff could not see these, the test above would
// certify a broken fallback.
func TestCredentialLookup_FallbackComparisonCatchesABrokenFallback(t *testing.T) {
	ls, _ := newPrincipalPermStorage(t, "sqlite")
	require.NoError(t, ls.db.AutoMigrate(&models.MachineIdentityCredential{}))
	w := ppWorld{t: t, ls: ls}
	ctx := context.Background()
	m := w.machine(w.project())
	later := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	require.NoError(t, ls.db.Create(&models.MachineIdentityCredential{
		MachineIdentityID: m, Name: "c", TokenHash: "mut-hash", TokenPrefix: "kx_m_mut", ExpiresAt: &later, CreatedAt: time.Now().UTC(),
	}).Error)
	want := lookupCredential(ctx, ls, "mut-hash")
	require.NoError(t, want.err)

	// The fallback's own chain, with one mutation each.
	brokenCopy := func(selectState, where string) credentialLookupResult {
		var row credentialWithIdentityState
		err := ls.db.WithContext(ctx).
			Table("machine_identity_credentials AS c").
			Select(modelColumns(ls.db, &models.MachineIdentityCredential{}, "c")+selectState).
			Joins("JOIN machine_identities AS m ON m.id = c.machine_identity_id").
			Where(where, "mut-hash").
			First(&row).Error
		if err != nil {
			return credentialLookupResult{err: err}
		}
		return credentialLookupResult{&row.MachineIdentityCredential, row.IdentityState, nil}
	}
	require.Empty(t, credentialLookupDiff(want, brokenCopy(", m.state AS identity_state", "c.token_hash = ?")),
		"calibration: the unmutated copy agrees")
	require.NotEmpty(t, credentialLookupDiff(want, brokenCopy("", "c.token_hash = ?")),
		"mutation: identity_state not selected")
	require.NotEmpty(t, credentialLookupDiff(want, brokenCopy(", m.state AS identity_state", "c.token_prefix = ?")),
		"mutation: looked up by the wrong column")
	var none credentialLookupResult
	none.err = gorm.ErrRecordNotFound
	require.NotEmpty(t, credentialLookupDiff(want, none), "mutation: not found")
	// A storage error is not a not-found: telling them apart is the caller's
	// revoke-vs-degrade decision (CRED-CACHE-REVOKE-1).
	notFound := credentialLookupResult{err: gorm.ErrRecordNotFound}
	require.NotEmpty(t, credentialLookupDiff(notFound, credentialLookupResult{err: errors.New("connection reset")}),
		"mutation: a storage error reported where the raw path says not found")
}
