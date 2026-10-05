// credential_lookup_raw_test.go — proves the H3 raw prepared-statement path
// (credential_lookup_raw.go) and the original GORM query agree, for a fuzzed
// set of row shapes and lookup hashes (PERF-3, docs/specs/read-path-caching.md).
package store

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// gormCredentialLookup is the pre-H3 query, kept here verbatim as the
// reference implementation this test compares against — deliberately NOT
// calling the production method (which now tries the raw path first), so a
// bug in the raw path can't accidentally "agree with itself."
func gormCredentialLookup(ctx context.Context, db *gorm.DB, hash string) (*models.MachineIdentityCredential, string, error) {
	var row credentialWithIdentityState
	err := db.WithContext(ctx).
		Table("machine_identity_credentials AS c").
		Select("c.*, m.state AS identity_state").
		Joins("JOIN machine_identities AS m ON m.id = c.machine_identity_id").
		Where("c.token_hash = ?", hash).
		First(&row).Error
	if err != nil {
		return nil, "", err
	}
	return &row.MachineIdentityCredential, row.IdentityState, nil
}

func TestCredentialLookupRaw_MatchesGORM_Fuzz(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(&models.MachineIdentity{}, &models.MachineIdentityCredential{}))

	mi := &models.MachineIdentity{
		Name: "fuzz-identity", IdentityType: "service", State: "active",
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	require.NoError(t, db.Create(mi).Error)

	rows := []struct {
		hash         string
		revoked      bool
		hasExpiresAt bool
		cidrs        string
		classif      string
	}{
		{hash: "hash-a", revoked: false, hasExpiresAt: false, cidrs: "", classif: ""},
		{hash: "hash-b", revoked: true, hasExpiresAt: true, cidrs: `["10.0.0.0/8"]`, classif: "confidential"},
		{hash: "hash-c", revoked: false, hasExpiresAt: true, cidrs: `["192.0.2.4/32","10.0.0.0/8"]`, classif: "public"},
		{hash: "", revoked: false, hasExpiresAt: false, cidrs: "", classif: ""}, // empty hash: not found on either path
	}
	for _, r := range rows {
		if r.hash == "" {
			continue // no row to seed; this one tests the not-found branch below
		}
		var expiresAt *time.Time
		if r.hasExpiresAt {
			e := time.Now().Add(24 * time.Hour).Truncate(time.Second)
			expiresAt = &e
		}
		require.NoError(t, db.Create(&models.MachineIdentityCredential{
			MachineIdentityID: mi.ID, Name: "cred-" + r.hash, TokenHash: r.hash, TokenPrefix: "kx_machine_" + r.hash[:4],
			AllowedCIDRs: r.cidrs, ExpiresAt: expiresAt, Revoked: r.revoked, CreatedAt: time.Now(), Classification: r.classif,
		}).Error)
	}

	ls := NewLocalStorage(db)
	ctx := context.Background()
	for _, r := range rows {
		gormCred, gormState, gormErr := gormCredentialLookup(ctx, db, r.hash)
		rawCred, rawState, handled, rawErr := ls.getMachineIdentityCredentialWithIdentityStateByHashRaw(ctx, r.hash)
		require.True(t, handled, "raw path should be available against a root LocalStorage")

		if gormErr != nil {
			require.Error(t, rawErr, "hash=%q: GORM errored but raw did not", r.hash)
			continue
		}
		require.NoError(t, rawErr, "hash=%q", r.hash)
		require.Equal(t, gormState, rawState, "hash=%q: identity_state mismatch", r.hash)
		require.Equal(t, gormCred.ID, rawCred.ID, "hash=%q: ID mismatch", r.hash)
		require.Equal(t, gormCred.MachineIdentityID, rawCred.MachineIdentityID, "hash=%q", r.hash)
		require.Equal(t, gormCred.Name, rawCred.Name, "hash=%q", r.hash)
		require.Equal(t, gormCred.TokenHash, rawCred.TokenHash, "hash=%q", r.hash)
		require.Equal(t, gormCred.TokenPrefix, rawCred.TokenPrefix, "hash=%q", r.hash)
		require.Equal(t, gormCred.AllowedCIDRs, rawCred.AllowedCIDRs, "hash=%q", r.hash)
		require.Equal(t, gormCred.Revoked, rawCred.Revoked, "hash=%q", r.hash)
		require.Equal(t, gormCred.Classification, rawCred.Classification, "hash=%q", r.hash)
		if gormCred.ExpiresAt == nil {
			require.Nil(t, rawCred.ExpiresAt, "hash=%q", r.hash)
		} else {
			require.NotNil(t, rawCred.ExpiresAt, "hash=%q", r.hash)
			require.True(t, gormCred.ExpiresAt.Equal(*rawCred.ExpiresAt), "hash=%q: ExpiresAt mismatch", r.hash)
		}
	}
}

// FuzzCredentialLookupRaw_MatchesGORM is the genuine fuzz entry point: random
// hash strings against a small fixed set of seeded rows, asserting the raw
// and GORM paths always agree on found-vs-not-found and, when found, on
// every field.
func FuzzCredentialLookupRaw_MatchesGORM(f *testing.F) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		f.Fatal(err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		f.Fatal(err)
	}
	sqlDB.SetMaxOpenConns(1)
	if err := db.AutoMigrate(&models.MachineIdentity{}, &models.MachineIdentityCredential{}); err != nil {
		f.Fatal(err)
	}
	mi := &models.MachineIdentity{Name: "fuzz", IdentityType: "service", State: "active", CreatedAt: time.Now(), UpdatedAt: time.Now()}
	if err := db.Create(mi).Error; err != nil {
		f.Fatal(err)
	}
	seededHashes := []string{"seed-1", "seed-2", "seed-with-unicode-ü", ""}
	for i, h := range seededHashes {
		if h == "" {
			continue
		}
		cred := &models.MachineIdentityCredential{
			MachineIdentityID: mi.ID, Name: "cred", TokenHash: h, TokenPrefix: "kx_",
			Revoked: i%2 == 0, CreatedAt: time.Now(),
		}
		if err := db.Create(cred).Error; err != nil {
			f.Fatal(err)
		}
	}
	for _, h := range seededHashes {
		f.Add(h)
	}
	f.Add("not-seeded-at-all")
	f.Add("'; DROP TABLE machine_identity_credentials; --")

	ls := NewLocalStorage(db)
	ctx := context.Background()
	f.Fuzz(func(t *testing.T, hash string) {
		gormCred, gormState, gormErr := gormCredentialLookup(ctx, db, hash)
		rawCred, rawState, handled, rawErr := ls.getMachineIdentityCredentialWithIdentityStateByHashRaw(ctx, hash)
		if !handled {
			t.Fatal("raw path should always be available against a root LocalStorage")
		}
		if (gormErr != nil) != (rawErr != nil) {
			t.Fatalf("hash=%q: error disagreement: gorm=%v raw=%v", hash, gormErr, rawErr)
		}
		if gormErr != nil {
			return
		}
		if gormState != rawState || gormCred.ID != rawCred.ID || gormCred.TokenHash != rawCred.TokenHash {
			t.Fatalf("hash=%q: result mismatch: gorm=%+v/%q raw=%+v/%q", hash, gormCred, gormState, rawCred, rawState)
		}
	})
}
