// credential_lookup_raw_bench_test.go — microbenchmark for H3's raw
// prepared-statement path vs the original GORM query (PERF-3,
// docs/specs/read-path-caching.md). Not a substitute for the pve01
// before/after harness numbers — a quick local sanity check.
package store

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"gorm.io/gorm"
)

func setupCredBenchFixture(b *testing.B) (*gorm.DB, *LocalStorage) {
	b.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		b.Fatal(err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		b.Fatal(err)
	}
	sqlDB.SetMaxOpenConns(1)
	if err := db.AutoMigrate(&models.MachineIdentity{}, &models.MachineIdentityCredential{}); err != nil {
		b.Fatal(err)
	}
	mi := &models.MachineIdentity{Name: "bench", IdentityType: "service", State: "active", CreatedAt: time.Now(), UpdatedAt: time.Now()}
	if err := db.Create(mi).Error; err != nil {
		b.Fatal(err)
	}
	cred := &models.MachineIdentityCredential{MachineIdentityID: mi.ID, Name: "bench-cred", TokenHash: "bench-hash", TokenPrefix: "kx_", CreatedAt: time.Now()}
	if err := db.Create(cred).Error; err != nil {
		b.Fatal(err)
	}
	return db, NewLocalStorage(db)
}

func BenchmarkCredentialLookup_Raw(b *testing.B) {
	_, ls := setupCredBenchFixture(b)
	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, handled, err := ls.getMachineIdentityCredentialWithIdentityStateByHashRaw(ctx, "bench-hash"); !handled || err != nil {
			b.Fatalf("handled=%v err=%v", handled, err)
		}
	}
}

func BenchmarkCredentialLookup_GORM(b *testing.B) {
	db, _ := setupCredBenchFixture(b)
	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, err := gormCredentialLookup(ctx, db, "bench-hash"); err != nil {
			b.Fatal(err)
		}
	}
}
