package config

// FuzzRemoteStorageServerBoundary — oracle for INV-STORAGE-35
// ("A process with server.http.enabled/server.grpc.enabled cannot boot on
// storage.type: remote"; internal/storage/INVARIANTS.md). The rule is enforced
// by validateStorageSection -> validateRemoteStorageNotServer
// (internal/config/config_storage.go), which as of the G80 follow-up
// (2026-08-24) rejects storage.type: remote UNCONDITIONALLY — including a
// scheduler-only "worker" process with server.http.enabled AND
// server.grpc.enabled both false, because server/main.go always starts its
// background schedulers regardless of either flag (ADR-083).
//
// Before this invariant-map campaign (IV1) the invariant was DOC-ONLY: no
// fuzz target and no unit test referenced it (validateRemoteStorageNotServer
// has unit coverage in connect_config_test.go, but nothing exercised the
// field-combination space of the storage.type switch under the remote rule).
//
// Two oracles, both white-box against the unexported validateStorageSection:
//
//	U (universal): ANY Config whose Storage.Type == "remote" must FAIL
//	  validateStorageSection with a non-nil error, for EVERY combination of the
//	  other storage/database fields and the http/grpc enable flags — and must
//	  never panic. A regression that let a remote config validate (e.g. a
//	  re-introduced flag-conditional gate that passes a worker with both flags
//	  false) is caught here.
//
//	M (metamorphic): if the SAME field set validates cleanly under a legal
//	  LOCAL storage.type, flipping ONLY Storage.Type to "remote" must turn that
//	  pass into a failure whose error names the remote rule. This proves the
//	  remote gate is load-bearing — that the universal failure is caused by the
//	  remote rule, not by an incidental error in an unrelated validator.
//
// What this oracle does NOT verify (stated per CLAUDE.md "name a mechanism for
// what it verifies, and state what it does not"):
//   - It does not prove the running server actually refuses remote storage at
//     boot end-to-end; it checks the config-validation gate only. The gate is
//     the sole mechanism (server/main.go calls cfg.Validate() before wiring
//     storage), but a bypass that skipped Validate() entirely is out of scope.
//   - It does not check the storage FACTORY's own remote handling
//     (internal/storage/factory.go), only the config layer.
//   - It says nothing about the http/grpc flags being honored for NON-remote
//     types; it only asserts the remote rule is independent of them.

import (
	"strings"
	"testing"
)

func FuzzRemoteStorageServerBoundary(f *testing.F) {
	// Seeds: the load-bearing case (scheduler-only worker, both flags false) +
	// a valid local baseline + a postgres-ish shape.
	f.Add("", "", "", "", "", "", "", 0, 0, 0, false, false, false, "", "", "", uint8(0))
	f.Add("/var/lib/keyorix/keyorix.db", "", "", "", "", "", "", 0, 0, 0, false, false, false, "", "", "", uint8(0))
	f.Add("/var/lib/keyorix/keyorix.db", "", "", "", "", "", "", 25, 5, 0, true, true, false, "flock", "", "", uint8(1))
	f.Add("", "host=h user=u dbname=d", "h", "d", "u", "5432", "require", 25, 5, 8, true, false, false, "", "", "standard", uint8(2))

	f.Fuzz(func(t *testing.T,
		path, dsn, host, name, user, port, sslmode string,
		maxOpen, maxIdle, nativeRead int,
		httpEnabled, grpcEnabled, insecureSkip bool,
		keyDirLock, pooler, auditDur string,
		typeSel uint8,
	) {
		// Build the shared field set once; mutate only Storage.Type per oracle.
		base := func() Config {
			var c Config
			c.Server.HTTP.Enabled = httpEnabled
			c.Server.GRPC.Enabled = grpcEnabled
			d := &c.Storage.Database
			d.Path = path
			d.DSN = dsn
			d.Host = host
			d.Name = name
			d.User = user
			d.Port = port
			d.SSLMode = sslmode
			d.MaxOpenConns = maxOpen
			d.MaxIdleConns = maxIdle
			d.NativeReadPoolMax = nativeRead
			d.InsecureAuditSkipReads = insecureSkip
			d.Pooler = pooler
			d.AuditDurability = auditDur
			c.Storage.Encryption.KeyDirLock = keyDirLock
			return c
		}

		// ---- Oracle U: remote always fails, never panics. ----
		cr := base()
		cr.Storage.Type = "remote"
		errRemote := validateStorageSectionNoPanic(t, &cr)
		if errRemote == nil {
			t.Fatalf("INV-STORAGE-35 violated: validateStorageSection accepted storage.type=remote "+
				"(http.enabled=%v grpc.enabled=%v path=%q dsn=%q pooler=%q nativeRead=%d keyDirLock=%q auditDur=%q)",
				httpEnabled, grpcEnabled, path, dsn, pooler, nativeRead, keyDirLock, auditDur)
		}

		// ---- Oracle M: a passing LOCAL baseline must flip to a remote failure. ----
		// Choose a legal local backend. "local" and "sqlite" are aliases; both
		// require a non-empty Path and !SingleWriter. Use the fuzz-chosen alias.
		localType := "local"
		if typeSel%2 == 1 {
			localType = "sqlite"
		}
		cl := base()
		cl.Storage.Type = localType
		if cl.Storage.Database.Path == "" {
			cl.Storage.Database.Path = "keyorix.db" // make a valid local baseline reachable
		}
		cl.Storage.Database.SingleWriter = false
		if validateStorageSectionNoPanic(t, &cl) == nil {
			// Baseline is valid under a local type. The ONLY change is the type.
			cl.Storage.Type = "remote"
			errFlip := validateStorageSectionNoPanic(t, &cl)
			if errFlip == nil {
				t.Fatalf("INV-STORAGE-35 metamorphic violation: a config valid under storage.type=%q "+
					"validated again after flipping ONLY storage.type to remote", localType)
			}
			// The failure after the flip must be the remote rule, not a
			// coincidental error from an unrelated validator (all pre-switch
			// validators already passed for the local baseline, and the type
			// flip does not change their inputs, so the error must come from the
			// remote switch case).
			if !strings.Contains(errFlip.Error(), "remote") {
				t.Fatalf("INV-STORAGE-35 metamorphic violation: remote flip failed, but not via the remote "+
					"rule (error=%q) — the universal failure may be incidental, not caused by the remote gate", errFlip.Error())
			}
		}
	})
}

// validateStorageSectionNoPanic calls validateStorageSection and turns a panic
// into a test failure: the config validator must never panic on any field
// combination (a panic at boot-config time is itself a denial-of-service of the
// security product).
func validateStorageSectionNoPanic(t *testing.T, c *Config) (err error) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("validateStorageSection panicked on storage.type=%q: %v", c.Storage.Type, r)
		}
	}()
	return validateStorageSection(c)
}
