// world_test.go builds a fresh world per operation: a real SQLite-backed
// storage.Storage wrapped in faultstorage.FaultyStorage, installed as
// KeyorixCore's storage, and driven through REAL transports — an httptest.Server
// over the actual server/http router for REST/system, and a real grpc.Server
// (server/grpc.NewServer, the exact production wiring including
// RecoveryInterceptor/AuthInterceptor) over bufconn for gRPC. Using the real
// interceptor chain (not calling *GRPCService methods in-process, which several
// existing unit tests do) matters specifically for oracle (b): a panic must
// reach the caller through the SAME recovery path a production panic would.
//
// Reproducibility (RULES): every world is built ONLY from the fuzz input (which
// op, which transport, which fault) — nothing carries over between fuzz
// iterations, so a saved input reproduces its failure standalone.
package faultops

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/delivery"
	"github.com/keyorixhq/keyorix/internal/dynamic"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	grpcserver "github.com/keyorixhq/keyorix/server/grpc"
	httpserver "github.com/keyorixhq/keyorix/server/http"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/test/bufconn"
	"gorm.io/gorm"
)

var memDBSeq atomic.Int64

func uniqueMemDSN() string {
	return fmt.Sprintf("file:faultops_%d?mode=memory&cache=shared&_timeout=30000&_journal_mode=WAL", memDBSeq.Add(1))
}

// pgDSNEnv matches CI's own convention (.github/workflows/ci.yml's test-suite
// job) and every other PG-gated fuzz world in this repo (e.g.
// server/http/concurrent_linearizable_fuzz_test.go): unset means SQLite-only,
// set means every world built for the rest of THIS run uses Postgres instead.
const pgDSNEnv = "KEYORIX_TEST_PG_DSN"

var pgSchemaSeq atomic.Int64

// openWorldDB opens the backend for one world: Postgres (a fresh, uniquely
// named schema, dropped via t.Cleanup) when pgDSNEnv is set, SQLite otherwise.
// Called once per newFaultWorld call — twice per fuzz iteration (reference +
// faulted) — so Postgres runs necessarily create/drop a schema twice per
// iteration; this is accepted validation-run overhead, not something this
// harness tries to amortize (unlike buildLinearizabilityWorldPostgres's
// per-testing.F reuse, newFaultWorld's own contract is a FRESH world per
// call, RULES-mandated for reproducibility — see the package doc comment).
func openWorldDB(t *testing.T) (*gorm.DB, string) {
	t.Helper()
	return openWorldDBTB(t)
}

func mustExec(t *testing.T, db *gorm.DB, sql string) {
	t.Helper()
	if err := db.Exec(sql).Error; err != nil {
		t.Fatalf("exec %q: %v", sql, err)
	}
}

// faultWorld is everything one fuzz iteration needs: the raw DB (for
// snapshotDB), the faulty storage wrapper (for arming/inspecting faults), and
// live REST + gRPC clients authenticated as the one bootstrapped admin.
type faultWorld struct {
	t          *testing.T
	db         *gorm.DB
	backend    string // "sqlite" or "postgres" -- set by buildReusableFaultWorld (world_reuse_test.go); zero-value ("") unused by newFaultWorld's own callers
	core       *core.KeyorixCore
	faulty     *faultstorage.FaultyStorage
	httpServer *httptest.Server
	httpClient *http.Client
	adminToken string
	scimToken  string
	grpcConn   *grpc.ClientConn
	grpcCtx    context.Context
	grpcSrv    *grpc.Server // set by buildReusableFaultWorld (world_reuse_test.go); zero-value (nil) unused by newFaultWorld's own callers

	encryptOnce sync.Once
	encryptErr  error
}

// ensureEncryption lazily wires ADR-004 encryption into this world's core: a
// real KEK path (password key provider, PBKDF2-derived, per-world DEK/salt
// files under a real temp directory — same shape production wires in
// server/main.go's initializeEncryption, not a stub encryptor), fails loud on
// SecretValueEncryptionActive()==false exactly like production's own
// fail-closed check. Built on FIRST USE rather than unconditionally in
// newFaultWorld: PBKDF2's deliberately-slow work factor (~125ms, confirmed by
// profiling — see the PR body) would regress every op's world-build time, not
// just the handful (MFA enrollment, signed audit checkpoints, dynamic-secret
// admin-DSN/lease-credential encryption) that actually need it. Safe to call
// more than once (sync.Once-guarded); returns the first call's error, if any.
// Uses the *testing.T newFaultWorld was built with (stored on w.t) rather than
// taking one as a parameter, so opCatalog Setup/Execute functions — which only
// receive (ctx, w) — can call it too, not just a test function with a t in scope.
func (w *faultWorld) ensureEncryption() error {
	w.t.Helper()
	w.encryptOnce.Do(func() {
		encKeyDir, err := os.MkdirTemp("", "faultops-enc-*")
		if err != nil {
			w.encryptErr = fmt.Errorf("mkdir encryption key dir: %w", err)
			return
		}
		w.t.Cleanup(func() { _ = os.RemoveAll(encKeyDir) })
		encSvc := encryption.NewService(&config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}, encKeyDir)
		if err := encSvc.Initialize("faultops-fixture-passphrase"); err != nil {
			w.encryptErr = fmt.Errorf("encryption Initialize: %w", err)
			return
		}
		w.core.SetSecretValueEncryptor(encSvc)
		if !w.core.SecretValueEncryptionActive() {
			w.encryptErr = fmt.Errorf("secret-value encryption did not activate — plaintext-at-rest would make an encryption-dependent op's oracle checks vacuous")
			return
		}
		w.core.SetAuthEncryptor(encSvc) // MFA TOTP secrets; dynamic-secret admin DSNs/lease credentials
		if key, keyVer, ok := encSvc.AuditCheckpointKey(); ok {
			w.core.SetAuditCheckpointKey(key, keyVer)
		}
	})
	return w.encryptErr
}

// newFaultWorld builds a fresh world with spec armed (nil arms nothing — a pure
// pass-through, used to run an unfaulted prefix/suffix or a fault-free reference
// world for the oracle's state comparison).
func newFaultWorld(t *testing.T, spec *faultstorage.FaultSpec) *faultWorld {
	t.Helper()

	// sync.Once-guarded internally — cheap to call once per world, and every
	// core code path that renders a user-facing message (BootstrapSystem
	// included) panics without it.
	if err := i18n.InitializeForTesting(); err != nil {
		t.Fatalf("i18n.InitializeForTesting: %v", err)
	}

	worldPhase := time.Now()
	db, backend := openWorldDB(t)
	if err := db.AutoMigrate(models.AllTestModels()...); err != nil {
		t.Fatal(err)
	}
	// audit_checkpoints is not in AllTestModels (so it stays out of the
	// oracle's state snapshots: a checkpoint's signature covers run-relative
	// chain content), but ensureEncryption wires the audit-checkpoint key, and
	// once that key is set VerifyAuditChain reads this table -- production
	// always has it. Without it, any op whose Setup activates encryption
	// (MFA enroll/activate, batch 25) failed FuzzAuditCompleteness with
	// "no such table: audit_checkpoints".
	if err := db.AutoMigrate(&models.AuditCheckpoint{}); err != nil {
		t.Fatal(err)
	}
	// Mirrors server/http/integration_test.go's partial-unique-index setup
	// (production migrations these AutoMigrate skips) — duplicated per this
	// repo's established fuzzworld_test.go convention of one copy per package
	// rather than a shared helper (see STEP 0 report). Standard partial-index
	// syntax; identical on SQLite and PostgreSQL, same as
	// buildLinearizabilityWorld's equivalent block.
	mustExec(t, db, "CREATE UNIQUE INDEX IF NOT EXISTS uniq_project_memberships_active "+
		"ON project_memberships (project_id, user_id) WHERE state <> 'revoked'")
	mustExec(t, db, "CREATE UNIQUE INDEX IF NOT EXISTS uniq_legal_holds_active "+
		"ON legal_holds (released) WHERE released = false")
	mustExec(t, db, "CREATE UNIQUE INDEX IF NOT EXISTS uniq_break_glass_active_project_user "+
		"ON break_glass_activations (project_id, user_id) WHERE state = 'active'")
	mustExec(t, db, "CREATE UNIQUE INDEX IF NOT EXISTS uniq_users_email_active "+
		"ON users (LOWER(email)) WHERE deleted_at IS NULL AND email <> ''")
	logWorldPhase(t, backend+" open+migrate+indexes", worldPhase)

	worldPhase = time.Now()
	real := store.NewLocalStorage(db)
	faulty := faultstorage.NewFaultyStorage(real, spec)
	testCore := core.NewKeyorixCore(faulty)

	// credential_delivery.base_url (ADR-028): the default mode (empty Mode, no
	// SMTP configured) resolves to delivery.New's own OutOfBandDelivery — the
	// same real, production-supported no-network default an install gets with
	// no credential_delivery block at all (server/main.go's initializeCoreService
	// calls delivery.New identically) — never a stub. Wired unconditionally
	// (not lazily like ensureEncryption): delivery.New does no key derivation or
	// I/O, so there is no world-build-time cost to defer.
	deliverer, err := delivery.New(delivery.Config{})
	if err != nil {
		t.Fatalf("delivery.New: %v", err)
	}
	testCore.SetCredentialDelivery(deliverer, "https://fuzz-world.invalid")

	// WebAuthn RP (ADR-036): newFaultWorld never called SetWebAuthn, so the
	// entire WebAuthn family (register/login/passwordless/reauth) returns
	// ErrWebAuthnDisabled unconditionally. A real webauthn.New RP config, same
	// shape production wires in server/main.go — a fixed test RP identity, not
	// derived from httpServer's own ephemeral origin, matching this exact
	// codebase's own established precedent for a webauthn.New call inside a
	// test world (server/http/handlers/mfa_webauthn_reauth_test.go uses the
	// identical RPID/RPOrigins).
	//
	// Session FI2: RPID/RPOrigins changed from "localhost" to "example.org" /
	// "https://example.org" to wire the first two WebAuthn opCatalog entries
	// (register/finish, login/finish). Those ops need go-webauthn's REAL
	// cryptographic verification path, which a hand-rolled fixture cannot
	// produce (see internal/core/webauthn_spec_vectors_test.go's file doc) —
	// the only real fixture available is the W3C spec test vectors
	// (https://www.w3.org/TR/webauthn-3/#sctn-test-vectors-none-es256), whose
	// authenticatorData RPIDHash and clientDataJSON "origin" field are baked
	// in at RPID "example.org" / origin "https://example.org" and can't be
	// re-targeted. Safe to change unconditionally (not just for those two
	// ops): no op in opCatalog used the old "localhost" identity before this,
	// and WebAuthn's origin check is clientDataJSON's own "origin" field
	// (part of what the authenticator signs), not an HTTP header — so this is
	// a one-time fixed RP identity, same as the old value, not something any
	// request needs to echo back per-call.
	rp, err := webauthn.New(&webauthn.Config{
		RPID: "example.org", RPDisplayName: "Keyorix", RPOrigins: []string{"https://example.org"},
	})
	if err != nil {
		t.Fatalf("webauthn.New: %v", err)
	}
	testCore.SetWebAuthn(rp)

	if err := wireSSOProviders(testCore); err != nil {
		t.Fatalf("wireSSOProviders: %v", err)
	}

	testCore.SetBootstrapToken("fault-fuzz-bootstrap")
	ctx := context.Background()
	if _, err := testCore.BootstrapSystem(ctx, &core.BootstrapRequest{
		Username: "faultadmin", Email: "faultadmin@example.com",
		Password: "FaultFuzzAdmin123!", Token: "fault-fuzz-bootstrap",
	}); err != nil {
		t.Fatalf("BootstrapSystem: %v", err)
	}
	session, _, err := testCore.Login(ctx, &core.LoginRequest{
		Username: "faultadmin", Password: "FaultFuzzAdmin123!",
	})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	logWorldPhase(t, "bootstrap+login", worldPhase)

	// Break-glass policy (self-service emergency access): newFaultWorld never
	// called SetBreakGlassPolicy, so ActivateBreakGlass (REST + 2 gRPC
	// siblings) refuses unconditionally with ErrorPermissionDenied regardless
	// of any fault armed. EmergencyRole is "project_developer" — a REAL
	// builtin role BootstrapSystem just seeded above (auth_bootstrap.go),
	// contained (no roles.assign — break_glass.go's own doc comment names this
	// exact role as the correct choice: "powerful-but-contained... not
	// project_admin"), not a role invented for this fixture. DefaultTTL/MaxTTL
	// match config.BreakGlassConfig{}'s own zero-value production defaults
	// (4h/24h — internal/config/config.go), not arbitrary test values.
	testCore.SetBreakGlassPolicy(core.BreakGlassPolicy{
		Enabled: true, EmergencyRole: "project_developer",
		DefaultTTL: 4 * time.Hour, MaxTTL: 24 * time.Hour,
	})

	// Dynamic-secrets engine factory: newFaultWorld never called
	// SetDynamicEngineFactory (nil factory), so CreateConfig fails at the gate
	// and every op needing an existing config is unreachable transitively (13
	// ops). The REAL factory function server/main.go's wireDynamicSecrets wires
	// in production — dynamic.New per backend type, not a fake/stub engine —
	// with the same safe (deny-by-default) allowPrivateNetwork/
	// allowInsecureTransport settings production defaults to absent explicit
	// operator opt-in. This registers only a FUNCTION (no I/O, no dial) — the
	// actual dynamic.New call, and whatever backend connectivity it needs, only
	// happens if/when a future operation (PR B) actually calls CreateConfig.
	testCore.SetDynamicEngineFactory(func(backendType string) (dynamic.CredentialEngine, error) {
		return dynamic.New(backendType, false, false)
	})

	worldPhase = time.Now()
	cfg := &config.Config{
		Server: config.ServerConfig{HTTP: config.ServerInstanceConfig{Enabled: true, Port: "8080"}},
		// Enables /scim/v2 (see faultopsSCIMToken's own doc comment,
		// dump_inventory_test.go) -- SAME token liveOperationKeys's own router
		// construction uses, so a route visible to the generated registry is
		// also reachable+authenticatable here.
		SCIM: config.SCIMConfig{Enabled: true, Token: faultopsSCIMToken},
	}
	handler, err := httpserver.NewRouter(cfg, testCore)
	if err != nil {
		t.Fatal(err)
	}
	httpSrv := httptest.NewServer(handler)
	t.Cleanup(httpSrv.Close)
	logWorldPhase(t, "REST router + httptest.Server", worldPhase)

	worldPhase = time.Now()
	grpcSrv, err := grpcserver.NewServer(&config.Config{}, testCore)
	if err != nil {
		t.Fatal(err)
	}
	lis := bufconn.Listen(1024 * 1024)
	go func() { _ = grpcSrv.Serve(lis) }()
	t.Cleanup(grpcSrv.Stop)

	conn, err := grpc.NewClient(
		"passthrough:///bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	logWorldPhase(t, "grpc.Server + bufconn + client", worldPhase)

	grpcCtx := metadata.NewOutgoingContext(context.Background(),
		metadata.Pairs("authorization", "Bearer "+session.SessionToken))

	return &faultWorld{
		t: t, db: db, core: testCore, faulty: faulty,
		httpServer: httpSrv, httpClient: &http.Client{Timeout: 10 * time.Second},
		adminToken: session.SessionToken,
		scimToken:  faultopsSCIMToken,
		grpcConn:   conn, grpcCtx: grpcCtx,
	}
}

// logWorldPhase records one newFaultWorld phase's duration — always-on since
// it's cheap and directly informs whether a slow iteration is DB/bootstrap-,
// REST-, or gRPC-server-bound (see PROFILE-tagged tests in
// profile_iteration_test.go and the STEP 1 execs/sec follow-up).
func logWorldPhase(t *testing.T, label string, start time.Time) {
	t.Helper()
	t.Logf("PROFILE world.%-28s %v", label, time.Since(start))
}
