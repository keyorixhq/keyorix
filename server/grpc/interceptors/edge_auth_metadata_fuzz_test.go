package interceptors

// FuzzGRPCEdgeAuthMetadata — GE1 fuzz target: hostile gRPC metadata driven
// through the REAL unary interceptor chain in its production order.
//
// Existing gRPC fuzzing (FuzzGRPCProtoreflectInvariants) builds WELL-TYPED
// requests for VALID principals and checks authz/no-leak/bounded-work; it never
// feeds byte-level hostile *metadata* (the authorization header and its
// neighbours) through the chain. The wire fuzzers (FuzzWireGRPCFraming,
// FuzzHTTP2AbusiveFrames) stop at HTTP/2 framing, below the interceptor layer.
// So the credential-PARSING edge — oversized / repeated / binary / odd-encoding
// authorization headers, malformed Bearer/PAT/session/machine forms — and the
// chain-ORDERING guarantee (a request must never reach a service method with a
// partially-evaluated auth/ratelimit/audit chain) had no target. This builds
// them.
//
// Shape: build the world once (private SQLite, real core, canary principals),
// compose the production-order security interceptor chain
// (Recovery → Timeout → WriteContention → Auth → RateLimit → ShareElevationAudit)
// in front of a sentinel handler, and for each fuzz input synthesize a hostile
// metadata.MD + context mode (normal / peer-IP / cancelled / past-deadline),
// then drive it through the chain.
//
// Oracles (each stated with what it does NOT verify in the GE1 report):
//
//  1. NO PANIC. RecoveryInterceptor is outermost (as in server.go). A panic
//     anywhere inner is caught and LOGGED as "gRPC PANIC in …"; the harness
//     scans the captured log for that marker and fails — a caught panic is a
//     DEFECT, not a clean result.
//  2. FAIL-CLOSED / NOTHING REACHES A HANDLER WITHOUT AUTH. The sentinel handler
//     records whether it ran and the UserContext it saw. Invariant: the handler
//     ran  ⟺  the chain returned no error AND a non-nil authenticated
//     UserContext was on its context. No partial-evaluation: a request that
//     erred must never have reached the handler, and a request that reached the
//     handler must carry a fully-resolved principal.
//  3. BOUNDED WORK / MEMORY (resguard). alloc/mallocs/log-volume metered against
//     a per-byte calibrated budget so a super-linear blow-up on an oversized or
//     repeated header fails. Advisory wall/cpu/goroutines reported, never fatal.
//  4. NO CREDENTIAL / SECRET LEAK IN ERROR + LOGS. The client-facing status
//     message and the captured server log must never contain a server-minted
//     secret (the canary session token / PAT / machine token / a stored secret
//     value) nor echo the caller's raw bearer token back.
//  5. STATUS DISCIPLINE. Every non-OK result is a well-formed gRPC status whose
//     code is in the expected fail-closed set (Unauthenticated / PermissionDenied
//     / ResourceExhausted / Unavailable / Internal / DeadlineExceeded / Canceled).

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/fuzzutil/resguard"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	store "github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/internal/testutil/fuzzworld"
	"github.com/keyorixhq/keyorix/internal/testutil/sqlitetest"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"net"
)

// ----- world -----

type edgeWorld struct {
	core *core.KeyorixCore

	// Canary server-minted secrets that must never surface in an error or log.
	sessTok    string // valid session token (success path when presented clean)
	patTok     string // valid kx_pat_ token
	machineTok string // valid kx_machine_ token ("" if setup failed; mode skipped)
	secretVal  string // a stored secret's plaintext
	adminID    uint
}

const (
	edgeCanarySession = "ge1-edge-canary-session-token-7f3a"
	edgeSecretValue   = "ge1edgesecretcanaryvalue9q7"
	edgePrincipalPW   = "TestPassword123!"
)

func buildEdgeWorld(f *testing.F) *edgeWorld {
	f.Helper()
	_ = i18n.InitializeForTesting()

	db := sqlitetest.Open(f, "ge1edge_")
	fuzzworld.Bootstrap(f, db)
	if err := db.AutoMigrate(models.AllTestModels()...); err != nil {
		f.Fatalf("migrate: %v", err)
	}
	c := core.NewKeyorixCore(store.NewLocalStorage(db))
	ls := store.NewLocalStorage(db)
	ctx := context.Background()

	c.SetBootstrapToken("ge1-bootstrap-token")
	if _, err := c.BootstrapSystem(ctx, &core.BootstrapRequest{
		Username: "ge1admin", Email: "ge1admin@example.com",
		Password: edgePrincipalPW, Token: "ge1-bootstrap-token",
	}); err != nil {
		f.Logf("bootstrap: %v (may already be initialised)", err)
	}
	admin, err := ls.GetUserByUsername(ctx, "ge1admin")
	if err != nil || admin == nil {
		f.Fatalf("admin lookup: %v", err)
	}
	w := &edgeWorld{core: c, secretVal: edgeSecretValue, adminID: admin.ID, sessTok: edgeCanarySession}

	// Valid session token (plaintext token stored, as mintSessionForTest does).
	exp := time.Now().Add(24 * time.Hour)
	if _, err := ls.CreateSession(ctx, &models.Session{
		UserID: admin.ID, SessionToken: edgeCanarySession, ExpiresAt: &exp,
	}); err != nil {
		f.Fatalf("seed session: %v", err)
	}

	// Valid PAT owned by the admin (unrestricted).
	if res, err := c.CreateOwnPAT(ctx, admin.ID, "ge1-edge", nil, nil, 0, 0, nil); err != nil {
		f.Logf("seed PAT: %v", err)
	} else {
		w.patTok = res.PlainToken
	}

	// A stored secret whose plaintext is the leak canary.
	if proj, err := ls.CreateProject(ctx, &models.Project{Name: "ge1-edge-proj"}); err == nil {
		if env, err := ls.CreateEnvironment(ctx, &models.Environment{Name: "prod", ProjectID: proj.ID}); err == nil {
			if _, err := c.CreateSecret(ctx, &core.CreateSecretRequest{
				Name: "ge1-edge-canary", Value: []byte(edgeSecretValue),
				ProjectID: proj.ID, EnvironmentID: env.ID, Type: "password",
				CreatedBy: "ge1admin", OwnerID: admin.ID,
			}); err != nil {
				f.Logf("seed secret: %v", err)
			}
		}
		// Valid machine token (best effort — more setup; skipped if it fails).
		if m, err := c.CreateMachineIdentity(ctx, proj.ID, "ge1-edge-bot", "service", "", "", admin.ID, 0); err == nil {
			if tok, err := c.IssueMachineToken(ctx, proj.ID, m.ID, admin.ID, core.IssueMachineTokenParams{Name: "ge1-edge-tok"}); err == nil {
				w.machineTok = tok.PlainToken
			} else {
				f.Logf("issue machine token: %v", err)
			}
		} else {
			f.Logf("create machine identity: %v", err)
		}
	}
	return w
}

// ----- log capture: volume meter + leak scanner -----

type edgeLogSink struct {
	meter    *resguard.LogMeter
	mu       sync.Mutex
	buf      []byte // capped ring of recent log bytes, scanned per input
	needles  []string
	leaked   []string
	sawPanic bool
}

const edgeLogCap = 1 << 20 // 1 MiB retained for scanning

func (s *edgeLogSink) Write(p []byte) (int, error) {
	_, _ = s.meter.Writer().Write(p) // volume (resguard reads/reset around each input)
	s.mu.Lock()
	if strings.Contains(string(p), "gRPC PANIC") {
		s.sawPanic = true
	}
	s.buf = append(s.buf, p...)
	if len(s.buf) > edgeLogCap {
		s.buf = s.buf[len(s.buf)-edgeLogCap:]
	}
	s.mu.Unlock()
	return len(p), nil
}

func (s *edgeLogSink) resetInput(needles []string) {
	s.mu.Lock()
	s.buf = s.buf[:0]
	s.needles = needles
	s.leaked = nil
	s.sawPanic = false
	s.mu.Unlock()
}

func (s *edgeLogSink) scan() (leaked []string, sawPanic bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	hay := string(s.buf)
	for _, n := range s.needles {
		if n != "" && strings.Contains(hay, n) {
			leaked = append(leaked, n)
		}
	}
	return leaked, s.sawPanic
}

// ----- chain composition (production order; see server/grpc/server.go) -----

func chainUnary(ics ...grpc.UnaryServerInterceptor) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		cur := handler
		for i := len(ics) - 1; i >= 0; i-- {
			ic := ics[i]
			next := cur
			cur = func(c context.Context, r any) (any, error) { return ic(c, r, info, next) }
		}
		return cur(ctx, req)
	}
}

var edgeExpectedCodes = map[codes.Code]bool{
	codes.Unauthenticated:   true,
	codes.PermissionDenied:  true,
	codes.ResourceExhausted: true,
	codes.Unavailable:       true,
	codes.Internal:          true,
	codes.DeadlineExceeded:  true,
	codes.Canceled:          true,
}

func FuzzGRPCEdgeAuthMetadata(f *testing.F) {
	w := buildEdgeWorld(f)

	// Capture the standard logger (Recovery/RateLimit/core log through it) for the
	// log-volume meter and the leak/panic scan. Restored on cleanup.
	logMeter := resguard.NewLogMeter()
	sink := &edgeLogSink{meter: logMeter}
	prevOut := log.Writer()
	prevFlags := log.Flags()
	log.SetOutput(sink)
	log.SetFlags(0)
	f.Cleanup(func() { log.SetOutput(prevOut); log.SetFlags(prevFlags) })

	// Isolate the process-global failed-auth limiter and reset it per input so the
	// per-IP brute-force budget never couples two inputs (its own throttling is
	// proven by TestAuthInterceptor_FailedAuthHammering_ThrottledByIP). Not an
	// oracle weakening: the limiter under test here is the auth parser, not the
	// budget.
	prevLimiter := globalGRPCTokenAuthFailureLimiter
	f.Cleanup(func() { globalGRPCTokenAuthFailureLimiter = prevLimiter })

	// Production-order security chain in front of a sentinel handler.
	rlCfg := config.RateLimitConfig{Enabled: true, RequestsPerSecond: 1_000_000, Burst: 1_000_000}
	chain := chainUnary(
		RecoveryInterceptor(),
		TimeoutInterceptor(10*time.Second),
		WriteContentionInterceptor(),
		AuthInterceptor(w.core, false),
		GRPCRateLimitInterceptor(rlCfg),
		ShareElevationAuditInterceptor(w.core),
	)
	info := &grpc.UnaryServerInfo{FullMethod: "/keyorix.v1.SecretService/GetSecret"}

	probe := resguard.New(f, resguard.Options{Log: logMeter})
	// Calibrate an in-process budget from a spread of representative inputs. The
	// calibration probe samples EVERY input (SampleEvery 1) so the sampled-only
	// alloc/mallocs meters get a real value for every code path — including the
	// fixed-cost success path (a valid session drives the full auth +
	// GetUserIdentity + rate-limit + share-audit work), which the default 1-in-64
	// sampling would otherwise miss, calibrating the floor far too low.
	calProbe := resguard.New(f, resguard.Options{Log: logMeter, SampleEvery: 1})
	budget := edgeCalibrate(f, w, chain, info, sink, calProbe)
	f.Logf("GE1 edge: %s (platform %s)", budget.Summary(), resguard.Platform())

	seeds := edgeSeeds(w)
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		// Fresh limiter each input (see above).
		globalGRPCTokenAuthFailureLimiter = &grpcIPFailureLimiter{limiters: map[string]*grpcPrincipalBucket{}}

		md, suppliedTok, ctxMode := buildHostileMD(data, w)

		// Server-minted secrets must never appear in error or log. The supplied
		// bearer token is additionally checked in the ERROR channel only (echoing a
		// caller credential into a client-facing error is an info leak), but only
		// when long enough to avoid trivial-substring false positives.
		serverSecrets := []string{w.sessTok, w.patTok, w.machineTok, w.secretVal}
		sink.resetInput(nonEmpty(serverSecrets))

		var (
			reached   bool
			reachedUC *UserContext
		)
		handler := func(hctx context.Context, _ any) (any, error) {
			reached = true
			reachedUC = GetUserFromGRPCContext(hctx)
			return "ok", nil
		}

		base, cancel := edgeContext(ctxMode)
		if cancel != nil {
			defer cancel()
		}
		ctx := metadata.NewIncomingContext(base, md)

		var (
			resp any
			err  error
		)
		cost := probe.Measure(len(data), func() { resp, err = chain(ctx, nil, info, handler) })

		leaked, sawPanic := sink.scan()
		obs := edgeObservation{
			reached: reached, reachedUC: reachedUC, resp: resp, err: err,
			suppliedTok: suppliedTok, serverSecrets: nonEmpty(serverSecrets),
			leakedLog: leaked, sawPanic: sawPanic, cost: cost,
		}
		if v := edgeViolation(obs, budget); v != "" {
			t.Fatalf("%s data=%q mode=%d", v, data, ctxMode)
		}
	})
}

// edgeObservation is everything the oracle predicate inspects for one input.
type edgeObservation struct {
	reached       bool
	reachedUC     *UserContext
	resp          any
	err           error
	suppliedTok   string
	serverSecrets []string
	leakedLog     []string
	sawPanic      bool
	cost          resguard.Cost
}

// edgeViolation is the GE1 oracle, factored out of the fuzz body so the
// red/green tests (edge_auth_metadata_redgreen_test.go) exercise the EXACT same
// predicate rather than a copy. Returns "" when every oracle holds, else a
// human-readable violation string. See the file header for oracle numbering.
func edgeViolation(o edgeObservation, budget resguard.Budget) string {
	// (1) No panic was caught by RecoveryInterceptor.
	if o.sawPanic {
		return "GE1[no-panic]: a panic was caught by RecoveryInterceptor (DEFECT)."
	}
	// (2) Fail-closed / nothing reaches a handler without full auth.
	if o.reached {
		if o.err != nil {
			return "GE1[fail-closed]: handler ran but chain returned error " + o.err.Error() + " — partial-evaluation."
		}
		if o.reachedUC == nil {
			return "GE1[fail-closed]: handler ran with NO authenticated UserContext — unauthenticated reach."
		}
	} else if o.err == nil {
		return "GE1[fail-closed]: chain returned OK but handler never ran."
	}
	// (5) Status discipline + (4) no leak in the error channel.
	if o.err != nil {
		st, ok := status.FromError(o.err)
		if !ok {
			return "GE1[status]: non-status error returned: " + o.err.Error()
		}
		if !edgeExpectedCodes[st.Code()] {
			return "GE1[status]: unexpected status code " + st.Code().String() + " (" + st.Message() + ")"
		}
		msg := st.Message()
		for _, sec := range o.serverSecrets {
			if strings.Contains(msg, sec) {
				return "GE1[leak]: server secret leaked in client error: " + msg
			}
		}
		if len(o.suppliedTok) >= 12 && strings.Contains(msg, o.suppliedTok) {
			return "GE1[leak]: client error echoes the supplied bearer token: " + msg
		}
	}
	// (4) no leak in the log channel.
	if len(o.leakedLog) > 0 {
		return "GE1[leak]: server secret(s) leaked into logs: " + strings.Join(o.leakedLog, ",")
	}
	// (3) bounded work / memory.
	var budgetMsg string
	budget.Check(func(f string, a ...any) { budgetMsg = fmt.Sprintf(f, a...) }, o.cost)
	if budgetMsg != "" {
		return "GE1[bounded]: " + budgetMsg
	}
	return ""
}

func nonEmpty(ss []string) []string {
	out := ss[:0:0]
	for _, s := range ss {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

// edgeContext builds the incoming base context for a mode.
func edgeContext(mode byte) (context.Context, context.CancelFunc) {
	switch mode % 4 {
	case 1: // peer IP present
		ctx := peer.NewContext(context.Background(), &peer.Peer{Addr: &net.TCPAddr{IP: net.ParseIP("203.0.113.7"), Port: 4444}})
		return ctx, nil
	case 2: // already cancelled — exercise cancellation mid-call
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		return ctx, func() {}
	case 3: // deadline already in the past
		ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
		return ctx, cancel
	default:
		return context.Background(), nil
	}
}

// buildHostileMD turns fuzz bytes into a hostile metadata.MD, returning the raw
// bearer token it placed (for the echo check) and the context-mode selector.
func buildHostileMD(data []byte, w *edgeWorld) (metadata.MD, string, byte) {
	md := metadata.MD{}
	if len(data) == 0 {
		return md, "", 0
	}
	mode := data[0]
	ctxMode := byte(0)
	if len(data) > 1 {
		ctxMode = data[1]
	}
	var rest []byte
	if len(data) > 2 {
		rest = data[2:]
	}

	supplied := ""
	setAuth := func(vals ...string) {
		for _, v := range vals {
			md.Append("authorization", v)
		}
	}
	tokenFrom := func() string {
		if len(rest) == 0 {
			return ""
		}
		return string(rest)
	}

	switch mode % 12 {
	case 0: // raw fuzzed authorization value (no scheme)
		supplied = tokenFrom()
		setAuth(supplied)
	case 1: // Bearer + fuzzed token
		supplied = tokenFrom()
		setAuth("Bearer " + supplied)
	case 2: // valid session (clean success path)
		supplied = w.sessTok
		setAuth("Bearer " + w.sessTok)
	case 3: // valid PAT
		supplied = w.patTok
		setAuth("Bearer " + w.patTok)
	case 4: // valid machine token
		supplied = w.machineTok
		setAuth("Bearer " + w.machineTok)
	case 5: // valid session mangled with a fuzzed suffix
		supplied = w.sessTok + tokenFrom()
		setAuth("Bearer " + supplied)
	case 6: // odd scheme casing / spacing
		supplied = w.sessTok
		variants := []string{"bearer " + w.sessTok, "BEARER " + w.sessTok, "Bearer  " + w.sessTok, "Bearer\t" + w.sessTok, "Bearer"}
		setAuth(variants[int(ctxMode)%len(variants)])
	case 7: // repeated authorization header (two values)
		supplied = w.patTok
		setAuth("Bearer "+w.patTok, "Bearer "+tokenFrom())
	case 8: // binary / invalid-utf8 value
		setAuth(string(rest))
		supplied = string(rest)
	case 9: // prefix-collision near-miss tokens
		pfx := []string{"kx_pat_", "kx_machine_", "kx_pat_" + string(rest), "kx_machine_" + string(rest)}
		supplied = pfx[int(ctxMode)%len(pfx)]
		setAuth("Bearer " + supplied)
	case 10: // empty / whitespace token
		opts := []string{"Bearer ", "Bearer    ", "Bearer \x00", "Bearer " + strings.Repeat(" ", 64)}
		supplied = opts[int(ctxMode)%len(opts)]
		setAuth(supplied)
	default: // no authorization header at all, only junk headers
	}

	// Junk neighbour headers carved from the rest: duplicate keys, -bin keys,
	// large values, user-agent, x-forwarded-for.
	carveJunkHeaders(md, rest)
	return md, supplied, ctxMode
}

// carveJunkHeaders splits b into key/value header pairs and appends them, mixing
// in binary ("-bin") keys, repeated keys and a user-agent.
func carveJunkHeaders(md metadata.MD, b []byte) {
	if len(b) == 0 {
		return
	}
	// A bounded number of pairs so one input can't allocate unboundedly in the
	// harness itself (the budget measures the code under test, not this builder).
	const maxPairs = 16
	n := 0
	for len(b) >= 2 && n < maxPairs {
		klen := int(b[0]) % 24
		b = b[1:]
		if klen > len(b) {
			klen = len(b)
		}
		key := "x-ge1-" + sanitizeKey(string(b[:klen]))
		b = b[klen:]
		if len(b) == 0 {
			md.Append(key, "")
			break
		}
		vlen := int(b[0])
		b = b[1:]
		if vlen > len(b) {
			vlen = len(b)
		}
		val := string(b[:vlen])
		b = b[vlen:]
		if n%3 == 0 {
			key += "-bin" // gRPC binary-metadata suffix
		}
		md.Append(key, val)
		n++
	}
	md.Append("user-agent", "ge1-fuzz/1.0")
}

// sanitizeKey keeps a metadata key to the lowercase ASCII HTTP/2 header charset
// so metadata.MD.Append does not reject it before the code under test sees it;
// the hostility is in the values and counts, which stay raw.
func sanitizeKey(s string) string {
	var sb strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-':
			sb.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			sb.WriteRune(r + ('a' - 'A'))
		}
	}
	if sb.Len() == 0 {
		return "k"
	}
	return sb.String()
}

// edgeSeeds is a spread of representative + hostile inputs.
func edgeSeeds(w *edgeWorld) [][]byte {
	s := [][]byte{
		{},
		{0},
		{2, 0},                     // valid session
		{3, 0},                     // valid PAT
		{1, 0, 'n', 'o', 'p', 'e'}, // Bearer nope
		{8, 0, 0xff, 0xfe, 0x00},   // binary value
		{7, 1, 'x'},                // repeated authorization
		{9, 2, 'z'},                // kx_ prefix near-miss
		{10, 3},                    // whitespace token
		{0, 2},                     // raw value + cancelled ctx
	}
	return s
}

// edgeCalibrate runs a fixed spread of inputs through the chain to derive the
// in-process budget (factor 8 for shared-host + process-global memory noise).
func edgeCalibrate(f *testing.F, w *edgeWorld, chain grpc.UnaryServerInterceptor, info *grpc.UnaryServerInfo, sink *edgeLogSink, probe *resguard.Probe) resguard.Budget {
	samples := make([]resguard.Cost, 0, 128)
	cal := edgeSeeds(w)
	// Cover every mode (first byte 0..11) small AND large, so alloc/mallocs are
	// calibrated against every code path's cost — crucially the success path
	// (mode 2/3/4, a fixed input-independent cost) and the oversized-header path
	// (a per-byte cost). ctxMode is varied too.
	for m := byte(0); m < 12; m++ {
		cal = append(cal, []byte{m, 0})
		cal = append(cal, []byte{m, 1, 'x', 'y', 'z'})
		cal = append(cal, append([]byte{m, 0}, []byte(strings.Repeat("a", 4096))...))
	}
	cal = append(cal,
		append([]byte{0, 0}, []byte(strings.Repeat("b", 8192))...),
		append([]byte{8, 0}, []byte(strings.Repeat("\xff", 4096))...),
	)
	handler := func(ctx context.Context, _ any) (any, error) { return "ok", nil }
	for i := 0; i < 3; i++ { // three passes to stabilise the p99
		for _, data := range cal {
			globalGRPCTokenAuthFailureLimiter = &grpcIPFailureLimiter{limiters: map[string]*grpcPrincipalBucket{}}
			md, _, cm := buildHostileMD(data, w)
			sink.resetInput(nil)
			base, cancel := edgeContext(cm)
			ctx := metadata.NewIncomingContext(base, md)
			c := probe.Measure(len(data), func() { _, _ = chain(ctx, nil, info, handler) })
			samples = append(samples, c)
			if cancel != nil {
				cancel()
			}
		}
	}
	b := resguard.Calibrate("grpc-edge-auth-metadata", samples, 10.0)
	// Keep only the per-input-attributable meters. live_heap is whole-process
	// HeapAlloc-after-GC — it reflects the entire process's live memory (the
	// private SQLite page cache, gorm prepared-statement cache, the grown corpus),
	// not THIS input's cost, and false-positives at ~2x on a 1-byte input (the
	// RSG2 precedent for a live-backed target). alloc_bytes/mallocs are the
	// complexity STW delta measured strictly around the chain call, so they ARE
	// this input's allocation and stay as the bounded-memory oracle. wall/cpu/
	// goroutines are advisory (never fatal) and kept for failure context.
	b.KeepOnly("alloc_bytes", "mallocs", "wall_ns", "cpu_ns", "goroutines")
	return b
}
