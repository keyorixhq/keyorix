package grpc_test

// grpc_existence_streaming_fuzz_test.go — PBG2: existence-leak oracle, streaming
// RPC harness, and resguard heap oracle.
//
// This file implements the PBG1 LEFTOVERS:
//
//  1. FuzzGRPCExistenceOracle — full existence-leak oracle (ADR-096 §4):
//     for every unary RPC whose request descriptor has a primary "id" field
//     (uint32, field name == "id"), the oracle calls that RPC as the zero-grant
//     identity twice — once with a known-existing resource ID, once with a
//     known-non-existing ID (999999) — and requires BOTH to return the SAME
//     gRPC error code. A PermissionDenied vs NotFound difference is an ADR-096
//     violation (the caller can distinguish "this resource exists" from "this
//     resource doesn't exist"). Also checked for the unauthenticated caller
//     (auth interceptor must reject before ID lookup; both must return
//     Unauthenticated).
//
//  2. FuzzGRPCStreamingRPCs — streaming RPC harness (server-streaming):
//     grammar-generated request + wire mutations sent to StreamAuditLogs
//     (and any other streaming RPCs registered in the live server).
//     Oracles:
//     (stream-auth) unauthenticated/zero-grant callers never receive data
//     frames before the stream closes.
//     (stream-no-panic) no panic-shaped error code/message for any caller.
//     (stream-client-error) malformed wire bytes → server codes.Internal is
//     a HARDENING finding (same class as HARDENING-1 in PBG1 for unary RPCs).
//     (stream-bounded) stream for unauthorized caller must close within
//     streamPerCallTimeout.
//
//  3. ResGuard heap oracle — both fuzzers use resguard.Probe to measure
//     per-input allocation. When AllocBytes/inputLen exceeds
//     allocAmplificationThreshold (10000), a RESOURCE-AMP finding is logged.
//     Not fatal: needs human review to distinguish legitimate large allocations
//     from real amplification. Not yet calibrated via resguard.Budget (LEFTOVER).
//
// WHAT THIS DOES NOT VERIFY (stated explicitly):
//   - RPCs whose `id` field has a name other than "id" exactly (e.g., "secret_id",
//     "project_id" — qualifier fields, not primary resource IDs). These are excluded
//     by primaryIDField's name == "id" restriction. See that function's doc comment.
//   - Timing side-channels for the existence oracle (ADR-096 §"Explicitly
//     deferred"). Routing through one shared mechanism (authorizeScopedTarget)
//     helps structurally but timing is not measured here.
//   - Long-lived authorized stream behavior — the stream is cancelled after
//     streamPerCallTimeout for every caller, so event delivery after the initial
//     auth/setup window is not exercised.
//   - Per-frame re-authorization in StreamAuditLogs (the reauthorizeAuditStream
//     ticker is not reached within the timeout window).
//   - The allocation oracle does NOT use a calibrated resguard.Budget — it uses a
//     fixed threshold that may miss gradual amplification. Calibrate with
//     resguard.Calibrate after a corpus has been collected (LEFTOVER).

import (
	"context"
	"io"
	"sort"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/dynamicpb"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/fuzzutil/resguard"
	grpcservices "github.com/keyorixhq/keyorix/server/grpc/services"
)

// knownNonExistingID is a uint32 ID that is definitely not a seeded resource
// ID in a fresh SQLite world (all seeded IDs are <= 10 in a fresh world).
const knownNonExistingID = uint32(999999)

// streamPerCallTimeout bounds one streaming RPC call. Shorter than perCallTimeout
// (4s) because: (a) unauthorized callers should be rejected immediately, (b)
// authorized callers' streams are legitimately long-lived but we only need to
// verify no crash/data-leak occurs during setup. The stream is cancelled when
// this timeout fires.
const streamPerCallTimeout = 2 * time.Second

// allocAmplificationThreshold is the per-byte allocation ratio above which the
// resguard oracle logs a RESOURCE-AMP finding. 10000 means 10 KB of server-side
// heap allocation per 1 byte of attacker-controlled input. Historical amplification
// incidents (pkcs7 130 B→1.8 GB ≈ 14M×) are far above this threshold.
const allocAmplificationThreshold = uint64(10000)

// --- streaming method discovery -------------------------------------------

// grpcStreamingMethod names one streaming RPC and its descriptor-level types.
// Analogous to grpcMethod (protoreflect_builder_fuzz_test.go) for streaming.
type grpcStreamingMethod struct {
	serviceFull     string
	methodName      string
	input           protoreflect.MessageDescriptor
	output          protoreflect.MessageDescriptor
	serverStreaming bool
	clientStreaming bool
}

func (m grpcStreamingMethod) fullMethod() string {
	return "/" + m.serviceFull + "/" + m.methodName
}
func (m grpcStreamingMethod) key() string {
	return m.serviceFull + "/" + m.methodName
}

// discoverStreamingMethods returns all server-streaming and bidi-streaming RPCs
// registered in the live server. Excludes unary RPCs (covered by existing
// fuzzers FuzzGRPCProtoreflectInvariants and FuzzGRPCProtobufGrammarWireInvariants).
// Deterministically sorted by serviceFull/methodName so the seed corpus indices
// are stable across runs.
func discoverStreamingMethods(srv *grpc.Server) []grpcStreamingMethod {
	info := srv.GetServiceInfo()
	names := make([]string, 0, len(info))
	for n := range info {
		names = append(names, n)
	}
	sort.Strings(names)

	var methods []grpcStreamingMethod
	for _, svcName := range names {
		d, err := protoregistry.GlobalFiles.FindDescriptorByName(protoreflect.FullName(svcName))
		if err != nil {
			continue
		}
		sd, ok := d.(protoreflect.ServiceDescriptor)
		if !ok {
			continue
		}
		mds := sd.Methods()
		for i := range mds.Len() {
			md := mds.Get(i)
			if !md.IsStreamingServer() && !md.IsStreamingClient() {
				continue // unary — handled by other fuzzers
			}
			methods = append(methods, grpcStreamingMethod{
				serviceFull:     svcName,
				methodName:      string(md.Name()),
				input:           md.Input(),
				output:          md.Output(),
				serverStreaming: md.IsStreamingServer(),
				clientStreaming: md.IsStreamingClient(),
			})
		}
	}
	return methods
}

// --- existence oracle helpers ----------------------------------------------

// primaryIDField returns the first field in desc satisfying all of:
//   - name == "id" exactly  (not an "_id" suffix like project_id or secret_id,
//     which are qualifier/filter fields rather than the primary resource being
//     looked up — including them would generate existence-oracle noise for RPCs
//     that use them as optional filters, not as the addressable resource ID)
//   - kind == uint32
//   - not a list or map field
//
// Returns nil if no such field exists (the method does not address a single
// resource by its primary ID and is not relevant for the existence oracle).
func primaryIDField(desc protoreflect.MessageDescriptor) protoreflect.FieldDescriptor {
	fields := desc.Fields()
	for i := range fields.Len() {
		fd := fields.Get(i)
		if fd.IsList() || fd.IsMap() {
			continue
		}
		if fd.Kind() != protoreflect.Uint32Kind {
			continue
		}
		if string(fd.Name()) == "id" {
			return fd
		}
	}
	return nil
}

// existenceCodeClass classifies a gRPC code for the existence-oracle report.
// The two cases the oracle distinguishes are PermissionDenied vs NotFound — the
// exact ADR-096 §4 violation shape. All other codes are classified as "OTHER".
func existenceCodeClass(c codes.Code) string {
	switch c {
	case codes.PermissionDenied:
		return "DENIED"
	case codes.NotFound:
		return "NOT_FOUND"
	case codes.OK:
		return "OK"
	case codes.Unauthenticated:
		return "UNAUTH"
	default:
		return "OTHER:" + c.String()
	}
}

// invokeWithID invokes method m using a typed proto request built from base, but
// with the primary "id" field overridden to idVal. Uses the standard proto codec
// (not rawProtoCodec) so the server parses the request normally. The clone is
// built by round-tripping through proto.Marshal/Unmarshal to avoid sharing
// any internal state from base.
func invokeWithID(
	ctx context.Context,
	conn *grpc.ClientConn,
	m grpcMethod,
	base *dynamicpb.Message,
	idField protoreflect.FieldDescriptor,
	idVal uint32,
	tok string,
) (codes.Code, error) {
	b, err := proto.Marshal(base)
	if err != nil {
		return codes.Unknown, err
	}
	req := dynamicpb.NewMessage(m.input)
	unmarshalOpts := proto.UnmarshalOptions{DiscardUnknown: true}
	if err := unmarshalOpts.Unmarshal(b, req); err != nil {
		return codes.Unknown, err
	}
	req.Set(idField, protoreflect.ValueOfUint32(idVal))

	if tok != "" {
		ctx = metadata.NewOutgoingContext(ctx, metadata.Pairs("authorization", "Bearer "+tok))
	}
	resp := dynamicpb.NewMessage(m.output)
	callErr := conn.Invoke(ctx, m.fullMethod(), req, resp)
	return status.Code(callErr), callErr
}

// --- existenceWorld -------------------------------------------------------

// existenceWorld extends prWorld with known resource IDs and streaming methods.
// Built on top of buildPRWorld (which seeds a project, environment, canary
// secret, admin user, zero-grant user, and read-only user), then queries the
// IDs from the SQLite DB for use in the existence oracle.
type existenceWorld struct {
	*prWorld
	projID   uint32
	envID    uint32
	secretID uint32
	// knownIDs is the set of seeded resource IDs the existence oracle uses as
	// the "known-existing" candidate. The fuzz cursor picks one per iteration.
	knownIDs      []uint32
	streamMethods []grpcStreamingMethod
}

func buildExistenceWorld(f *testing.F) *existenceWorld {
	f.Helper()
	w := buildPRWorld(f)

	// Query the IDs of the resources seeded by buildPRWorld from the live DB.
	var projID, envID, secretID uint32
	if err := w.db.QueryRow("SELECT id FROM projects WHERE name = ?", "prfuzz-proj").Scan(&projID); err != nil {
		f.Fatalf("buildExistenceWorld: query project ID: %v", err)
	}
	if err := w.db.QueryRow("SELECT id FROM environments WHERE name = ? AND project_id = ?", "prod", projID).Scan(&envID); err != nil {
		f.Fatalf("buildExistenceWorld: query environment ID: %v", err)
	}
	// secret_nodes is the storage table for secrets (confirmed from bestEffortSideEffectTables).
	if err := w.db.QueryRow("SELECT id FROM secret_nodes WHERE name = ?", "prfuzz-canary").Scan(&secretID); err != nil {
		f.Fatalf("buildExistenceWorld: query secret ID: %v", err)
	}

	// Build a deduplicated list of known IDs from all seeded resources.
	seen := map[uint32]bool{}
	var knownIDs []uint32
	for _, id := range []uint32{projID, envID, secretID, uint32(w.zeroGrantUID), uint32(w.readOnlyUID)} {
		if id > 0 && !seen[id] {
			seen[id] = true
			knownIDs = append(knownIDs, id)
		}
	}
	if len(knownIDs) == 0 {
		f.Fatalf("buildExistenceWorld: no known resource IDs found — world is empty")
	}

	streamMethods := discoverStreamingMethods(w.srv)

	return &existenceWorld{
		prWorld:       w,
		projID:        projID,
		envID:         envID,
		secretID:      secretID,
		knownIDs:      knownIDs,
		streamMethods: streamMethods,
	}
}

// --- streaming RPC invoker ------------------------------------------------

// invokeStreamRaw calls a server-streaming RPC with rawBytes as the request
// payload (sent via rawProtoCodec, bypassing proto.Marshal on the client side).
// It drains all server-sent frames within ctx's deadline and returns:
//   - numFrames: the number of well-formed data frames received before close
//   - err: the final stream error (nil or io.EOF for a cleanly-closed stream)
//
// A cleanly-closed stream (server sent NO data, then closed with status OK)
// returns (0, nil). A denied stream returns (0, status.Error(PermissionDenied)).
func invokeStreamRaw(
	ctx context.Context,
	conn *grpc.ClientConn,
	m grpcStreamingMethod,
	rawBytes []byte,
	tok string,
) (numFrames int, err error) {
	if tok != "" {
		ctx = metadata.NewOutgoingContext(ctx, metadata.Pairs("authorization", "Bearer "+tok))
	}
	codec := rawProtoCodec{raw: rawBytes}
	cs, streamErr := conn.NewStream(ctx, &grpc.StreamDesc{
		ServerStreams: m.serverStreaming,
		ClientStreams: m.clientStreaming,
	}, m.fullMethod(), grpc.ForceCodec(codec))
	if streamErr != nil {
		return 0, streamErr
	}
	// Server-streaming: send the one client→server message, then close the send side.
	placeholder := dynamicpb.NewMessage(m.input)
	if sendErr := cs.SendMsg(placeholder); sendErr != nil {
		return 0, sendErr
	}
	if csErr := cs.CloseSend(); csErr != nil {
		return 0, csErr
	}
	// Drain response frames. io.EOF means clean stream end (status OK from server).
	resp := dynamicpb.NewMessage(m.output)
	for {
		recvErr := cs.RecvMsg(resp)
		if recvErr != nil {
			if recvErr == io.EOF {
				return numFrames, nil
			}
			return numFrames, recvErr
		}
		numFrames++
	}
}

// --- FuzzGRPCExistenceOracle ----------------------------------------------

// FuzzGRPCExistenceOracle — fuzzer inventory item #8: existence-leak oracle.
//
// For every unary RPC whose request descriptor has a primary uint32 "id" field,
// the oracle checks that a zero-grant identity gets the SAME gRPC error code
// for a known-existing resource ID and the known-non-existing ID (999999). An
// unauthenticated caller is also required to get the same code for both IDs.
//
// ADR-096 §4 (gRPC rule): a caller without global permission gets
// codes.PermissionDenied for both "exists but denied" and "does not exist" —
// the same code and message regardless of which case happened. A
// PermissionDenied vs NotFound difference leaks resource existence and is
// classified as VULNERABILITY.
//
// ResGuard heap oracle: measures per-input allocation via resguard.Probe.
// When AllocBytes/inputLen > allocAmplificationThreshold, logs RESOURCE-AMP.
// Not fatal (needs human review). Not yet calibrated via resguard.Budget.
//
// WHAT THIS DOES NOT VERIFY: see file header.
func FuzzGRPCExistenceOracle(f *testing.F) {
	ew := buildExistenceWorld(f)

	// Build the resguard Probe once per testing.F — one Probe per process is
	// correct since -parallel forks processes (one body at a time per process).
	rg := resguard.New(f, resguard.Options{
		SampleEvery: 32, // sample allocation on every 32nd input (more frequent than the default 64)
	})

	// Find all unary methods that have a primary "id" field.
	type methodWithID struct {
		m       grpcMethod
		idField protoreflect.FieldDescriptor
	}
	var idMethods []methodWithID
	for _, m := range ew.methods {
		if fd := primaryIDField(m.input); fd != nil {
			idMethods = append(idMethods, methodWithID{m: m, idField: fd})
		}
	}

	var amplificationCount atomic.Int64

	f.Cleanup(func() {
		ew.close()
		f.Logf("existence oracle: %d/%d unary methods have a primary uint32 'id' field",
			len(idMethods), len(ew.methods))
		f.Logf("existence oracle: known resource IDs: %v, non-existing probe ID: %d",
			ew.knownIDs, knownNonExistingID)
		if n := amplificationCount.Load(); n > 0 {
			f.Logf("RESOURCE-AMP: %d inputs exceeded the %dx allocation-per-byte threshold — review for amplification",
				n, allocAmplificationThreshold)
		}
	})

	if len(idMethods) == 0 {
		f.Logf("FuzzGRPCExistenceOracle: no unary methods with a primary 'id' field found — no methods to test")
		return
	}

	// Seeds: all method × knownID combinations so that every (method, resource
	// type) pair is covered at least once. For 29 methods × 4 IDs = 116 seeds.
	// Covering all combinations ensures the red-proof (planted defect) exercises
	// at least one seed where the method type matches the knownID type.
	for i := range len(idMethods) {
		for j := range len(ew.knownIDs) {
			f.Add([]byte{byte(i), byte(j)})
		}
	}

	f.Fuzz(func(t *testing.T, program []byte) {
		ew.resetPrincipalGrants(t, context.Background())

		cur := newFuzzCursor(program)
		pick := int(cur.byte()) % len(idMethods)
		mwf := idMethods[pick]
		m, idField := mwf.m, mwf.idField

		// Pick which knownID to use as the "existing" candidate.
		knownExistingID := ew.knownIDs[int(cur.byte())%len(ew.knownIDs)]

		bodyOffset := cur.pos
		buildFresh := func() *dynamicpb.Message {
			fresh := &fuzzCursor{data: program, pos: bodyOffset}
			return buildMessage(m.input, fresh, 0)
		}

		drain := func() {
			core.DrainBackgroundGoroutines()
			grpcservices.DrainBackgroundGoroutines()
		}

		// Measure the allocation cost of the two zero-grant existence calls.
		var existsCode, nonExistsCode codes.Code
		cost := rg.Measure(len(program), func() {
			drain()

			// Call 1: known-existing resource ID.
			cctx1, cancel1 := context.WithTimeout(context.Background(), perCallTimeout)
			defer cancel1()
			existsCode, _ = invokeWithID(cctx1, ew.conn, m, buildFresh(), idField, knownExistingID, ew.zeroGrantTok)
			drain()

			// Call 2: known-non-existing resource ID.
			cctx2, cancel2 := context.WithTimeout(context.Background(), perCallTimeout)
			defer cancel2()
			nonExistsCode, _ = invokeWithID(cctx2, ew.conn, m, buildFresh(), idField, knownNonExistingID, ew.zeroGrantTok)
			drain()
		})

		// Oracle: heap amplification.
		if cost.AllocSampled && cost.InputLen > 0 &&
			cost.AllocBytes > allocAmplificationThreshold*uint64(cost.InputLen) {
			amplificationCount.Add(1)
			t.Logf("RESOURCE-AMP op=%s: %d input bytes → %d alloc bytes (%.0fx) — review for amplification",
				m.key(), cost.InputLen, cost.AllocBytes,
				float64(cost.AllocBytes)/float64(max(cost.InputLen, 1)))
		}

		// Oracle: existence leak for zero-grant identity.
		// ADR-096 §4: for a caller without global permission, both "exists but
		// denied" and "does not exist" must return codes.PermissionDenied.
		if existsCode != nonExistsCode {
			existsClass := existenceCodeClass(existsCode)
			nonExistsClass := existenceCodeClass(nonExistsCode)

			if (existsCode == codes.PermissionDenied && nonExistsCode == codes.NotFound) ||
				(existsCode == codes.NotFound && nonExistsCode == codes.PermissionDenied) {
				t.Fatalf("EXISTENCE-ORACLE VIOLATION op=%s zero-grant: "+
					"id=%d→%s id=%d→%s — ADR-096 §4 violation: "+
					"zero-grant caller can probe resource existence by comparing error codes",
					m.key(), knownExistingID, existsClass, knownNonExistingID, nonExistsClass)
			}

			// Other code differences (not PermissionDenied/NotFound): logged but not fatal.
			// These can legitimately occur when knownExistingID is the wrong type for this
			// RPC (e.g., GetSecret called with a project ID → NotFound for wrong type, same
			// NotFound for 999999 → no meaningful difference). The fuzzer explores many
			// combinations; only PermissionDenied vs NotFound is an ADR-096 violation.
			t.Logf("EXISTENCE-CANDIDATE op=%s zero-grant: id=%d→%s id=%d→%s — codes differ (not PermissionDenied/NotFound; likely wrong resource type)",
				m.key(), knownExistingID, existsClass, knownNonExistingID, nonExistsClass)
		}

		// Oracle: unauthenticated caller existence leak.
		// The auth interceptor must reject BEFORE any resource lookup; both IDs
		// must therefore return the same code (Unauthenticated).
		{
			drain()
			cctx3, cancel3 := context.WithTimeout(context.Background(), perCallTimeout)
			defer cancel3()
			unauthExistsCode, _ := invokeWithID(cctx3, ew.conn, m, buildFresh(), idField, knownExistingID, "")
			drain()

			cctx4, cancel4 := context.WithTimeout(context.Background(), perCallTimeout)
			defer cancel4()
			unauthNonExistsCode, _ := invokeWithID(cctx4, ew.conn, m, buildFresh(), idField, knownNonExistingID, "")
			drain()

			if unauthExistsCode != unauthNonExistsCode {
				t.Fatalf("EXISTENCE-ORACLE VIOLATION op=%s unauthenticated: "+
					"id=%d→%s id=%d→%s — auth interceptor must reject before ID lookup; "+
					"both calls must return the same code",
					m.key(), knownExistingID, existenceCodeClass(unauthExistsCode),
					knownNonExistingID, existenceCodeClass(unauthNonExistsCode))
			}
		}
	})
}

// --- FuzzGRPCStreamingRPCs ------------------------------------------------

// FuzzGRPCStreamingRPCs — fuzzer inventory item #9: streaming RPC harness.
//
// Fuzz-tests server-streaming and bidi-streaming RPCs registered in the live
// server (currently: StreamAuditLogs). Grammar-generated first message +
// wire mutations (the same 7 kinds as FuzzGRPCProtobufGrammarWireInvariants).
//
// Oracles:
//
//	(stream-auth) unauthenticated/zero-grant callers never receive data frames
//	before the stream closes with an error.
//	(stream-no-panic) no panic-shaped error code/message for any caller.
//	(stream-client-error) malformed wire bytes → server codes.Internal is a
//	HARDENING finding (HARDENING-2 for streaming; not fatal).
//	(stream-bounded) unauthorized caller stream must close within
//	streamPerCallTimeout; DeadlineExceeded for the zero-grant caller is fatal.
//	(stream-amp) allocation oracle (same as FuzzGRPCExistenceOracle).
//
// WHAT THIS DOES NOT VERIFY: see file header.
func FuzzGRPCStreamingRPCs(f *testing.F) {
	ew := buildExistenceWorld(f)

	rg := resguard.New(f, resguard.Options{SampleEvery: 32})

	var streamHardeningCount atomic.Int64

	f.Cleanup(func() {
		ew.close()
		f.Logf("FuzzGRPCStreamingRPCs: %d streaming methods fuzzed", len(ew.streamMethods))
		if n := streamHardeningCount.Load(); n > 0 {
			f.Logf("HARDENING-2 (streaming): %d inputs caused codes.Internal on malformed wire input (expected codes.InvalidArgument)",
				n)
		}
	})

	if len(ew.streamMethods) == 0 {
		f.Logf("FuzzGRPCStreamingRPCs: no streaming methods found in live server — skipping fuzz body")
		return
	}

	// Seeds: one per method in pure-grammar mode (k=0, no wire mutation).
	for i := range len(ew.streamMethods) {
		f.Add([]byte{byte(i), 0})
	}
	// Seeds exercising wire mutation kinds on method 0.
	for k := range wireMutNumKinds {
		f.Add([]byte{0, byte(k)})
	}

	f.Fuzz(func(t *testing.T, program []byte) {
		ew.resetPrincipalGrants(t, context.Background())

		cur := newFuzzCursor(program)
		m := ew.streamMethods[int(cur.byte())%len(ew.streamMethods)]
		bodyOffset := cur.pos
		k := wireMutKind(cur.byte() % uint8(wireMutNumKinds))

		buildFresh := func() *dynamicpb.Message {
			fresh := &fuzzCursor{data: program, pos: bodyOffset}
			return buildMessage(m.input, fresh, 0)
		}
		validBytes, err := proto.Marshal(buildFresh())
		if err != nil {
			t.Skipf("proto.Marshal failed: %v", err)
		}
		mutCur := &fuzzCursor{data: program, pos: cur.pos}
		rawBytes := applyWireMut(k, validBytes, mutCur, m.input)

		drain := func() {
			core.DrainBackgroundGoroutines()
			grpcservices.DrainBackgroundGoroutines()
		}

		var zeroFrames, unauthFrames int
		var zeroErr, unauthErr, adminErr error

		cost := rg.Measure(len(program), func() {
			// Zero-grant identity.
			drain()
			cctx1, cancel1 := context.WithTimeout(context.Background(), streamPerCallTimeout)
			defer cancel1()
			zeroFrames, zeroErr = invokeStreamRaw(cctx1, ew.conn, m, rawBytes, ew.zeroGrantTok)
			drain()

			// Unauthenticated identity.
			cctx2, cancel2 := context.WithTimeout(context.Background(), streamPerCallTimeout)
			defer cancel2()
			unauthFrames, unauthErr = invokeStreamRaw(cctx2, ew.conn, m, rawBytes, "")
			drain()

			// Admin identity: exercise the actual streaming path without authz assertions.
			cctx3, cancel3 := context.WithTimeout(context.Background(), streamPerCallTimeout)
			defer cancel3()
			_, adminErr = invokeStreamRaw(cctx3, ew.conn, m, rawBytes, ew.adminTok)
			drain()
		})

		// Oracle stream-auth: unauthorized/unauthenticated callers must NEVER
		// receive data frames before the stream closes with an error.
		if zeroFrames > 0 {
			t.Fatalf("STREAM-DATA-LEAK op=%s zero-grant mutKind=%d: "+
				"received %d data frame(s) before stream closed — unauthorized data disclosure",
				m.key(), k, zeroFrames)
		}
		if unauthFrames > 0 {
			t.Fatalf("STREAM-DATA-LEAK op=%s unauthenticated mutKind=%d: "+
				"received %d data frame(s) before stream closed — unauthorized data disclosure",
				m.key(), k, unauthFrames)
		}

		// Oracle stream-no-panic: no panic-shaped error for zero-grant, unauthenticated, admin.
		if bad, reason := classifyStatusLeak(zeroErr); bad {
			t.Fatalf("STREAM-LEAK op=%s zero-grant mutKind=%d: %s", m.key(), k, reason)
		}
		if bad, reason := classifyStatusLeak(unauthErr); bad {
			t.Fatalf("STREAM-LEAK op=%s unauthenticated mutKind=%d: %s", m.key(), k, reason)
		}
		if bad, reason := classifyStatusLeak(adminErr); bad {
			t.Fatalf("STREAM-LEAK op=%s admin mutKind=%d: %s", m.key(), k, reason)
		}

		// Oracle stream-client-error: for mutations that make the bytes
		// syntactically unparseable, codes.Internal from the server is a HARDENING
		// finding (the server should return codes.InvalidArgument for client-caused
		// decode errors — same as HARDENING-1 in PBG1 for unary RPCs).
		if k.expectedDecodeError() {
			zeroCode := status.Code(zeroErr)
			if zeroCode == codes.Internal || zeroCode == codes.Unknown {
				streamHardeningCount.Add(1)
				t.Logf("HARDENING-2 (streaming) op=%s zero-grant mutKind=%d: "+
					"codes.%v for malformed wire input — expected codes.InvalidArgument",
					m.key(), k, zeroCode)
			}
		}

		// Oracle stream-bounded: the zero-grant caller's stream must close
		// promptly. DeadlineExceeded means the server did not reject the
		// unauthorized caller within streamPerCallTimeout.
		zeroCode := status.Code(zeroErr)
		if zeroCode == codes.DeadlineExceeded {
			t.Fatalf("STREAM-HUNG op=%s zero-grant mutKind=%d: "+
				"stream exceeded %s deadline — server should reject unauthorized caller immediately",
				m.key(), k, streamPerCallTimeout)
		}

		// Oracle stream-amp: heap amplification.
		if cost.AllocSampled && cost.InputLen > 0 &&
			cost.AllocBytes > allocAmplificationThreshold*uint64(cost.InputLen) {
			t.Logf("RESOURCE-AMP (streaming) op=%s mutKind=%d: %d bytes → %d alloc (%.0fx) — review",
				m.key(), k, cost.InputLen, cost.AllocBytes,
				float64(cost.AllocBytes)/float64(max(cost.InputLen, 1)))
		}
	})
}
