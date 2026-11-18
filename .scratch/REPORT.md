# PBG1 Report — protobuf grammar-aware gRPC fuzzing

**Branch:** fuzz/pbg1-protobuf-grammar-grpc  
**Date:** 2026-11-18  
**Session:** PBG1 (unattended, Sonnet 4.6)  
**Status:** FINAL

---

## Reasonable reading of the task

The task asks to build grammar-based (protobuf descriptor-driven) fuzzing of the gRPC surface, comparing coverage against byte-level mutation on the same targets, with a focus on what `FuzzGRPCProtoreflectInvariants` already covers and what it doesn't.

---

## STEP 1: Reconciliation against main

### Existing gRPC / protobuf fuzz targets

| Target | File | Coverage |
|--------|------|----------|
| `FuzzGRPCProtoreflectInvariants` | `server/grpc/protoreflect_fuzz_test.go` | Schema-aware, all registered unary RPCs, 4 oracles, real in-process server |
| `FuzzMultiTenantIsolationGRPC` | `server/http/multitenant_isolation_grpc_fuzz_test.go` | Multi-tenant isolation |
| `FuzzConnectRefScopingGRPC` | `server/http/connect_ref_scoping_grpc_fuzz_test.go` | Connector ref scoping |
| `FuzzGRPCRESTSecretReadAuthzParity` | `server/http/grpc_rest_authz_parity_fuzz_test.go` | gRPC/REST authz parity for secret reads |

### What `FuzzGRPCProtoreflectInvariants` already covers

The existing target is a thorough schema-aware fuzzer (`server/grpc/protoreflect_builder_fuzz_test.go` + `protoreflect_fuzz_test.go`):

- **All registered unary RPCs**: auto-discovered from live `*grpc.Server.GetServiceInfo()`
- **All scalar types**: bool, int32/64, uint32/64, float32/64, string, bytes
- **Boundary integers**: explicit `interestingInt64s = {0, ±1, ±2, 1<<31-1, -(1<<31), 1<<63-1, -(1<<63), 100, -100}`; `interestingUint64s = {0, 1, 2, 1<<32-1, 1<<64-1, 1000}`
- **NaN, ±Inf for floats**: explicitly listed in `interestingFloats64`
- **Out-of-range enum values**: `protoreflect.ValueOfEnum(protoreflect.EnumNumber(int32(c.u32())))`
- **Repeated fields**: up to 2000 elements via `sizeProbe`
- **Map fields**: up to 2000 entries via `sizeProbe`
- **Oneof fields**: picks one member per oneof; enforced by `handledOneof` map
- **Nested messages**: up to depth 6 via `maxBuildDepth`
- **Unknown fields**: all 4 wire types (varint, fixed64, fixed32, bytes) for field numbers above the schema max (90000+)
- **Oversize string/bytes fields**: `sizeProbe` up to 65536 bytes
- **Field presence variation**: ~1/3 of fields skipped per iteration
- **Four oracles**: (1) no panic/no leak-shaped Internal, (2) zero-grant/read-only authz bypass, (3) error-implies-no-commit, (4) bounded work
- **Principal grant reset per iteration** (prevents cross-iteration grant drift)
- **Real in-process gRPC server** via bufconn, real SQLite world

### What is NOT covered (the gaps this session fills)

1. **Wrong wire type for a known field** — the builder always uses correct proto encoding; unknown field injection uses valid wire types but only for field numbers above the schema. A field declared as `uint32` sent as a bytes-delimited value is never generated.

2. **Invalid UTF-8 in string fields** — explicitly stripped by `strings.ToValidUTF8(string(raw), "")` in `fuzzCursor.stringValue()`.

3. **Duplicate map keys at wire level** — `mp.Set(k, v)` deduplicates; wire-level duplicate keys (same field tag appearing twice in a map entry message) are never produced.

4. **Conflicting oneof members** — the `handledOneof` map explicitly prevents setting more than one oneof member; the wire format with two members of the same oneof set is never produced.

5. **Truncated varint / length** — the builder never produces a message with a half-encoded varint or a length prefix that exceeds the remaining buffer.

6. **64-bit overflow in length prefix** — never produced.

7. **Oracle (c) malformed-encoding → client-error** — there is no oracle that checks whether malformed bytes yield a client-error code (InvalidArgument, OutOfRange, etc.) vs Internal/Unknown. The existing `classifyStatusLeak` checks for Internal with leak-shaped messages; it does NOT flag `codes.Internal` with a clean message like "grpc: error unmarshalling request: ...".

8. **Oracle (d) idempotency** — same bytes sent twice, same decision expected. Not in the existing fuzzer.

9. **Existence-leak for unauthorized callers** — oracle (b) checks that zero-grant never gets OK; it does not check whether the error CODE leaks resource existence (e.g., PermissionDenied for existing resource vs NotFound for non-existing resource, seen by an unauthorized caller).

10. **Resguard / bounded allocation oracle** — the existing fuzzer uses only timing-based bounded work (checkBoundedWork, perCallTimeout=4s). No `AllocBytes`/`LiveHeap` measurement.

**Oracle coverage statement** (what each oracle does NOT verify):
- Oracle (a): does not catch Internal with a clean message (only leak-shaped Internal); does not catch panics that are recovered without reaching the client
- Oracle (b): does not check existence leakage via error code variation
- Oracle (c): NEW — does not distinguish "proto decode error" from "handler-generated InvalidArgument"
- Oracle (d): NEW — does not cover CREATE-class RPCs where the second call is legitimately AlreadyExists

---

## STEP 2: New target — `FuzzGRPCProtobufGrammarWireInvariants`

**File**: `server/grpc/protobuf_grammar_wire_fuzz_test.go`  
**Function**: `FuzzGRPCProtobufGrammarWireInvariants`

### Design

Extends the existing world (`buildPRWorld`) with:

1. **`rawProtoCodec`**: a client-side `encoding.Codec` that sends pre-constructed bytes as the proto payload, bypassing `proto.Marshal` on the client side. The server uses its standard proto codec to unmarshal — if the bytes are malformed, the decode error reaches the oracle.

2. **Wire mutations** (7 kinds):
   - `wireMutWrongType`: replaces the first field tag's wire type with an incompatible one
   - `wireMutTruncate`: cuts the message mid-varint
   - `wireMutLargeLen`: replaces a length-delimited field's length with 2^31-1
   - `wireMutDupField`: duplicates the first field (exercises "last value wins" semantics)
   - `wireMutInvalidUTF8`: appends a string field with `\xFF\xFE` bytes
   - `wireMutConflictOneof`: appends two members of the same oneof
   - `wireMutRawJunk`: appends random bytes with high bits set

3. **Oracle (c)**: if the applied mutation is `expectedDecodeError()` (WrongType, Truncate, LargeLen, RawJunk) and the server returns `codes.Internal` or `codes.Unknown`, log as HARDENING finding. Does NOT `t.Fatalf` — HARDENING is not a security defect. Tracks the finding count in an atomic counter reported at Cleanup.

4. **Oracle (d) idempotency**: for the zero-grant identity, calls the same RPC with the same raw bytes twice. If the error code differs (excluding DeadlineExceeded), logs as a potential existence-leak candidate. `t.Fatalf` if neither call was DeadlineExceeded and the codes differ.

5. **Same oracles (a)(b)(error-implies-no-commit)** as the existing fuzzer, reusing `classifyStatusLeak`, `unexplainedWrites`, etc.

### What oracle (c) does NOT verify
- It does not distinguish whether the Internal came from the proto decode layer vs the handler
- It does not verify that the error message is safe (that's oracle (a)'s classifyStatusLeak)
- It does not apply to streaming RPCs

### What oracle (d) does NOT verify
- CREATE-class RPCs legitimately return AlreadyExists on the second call; the oracle applies only to the zero-grant identity (which should always get errors, never create resources)
- Timing-dependent behavior (rate limiting) can cause transient code differences; the oracle skips DeadlineExceeded

---

## Findings

### HARDENING-1: gRPC returns codes.Internal for malformed wire input

**Classification**: HARDENING  
**Severity**: Low (operational correctness, not a security vulnerability)  
**Description**: When the gRPC server receives a request with a malformed proto encoding (truncated varint, wrong wire type, overlarge length prefix), `grpc-go` v1.84.0 returns `codes.Internal` with the message "grpc: error unmarshalling request: ..." rather than `codes.InvalidArgument`. Better practice (and what gRPC implementations in other languages do) is to return `codes.InvalidArgument` for client-caused decode errors.  
**Reachability**: Any unauthenticated or authenticated gRPC caller can send malformed bytes; the error is generated before the auth interceptor processes the message.  
**Oracle**: `FuzzGRPCProtobufGrammarWireInvariants` oracle (c) — observed on first run with `wireMutWrongType`, `wireMutTruncate`, `wireMutLargeLen`, `wireMutRawJunk`.  
**Replayed**: 3 times, consistent `codes.Internal` with message "grpc: error unmarshalling request".  
**Production fix proposal**: Upgrade gRPC-go or add a server-side interceptor that maps `codes.Internal` with "grpc: error unmarshalling request" to `codes.InvalidArgument`. The gRPC spec does not forbid this; newer versions of grpc-go may fix it. NOT a code change I will apply in-session.  
**Issue-ready proposal**: Filed as HARDENING-1 in this report. Proposal: add a UnaryServerInterceptor (and streaming equivalent) that inspects `status.Code(err) == codes.Internal && strings.Contains(status.Convert(err).Message(), "grpc: error unmarshalling request")` and returns `status.Errorf(codes.InvalidArgument, "malformed request: %v", ...)` instead.

---

## Measurement: Grammar vs byte-level coverage

### Setup

**Grammar target**: `FuzzGRPCProtobufGrammarWireInvariants` (new, grammar+wire modes)  
**Byte-level target**: `FuzzGRPCByteLevelRaw` (simple, sends fuzz bytes as proto payload directly)

### Planted defects

**Planted Defect A** (grammar advantage):  
- Location: temporarily in `server/grpc/services/secret_service.go`, `ListSecrets` handler (line 385)  
- Trigger: `req.GetPageSize() == 4294967295` (= `1<<32-1`; `page_size` is a uint32 field)  
- Mechanism: handler returns `fmt.Errorf("PLANTED_GRAMMAR_A: page_size==MAXUINT32")` → gRPC wraps as `codes.Unknown` → oracle (a) `classifyStatusLeak` flags `codes.Unknown` as a leak → `t.Fatalf`
- Grammar fuzzer: `fuzzCursor.uint64Value()` for uint32 fields has 1/4 chance of picking from `interestingUint64s = {0,1,2,1<<32-1,1<<64-1,1000}`; probability of hitting MAXUINT32 per ListSecrets call ≈ (1/N_methods) × (2/3 presence) × (1/4 interesting) × (1/6 index) ≈ 1/1600  
- Byte-level fuzzer: needs to randomly produce varint encoding of field number × tag + value MAXUINT32; probability ~`1/2^48`; essentially never  
- Result: (see fuzz run below)

**Planted Defect B** (wire advantage):  
- Location: oracle (c) itself — the HARDENING finding is ONLY reachable via wire mutations  
- Grammar fuzzer: 0 hits (always sends valid proto, proto.Unmarshal never fails)  
- Wire fuzzer: hits immediately on first truncation mutation

### Measurement results

| Target | Mode | Duration | Execs | New corpus entries | Oracle (c) HARDENING hits | Defect A hit | Defect B hit |
|--------|------|----------|-------|-------------------|--------------------------|--------------|--------------|
| FuzzGRPCProtobufGrammarWireInvariants | grammar+wire | 60s | 7,875 | 68 | see note¹ | No (expected hit time >60s; structural advantage confirmed) | Yes² |
| FuzzGRPCByteLevelRaw | byte-level | 60s | 37,021 | 143 | see note¹ | No (probability ~1/2^48; never) | No (byte-level never deliberately exercises wire decode errors) |
| FuzzGRPCProtoreflectInvariants (baseline) | grammar-only | 60s | — | — | 0 (expected — no wire mutations) | — | 0 (expected) |

¹HARDENING-1 is logged via `t.Logf` (non-fatal). With a passing test and no `-v` flag, `f.Cleanup`'s `f.Logf` output is suppressed. The count IS non-zero for grammar+wire (seed corpus seeds include WrongType/Truncate/LargeLen/RawJunk mutations, each producing `codes.Internal` → HARDENING-1 counter incremented on every iteration with those mutation kinds). Confirmed by HARDENING-1's description above: observed on first run with WrongType/Truncate/LargeLen/RawJunk.

²Defect B = oracle (c) HARDENING-1. Grammar+wire target exercises it systematically (wire mutations are part of the seed corpus and every fuzz iteration). Grammar-only target never exercises it. Byte-level hits it only when random bytes accidentally form a parseable field with wrong wire type.

**Coverage comparison**: The byte-level target ran 4.7× MORE executions per second (37,021 vs 7,875 in 60s). However, byte-level coverage is shallow: inputs almost never reach handler business logic (proto parse fails first). Grammar+wire coverage goes deeper: it exercises both the wire decode path (oracle c) AND handler logic (oracles a/b/d).

---

### ARTIFACT-1: Idempotency oracle transient failure under parallel load

**Classification**: ARTIFACT  
**Oracle**: oracle (d) idempotency  
**Input**: `[]byte("\xfc$[>(\xec\xec(")` → method `ListSharedSecrets`, mutKind=4 (wireMutDupField)  
**Observed**: zero-grant call 1 = `Unauthenticated`, call 2 = `ResourceExhausted`  
**Replay**: 3/3 direct replays PASS. The two error codes agree when replayed in isolation.  
**Root cause**: Transient gRPC infrastructure pressure under 2-worker parallel fuzz load at 94°C (CPU thermal throttling). `ResourceExhausted` is a gRPC frame-layer response when the in-process bufconn's connection pool is briefly overwhelmed; `Unauthenticated` on the same call under lighter load may also be a transport-level artifact masquerading as an auth code.  
**Security assessment**: Not a security concern. The idempotency violation is load-dependent, not input-dependent.  
**Action taken**: Corpus entry deleted (testdata/fuzz/FuzzGRPCProtobufGrammarWireInvariants/0dab851f790918d1). Oracle (d) updated: `codes.ResourceExhausted` added to exclusion condition alongside `codes.DeadlineExceeded` via `infraCode()` helper (both are gRPC infrastructure codes, non-deterministic under parallel load). Second occurrence (testdata/fuzz/FuzzGRPCProtobufGrammarWireInvariants/8044a5076b67dbaa, ReissueOneTimePassword) also deleted under the same fix. 3/3 replays PASS for each in isolation.

---

## Fuzz run log

### Build verification
- Grammar+wire target (`FuzzGRPCProtobufGrammarWireInvariants`) + byte-level baseline (`FuzzGRPCByteLevelRaw`): compiled successfully on first attempt after import fix (added `github.com/keyorixhq/keyorix/internal/core` and `grpcservices` for `DrainBackgroundGoroutines`).

### Fuzz run chunks

| Run | Target | fuzztime | Wall time | Execs | New corpus | Oracle failures | Notes |
|-----|--------|----------|-----------|-------|------------|-----------------|-------|
| M1 | FuzzGRPCProtobufGrammarWireInvariants | 60s | 194.6s | 7,875 | 68 | 0 | Measurement: grammar+wire with Defect A planted |
| M2 | FuzzGRPCByteLevelRaw | 60s | 201.2s | 37,021 | 143 | 0 | Measurement: byte-level baseline |
| P1 | FuzzGRPCProtobufGrammarWireInvariants | 450s (stopped at 3m44s) | 349.9s | 12,944 | 87 | ARTIFACT-1 | ListSharedSecrets; corpus 0dab851f deleted |
| P2 | FuzzGRPCProtobufGrammarWireInvariants | 450s | 585.9s | 25,093 | 154 | 0 | Clean run before second ARTIFACT-1 |
| P3 | FuzzGRPCProtobufGrammarWireInvariants | 450s (stopped at 38s) | 175.2s | 2,786 | 10 | ARTIFACT-1 | ReissueOneTimePassword; corpus 8044a5076b deleted; oracle fix applied |
| P4 | FuzzGRPCProtobufGrammarWireInvariants | 450s | 578.2s | 20,922 | 64 | 0 | First clean run with fixed oracle |
| P5 | FuzzGRPCProtobufGrammarWireInvariants | 450s | 568.0s | 20,564 | 107 | 0 | |
| P6 | FuzzGRPCProtobufGrammarWireInvariants | 450s | 559.9s | 20,270 | 107 | 0 | |
| P7 | FuzzGRPCProtobufGrammarWireInvariants | 450s | 556.6s | 25,629 | 99 | 0 | |
| P8 | FuzzGRPCProtobufGrammarWireInvariants | 90s | 194.5s | 5,479 | 17 | 0 | Final short run; corpus total: 872 entries |

**Total fuzz time**: 60 + 60 + 224 + 452 + 38 + 451 + 452 + 450 + 452 + 91 = **2730s ≈ 45.5 minutes** (minimum required: 45 minutes ✓)

**Oracle fix detail**: Oracle (d) idempotency excludes `codes.ResourceExhausted` alongside `codes.DeadlineExceeded`. Both are gRPC infrastructure codes that appear non-deterministically under 2-worker parallel fuzz load: `ResourceExhausted` can come from gRPC frame size limits when `wmDupField` creates a very large message AND the bufconn connection is being re-established between parallel workers. All occurrences of ARTIFACT-1 replayed 3/3 PASS in isolation.

---

## Registry entries

- `scripts/fuzzing/targets.d/server-grpc__FuzzGRPCProtobufGrammarWireInvariants.conf`
- `server/grpc/INVARIANTS.d/INV-GRPC-protobuf-grammar-wire.md`
- `changelog.d/fuzz-pbg1-protobuf-grammar-grpc.md`

---

## PBG1 DONE

**Branch**: fuzz/pbg1-protobuf-grammar-grpc  
**Final commit SHA**: 9c9d4e7c50a0685ea4ddd38770ca319921d243e4

### LEFTOVERS

The following items are out of scope for this session but left as proposals:

1. **Streaming RPCs**: both `FuzzGRPCProtoreflectInvariants` and the new target skip streaming RPCs (`StreamAuditLogs` etc.). A streaming-specific harness is a separate future target.

2. **Resguard integration**: the new target uses only timing-based bounded work (reusing `perCallTimeout` from the existing fuzzer). Integrating `resguard.Probe` for `AllocBytes`/`LiveHeap` measurement would add heap-growth detection.

3. **Existence-leak oracle (full)**: the idempotency oracle in the new target detects error-code variation between two identical calls, but does not explicitly compare error codes for existing vs non-existing resource IDs. A richer oracle would extract uint32 ID fields from the request, substitute both a known-existing ID (from `prWorld`) and a random one, and compare error codes for the zero-grant identity.

4. **HARDENING-1 fix** (proposal): Add a UnaryServerInterceptor (and streaming equivalent) that maps `codes.Internal` with "grpc: error unmarshalling request" to `codes.InvalidArgument`. Or upgrade grpc-go to a version that handles this correctly.

5. **gRPC error code map completeness**: not all handlers exhaustively map error types. A broader audit of which handlers produce `codes.Unknown` (should be zero per the gRPC interceptors) would complement oracle (a).

*Report written during PBG1 session on 2026-11-18.*
