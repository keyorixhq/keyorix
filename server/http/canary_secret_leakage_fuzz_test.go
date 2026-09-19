package http

// canary_secret_leakage_fuzz_test.go — FuzzCanarySecretLeakage.
//
// Keyorix's core promise: a secret value never appears anywhere it shouldn't. This
// fuzzer plants unique canary values — for Secret VALUES (regenerated every
// iteration), and once per world for Personal Access Tokens, a session/login token,
// a dynamic-secret admin DSN, a dynamic-secret issued lease credential, and an MFA
// enrollment secret — and drives a fuzzed sequence of hostile operations
// (cross-project reads, malformed/oversized/wrong-content-type requests, rotation,
// version reads, deletes, audit queries, list/export endpoints) through the REAL,
// fully-wired stack — the actual chi router + auth middleware + handlers + core +
// crypto + storage, PLUS the real gRPC server over bufconn — and scans EVERY
// reachable output channel for every canary after every op and at sequence end.
//
// PERFORMANCE: cost-independent-of-history-size scanning. An earlier version of this
// file scanned each output against every encoded variant of every canary ever
// planted (a list that grows every iteration) — the same per-input decay observed in
// FuzzGRPCRESTSecretReadAuthzParity. Two changes fix that:
//
//  1. Secret-VALUE-family canaries (secretA/B, the mutation-lifecycle probe's
//     throwaway values, the dynamic-secret DSN/lease canaries) all share one fixed
//     shape: deriveCanary's "kxcanary-" + 32 lowercase hex chars. Instead of
//     checking each output against N known values, every scan does a CONSTANT number
//     of passes over the output — one for the literal "kxcanary-" prefix (raw form,
//     which also covers JSON/URL-escaped since this charset needs no escaping), one
//     each for its hex encoding (lower/upper), and one each for its alignment-
//     independent base64 middle-pattern (3 phase alignments × std/url = 6) — extracts
//     the fixed-length candidate token that follows, and looks it up in a
//     map[string]struct{} (O(1) regardless of how many canaries have been planted).
//     An unrecognized-but-canary-shaped token is treated exactly like a recognized
//     one: both fail (see scanCanaryLeaks). Base64/hex hits fail on pattern match
//     alone without attempting offset-aware decode-back-to-source — no legitimate
//     channel in this codebase ever base64/hex-encodes a secret value, so a match is
//     already sufficient evidence; recovering exactly which canary leaked via a
//     base64 hit would require materially more machinery (tracking the actual
//     encoding run's start offset) for no gain in detection power. See
//     scanCanaryLeaks's doc comment for the full account.
//  2. PAT / session / MFA-enrollment secrets don't share that prefix (a raw PAT
//     token, an opaque session token, and a base32 TOTP secret are each a different,
//     system-generated shape) and are comparatively expensive to mint (PAT creation,
//     bcrypt-backed login, MFA enrollment). These are now planted ONCE per world
//     (buildCanaryWorld), not once per input — cross-input tracking still checks
//     them on every later input (a fixed, small set of ~3 literal values + their
//     encodings, itself O(1) regardless of iteration count), it just doesn't keep
//     re-minting new ones. The dynamic-secret admin DSN, its issued lease
//     credential, and the known-open webhook-URL probe (see below) moved to
//     world-build time for the same reason — real per-call cost (a DB write, or for
//     the webhook case, the audit-diff introspection query), not scan cost, was the
//     concern there.
//
// Oracle (exact-match, no heuristics): a Secret-VALUE-family canary may appear ONLY
// in the JSON response body of one of three designated, permission-checked
// value-disclosure calls — HTTP GET /secrets/value?ref=, HTTP GET
// /secrets/{id}?include_value=true, gRPC SecretService.GetSecretValue — made by a
// principal the live shadow-grant model says currently holds read access to THAT
// EXACT secret (or is admin), and even then only in the `value` field, never
// alongside any OTHER canary ever planted. PAT/session/MFA/DSN/lease are all
// generated and consumed via direct in-process core calls, so their sole
// "authorized channel" is the Go return value itself — nothing to special-case in
// the scanners; from the moment each is planted it is zero-tolerance everywhere this
// harness looks (DB, logs, every HTTP/gRPC response). This is also a genuine, useful
// assertion for two of them: PAT tokens and session tokens are stored in the DB only
// as a SHA-256 hash (see TokenHash / Session.SessionToken's doc comments), so
// scanning the DB for the RAW value additionally confirms that hashing property
// live, not just secret-value encryption.
//
// KNOWN-OPEN EXCEPTION: NotificationChannel.URL (the webhook/Slack/Teams bearer
// credential — internal/notifychan/delivery.go's own comment: "the destination URL
// IS the bearer credential") is CONFIRMED, on this branch, to leak into
// audit_events.Diff via internal/core/config_change_audit.go's
// writeConfigChangeAuditEvent, which json.Marshals the full NotificationChannel
// struct (internal/core/notification_channels.go:65-68 on create; :108,:126 on
// update/delete). See keyorix-private/adversarial-review/
// NOTIFICATION-CHANNEL-URL-AUDIT-DIFF-LEAK-2026-09-19.md (private repo, not in this
// tree) for the full trace, who-can-read analysis, and fix options. buildCanaryWorld
// creates ONE webhook channel with a canary URL and confirms the leak ONCE via
// f.Logf (not t.Fatalf) — informational, not gating, and not repeated on every
// input (re-confirming a known, unfixed, single-cause bug on every iteration adds
// cost for no new information). The webhook canary is never added to the shared
// knownCanaries map, so it plays no further part in any later scan.
// TODO(NOTIFICATION-CHANNEL-URL-AUDIT-DIFF-LEAK-2026-09-19): once fixed, delete this
// paragraph and the special-cased block in buildCanaryWorld, and fold the webhook
// canary into the normal plant() flow.
//
// Every reachable output channel is captured in-process: stdlib `log` (the sole
// logger in this codebase, redirected to a buffer), every other HTTP response body/
// header (list, versions, diff, access-log export, audit search/export, inventory
// CSV, metrics, health, every mutation response), every gRPC response/error/
// metadata/trailer, the full SQLite schema (every table, every column, introspected
// — not hand-enumerated, so a table this file's author didn't think of is still
// covered), and the raw on-disk SQLite file bytes.
//
// Audit rows are written asynchronously (goSafe, detached context). Rather than a
// fixed sleep before scanning (which can race a slow write and silently miss a real
// leak), server/http/handlers, server/grpc/services, and internal/core each expose a
// DrainBackgroundGoroutines() test hook — a WaitGroup tracking every goSafe dispatch
// — that this fuzzer calls to deterministically wait for every in-flight background
// write to land before the DB/raw-file scan.
//
// See docs/findings/ for any confirmed leak this harness's red-proofs or live runs
// surface in the public repo, keyorix-private/adversarial-review/ for the private
// finding above, and scripts/fuzzing/targets.conf for this target's soak tier.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/test/bufconn"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/dynamic"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	sqlite "github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	keyorixgrpc "github.com/keyorixhq/keyorix/server/grpc"
	grpcservices "github.com/keyorixhq/keyorix/server/grpc/services"
	"github.com/keyorixhq/keyorix/server/http/handlers"
	customMiddleware "github.com/keyorixhq/keyorix/server/middleware"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
)

// canaryPrefix identifies every deriveCanary-produced token: "kxcanary-" + 32
// lowercase hex chars, a fixed canaryTokenLen. Every Secret-VALUE-family canary in
// this file (secretA/B, the mutation-lifecycle probe, the dynamic-secret DSN/lease
// canaries) shares this exact shape, which is what makes prefix-based detection
// possible — see the file header's PERFORMANCE section.
const (
	canaryPrefix   = "kxcanary-"
	canaryBodyLen  = 32
	canaryTokenLen = len(canaryPrefix) + canaryBodyLen
)

// Precomputed once at package init -- pure functions of canaryPrefix, independent of
// any planted value, so there is nothing to recompute per scan or per plant.
var (
	canaryHexLowerPattern []byte
	canaryHexUpperPattern []byte
	canaryB64Patterns     [][]byte
)

func init() {
	h := hex.EncodeToString([]byte(canaryPrefix))
	canaryHexLowerPattern = []byte(h)
	canaryHexUpperPattern = []byte(strings.ToUpper(h))
	canaryB64Patterns = computeB64AlignmentPatterns(canaryPrefix)
}

// computeB64AlignmentPatterns returns, for each of 3 possible byte-phase alignments
// (0,1,2 — the offset canaryPrefix's bytes might start at within some larger
// base64-encoded byte stream we don't control) and each of std/url encoding, the
// substring of the base64 output that depends ONLY on canaryPrefix's own bytes —
// i.e. the run of complete 3-byte-input groups that lies entirely within the prefix,
// excluding any leading/trailing group that would also depend on unknown
// neighbouring bytes. This is the standard "carve a fixed string out of an
// unknown-offset base64 stream" technique: a complete 3-byte group always encodes to
// the same 4 base64 chars regardless of what comes before or after it, so a pattern
// built this way is a reliable, alignment-independent signal that these exact bytes
// were present, without needing to know where the encoded run itself begins.
func computeB64AlignmentPatterns(s string) [][]byte {
	var patterns [][]byte
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding} {
		for a := 0; a < 3; a++ {
			padded := append(make([]byte, a), []byte(s)...)
			full := enc.EncodeToString(padded)
			groupStart := ((a + 2) / 3) * 3
			groupEnd := ((a + len(s)) / 3) * 3
			if groupEnd <= groupStart {
				continue
			}
			charStart := (groupStart / 3) * 4
			charEnd := (groupEnd / 3) * 4
			if charStart < charEnd && charEnd <= len(full) {
				patterns = append(patterns, []byte(full[charStart:charEnd]))
			}
		}
	}
	return patterns
}

func isHexDigit(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')
}

// lockedBuffer is a mutex-guarded io.Writer standing in for stdlib log's default
// output. A goSafe-launched background goroutine can log concurrently with the
// foreground fuzz iteration draining/resetting the buffer between ops, so this needs
// real synchronization, not the single-goroutine assumption the rest of this harness
// can otherwise make (buildCanaryWorld runs once per fuzz worker PROCESS — see below).
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *lockedBuffer) Bytes() []byte {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]byte(nil), l.buf.Bytes()...)
}

func (l *lockedBuffer) Reset() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.buf.Reset()
}

type canaryPrincipal struct {
	id    uint
	token string
}

// fixedCredential is a one-time, world-lifetime credential (PAT/session/MFA) that
// doesn't share canaryPrefix's shape -- checked via a small, constant-size variant
// list (fixedValueVariants) instead of the prefix mechanism. Never grows past the
// handful planted in buildCanaryWorld, so this stays O(1) regardless of how many
// fuzz iterations run.
type fixedCredential struct {
	label    string
	variants [][]byte
}

type canaryWorld struct {
	router http.Handler
	grpc   pb.SecretServiceClient
	db     *gorm.DB
	dbPath string // on-disk SQLite file -- required for the raw-bytes plaintext-at-rest scan
	c      *core.KeyorixCore

	readerRole uint
	adminTok   string
	adminID    uint

	projAID, projBID uint
	envAID, envBID   uint
	secAID, secBID   uint
	refA, refB       string

	principals []canaryPrincipal // 3: index 2 is the deliberate "never granted by fixture setup" outsider anchor
	logBuf     *lockedBuffer

	// knownCanaries accumulates the raw ("kxcanary-"+hex) value of every
	// Secret-VALUE-family canary planted across the WHOLE fuzz world's lifetime (see
	// plant) -- every scan in this file checks against the full history via O(1) map
	// lookup, not just the current iteration's canaries, so a cross-input leak
	// (iteration 50's response containing iteration 3's stale canary) is caught, not
	// just a same-iteration one. Single-goroutine access only (one f.Fuzz iteration
	// runs at a time per worker process; goSafe background goroutines never touch
	// this map).
	knownCanaries map[string]struct{}

	// fixedCreds holds the one-time PAT/session/MFA credentials -- see fixedCredential.
	fixedCreds []fixedCredential

	// webhookExemptions holds the standing (value, channel) exceptions for the single
	// known-open webhook-URL canary (see the file header's KNOWN-OPEN EXCEPTION
	// section) -- one entry per channel where the finding is confirmed to surface
	// (db:audit_events.diff, db:raw-file, http:audit-search, http:audit-export-csv).
	// Every other channel (log/HTTP responses not listed/gRPC) never receives this
	// set, so the SAME value is still zero-tolerance there.
	webhookExemptions []exemption

	// dbWatermarks tracks, per table, the highest SQLite rowid scanDBGeneric has
	// already scanned -- see that function's doc comment for why (bounds per-input
	// DB-scan cost to rows added since the last scan, not total accumulated rows).
	dbWatermarks map[string]int64
}

// plant registers a newly-generated Secret-VALUE-family canary into the world's
// permanent knownCanaries set and returns the value unchanged, so call sites read
// naturally: valA := w.plant(deriveCanary("A", program)).
func (w *canaryWorld) plant(value string) string {
	w.knownCanaries[value] = struct{}{}
	return value
}

func (w *canaryWorld) drainLog() []byte {
	b := w.logBuf.Bytes()
	w.logBuf.Reset()
	return b
}

func (w *canaryWorld) adminReq(method, target, body string) *httptest.ResponseRecorder {
	var req *http.Request
	if body != "" {
		req = httptest.NewRequest(method, target, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequest(method, target, nil)
	}
	req.Header.Set("Authorization", "Bearer "+w.adminTok)
	rec := httptest.NewRecorder()
	w.router.ServeHTTP(rec, req)
	return rec
}

// scanOp applies the zero-tolerance oracle (against the FULL canary history) to an
// ordinary (non-value-disclosure) HTTP call's body, headers, and the log lines
// emitted while handling it. Every op in this fuzzer other than the three designated
// read endpoints, and other than the audit-record-surfacing ones (see
// scanOpAuditSurface), goes through this.
func (w *canaryWorld) scanOp(t *testing.T, opIdx int, channel, principal string, rec *httptest.ResponseRecorder) {
	t.Helper()
	w.scanOpExempt(t, opIdx, channel, principal, rec, nil)
}

// scanOpAuditSurface is scanOp's twin for the audit-search/export endpoints, which
// legitimately return audit_events content (including Diff) to any audit.read
// holder. It exempts the KNOWN-OPEN webhook-URL canary (see the file header) from
// the body/headers checks -- proven live: a 5-minute burst caught this channel
// surfacing the same known bug the DB scan already exempts (GET /api/v1/audit/search
// returns the offending Diff verbatim), which is expected and already documented in
// the private finding doc's "who can read it" section, not a new bug -- while
// keeping log zero-tolerance (a webhook URL landing in a LOG line would be a
// genuinely different, new problem).
func (w *canaryWorld) scanOpAuditSurface(t *testing.T, opIdx int, channel, principal string, rec *httptest.ResponseRecorder) {
	t.Helper()
	w.scanOpExempt(t, opIdx, channel, principal, rec, w.webhookExemptions)
}

func (w *canaryWorld) scanOpExempt(t *testing.T, opIdx int, channel, principal string, rec *httptest.ResponseRecorder, exemptions []exemption) {
	t.Helper()
	scanCanaryLeaks(t, channel+":body", opIdx, principal, rec.Body.Bytes(), w.knownCanaries, "", w.fixedCreds, exemptions)
	scanCanaryLeaks(t, channel+":headers", opIdx, principal, []byte(fmt.Sprintf("%v", rec.Header())), w.knownCanaries, "", w.fixedCreds, exemptions)
	scanCanaryLeaks(t, "log", opIdx, principal, w.drainLog(), w.knownCanaries, "", w.fixedCreds, nil)
}

// drainAllBackgroundGoroutines deterministically waits for every in-flight goSafe
// goroutine, across all three packages that duplicate the goSafe helper (handlers,
// grpc/services, core — see each package's own DrainBackgroundGoroutines doc
// comment), so a DB/raw-file scan that follows never races a slow async audit write.
// Replaces a fixed sleep, which can only ever be a guess and can silently miss a
// real leak that lands just after the sleep ends.
func drainAllBackgroundGoroutines() {
	handlers.DrainBackgroundGoroutines()
	grpcservices.DrainBackgroundGoroutines()
	core.DrainBackgroundGoroutines()
}

// deriveCanary produces a per-label canary deterministically from the given seed
// bytes -- reproducible corpus replay (same input -> same canary -> same failure),
// not crypto/rand, and safe under Go's ban on nondeterministic sources
// (Date.Now/math-rand-style) inside fuzz targets meant to be resumable/replayable.
// Called with the live `program` for per-iteration canaries, and with a fixed
// constant seed for the once-per-world ones in buildCanaryWorld.
func deriveCanary(label string, seed []byte) string {
	h := sha256.Sum256(append([]byte("kx-canary-"+label+"-"), seed...))
	return canaryPrefix + hex.EncodeToString(h[:16])
}

// fixedValueVariants computes the small set of encodings checked for the one-time
// fixedCredentials (PAT/session/MFA) -- these don't share canaryPrefix's shape, so
// they can't use the prefix mechanism above, but a plain variant list is fine here:
// there are only ever ~3 such values for the whole world's lifetime (not growing),
// so this stays O(1) regardless of how many fuzz iterations run. JSON-escaping and
// URL-encoding are omitted: neither this fuzzer's own canary charset nor a PAT's raw
// token charset ("kx_pat_" + base64.RawURLEncoding, already URL-safe) contains a
// character either encoding would alter.
func fixedValueVariants(v string) [][]byte {
	b := []byte(v)
	h := hex.EncodeToString(b)
	return [][]byte{
		b,
		[]byte(base64.StdEncoding.EncodeToString(b)),
		[]byte(base64.RawStdEncoding.EncodeToString(b)),
		[]byte(base64.URLEncoding.EncodeToString(b)),
		[]byte(base64.RawURLEncoding.EncodeToString(b)),
		[]byte(h),
		[]byte(strings.ToUpper(h)),
	}
}

func snippetAround(haystack []byte, idx, matchLen int) string {
	start := idx - 12
	if start < 0 {
		start = 0
	}
	end := idx + matchLen + 12
	if end > len(haystack) {
		end = len(haystack)
	}
	return fmt.Sprintf("context=%q", string(haystack[start:end]))
}

// exemption is ONE specific, known-open finding accepted at ONE specific channel --
// see the file header's KNOWN-OPEN EXCEPTION section. A candidate must equal `value`
// exactly (or, for a truncated/malformed byte-stream match, satisfy
// exemptionMinMatchLen -- see matchesAcceptedPartial) AND the scan's `channel` string
// must have `channelPrefix` as a prefix. Both checks are required: a DIFFERENT
// canary on the SAME channel, or this SAME value surfacing on a DIFFERENT
// (non-listed) channel, both still fail -- see the red-proof in this file's git
// history validating exactly that.
type exemption struct {
	value         string
	channelPrefix string
	reason        string // human-readable, cites the private finding doc by name
}

// matchesAcceptedPartial reports whether a truncated/malformed partial candidate
// (found on channel `channel`) is a byte-for-byte prefix of `allowed` or of some
// exemption whose channelPrefix matches `channel` -- AND, critically, is NOT ALSO a
// prefix of any OTHER currently-known canary (from `known`, or any OTHER
// exemption's value). Used when a raw-byte stream cuts an otherwise-legitimate value
// short -- e.g. a SQLite page boundary or page-slack (freed/reused page space still
// holding a fragment of a PAST write) landing inside the known-open webhook canary's
// own bytes, observed live during burst runs at unpredictable, sometimes short,
// lengths -- so that byte-level truncation of an already-accepted value doesn't read
// as a brand-new finding.
//
// A FIXED minimum match length was tried first and rejected: every canary shares the
// identical 9-byte canaryPrefix, so any fixed threshold is either too strict (a real,
// live burst produced a 16-byte match -- prefix + 7 hex chars -- for the SAME already
// -accepted webhook value, which a length-25 floor wrongly rejected as a new finding)
// or, lowered enough to accept that, too permissive (a short match could equally be
// the START of a genuinely different, unrelated canary). The ambiguity check below is
// the actually-correct test: a partial is safe to accept only if it uniquely
// identifies the accepted value among every canary this run currently knows about --
// if the SAME partial bytes could equally be the start of some OTHER live canary, we
// cannot tell which one actually produced them, so it fails as a genuine finding
// rather than being silently waved through. This scales with entropy actually in
// play (how many distinct canaries currently exist), not a number picked in advance.
// Only the RARE truncated/malformed path pays this known-set scan; the common-case
// full-candidate match stays a single O(1) map lookup (see exemptedFull), so this
// does not reopen the O(history) cost this file's PERFORMANCE section fixed.
func matchesAcceptedPartial(channel, partial, allowed string, exemptions []exemption, known map[string]struct{}) bool {
	if len(partial) < len(canaryPrefix) {
		return false // shorter than the shared literal prefix itself carries no information at all
	}
	acceptedVia := "" // the ONE value this partial is being provisionally credited to
	if allowed != "" && len(partial) <= len(allowed) && allowed[:len(partial)] == partial {
		acceptedVia = allowed
	}
	for _, ex := range exemptions {
		if !strings.HasPrefix(channel, ex.channelPrefix) {
			continue
		}
		if len(partial) <= len(ex.value) && ex.value[:len(partial)] == partial {
			acceptedVia = ex.value
		}
	}
	if acceptedVia == "" {
		return false
	}
	// Ambiguity check: this partial is only safe to accept if it does NOT also match
	// the start of some OTHER live canary -- otherwise we cannot tell which one
	// actually produced these bytes, and waving it through would risk hiding a
	// genuinely different canary's own truncated leak.
	for k := range known {
		if k == acceptedVia {
			continue
		}
		if len(partial) <= len(k) && k[:len(partial)] == partial {
			return false
		}
	}
	for _, ex := range exemptions {
		if ex.value == acceptedVia {
			continue
		}
		if len(partial) <= len(ex.value) && ex.value[:len(partial)] == partial {
			return false
		}
	}
	if allowed != "" && allowed != acceptedVia && len(partial) <= len(allowed) && allowed[:len(partial)] == partial {
		return false
	}
	return true
}

// exemptedFull is matchesAcceptedPartial's twin for a COMPLETE, well-formed
// candidate (no length gate needed -- a full match is already maximally specific):
// true only if some exemption's value equals candidate exactly AND channel has that
// exemption's channelPrefix. A different canary value is never exempted just because
// it lands on an exempted channel, and this value is never exempted on a channel not
// listed.
func exemptedFull(channel, candidate string, exemptions []exemption) bool {
	for _, ex := range exemptions {
		if candidate == ex.value && strings.HasPrefix(channel, ex.channelPrefix) {
			return true
		}
	}
	return false
}

// hexEncodedCandidateAt attempts to decode a full canary token immediately following
// a hex-encoded-prefix match at haystack[pos:pos+prefixPatternLen]: reads the next
// canaryBodyLen*2 hex chars, decodes them back to canaryBodyLen raw bytes, and
// validates every decoded byte is itself a lowercase hex digit (since a genuine
// canary body is "kxcanary-" + hex digits — decoding its hex ENCODING must yield hex
// digit bytes back). Returns the reconstructed raw candidate token and true on
// success.
func hexEncodedCandidateAt(haystack []byte, pos, prefixPatternLen int) (string, bool) {
	bodyHexLen := canaryBodyLen * 2
	start := pos + prefixPatternLen
	end := start + bodyHexLen
	if end > len(haystack) {
		return "", false
	}
	decoded, err := hex.DecodeString(string(haystack[start:end]))
	if err != nil {
		return "", false
	}
	for _, c := range decoded {
		if !isHexDigit(c) {
			return "", false
		}
	}
	return canaryPrefix + string(decoded), true
}

// scanCanaryLeaks is the sole scanning primitive in this file (see the header's
// PERFORMANCE section for why). Cost is O(len(haystack)) times a CONSTANT number of
// pattern passes (1 raw + 2 hex + 6 base64 + 7×len(fixedCreds)) — independent of
// len(known), which is what keeps per-input scan cost flat as knownCanaries grows
// across a long soak.
//
//   - Raw form ("kxcanary-"+hex, literal): every occurrence is extracted as a
//     candidate 41-byte token. `allowed`, if non-empty, is the one candidate value
//     exempted (the authorized read's own legitimately-disclosed value — see
//     checkValueEndpoint). Any OTHER candidate fails, whether it's in `known` (a
//     historical/cross-input leak) or not (an unrecognized-but-canary-shaped token —
//     could be a tracking gap in this harness itself, but is exactly as much a
//     finding either way, so it fails the same). A prefix match with insufficient
//     trailing bytes, or trailing bytes that aren't all hex digits, also fails
//     (malformed/truncated is still suspicious, never silently ignored).
//   - Hex-encoded form: same extract-and-classify, via hexEncodedCandidateAt.
//   - Base64 form (any of 3 phase alignments, std/url): pattern match alone fails —
//     no legitimate channel in this codebase ever base64-encodes a secret value, so
//     recovering exactly which canary leaked isn't needed to know it's a leak.
//   - fixedCreds (PAT/session/MFA): a small, constant-size direct Contains check per
//     precomputed variant.
//
// exemptions is a small, standing set of (value, channel) exceptions that must
// NEVER fail here -- checked in addition to `allowed` -- unlike `allowed` (one
// call's own legitimate disclosure), an exemption is permanent for every call whose
// channel matches its channelPrefix. Its only use in this file is the known-open
// webhook-URL-into-audit-diff finding (see the file header): the webhook canary
// shares canaryPrefix's shape, so without this it would be flagged as an
// "unknown/unrecognized" token on every scan of an affected channel for the rest of
// the run. A DIFFERENT canary value is never exempted just because it lands on the
// same channel, and this SAME value is never exempted on a channel not listed. Pass
// nil for channels where no such standing exception exists (most of them).
//
// rawFileChannel (below) is the one channel where a truncated/malformed prefix match
// is informational (t.Logf) rather than fatal. This is NOT an exemption of a
// specific value -- it applies regardless of whether the fragment matches anything
// known. Rationale: db:raw-file is the only channel in this file that scans
// UNSTRUCTURED bytes spanning SQLite page/B-tree-internal structure and (confirmed
// live, twice, during burst runs) freed-page slack from a row that physically
// relocated -- a canary's own bytes interrupted by binary garbage at an
// unpredictable, sometimes very short, offset. No fixed length or "unambiguous
// against the known set" heuristic can soundly attribute an arbitrarily short
// fragment (a live burst produced one just 1 hex digit past the shared prefix,
// genuinely ambiguous against a large known-canary population) to a specific source
// value -- and it doesn't need to: every OTHER channel in this file only ever
// contains well-formed, complete values (a SQL cell is never partial; an HTTP/gRPC/
// log payload is structured text, never raw disk bytes), so a truncated/malformed
// match there is genuinely suspicious and stays fatal. A COMPLETE, well-formed match
// on db:raw-file (the exemptedFull / candidate==allowed paths below) is UNCHANGED --
// still zero-tolerance -- so a real, whole leaked value sitting anywhere in the file,
// fragmented or not, is still caught; only unattributable partial fragments are
// downgraded to a log line.
const rawFileChannel = "db:raw-file"

func scanCanaryLeaks(t *testing.T, channel string, opIdx int, principal string, haystack []byte, known map[string]struct{}, allowed string, fixedCreds []fixedCredential, exemptions []exemption) {
	t.Helper()

	prefixBytes := []byte(canaryPrefix)
	pos := 0
	for {
		rel := bytes.Index(haystack[pos:], prefixBytes)
		if rel < 0 {
			break
		}
		start := pos + rel
		end := start + canaryTokenLen
		if end > len(haystack) {
			// A real DB/file byte stream can legitimately cut an exempted value off
			// mid-token (e.g. a SQLite page boundary landing inside the known-open
			// webhook canary's own bytes -- observed live during a burst run). If every
			// available byte matches the START of allowed or a channel-matching
			// exemption, AND that match is unambiguous against every OTHER currently
			// known canary (see matchesAcceptedPartial), this is that same accepted
			// artifact, not a new finding.
			if matchesAcceptedPartial(channel, string(haystack[start:]), allowed, exemptions, known) {
				break
			}
			if channel == rawFileChannel {
				t.Logf("canary-prefixed fragment (truncated at end-of-file, unattributable) on %s op #%d principal=%s -- %s -- not failing, see rawFileChannel's doc comment",
					channel, opIdx, principal, snippetAround(haystack, start, len(haystack)-start))
				break
			}
			t.Fatalf("CANARY LEAK [%s:raw] op #%d principal=%s: truncated canary-prefixed token -- %s",
				channel, opIdx, principal, snippetAround(haystack, start, len(haystack)-start))
		}
		body := haystack[start+len(canaryPrefix) : end]
		validLen := 0
		for _, c := range body {
			if !isHexDigit(c) {
				break
			}
			validLen++
		}
		candidate := string(haystack[start:end])
		if malformed := validLen < len(body); malformed {
			// Same reasoning as the truncated-token branch above, but here the byte
			// stream didn't run out -- it just stopped being valid hex partway
			// through (observed live: SQLite page/pointer bytes immediately after a
			// handful of the webhook canary's own leading hex chars). Compare only
			// the leading VALID portion against allowed/exemptions, not the full
			// fixed-length candidate (which includes the garbage tail and could
			// never equal a clean known value).
			partial := canaryPrefix + string(body[:validLen])
			if matchesAcceptedPartial(channel, partial, allowed, exemptions, known) {
				pos = start + 1
				continue
			}
			if channel == rawFileChannel {
				t.Logf("canary-prefixed fragment (malformed, unattributable) on %s op #%d principal=%s: %q -- %s -- not failing, see rawFileChannel's doc comment",
					channel, opIdx, principal, candidate, snippetAround(haystack, start, canaryTokenLen))
				pos = start + 1
				continue
			}
			t.Fatalf("CANARY LEAK [%s:raw] op #%d principal=%s: malformed canary-prefixed token %q -- %s",
				channel, opIdx, principal, candidate, snippetAround(haystack, start, canaryTokenLen))
		}
		if candidate == allowed {
			pos = start + 1
			continue
		}
		if exemptedFull(channel, candidate, exemptions) {
			pos = start + 1
			continue
		}
		_, isKnown := known[candidate]
		label := "unknown/unrecognized"
		if isKnown {
			label = "known/historical"
		}
		t.Fatalf("CANARY LEAK [%s:raw] op #%d principal=%s: %s token %q -- %s",
			channel, opIdx, principal, label, candidate, snippetAround(haystack, start, canaryTokenLen))
	}

	for _, hp := range [][]byte{canaryHexLowerPattern, canaryHexUpperPattern} {
		pos := 0
		for {
			rel := bytes.Index(haystack[pos:], hp)
			if rel < 0 {
				break
			}
			start := pos + rel
			candidate, ok := hexEncodedCandidateAt(haystack, start, len(hp))
			if !ok {
				pos = start + 1
				continue // insufficient/undecodable trailing bytes -- not a fabricated hex-encoded canary, just noise; the raw-form loop above is what actually proves presence
			}
			if candidate == allowed {
				pos = start + 1
				continue
			}
			if exemptedFull(channel, candidate, exemptions) {
				pos = start + 1
				continue
			}
			_, isKnown := known[candidate]
			label := "unknown/unrecognized"
			if isKnown {
				label = "known/historical"
			}
			t.Fatalf("CANARY LEAK [%s:hex] op #%d principal=%s: %s token %q -- %s",
				channel, opIdx, principal, label, candidate, snippetAround(haystack, start, len(hp)+canaryBodyLen*2))
		}
	}

	for _, p := range canaryB64Patterns {
		if idx := bytes.Index(haystack, p); idx >= 0 {
			t.Fatalf("CANARY LEAK [%s:base64] op #%d principal=%s: matched %q -- %s",
				channel, opIdx, principal, string(p), snippetAround(haystack, idx, len(p)))
		}
	}

	for _, fc := range fixedCreds {
		for _, v := range fc.variants {
			if idx := bytes.Index(haystack, v); idx >= 0 {
				t.Fatalf("CANARY LEAK [%s:%s] op #%d principal=%s: matched %q -- %s",
					channel, fc.label, opIdx, principal, string(v), snippetAround(haystack, idx, len(v)))
			}
		}
	}
}

type valueEnvelope struct {
	Data struct {
		Value string `json:"value"`
	} `json:"data"`
}

// checkValueEndpoint is the nuanced oracle for the three designated Secret-VALUE
// disclosure calls. allowed comes from the live shadow-grant model (or admin), NOT
// from the HTTP/gRPC status code -- so an authz bug that returns 200 to an
// unauthorized principal is still caught (AUTHZ BYPASS below), same as the
// wantVal/gotValue mismatch catches a cross-secret substitution bug (INTEGRITY
// below). The final cross-check exempts only wantVal's own raw form -- so it catches
// not just "the other of A/B" riding along, but any historical canary of any type.
func checkValueEndpoint(t *testing.T, w *canaryWorld, opIdx int, channel, principal string, allowed, statusOK bool, gotValue string, code int, body, headerBytes []byte, wantVal string) {
	t.Helper()
	if len(headerBytes) > 0 {
		scanCanaryLeaks(t, channel+":headers", opIdx, principal, headerBytes, w.knownCanaries, "", w.fixedCreds, nil)
	}
	if !allowed {
		if statusOK {
			t.Fatalf("op #%d [%s]: AUTHZ BYPASS -- unauthorized principal=%s got a successful response (code=%d)", opIdx, channel, principal, code)
		}
		scanCanaryLeaks(t, channel+":deny-body", opIdx, principal, body, w.knownCanaries, "", w.fixedCreds, nil)
		return
	}
	if !statusOK {
		// Never assert must-200 for an allowed call (matches FuzzKeyorixHTTPAPISequence's
		// own convention) -- but whatever came back still gets zero tolerance.
		scanCanaryLeaks(t, channel+":allow-nonOK-body", opIdx, principal, body, w.knownCanaries, "", w.fixedCreds, nil)
		return
	}
	if gotValue != wantVal {
		t.Fatalf("op #%d [%s]: INTEGRITY -- authorized read by %s returned a value that does not match the requested secret's canary (got len=%d want len=%d) -- possible cross-secret leak",
			opIdx, channel, principal, len(gotValue), len(wantVal))
	}
	scanCanaryLeaks(t, channel+":allow-body-cross-check", opIdx, principal, body, w.knownCanaries, wantVal, w.fixedCreds, nil)
}

var canaryTableNameRe = regexp.MustCompile(`^[A-Za-z0-9_]+$`)

func cellBytes(v interface{}) []byte {
	switch x := v.(type) {
	case nil:
		return nil
	case []byte:
		return x
	case string:
		return []byte(x)
	default:
		return []byte(fmt.Sprintf("%v", x))
	}
}

// scanDBGeneric introspects the live schema (sqlite_master + PRAGMA table_info) and
// applies scanCanaryLeaks to every cell of every table. Introspection, not a
// hand-enumerated table list, on purpose -- this codebase's own standing lesson is
// that a hand-maintained enumeration of call/storage shapes reliably misses one (see
// CLAUDE.md's "an enumeration is only as complete as the idioms it knows about").
// This single mechanism is what makes audit_events, notifications, anomaly_alerts,
// secret_metadata_histories, dynamic_secret_configs/leases, mfa_secrets,
// personal_access_tokens, sessions, and secret_versions.encrypted_value all covered
// without a per-table special case.
//
// Each table's rows are read fully into memory and dataRows is closed BEFORE any
// scanCanaryLeaks call for that table -- not interleaved. scanCanaryLeaks can
// t.Fatalf mid-scan, and with SetMaxOpenConns(1) an open *sql.Rows left behind by an
// abrupt Fatalf-triggered goroutine exit (no deferred Close reached) permanently
// starves the connection pool: the very next query, on the very next fuzz input,
// blocks forever waiting for a connection that will never be released. An earlier
// version of this function scanned while iterating dataRows directly and hit exactly
// this deadlock the first time a DB-scan leak actually fired.
//
// INCREMENTAL, via watermarks: without this, "SELECT * FROM tbl" re-reads and
// re-scans every row on every single fuzz input, so per-input cost grows with total
// accumulated row count (audit_events/secret_versions grow every iteration) even
// after the canary-tracking side is O(1) -- observed live as ~3x throughput decay
// over a 5-minute burst before this fix. watermarks[tbl] is the highest SQLite
// rowid already scanned for that table; each call only reads WHERE rowid >
// watermark, so cost is O(rows added since the last scan), not O(total rows).
//
// Soundness rests on this codebase's actual write patterns being append-only for
// every canary-relevant table this fuzzer touches: secret_versions/audit_events/
// personal_access_tokens/sessions/mfa_secrets/dynamic_secret_configs/leases/
// notification_channels are all created once and never have a NEW canary value
// written into an EXISTING row afterward (secret_nodes rows do get updated, e.g. a
// current-version pointer, but never with value content). If some future write path
// broke that assumption, an in-place UPDATE introducing a leak into an
// already-scanned rowid would be invisible here -- but scanRawDBFile (unavoidably
// O(file size), run every iteration, no watermark) reads the CURRENT bytes of the
// whole file every time, so it remains a full backstop regardless of this
// assumption; this function's incremental scan is a speed optimization on top of
// that guarantee, not a narrowing of it.
func scanDBGeneric(t *testing.T, sqlDB *sql.DB, known map[string]struct{}, fixedCreds []fixedCredential, exemptions []exemption, watermarks map[string]int64) {
	t.Helper()
	rows, err := sqlDB.Query(`SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'`)
	if err != nil {
		t.Fatalf("db scan: list tables: %v", err)
	}
	var tables []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			rows.Close()
			t.Fatalf("db scan: scan table name: %v", err)
		}
		if canaryTableNameRe.MatchString(n) {
			tables = append(tables, n)
		}
	}
	rows.Close()

	for _, tbl := range tables {
		colRows, err := sqlDB.Query("PRAGMA table_info(" + tbl + ")")
		if err != nil {
			t.Fatalf("db scan: table_info %s: %v", tbl, err)
		}
		var cols []string
		for colRows.Next() {
			var cid int
			var name, ctype string
			var notnull, pk int
			var dflt interface{}
			if err := colRows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
				colRows.Close()
				t.Fatalf("db scan: table_info scan %s: %v", tbl, err)
			}
			if canaryTableNameRe.MatchString(name) {
				cols = append(cols, name)
			}
		}
		colRows.Close()
		if len(cols) == 0 {
			continue
		}

		quoted := make([]string, len(cols))
		for i, c := range cols {
			quoted[i] = `"` + c + `"`
		}
		wm := watermarks[tbl]
		//nolint:gosec -- table/col names are schema-introspected (sqlite_master/PRAGMA), not attacker input, and regex-validated above; wm is a bound parameter, not interpolated
		dataRows, err := sqlDB.Query("SELECT rowid, "+strings.Join(quoted, ",")+" FROM "+tbl+" WHERE rowid > ? ORDER BY rowid", wm)
		if err != nil {
			t.Fatalf("db scan: select %s: %v", tbl, err)
		}
		dest := make([]interface{}, len(cols)+1) // [0] = rowid
		ptrs := make([]interface{}, len(cols)+1)
		for i := range dest {
			ptrs[i] = &dest[i]
		}
		var cellData [][]byte
		var cellCol []string
		maxRowid := wm
		for dataRows.Next() {
			if err := dataRows.Scan(ptrs...); err != nil {
				dataRows.Close()
				t.Fatalf("db scan: row scan %s: %v", tbl, err)
			}
			if rid, ok := dest[0].(int64); ok && rid > maxRowid {
				maxRowid = rid
			}
			for i := 1; i < len(dest); i++ {
				b := cellBytes(dest[i])
				if b == nil {
					continue
				}
				cellData = append(cellData, b)
				cellCol = append(cellCol, cols[i-1])
			}
		}
		dataRows.Close() // closed BEFORE scanning below -- see the doc comment above
		watermarks[tbl] = maxRowid

		for i, b := range cellData {
			scanCanaryLeaks(t, fmt.Sprintf("db:%s.%s", tbl, cellCol[i]), 0, "n/a", b, known, "", fixedCreds, exemptions)
		}
	}
}

// scanRawDBFile scans the raw on-disk SQLite file bytes -- the literal plaintext-
// at-rest check the RULES call for, distinct from and in addition to scanDBGeneric's
// column-level scan (this also catches anything sitting in freelist/overflow pages a
// column-level SELECT wouldn't surface). Requires a FILE-backed DB, not :memory: --
// see buildCanaryWorld.
func scanRawDBFile(t *testing.T, path string, known map[string]struct{}, fixedCreds []fixedCredential, exemptions []exemption) {
	t.Helper()
	data, err := os.ReadFile(path) //nolint:gosec -- path is this fuzz target's own f.TempDir()-scoped file, not user input
	if err != nil {
		t.Fatalf("db scan: read raw file %s: %v", path, err)
	}
	scanCanaryLeaks(t, rawFileChannel, 0, "n/a", data, known, "", fixedCreds, exemptions)
}

// buildCanaryWorld stands up the real production stack once per fuzz worker PROCESS
// (Go's native fuzzer runs each -fuzz worker as a separate OS process; within one
// process, f.Fuzz iterations run sequentially on one goroutine, so buildCanaryWorld's
// single shared world is never touched by two iterations concurrently -- only by the
// occasional goSafe background goroutine, which is why logBuf needs its own mutex).
//
// Unlike the sibling fuzz harnesses in this package, this world is FILE-backed SQLite
// (not :memory:) -- the RULES require scanning the raw on-disk file, which is only
// meaningful for a real file -- and wires BOTH secret-value and auth-secret
// encryptors (SetSecretValueEncryptor / SetAuthEncryptor), so the plaintext-at-rest
// assertion is live for secret values, MFA secrets, and dynamic-secret DSNs/leases
// alike, not vacuous. A fake dynamic-secret engine (dynamic.FakeEngine, the same one
// internal/core's own tests use) is injected so lease issuance works without a real
// Postgres/MySQL target -- FakeEngine.IssueFields lets a test-chosen canary become
// the issued credential.
//
// PAT / session / MFA / dynamic-secret DSN+lease / the known-open webhook probe are
// all planted HERE, once, not per fuzz input -- see the file header's PERFORMANCE
// section for why.
func buildCanaryWorld(f *testing.F) *canaryWorld {
	f.Helper()
	if err := i18n.InitializeForTesting(); err != nil {
		f.Fatalf("i18n: %v", err)
	}

	dbPath := filepath.Join(f.TempDir(), "canary.db")
	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		f.Fatalf("open sqlite: %v", err)
	}
	if sqlDB, e := db.DB(); e == nil {
		sqlDB.SetMaxOpenConns(1)
	}
	if err := db.AutoMigrate(models.AllTestModels()...); err != nil {
		f.Fatalf("migrate: %v", err)
	}
	for _, ix := range []string{
		"CREATE UNIQUE INDEX IF NOT EXISTS uniq_project_memberships_active ON project_memberships (project_id, user_id) WHERE state <> 'revoked'",
		"CREATE UNIQUE INDEX IF NOT EXISTS uniq_legal_holds_active ON legal_holds (released) WHERE released = false",
		"CREATE UNIQUE INDEX IF NOT EXISTS uniq_break_glass_active_project_user ON break_glass_activations (project_id, user_id) WHERE state = 'active'",
		"CREATE UNIQUE INDEX IF NOT EXISTS uniq_users_email_active ON users (LOWER(email)) WHERE deleted_at IS NULL AND email <> ''",
		"CREATE UNIQUE INDEX IF NOT EXISTS uniq_dynamic_secret_configs_project_env_name ON dynamic_secret_configs (project_id, environment_id, name)",
	} {
		_ = db.Exec(ix).Error
	}

	enc := encryption.NewService(&config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}, f.TempDir())
	if err := enc.Initialize("canary-fuzz-test-passphrase"); err != nil {
		f.Fatalf("encryption init: %v", err)
	}

	c := core.NewKeyorixCore(store.NewLocalStorage(db))
	c.SetSecretValueEncryptor(enc)
	if !c.SecretValueEncryptionActive() {
		f.Fatalf("encryption did not activate -- plaintext-at-rest check would be vacuous")
	}
	c.SetAuthEncryptor(enc) // MFA secrets + dynamic-secret admin DSNs/lease credentials
	fakeDyn := &dynamic.FakeEngine{NativeExpiry: true}
	c.SetDynamicEngineFactory(func(string) (dynamic.CredentialEngine, error) { return fakeDyn, nil })
	c.SetTokenCacheInvalidator(customMiddleware.InvalidateTokenCacheByHash)
	ls := store.NewLocalStorage(db)
	ctx := context.Background()

	c.SetBootstrapToken("test-bootstrap-token")
	if _, err := c.BootstrapSystem(ctx, &core.BootstrapRequest{
		Username: "testadmin", Email: "testadmin@example.com",
		Password: "TestPassword123!", Token: "test-bootstrap-token",
	}); err != nil {
		f.Logf("bootstrap: %v (may already be initialised)", err)
	}
	adminSess, _, err := c.Login(ctx, &core.LoginRequest{Username: "testadmin", Password: "TestPassword123!"})
	if err != nil {
		f.Fatalf("admin login: %v", err)
	}
	admin, err := ls.GetUserByUsername(ctx, "testadmin")
	if err != nil || admin == nil {
		f.Fatalf("admin lookup: %v", err)
	}

	pA, err := ls.CreateProject(ctx, &models.Project{Name: "canary-proja"})
	if err != nil {
		f.Fatalf("projA: %v", err)
	}
	eA, err := ls.CreateEnvironment(ctx, &models.Environment{Name: "prod", ProjectID: pA.ID})
	if err != nil {
		f.Fatalf("envA: %v", err)
	}
	pB, err := ls.CreateProject(ctx, &models.Project{Name: "canary-projb"})
	if err != nil {
		f.Fatalf("projB: %v", err)
	}
	eB, err := ls.CreateEnvironment(ctx, &models.Environment{Name: "prod", ProjectID: pB.ID})
	if err != nil {
		f.Fatalf("envB: %v", err)
	}

	var perm models.Permission
	if e := db.Where("name = ?", "secrets.read").First(&perm).Error; e != nil {
		perm = models.Permission{Name: "secrets.read", Resource: "secrets", Action: "read"}
		if e2 := db.Create(&perm).Error; e2 != nil {
			f.Fatalf("seed permission: %v", e2)
		}
	}
	role := models.Role{Name: "canary-fuzz-reader", NameFolded: "canary-fuzz-reader"}
	if e := db.Create(&role).Error; e != nil {
		f.Fatalf("seed role: %v", e)
	}
	if e := db.Create(&models.RolePermission{RoleID: role.ID, PermissionID: perm.ID}).Error; e != nil {
		f.Fatalf("seed role-permission: %v", e)
	}

	sA, err := c.CreateSecret(ctx, &core.CreateSecretRequest{
		Name: "sa", Value: []byte("kxcanary-initial-a"), ProjectID: pA.ID, EnvironmentID: eA.ID,
		Type: "password", CreatedBy: "testadmin", OwnerID: admin.ID,
	})
	if err != nil || sA == nil {
		f.Fatalf("secretA: %v", err)
	}
	sB, err := c.CreateSecret(ctx, &core.CreateSecretRequest{
		Name: "sb", Value: []byte("kxcanary-initial-b"), ProjectID: pB.ID, EnvironmentID: eB.ID,
		Type: "password", CreatedBy: "testadmin", OwnerID: admin.ID,
	})
	if err != nil || sB == nil {
		f.Fatalf("secretB: %v", err)
	}

	mkPrincipal := func(uname, email string) canaryPrincipal {
		u, err := c.CreateUser(ctx, &core.CreateUserRequest{Username: uname, Email: email, Password: apiFuzzPrincipalPassword})
		if err != nil || u == nil {
			f.Fatalf("create user %s: %v", uname, err)
		}
		tok := ""
		if sess, _, lerr := c.Login(ctx, &core.LoginRequest{Username: uname, Password: apiFuzzPrincipalPassword}); lerr == nil && sess != nil {
			tok = sess.SessionToken
		} else {
			f.Logf("principal %s could not obtain a session (%v) -- treated as no-token", uname, lerr)
		}
		return canaryPrincipal{id: u.ID, token: tok}
	}
	principals := []canaryPrincipal{
		mkPrincipal("canary-readera", "canary-readera@x.io"),
		mkPrincipal("canary-readerb", "canary-readerb@x.io"),
		mkPrincipal("canary-outsider", "canary-outsider@x.io"),
	}

	knownCanaries := map[string]struct{}{}
	plantOnce := func(v string) string {
		knownCanaries[v] = struct{}{}
		return v
	}
	var fixedCreds []fixedCredential

	// PAT: DB stores only TokenHash (SHA-256); scanning the DB for the raw token
	// additionally confirms that hashing property live.
	if patRes, err := c.CreateOwnPAT(ctx, principals[0].id, "canary-pat-world", nil, []string{"secrets.read"}, 0, 0, nil); err == nil && patRes != nil {
		fixedCreds = append(fixedCreds, fixedCredential{label: "pat", variants: fixedValueVariants(patRes.PlainToken)})
	} else {
		f.Logf("PAT canary setup skipped (%v)", err)
	}

	// Session token: DB stores only a SHA-256 hash (Session.SessionToken); same
	// confirmation as PAT, for a completely different subsystem. A dedicated fresh
	// login (not one of the principals' own already-tracked sessions) so this
	// checks a token that was never used as a Bearer credential anywhere in this
	// harness -- its ONLY legitimate appearance is this one Login return value.
	if sess, _, lerr := c.Login(ctx, &core.LoginRequest{Username: "canary-readera", Password: apiFuzzPrincipalPassword}); lerr == nil && sess != nil {
		fixedCreds = append(fixedCreds, fixedCredential{label: "session", variants: fixedValueVariants(sess.SessionToken)})
	} else {
		f.Logf("session canary setup skipped (%v)", lerr)
	}

	// MFA enrollment secret: DB stores only SecretEnc (encrypted). A dedicated
	// throwaway user avoids interfering with the fixture principals.
	if mfaUser, uerr := c.CreateUser(ctx, &core.CreateUserRequest{
		Username: "canary-mfa-world", Email: "canary-mfa-world@x.io", Password: apiFuzzPrincipalPassword,
	}); uerr == nil && mfaUser != nil {
		if _, secret, merr := c.BeginMFAEnrollment(ctx, mfaUser.ID); merr == nil {
			fixedCreds = append(fixedCreds, fixedCredential{label: "mfa", variants: fixedValueVariants(secret)})
		} else {
			f.Logf("MFA canary setup skipped (%v)", merr)
		}
	} else {
		f.Logf("MFA canary user setup skipped (%v)", uerr)
	}

	// Dynamic-secret admin DSN: never echoed back in ANY response (AdminDSNEnc/
	// AdminDSNMeta are both encrypted, json:"-") -- zero-tolerance from the moment
	// it's supplied as create input, no allowlisted channel at all. Shares
	// canaryPrefix's shape, so it goes through plantOnce into knownCanaries like any
	// Secret-VALUE-family canary, not a fixedCredential.
	dsnCanary := plantOnce(deriveCanary("dsn-world", []byte("world-init")))
	dsn := fmt.Sprintf("postgres://admin:%s@db.internal:5432/app", dsnCanary)
	cfg, cfgErr := c.CreateDynamicSecretConfig(ctx, &core.CreateDynamicSecretConfigRequest{
		Name: "canary-dyn-world", ProjectID: pA.ID, EnvironmentID: eA.ID,
		BackendType: "fake", AdminDSN: dsn, DefaultTTLSeconds: 3600,
		CreatedBy: "testadmin", ActorID: admin.ID,
	})
	if cfgErr != nil {
		f.Logf("dynamic-secret config canary setup skipped (%v)", cfgErr)
	} else {
		// Lease credential: the injected FakeEngine's IssueFields makes the issued
		// credential itself the canary -- must appear only in the IssueLease return
		// value; DB persists only CredentialEnc (encrypted). Also shares
		// canaryPrefix's shape.
		leaseCanary := deriveCanary("lease-world", []byte("world-init"))
		fakeDyn.IssueFields = map[string]string{"canary": leaseCanary}
		if _, lerr := c.IssueLease(ctx, cfg.ID, 3600, admin.ID); lerr == nil {
			plantOnce(leaseCanary)
		} else {
			f.Logf("lease canary setup skipped (%v)", lerr)
		}
	}

	// KNOWN-OPEN FINDING (see file header): confirm ONCE, informationally, that
	// NotificationChannel.URL leaks into audit_events.Diff -- AND, confirmed live by
	// an earlier burst, into the audit-search/audit-export-csv HTTP read surfaces too
	// (see keyorix-private/adversarial-review/
	// NOTIFICATION-CHANNEL-URL-AUDIT-DIFF-LEAK-2026-09-19.md, "who can read it").
	// webhookCanary is deliberately never passed to plantOnce (knownCanaries) --
	// instead each confirmed-affected channel gets its OWN exemption entry below (one
	// value, one channel each -- see exemption's doc comment), so a DIFFERENT canary
	// on the same channel, or this SAME value on an unlisted channel, both still fail.
	webhookCanary := deriveCanary("webhook-world", []byte("world-init"))
	var webhookExemptions []exemption
	ch := &models.NotificationChannel{
		Name: "canary-webhook-world", Type: "webhook",
		URL:     "https://example.com/hooks/" + webhookCanary,
		Enabled: true, Events: "secret.rotated", CreatedBy: "testadmin",
	}
	if _, cherr := c.CreateNotificationChannel(ctx, ch, "testadmin", admin.ID); cherr == nil {
		const findingRef = "keyorix-private/adversarial-review/NOTIFICATION-CHANNEL-URL-AUDIT-DIFF-LEAK-2026-09-19.md"
		webhookExemptions = []exemption{
			{value: webhookCanary, channelPrefix: "db:audit_events.diff", reason: findingRef + ": writeConfigChangeAuditEvent json.Marshals the whole NotificationChannel struct (incl. URL) into audit_events.diff"},
			{value: webhookCanary, channelPrefix: rawFileChannel, reason: findingRef + ": same root cause -- the diff column's bytes are part of the raw DB file"},
			{value: webhookCanary, channelPrefix: "http:audit-search", reason: findingRef + ": GET /api/v1/audit/search returns audit_events rows including Diff verbatim to any audit.read holder"},
			{value: webhookCanary, channelPrefix: "http:audit-export-csv", reason: findingRef + ": GET /api/v1/audit/export.csv, same exposure"},
			// DISTINCT from the audit-diff finding above (not covered by findingRef): this
			// is the channel's OWN canonical storage column, where this fuzzer itself put
			// it via CreateNotificationChannel -- not a duplication into a second, wrong
			// place. Exempted here because NotificationChannel.URL has NO at-rest
			// encryption at all in this codebase (unlike the DSN/lease/MFA credentials
			// this same fuzzer DOES verify are encrypted -- see secret_value_crypto.go /
			// SetAuthEncryptor), so its own column being plaintext is that design's
			// expected, if separately noteworthy, consequence -- surfaced to the user as
			// its own observation, not silently folded into this exemption's reasoning.
			{value: webhookCanary, channelPrefix: "db:notification_channels.url", reason: "own canonical storage column -- see the comment above this entry, not the audit-diff finding"},
		}
		drainAllBackgroundGoroutines()
		if sqlDB, dberr := db.DB(); dberr == nil {
			rows, qerr := sqlDB.Query("SELECT 1 FROM audit_events WHERE diff LIKE ? LIMIT 1", "%"+webhookCanary+"%")
			if qerr == nil {
				if rows.Next() {
					f.Logf("KNOWN-OPEN FINDING confirmed live: webhook URL canary present in audit_events.diff -- see " + findingRef)
				}
				rows.Close()
			}
		}
	} else {
		f.Logf("webhook canary setup skipped (%v)", cherr)
	}

	r, err := NewRouter(&config.Config{}, c)
	if err != nil {
		f.Fatalf("router: %v", err)
	}

	grpcSrv, err := keyorixgrpc.NewServer(&config.Config{}, c)
	if err != nil {
		f.Fatalf("grpc server: %v", err)
	}
	lis := bufconn.Listen(1 << 20)
	go func() { _ = grpcSrv.Serve(lis) }()
	f.Cleanup(grpcSrv.Stop)
	conn, err := grpc.NewClient(
		"passthrough:///bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		f.Fatalf("grpc dial: %v", err)
	}
	f.Cleanup(func() { _ = conn.Close() })

	lb := &lockedBuffer{}
	prevOut := log.Writer()
	log.SetOutput(lb)
	f.Cleanup(func() { log.SetOutput(prevOut) })

	return &canaryWorld{
		router: r, grpc: pb.NewSecretServiceClient(conn), db: db, dbPath: dbPath, c: c,
		readerRole: role.ID, adminTok: adminSess.SessionToken, adminID: admin.ID,
		projAID: pA.ID, projBID: pB.ID, envAID: eA.ID, envBID: eB.ID,
		secAID: sA.ID, secBID: sB.ID,
		refA: "canary-proja/prod/sa", refB: "canary-projb/prod/sb",
		principals: principals, logBuf: lb,
		knownCanaries: knownCanaries, fixedCreds: fixedCreds, webhookExemptions: webhookExemptions,
		dbWatermarks: map[string]int64{},
	}
}

func FuzzCanarySecretLeakage(f *testing.F) {
	w := buildCanaryWorld(f)
	f.Cleanup(i18n.ResetForTesting)

	f.Add([]byte{0, 0, 0, 2, 0, 3, 4, 2, 5, 9, 1, 4})
	f.Add([]byte{2, 0, 0})
	f.Add([]byte{9, 1, 0})
	f.Add([]byte{11, 0, 0, 10, 1, 0})
	f.Add([]byte{})

	var probeSeq atomic.Int64

	f.Fuzz(func(t *testing.T, program []byte) {
		ctx := context.Background()
		opIdx := 0

		// Per-iteration reset: drop fuzz-principal grants (no token-cache flush -- the
		// permission check re-reads grants from the DB every request; flushing writes a
		// negative tombstone that would mask an authorized read -- see the sibling
		// FuzzKeyorixHTTPAPISequence's own comment on this exact trap).
		w.db.Exec("DELETE FROM user_roles WHERE user_id IN (?,?,?)",
			w.principals[0].id, w.principals[1].id, w.principals[2].id)
		canRead := map[uint]map[uint]bool{}
		for _, p := range w.principals {
			canRead[p.id] = map[uint]bool{w.projAID: false, w.projBID: false}
		}

		// Deterministic fixture anchor required by spec: principals[0] may read A, may
		// not read B (never granted); principals[2] stays the "outsider" anchor. The
		// fuzzed grant/revoke ops below can still perturb this further -- canRead tracks
		// truth throughout regardless of who ends up granted what.
		if err := w.c.AssignUserRole(ctx, 0, w.principals[0].id, w.readerRole, core.Scope{ProjectID: w.projAID}, false); err == nil {
			canRead[w.principals[0].id][w.projAID] = true
		}

		// Regenerate both Secret-VALUE canaries for this iteration, deterministically
		// from the input, and plant them into the world's permanent scan history.
		valA := w.plant(deriveCanary("A", program))
		valB := w.plant(deriveCanary("B", program))

		rotate := func(id uint, newVal string) {
			opIdx++
			rec := w.adminReq(http.MethodPost, fmt.Sprintf("/api/v1/secrets/%d/rotate", id), fmt.Sprintf(`{"new_value":%q}`, newVal))
			w.scanOp(t, opIdx, "http:rotate-admin-setup", "admin", rec)
		}
		rotate(w.secAID, valA)
		rotate(w.secBID, valB)

		projFor := func(sel byte) uint {
			if sel%2 == 1 {
				return w.projBID
			}
			return w.projAID
		}
		secretFor := func(which byte) (id uint, ref, val string, projID uint) {
			if which%2 == 1 {
				return w.secBID, w.refB, valB, w.projBID
			}
			return w.secAID, w.refA, valA, w.projAID
		}
		tokenFor := func(mode, who byte) (label, token string, pid uint) {
			switch mode % 5 {
			case 0:
				return "no-token", "", 0
			case 1:
				return "garbage-token", "garbage-not-a-real-token", 0
			case 2:
				return "admin", w.adminTok, w.adminID
			case 3:
				p := w.principals[int(who)%len(w.principals)]
				return "principal", p.token, p.id
			default:
				p := w.principals[2]
				return "outsider", p.token, p.id
			}
		}
		isAllowed := func(label string, pid, projID uint) bool {
			return label == "admin" || ((label == "principal" || label == "outsider") && canRead[pid][projID])
		}

		readByRef := func(mode, which byte) {
			opIdx++
			_, ref, val, projID := secretFor(which)
			label, tok, pid := tokenFor(mode, which)
			allowed := isAllowed(label, pid, projID)
			req := httptest.NewRequest(http.MethodGet, "/api/v1/secrets/value?ref="+ref, nil)
			if tok != "" {
				req.Header.Set("Authorization", "Bearer "+tok)
			}
			rec := httptest.NewRecorder()
			w.router.ServeHTTP(rec, req)
			statusOK := rec.Code == http.StatusOK
			var env valueEnvelope
			if statusOK {
				_ = json.Unmarshal(rec.Body.Bytes(), &env)
			}
			checkValueEndpoint(t, w, opIdx, "http:ref", label, allowed, statusOK, env.Data.Value, rec.Code, rec.Body.Bytes(), []byte(fmt.Sprintf("%v", rec.Header())), val)
			scanCanaryLeaks(t, "log", opIdx, label, w.drainLog(), w.knownCanaries, "", w.fixedCreds, nil)
		}

		readByID := func(mode, which byte) {
			opIdx++
			id, _, val, projID := secretFor(which)
			label, tok, pid := tokenFor(mode, which)
			allowed := isAllowed(label, pid, projID)
			req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/secrets/%d?include_value=true", id), nil)
			if tok != "" {
				req.Header.Set("Authorization", "Bearer "+tok)
			}
			rec := httptest.NewRecorder()
			w.router.ServeHTTP(rec, req)
			statusOK := rec.Code == http.StatusOK
			var env valueEnvelope
			if statusOK {
				_ = json.Unmarshal(rec.Body.Bytes(), &env)
			}
			checkValueEndpoint(t, w, opIdx, "http:id", label, allowed, statusOK, env.Data.Value, rec.Code, rec.Body.Bytes(), []byte(fmt.Sprintf("%v", rec.Header())), val)
			scanCanaryLeaks(t, "log", opIdx, label, w.drainLog(), w.knownCanaries, "", w.fixedCreds, nil)
		}

		readGRPC := func(mode, which byte) {
			opIdx++
			id, _, val, projID := secretFor(which)
			label, tok, pid := tokenFor(mode, which)
			allowed := isAllowed(label, pid, projID)
			gctx := context.Background()
			if tok != "" {
				gctx = metadata.NewOutgoingContext(gctx, metadata.Pairs("authorization", "Bearer "+tok))
			}
			var hdr, trl metadata.MD
			resp, err := w.grpc.GetSecretValue(gctx, &pb.GetSecretRequest{Id: uint32(id), IncludeValue: true}, grpc.Header(&hdr), grpc.Trailer(&trl))
			scanCanaryLeaks(t, "grpc:metadata", opIdx, label, []byte(fmt.Sprintf("%v %v", hdr, trl)), w.knownCanaries, "", w.fixedCreds, nil)
			statusOK := err == nil
			gotVal := ""
			var body []byte
			if statusOK {
				gotVal = resp.GetValue()
			} else {
				body = []byte(err.Error())
			}
			checkValueEndpoint(t, w, opIdx, "grpc", label, allowed, statusOK, gotVal, 0, body, nil, val)
			scanCanaryLeaks(t, "log", opIdx, label, w.drainLog(), w.knownCanaries, "", w.fixedCreds, nil)
		}

		listSecrets := func(mode, which byte) {
			opIdx++
			_, _, _, projID := secretFor(which)
			label, tok, _ := tokenFor(mode, which)
			req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/secrets/?project_id=%d", projID), nil)
			if tok != "" {
				req.Header.Set("Authorization", "Bearer "+tok)
			}
			rec := httptest.NewRecorder()
			w.router.ServeHTTP(rec, req)
			w.scanOp(t, opIdx, "http:list", label, rec)
		}

		getVersions := func(mode, which byte) {
			opIdx++
			id, _, _, _ := secretFor(which)
			label, tok, _ := tokenFor(mode, which)
			req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/secrets/%d/versions", id), nil)
			if tok != "" {
				req.Header.Set("Authorization", "Bearer "+tok)
			}
			rec := httptest.NewRecorder()
			w.router.ServeHTTP(rec, req)
			w.scanOp(t, opIdx, "http:versions", label, rec)
		}

		diffVersions := func(mode, which byte) {
			opIdx++
			id, _, _, _ := secretFor(which)
			label, tok, _ := tokenFor(mode, which)
			req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/secrets/%d/versions/1/diff/2", id), nil)
			if tok != "" {
				req.Header.Set("Authorization", "Bearer "+tok)
			}
			rec := httptest.NewRecorder()
			w.router.ServeHTTP(rec, req)
			w.scanOp(t, opIdx, "http:diff", label, rec)
		}

		accessLogExport := func(mode, which byte) {
			opIdx++
			id, _, _, _ := secretFor(which)
			label, tok, _ := tokenFor(mode, which)
			req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/secrets/%d/access-log/export", id), nil)
			if tok != "" {
				req.Header.Set("Authorization", "Bearer "+tok)
			}
			rec := httptest.NewRecorder()
			w.router.ServeHTTP(rec, req)
			w.scanOp(t, opIdx, "http:access-log-export", label, rec)
		}

		auditSearch := func(mode byte) {
			opIdx++
			label, tok, _ := tokenFor(mode, 0)
			req := httptest.NewRequest(http.MethodGet, "/api/v1/audit/search", nil)
			if tok != "" {
				req.Header.Set("Authorization", "Bearer "+tok)
			}
			rec := httptest.NewRecorder()
			w.router.ServeHTTP(rec, req)
			w.scanOpAuditSurface(t, opIdx, "http:audit-search", label, rec)
		}

		inventoryCSV := func(mode byte) {
			opIdx++
			label, tok, _ := tokenFor(mode, 0)
			req := httptest.NewRequest(http.MethodGet, "/api/v1/secrets/inventory.csv", nil)
			if tok != "" {
				req.Header.Set("Authorization", "Bearer "+tok)
			}
			rec := httptest.NewRecorder()
			w.router.ServeHTTP(rec, req)
			w.scanOp(t, opIdx, "http:inventory-csv", label, rec)
		}

		auditExportCSV := func(mode byte) {
			opIdx++
			label, tok, _ := tokenFor(mode, 0)
			req := httptest.NewRequest(http.MethodGet, "/api/v1/audit/export.csv", nil)
			if tok != "" {
				req.Header.Set("Authorization", "Bearer "+tok)
			}
			rec := httptest.NewRecorder()
			w.router.ServeHTTP(rec, req)
			w.scanOpAuditSurface(t, opIdx, "http:audit-export-csv", label, rec)
		}

		// hostileMutate drives rotation/update/delete attempts -- incl. malformed,
		// wrong-content-type, and oversized bodies that BAIT the current canary directly
		// into the request -- against the FIXED fixture secrets A/B, but is restricted to
		// non-admin tokens only. The only grantable role in this fuzzer is read-only
		// (readerRole = secrets.read), so a non-admin attempt against A/B can never
		// actually succeed regardless of grant state -- this keeps A/B's state stable for
		// the later integrity anchors while still exercising the real hostile-input/deny
		// code paths. A surprise success is itself treated as a finding.
		hostileMutate := func(mode, which, kind byte) {
			opIdx++
			id, _, val, _ := secretFor(which)
			label, tok, _ := tokenFor(mode, which)
			if label == "admin" {
				label, tok = "no-token", ""
			}
			var req *http.Request
			switch kind % 4 {
			case 0:
				req = httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/v1/secrets/%d/rotate", id), strings.NewReader(fmt.Sprintf(`{"new_value":%q}`, val)))
				req.Header.Set("Content-Type", "application/json")
			case 1: // truncated JSON, bait
				req = httptest.NewRequest(http.MethodPut, fmt.Sprintf("/api/v1/secrets/%d", id), strings.NewReader(fmt.Sprintf(`{"value":"%s`, val)))
				req.Header.Set("Content-Type", "application/json")
			case 2: // wrong content-type
				req = httptest.NewRequest(http.MethodPut, fmt.Sprintf("/api/v1/secrets/%d", id), strings.NewReader(fmt.Sprintf(`{"value":%q}`, val)))
				req.Header.Set("Content-Type", "text/plain")
			default: // oversized, bait
				oversized := strings.Repeat("A", 200_000) + val
				req = httptest.NewRequest(http.MethodDelete, fmt.Sprintf("/api/v1/secrets/%d", id), strings.NewReader(oversized))
				req.Header.Set("Content-Type", "application/json")
			}
			if tok != "" {
				req.Header.Set("Authorization", "Bearer "+tok)
			}
			rec := httptest.NewRecorder()
			w.router.ServeHTTP(rec, req)
			if rec.Code >= 200 && rec.Code < 300 {
				t.Fatalf("op #%d [http:hostile-mutate]: unexpected success (code=%d) for non-admin principal=%s against a fixture secret -- fixture-corruption risk, investigate authz before trusting later anchors", opIdx, rec.Code, label)
			}
			w.scanOp(t, opIdx, "http:hostile-mutate", label, rec)
		}

		// mutationLifecycleProbe drives a full admin-authenticated create/rotate/update/
		// read/delete/post-delete-read lifecycle against a FRESH throwaway secret (never
		// A/B), each step with its own fresh canary, so the confidentiality oracle gets
		// exercised across the whole CRUD surface without risking the A/B fixtures.
		mutationLifecycleProbe := func() {
			n := probeSeq.Add(1)
			name := fmt.Sprintf("canary-probe-%d", n)
			probeVal := w.plant(deriveCanary(fmt.Sprintf("probe-%d", n), program))
			defer w.db.Exec("DELETE FROM secret_nodes WHERE name = ? AND project_id = ?", name, w.projAID)

			createBody := fmt.Sprintf(`{"name":%q,"value":%q,"project_id":%d,"environment_id":%d,"type":"password"}`, name, probeVal, w.projAID, w.envAID)
			rec := w.adminReq(http.MethodPost, "/api/v1/secrets/", createBody)
			opIdx++
			w.scanOp(t, opIdx, "http:probe-create", "admin", rec)
			if rec.Code != http.StatusCreated {
				return
			}
			var node models.SecretNode
			if e := w.db.Where("name = ? AND project_id = ?", name, w.projAID).First(&node).Error; e != nil || node.ID == 0 {
				return
			}
			sid := node.ID

			rotVal := w.plant(deriveCanary(fmt.Sprintf("probe-%d-rot", n), program))
			rec = w.adminReq(http.MethodPost, fmt.Sprintf("/api/v1/secrets/%d/rotate", sid), fmt.Sprintf(`{"new_value":%q}`, rotVal))
			opIdx++
			w.scanOp(t, opIdx, "http:probe-rotate", "admin", rec)

			updVal := w.plant(deriveCanary(fmt.Sprintf("probe-%d-upd", n), program))
			rec = w.adminReq(http.MethodPut, fmt.Sprintf("/api/v1/secrets/%d", sid), fmt.Sprintf(`{"value":%q}`, updVal))
			opIdx++
			w.scanOp(t, opIdx, "http:probe-update", "admin", rec)

			rec = w.adminReq(http.MethodGet, fmt.Sprintf("/api/v1/secrets/%d?include_value=true", sid), "")
			opIdx++
			var env valueEnvelope
			if rec.Code == http.StatusOK {
				_ = json.Unmarshal(rec.Body.Bytes(), &env)
			}
			checkValueEndpoint(t, w, opIdx, "http:probe-read", "admin", true, rec.Code == http.StatusOK, env.Data.Value, rec.Code, rec.Body.Bytes(), []byte(fmt.Sprintf("%v", rec.Header())), updVal)
			scanCanaryLeaks(t, "log", opIdx, "admin", w.drainLog(), w.knownCanaries, "", w.fixedCreds, nil)

			rec = w.adminReq(http.MethodDelete, fmt.Sprintf("/api/v1/secrets/%d", sid), "")
			opIdx++
			w.scanOp(t, opIdx, "http:probe-delete", "admin", rec)

			rec = w.adminReq(http.MethodGet, fmt.Sprintf("/api/v1/secrets/%d?include_value=true", sid), "")
			opIdx++
			w.scanOp(t, opIdx, "http:probe-post-delete-read", "admin", rec)
		}

		const maxSteps = 40
		for i := 0; i+2 < len(program) && i < maxSteps*3; i += 3 {
			switch program[i] % 12 {
			case 0:
				p := w.principals[int(program[i+1])%len(w.principals)]
				projID := projFor(program[i+2])
				if err := w.c.AssignUserRole(ctx, 0, p.id, w.readerRole, core.Scope{ProjectID: projID}, false); err == nil {
					canRead[p.id][projID] = true
				}
			case 1:
				p := w.principals[int(program[i+1])%len(w.principals)]
				projID := projFor(program[i+2])
				if err := w.c.RemoveUserRole(ctx, 0, p.id, w.readerRole, core.Scope{ProjectID: projID}); err == nil {
					canRead[p.id][projID] = false
				}
			case 2:
				readByRef(program[i+1], program[i+2])
			case 3:
				readByID(program[i+1], program[i+2])
			case 4:
				readGRPC(program[i+1], program[i+2])
			case 5:
				listSecrets(program[i+1], program[i+2])
			case 6:
				getVersions(program[i+1], program[i+2])
			case 7:
				diffVersions(program[i+1], program[i+2])
			case 8:
				accessLogExport(program[i+1], program[i+2])
			case 9:
				hostileMutate(program[i+1], program[i+2], program[i+2])
			case 10:
				auditSearch(program[i+1])
			default: // 11
				if program[i+1]%2 == 0 {
					inventoryCSV(program[i+1])
				} else {
					auditExportCSV(program[i+1])
				}
			}
		}

		// Anchors, every iteration regardless of input.
		readByRef(2, 0) // admin reads A -> integrity/round-trip
		readByRef(4, 1) // outsider anchor reads B -> fail-closed (unless fuzzed grants happened to change canRead)

		opIdx++
		mrec := httptest.NewRecorder()
		w.router.ServeHTTP(mrec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
		w.scanOp(t, opIdx, "http:metrics", "n/a", mrec)

		opIdx++
		hrec := httptest.NewRecorder()
		w.router.ServeHTTP(hrec, httptest.NewRequest(http.MethodGet, "/health", nil))
		w.scanOp(t, opIdx, "http:health", "n/a", hrec)

		// Gated to keep average throughput high -- unlike the pre-refactor version, this
		// gate exists only to bound REAL per-op cost (an admin-authenticated CRUD
		// lifecycle over HTTP), not scan cost, which is now flat regardless of how many
		// canaries knownCanaries has accumulated.
		if len(program) >= 1 && program[0]%2 == 0 {
			mutationLifecycleProbe()
		}

		// Sequence-end: full generic DB scan + raw-file plaintext-at-rest scan, against
		// the FULL canary history (w.knownCanaries), not just this iteration's. A
		// deterministic drain (not a sleep) absorbs every in-flight goSafe audit write
		// first -- see drainAllBackgroundGoroutines's doc comment.
		drainAllBackgroundGoroutines()
		sqlDB, err := w.db.DB()
		if err != nil {
			t.Fatalf("db scan: get sql.DB: %v", err)
		}
		scanDBGeneric(t, sqlDB, w.knownCanaries, w.fixedCreds, w.webhookExemptions, w.dbWatermarks)
		scanRawDBFile(t, w.dbPath, w.knownCanaries, w.fixedCreds, w.webhookExemptions)
	})
}
