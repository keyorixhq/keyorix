// snapshot_test.go builds a canonical, hashable dump of every table in
// models.AllTestModels() — the "logical-state snapshot, taken with faults off"
// STEP 0 asked for. It exists so an oracle can compare pre-fault and post-fault
// (or post-drop-fault) database state without depending on a hand-maintained
// shadow model that can drift from the real schema (models.AllTestModels() is
// this repo's own single source of truth for the SQLite test schema — see its
// doc comment — so this snapshot can never silently miss a table that gets
// migrated).
package faultops

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"gorm.io/gorm"
)

// timeType/timePtrType back the STRUCTURAL timestamp exclusion below: every
// time.Time/*time.Time field is wall-clock and run-relative by construction, so
// it is excluded by TYPE rather than by hand-enumerated field name. An earlier
// version of this file excluded timestamps by name (CreatedAt, UpdatedAt, ...)
// and missed LastSeenAt, LastLoginAt, PasswordChangedAt, LastFailedLoginAt,
// LoginLockedUntil, AbsoluteExpiresAt, ImpersonationStartedAt one at a time as
// each caused a false "state differs" oracle failure between two independently
// bootstrapped worlds — textbook "enumeration only as complete as the idioms it
// knows about" (CLAUDE.md). Excluding by type closes the whole class at once;
// see timeFieldOverrides below for the (currently empty) escape hatch if a
// future op ever needs to assert on a specific timestamp's VALUE.
var timeType = reflect.TypeOf(time.Time{})
var timePtrType = reflect.TypeOf(&time.Time{})

// timeFieldOverrides lists time.Time/*time.Time fields that ARE logically
// meaningful and must NOT be excluded by the structural rule above — empty
// today because no opCatalog operation asserts on a specific timestamp value.
var timeFieldOverrides = map[string]bool{}

// excludedFields are dropped entirely before hashing for reasons OTHER than
// "it's a timestamp" (that whole class is handled structurally by type, see
// above): PrevHash/EntryHash/HeadHash are derived from other excluded,
// run-relative fields and therefore run-relative too. One justification each,
// per STEP 0's requirement.
var excludedFields = map[string]string{
	"PrevHash":  "audit hash-chain link (ADR-029): SHA256 over every prior row's content, which itself includes excluded run-relative fields — comparing it is comparing excluded data transitively",
	"EntryHash": "see PrevHash",
	"HeadHash":  "audit checkpoint hash — see PrevHash",
}

// presenceOnlyFields are reduced to a "was a value written at all" boolean
// instead of compared byte-for-byte: each holds AEAD ciphertext, a salted hash,
// or authenticator-generated key material, so an identical logical operation
// legitimately produces different bytes on every run (a fresh random nonce/salt
// each time). Derived by grepping internal/storage/models/models.go for every
// field whose name ends in Hash/Enc, or that holds WebAuthn credential material
// (2026-09-21) — not guessed; extend this list the same way if a new one
// appears, per CLAUDE.md's "state which call forms the enumeration recognizes."
var presenceOnlyFields = map[string]string{
	"PasswordHash":   "bcrypt includes a random salt per hash",
	"TokenHash":      "the raw token is randomly generated before hashing",
	"CodeHash":       "the raw MFA recovery code is randomly generated before hashing",
	"SecretEnc":      "AEAD ciphertext includes a random nonce",
	"AdminDSNEnc":    "AEAD ciphertext includes a random nonce",
	"CredentialEnc":  "AEAD ciphertext includes a random nonce",
	"CredentialID":   "authenticator-generated WebAuthn credential identifier",
	"CredentialBlob": "authenticator-generated WebAuthn public key material",
	"SessionToken":   "SHA-256 hash of a randomly generated per-login session token (models.go:1217) — two independent bootstrap logins (reference world vs fault world) never produce the same raw token, so never the same hash",
	"FamilyID":       "randomly generated per-login refresh-token family identifier (models.go:1243) — same reasoning as SessionToken; found via this file's own Session-row debug dump when the structural timestamp fix alone didn't make two independently-bootstrapped worlds' Session tables match",
}

// tableSnapshot is one table's canonical dump: Hash over every row's
// (excluded-stripped, presence-redacted) JSON encoding, sorted so row order
// never affects the hash, plus the rows themselves for readable tracing when an
// oracle fails.
type tableSnapshot struct {
	Table string
	Hash  string
	Rows  []string // canonical per-row JSON, sorted
}

// dbSnapshot is the full logical-state snapshot: one tableSnapshot per model in
// models.AllTestModels(), plus a combined Hash over all of them so two snapshots
// can be compared with one string equality check before drilling into per-table
// detail.
type dbSnapshot struct {
	Hash   string
	Tables map[string]tableSnapshot
}

// snapshotDB dumps every table in models.AllTestModels() from db. It never
// touches models.AllTestModels() by name — using the same slice this repo's
// AutoMigrate calls use means a new model added there is picked up here
// automatically, with no separate list to keep in sync.
func snapshotDB(db *gorm.DB) (dbSnapshot, error) {
	snap := dbSnapshot{Tables: make(map[string]tableSnapshot)}
	var tableLines []string

	for _, m := range models.AllTestModels() {
		mt := reflect.TypeOf(m).Elem() // m is a *models.X zero value
		sliceType := reflect.SliceOf(reflect.PointerTo(mt))
		rowsPtr := reflect.New(sliceType)
		if err := db.Find(rowsPtr.Interface()).Error; err != nil {
			return dbSnapshot{}, fmt.Errorf("dumping %s: %w", mt.Name(), err)
		}
		rows := rowsPtr.Elem()

		var canon []string
		for i := 0; i < rows.Len(); i++ {
			line, err := canonicalRow(rows.Index(i).Interface())
			if err != nil {
				return dbSnapshot{}, fmt.Errorf("canonicalizing %s row %d: %w", mt.Name(), i, err)
			}
			canon = append(canon, line)
		}
		sort.Strings(canon)

		h := sha256.Sum256([]byte(strings.Join(canon, "\n")))
		ts := tableSnapshot{Table: mt.Name(), Hash: hex.EncodeToString(h[:]), Rows: canon}
		snap.Tables[mt.Name()] = ts
		tableLines = append(tableLines, ts.Table+":"+ts.Hash)
	}

	sort.Strings(tableLines)
	overall := sha256.Sum256([]byte(strings.Join(tableLines, "\n")))
	snap.Hash = hex.EncodeToString(overall[:])
	return snap, nil
}

// canonicalRow walks row's exported struct fields directly via reflection
// (NOT a json.Marshal round-trip, which silently drops any `json:"-"` field —
// several of this schema's sensitive fields carry that tag specifically to
// keep them out of API responses, which is irrelevant to what this snapshot
// needs to see) and produces a stable, sorted-key JSON-ish encoding: a
// time.Time/*time.Time field is dropped (structural timestamp exclusion,
// unless overridden in timeFieldOverrides), a field in excludedFields is
// dropped, a field in presenceOnlyFields becomes a boolean, everything else is
// marshaled as-is.
func canonicalRow(row interface{}) (string, error) {
	rv := reflect.ValueOf(row)
	if rv.Kind() == reflect.Pointer {
		rv = rv.Elem()
	}
	rt := rv.Type()

	out := make(map[string]interface{}, rt.NumField())
	for i := 0; i < rt.NumField(); i++ {
		f := rt.Field(i)
		if f.PkgPath != "" { // unexported
			continue
		}
		name := f.Name
		fv := rv.Field(i)

		if (f.Type == timeType || f.Type == timePtrType) && !timeFieldOverrides[name] {
			continue
		}
		if _, excluded := excludedFields[name]; excluded {
			continue
		}
		if _, presence := presenceOnlyFields[name]; presence {
			out[name] = !isGoZero(fv)
			continue
		}
		out[name] = fv.Interface()
	}

	keys := make([]string, 0, len(out))
	for k := range out {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(',')
		}
		kb, _ := json.Marshal(k)
		vb, err := json.Marshal(out[k])
		if err != nil {
			return "", fmt.Errorf("marshaling field %s.%s: %w", rt.Name(), k, err)
		}
		b.Write(kb)
		b.WriteByte(':')
		b.Write(vb)
	}
	b.WriteByte('}')
	return b.String(), nil
}

// isGoZero reports whether v holds its type's zero value — used by
// presenceOnlyFields to reduce a randomized field to "was anything written at
// all" without depending on JSON's looser empty-string/empty-array notion,
// which a []byte ciphertext field doesn't naturally produce.
func isGoZero(v reflect.Value) bool {
	return v.IsZero()
}
