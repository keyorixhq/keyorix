package core

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/identity"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	sqlite "github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// identity_boundary_sso_scim_sweep_test.go -- task S4 identity-boundary probe.
//
// The decision pinned by internal/identity (NFC, not NFKC; see that package's
// "Why NFC and not NFKC" header and
// TestNewFoldedName_CompatibilityFormsAreDistinctPrincipals) is only SAFE for
// SSO/SCIM if every place that maps an external identifier to a Keyorix principal
// folds confusable forms the SAME way storage does. The load-bearing fact is that
// the storage lookups the SSO/SCIM paths call (GetUserByEmail / GetUserByUsername)
// fold the lookup key through identity.NewFoldedName and compare against the stored
// *_folded column -- the same fold used at write time
// (internal/storage/store/local_users.go). These tests drive the full confusable
// corpus the task names through that real boundary (real file-backed SQLite, the
// same partial folded unique indexes production installs get) and through
// resolveSSOUser (the account-linking-by-email choke point), asserting:
//
//	P1 (no false merge / no confusable takeover): two DIFFERENT external strings
//	    never resolve to the same principal unless they are the same text in a
//	    different normalization (NFC vs NFD) or differ only in case.
//	P2 (no false split): one human / one IdP identity never produces two
//	    principals through NFC/NFD differences alone.
//	P3 (unverified-email gate): an unverified external email can NEVER link to an
//	    existing local account; a verified confusable email still cannot take one
//	    over, because NFC keeps the confusable distinct.
//
// What these tests do NOT verify: they exercise the core/storage boundary
// directly, not the HTTP transport (SAML XML parse, OIDC token parse, SCIM
// middleware) end to end; and they cover LocalStorage (SQLite/Postgres GORM),
// not the RemoteStorage proxy (out of scope, /system tier deleted, ADR-108).
//
// Every non-ASCII corpus string is built from explicit code points via cp() (the
// source is 100% ASCII) so no editor/terminal/file-write layer can silently
// re-normalize a literal on save -- the exact gotcha the #1642 recon called out.

// cp builds a string from explicit Unicode code points (ASCII source, no literal
// non-ASCII runes anywhere in this file).
func cp(runes ...rune) string { return string(runes) }

// identityBoundaryStore builds a fresh file-backed SQLite LocalStorage with the
// same partial, case-insensitive folded unique indexes factory.go installs
// (ensureUserEmailIndex / ensureUserUsernameIndex, #1642) -- so the test exercises
// the production fold boundary, not a bare table.
func identityBoundaryStore(t *testing.T) *store.LocalStorage {
	t.Helper()
	dsn := "file:" + filepath.Join(t.TempDir(), "idb.db") + "?_busy_timeout=10000&_journal_mode=WAL"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.User{}))
	require.NoError(t, db.Exec("CREATE UNIQUE INDEX IF NOT EXISTS uniq_users_email_folded_active "+
		"ON users (email_folded) WHERE deleted_at IS NULL AND email <> ''").Error)
	require.NoError(t, db.Exec("CREATE UNIQUE INDEX IF NOT EXISTS uniq_users_username_folded_active "+
		"ON users (username_folded) WHERE deleted_at IS NULL AND username <> ''").Error)
	return store.NewLocalStorage(db)
}

func seedIdentityUser(t *testing.T, ls *store.LocalStorage, username, email, externalID string) *models.User {
	t.Helper()
	fu, err := identity.NewFoldedName(username)
	require.NoError(t, err, "seed username must normalize: %q", username)
	fe, err := identity.NewFoldedName(email)
	require.NoError(t, err, "seed email must normalize: %q", email)
	now := time.Now().UTC()
	u, err := ls.CreateUser(context.Background(), &models.User{
		Username: username, UsernameFolded: fu.Folded(),
		Email: email, EmailFolded: fe.Folded(), DisplayName: username,
		ExternalID: externalID, IsActive: true, AccountState: AccountActive,
		CreatedAt: now, UpdatedAt: now,
	})
	require.NoError(t, err)
	return u
}

// confusableCase: `stored` is the canonical identity actually provisioned;
// `variant` is the external string an IdP could assert. wantMerge is true ONLY when
// `variant` is the same text as `stored` in a different encoding (NFC vs NFD) or
// differs only in case -- the only cases that may resolve to the same principal.
// Every confusable/compatibility/whitespace variant is false: it must resolve to a
// DIFFERENT principal (or to nothing), never to `stored`.
type confusableCase struct {
	name      string
	stored    string
	variant   string
	wantMerge bool
}

func confusableCorpus() []confusableCase {
	nfcCafe := cp('c', 'a', 'f', 0x00e9)      // e-acute precomposed
	nfdCafe := cp('c', 'a', 'f', 'e', 0x0301) // e + combining acute
	return []confusableCase{
		// --- the only legitimate merges ---
		{"case-variant upper", "admin", "ADMIN", true},
		{"case-variant mixed", "admin", "Admin", true},
		{"nfc-stored-nfd-lookup", nfcCafe, nfdCafe, true},
		{"nfd-stored-nfc-lookup", nfdCafe, nfcCafe, true},

		// --- confusables / compatibility forms: MUST stay distinct (NFC, not NFKC) ---
		{"fullwidth latin admin", "admin", cp(0xff41, 0xff44, 0xff4d, 0xff49, 0xff4e), false},
		{"fullwidth single a", "admin", cp(0xff41, 'd', 'm', 'i', 'n'), false},
		{"ligature fi", "fiona", cp(0xfb01, 'o', 'n', 'a'), false},   // U+FB01 fi-ligature
		{"ligature ffi", "office", cp('o', 0xfb03, 'c', 'e'), false}, // U+FB03 ffi-ligature
		{"roman numeral one", "i", cp(0x2160), false},                // roman numeral I vs ASCII i
		{"roman numeral x", "x", cp(0x2169), false},                  // roman numeral X vs ASCII x
		{"circled digit one", "user1", cp('u', 's', 'e', 'r', 0x2460), false},
		{"cyrillic homograph a", "admin", cp(0x0430, 'd', 'm', 'i', 'n'), false}, // Cyrillic a
		{"cyrillic homograph o", "root", cp('r', 0x043e, 0x043e, 't'), false},    // Cyrillic o
		{"turkish dotless i", "admin", cp('a', 'd', 'm', 0x0131, 'n'), false},    // dotless i
		{"turkish dotted I", "admin", cp('a', 'd', 'm', 0x0130, 'n'), false},     // dotted I
		{"trailing space", "admin", "admin ", false},
		{"leading space", "admin", " admin", false},
		{"nbsp inside", "admin", cp('a', 'd', 0x00a0, 'm', 'i', 'n'), false},       // NBSP
		{"zero-width space", "admin", cp('a', 'd', 0x200b, 'm', 'i', 'n'), false},  // ZWSP
		{"zero-width joiner", "admin", cp('a', 'd', 0x200d, 'm', 'i', 'n'), false}, // ZWJ
	}
}

// TestIdentityBoundary_UserLookupFold_NoConfusableMerge drives the corpus through
// the two storage lookups every SSO/SCIM account resolution ultimately calls
// (GetUserByUsername, GetUserByEmail). It proves P1 and P2 at the real fold
// boundary: a confusable variant never resolves to the stored principal, while an
// NFC/NFD or case variant of the same identity does.
func TestIdentityBoundary_UserLookupFold_NoConfusableMerge(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	for _, tc := range confusableCorpus() {
		t.Run("username/"+tc.name, func(t *testing.T) {
			ls := identityBoundaryStore(t)
			stored := seedIdentityUser(t, ls, tc.stored, tc.stored+"@corp.example", "")
			got, err := ls.GetUserByUsername(ctx, tc.variant)
			assertConfusableResolution(t, "username", tc, stored, got, err)
		})
		t.Run("email/"+tc.name, func(t *testing.T) {
			ls := identityBoundaryStore(t)
			stored := seedIdentityUser(t, ls, tc.stored, tc.stored+"@corp.example", "")
			got, err := ls.GetUserByEmail(ctx, tc.variant+"@corp.example")
			assertConfusableResolution(t, "email", tc, stored, got, err)
		})
	}
}

func assertConfusableResolution(t *testing.T, field string, tc confusableCase, stored, got *models.User, err error) {
	t.Helper()
	if tc.wantMerge {
		require.NoError(t, err, "%s %q: a true-same identity must resolve", field, tc.name)
		require.NotNil(t, got)
		require.Equal(t, stored.ID, got.ID,
			"%s %q: NFC/NFD or case variant must resolve to the SAME principal (no false split)", field, tc.name)
		return
	}
	// A confusable/compatibility/whitespace variant must NOT resolve to the stored
	// principal: either genuinely not-found, or some different row -- never the one
	// we stored.
	if err != nil {
		require.True(t, storage.IsUserNotFound(err),
			"%s %q: a non-merge variant must be not-found, got %v", field, tc.name, err)
		return
	}
	require.NotEqual(t, stored.ID, got.ID,
		"%s %q: confusable variant resolved to the stored principal -- NFKC-style over-merge / takeover",
		field, tc.name)
}

// TestIdentityBoundary_ResolveSSOUser_EmailLinkGate proves the highest-risk row:
// account linking by email in resolveSSOUser (the shared OIDC + SAML choke point).
//
//	P3a: an UNVERIFIED external email can never claim an existing local account.
//	P3b: a VERIFIED confusable (Cyrillic-homograph) email still cannot take over an
//	     existing account -- NFC keeps it distinct from the victim's folded email.
//	P3c: a VERIFIED exact email links to the existing account (the intended
//	     trusted-IdP behaviour), and an NFD form of that same verified email links to
//	     the SAME account (no false split).
func TestIdentityBoundary_ResolveSSOUser_EmailLinkGate(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	const provider = "okta"
	cyrillicAdminEmail := cp(0x0430, 'd', 'm', 'i', 'n') + "@corp.example"
	joseNFC := cp('j', 'o', 's', 0x00e9) + "@corp.example"
	joseNFD := cp('j', 'o', 's', 'e', 0x0301) + "@corp.example"

	newCore := func(t *testing.T) (*KeyorixCore, *store.LocalStorage) {
		ls := identityBoundaryStore(t)
		return &KeyorixCore{storage: ls, now: func() time.Time { return time.Now().UTC() }}, ls
	}

	t.Run("unverified email cannot claim an existing native account", func(t *testing.T) {
		c, ls := newCore(t)
		victim := seedIdentityUser(t, ls, "admin", "admin@corp.example", "")
		got, err := c.resolveSSOUser(ctx, provider, "att|sub", "admin@corp.example", false)
		require.NoError(t, err)
		require.Nil(t, got, "an unverified IdP email must not resolve to the existing account (it would JIT a new one)")
		fresh, gerr := ls.GetUser(ctx, victim.ID)
		require.NoError(t, gerr)
		require.Empty(t, fresh.ExternalID, "a refused unverified link must not stamp the victim's external_id")
	})

	t.Run("verified confusable email cannot take over", func(t *testing.T) {
		c, ls := newCore(t)
		victim := seedIdentityUser(t, ls, "admin", "admin@corp.example", "")
		// Cyrillic 'a' (U+0430) homograph of ASCII 'a': verified at the IdP, yet NFC
		// keeps it a DIFFERENT address than the victim's -- no takeover.
		got, err := c.resolveSSOUser(ctx, provider, "att|sub", cyrillicAdminEmail, true)
		require.NoError(t, err)
		require.Nil(t, got, "a verified confusable email must not resolve to the victim (NFC keeps it distinct)")
		fresh, gerr := ls.GetUser(ctx, victim.ID)
		require.NoError(t, gerr)
		require.Empty(t, fresh.ExternalID, "the victim's account must stay unfederated")
	})

	t.Run("verified exact email links to the existing account (intended)", func(t *testing.T) {
		c, ls := newCore(t)
		victim := seedIdentityUser(t, ls, "admin", "admin@corp.example", "")
		got, err := c.resolveSSOUser(ctx, provider, "real|sub", "admin@corp.example", true)
		require.NoError(t, err)
		require.NotNil(t, got, "a verified exact email is the trusted-IdP link path and must resolve")
		require.Equal(t, victim.ID, got.ID)
	})

	t.Run("verified NFD of the exact email links to the same account (no split)", func(t *testing.T) {
		c, ls := newCore(t)
		// Victim email carries precomposed e-acute (U+00E9); the IdP asserts the NFD form.
		victim := seedIdentityUser(t, ls, "jose", joseNFC, "")
		got, err := c.resolveSSOUser(ctx, provider, "real|sub", joseNFD, true)
		require.NoError(t, err)
		require.NotNil(t, got, "NFD form of the same verified email must resolve")
		require.Equal(t, victim.ID, got.ID, "one human, one IdP email, NFC vs NFD -> one principal (no split)")
	})

	t.Run("email plus-tag and dot-variant are distinct accounts (no canonicalization)", func(t *testing.T) {
		c, ls := newCore(t)
		seedIdentityUser(t, ls, "admin", "admin@corp.example", "")
		for _, probe := range []string{"admin+tag@corp.example", "ad.min@corp.example"} {
			got, err := c.resolveSSOUser(ctx, provider, "x|sub", probe, true)
			require.NoError(t, err)
			require.Nil(t, got, "Keyorix does not Gmail-canonicalize; %q must not link to admin@corp.example", probe)
		}
	})
}
