// Package identity provides constructor-enforced Unicode normalization for
// identity-bearing strings (#1642). A raw string cannot become a FoldedName or
// AddressName except through NewFoldedName/NewAddressName — so any function
// that takes one of these types as a parameter, rather than a plain string,
// cannot be called with an un-normalized value. This is deliberately a
// function-signature boundary, not a write-vs-read split: a "normalize on
// write only" design turns a collision bug into a not-found bug the moment a
// client submits the same identity in a different normalization form on a
// lookup. Every entry point — INSERT or WHERE — must go through the same
// constructor.
//
// Two profiles, matching two different real-world expectations:
//
//   - FoldedName folds case in addition to NFC-normalizing (via a custom
//     precis Freeform profile: golang.org/x/text/secure/precis's own
//     UsernameCaseMapped rejects spaces, which would break existing
//     space-containing usernames/role/group/project names in this codebase —
//     Freeform allows them). Use for identity a human reads to decide who has
//     what: usernames, role names, group names, project names. "Admin" and
//     "admin" coexisting as distinct principals is an impersonation risk
//     exactly where an access review's value lives.
//
//   - AddressName NFC-normalizes only, via precis.OpaqueString, and does NOT
//     fold case. Use for identity that functions as an address rather than a
//     human-verified identity: secret names. Operators expect PROD_KEY and
//     prod_key to remain distinct, the same way environment variables and
//     filesystem paths are case-sensitive.
//
// Both profiles reject control characters and bidirectional-override
// characters as part of the underlying PRECIS class restrictions (RFC 8264) —
// this is the first character-set validation several of these fields have
// ever had, independent of the normalization fix itself.
//
// # Why NFC and not NFKC
//
// Both profiles normalize with NFC (canonical equivalence), not NFKC
// (compatibility equivalence), and that is a decision, not an omission. NFC
// merges only strings that are the same text in different encodings (a
// precomposed letter versus a base letter plus a combining mark). NFKC would
// also merge strings that are distinct but look alike or behave alike:
// fullwidth and ASCII letters, ligatures, roman numerals, circled digits. For
// an access-review identity that widens the set of names treated as one
// principal and makes two accounts a human reviewer sees as different collapse
// into one, which is a worse failure than the reverse.
//
// The consequence callers must know: the fullwidth form of "admin" and the
// ASCII form are two different principals here. Where an external identity
// provider (SSO, SCIM) maps its identifiers to principals and folds
// differently, the mapping layer must fold or reject at its own boundary
// before calling these constructors; this package does not guess the
// provider's rules. FoldedName also accepts characters that RFC 8265 rejects
// (ligatures, roman numerals, circled digits, spaces) so that existing names
// keep working; that is the same trade-off, taken deliberately.
package identity

import (
	"errors"
	"fmt"

	"golang.org/x/text/secure/precis"
	"golang.org/x/text/unicode/norm"
)

// ErrEmpty is returned when a name is empty after normalization.
var ErrEmpty = errors.New("name must not be empty")

// foldedProfile NFC-normalizes and case-folds, allowing spaces (unlike
// precis.UsernameCaseMapped's Identifier class, which rejects them) since
// usernames/role/group/project names in this codebase are permitted to
// contain spaces today (see internal/core/catalog.go's validateIdentifier).
var foldedProfile = precis.NewFreeform(precis.LowerCase(), precis.Norm(norm.NFC))

// FoldedName is a case-folded, NFC-normalized identity string — the display
// form as the user typed it, and the folded form used for storage-key
// comparison/uniqueness. Construct only via NewFoldedName.
type FoldedName struct {
	display string
	folded  string
}

// NewFoldedName normalizes raw into a FoldedName. Use for usernames, role
// names, group names, and project names.
func NewFoldedName(raw string) (FoldedName, error) {
	folded, err := foldedProfile.String(raw)
	if err != nil {
		return FoldedName{}, fmt.Errorf("invalid name %q: %w", raw, err)
	}
	if folded == "" {
		return FoldedName{}, ErrEmpty
	}
	return FoldedName{display: raw, folded: folded}, nil
}

// Display returns the name exactly as the caller supplied it — the form to
// store in the display column and show in UI/audit output.
func (n FoldedName) Display() string { return n.display }

// Folded returns the case-folded, NFC-normalized form — the form to store in
// the indexed/comparison column and use in every WHERE-clause lookup.
func (n FoldedName) Folded() string { return n.folded }

// String implements fmt.Stringer, returning the display form.
func (n FoldedName) String() string { return n.display }

// addressProfile NFC-normalizes without folding case, via RFC 8265's
// OpaqueString profile (freeform class: allows spaces, maps Unicode
// space-variant runes to plain space, rejects control/bidi characters).
var addressProfile = precis.OpaqueString

// AddressName is an NFC-normalized, case-preserved identity string.
// Construct only via NewAddressName.
type AddressName struct {
	value string
}

// NewAddressName normalizes raw into an AddressName. Use for secret names —
// addresses, not human-verified identity, so case is preserved rather than
// folded (PROD_KEY and prod_key must remain distinct). precis.OpaqueString
// itself rejects a raw or transformed-empty value (RFC 8265 DisallowEmpty),
// so no separate empty check is needed here — contrast with NewFoldedName's
// custom profile, which doesn't set that option and needs its own check.
func NewAddressName(raw string) (AddressName, error) {
	v, err := addressProfile.String(raw)
	if err != nil {
		return AddressName{}, fmt.Errorf("invalid name %q: %w", raw, err)
	}
	return AddressName{value: v}, nil
}

// String returns the NFC-normalized value — the single form to store and
// compare, since this profile does not fold case.
func (n AddressName) String() string { return n.value }
