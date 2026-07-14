package core

import (
	"fmt"
	"strings"
	"unicode"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// PasswordPolicy is the full set of password rules from ADR-025. The complexity
// rules (length, character classes, personal-info, common-password) are
// stateless and enforced by Validate. The stateful rules — HistoryCount (no
// reuse of the last N passwords) and MaxAgeDays (expiry) — are enforced by core
// against the password-history table and PasswordChangedAt (see account.go).
type PasswordPolicy struct {
	MinLength             int
	RequireUppercase      bool
	RequireLowercase      bool
	RequireDigit          bool
	RequireSpecial        bool
	RejectPersonalInfo    bool // reject if the password contains the user's email/display name/username
	RejectCommonPasswords bool // reject passwords on the curated common-password list
	HistoryCount          int  // forbid reuse of the last N passwords (0 = off)
	MaxAgeDays            int  // expire a password after N days (0 = never)
}

// DefaultPasswordPolicy returns the conservative, NIS2/DORA-aligned defaults
// from ADR-025. Installs may relax these per-config (e.g. lab installs), but the
// built-in default is intentionally not lab-grade. MaxAgeDays defaults to 0
// (no forced rotation) — expiry is opt-in until the account-state-machine ships
// the restricted-session gate, so a default can't silently lock anyone out.
func DefaultPasswordPolicy() PasswordPolicy {
	return PasswordPolicy{
		MinLength:             16,
		RequireUppercase:      true,
		RequireLowercase:      true,
		RequireDigit:          true,
		RequireSpecial:        true,
		RejectPersonalInfo:    true,
		RejectCommonPasswords: true,
		HistoryCount:          5,
		MaxAgeDays:            0,
	}
}

// Validate checks pw against the policy. user may be nil (personal-info checks
// are skipped when it is). It returns a single error listing every unmet
// requirement, so the caller can surface all of them at once.
func (p PasswordPolicy) Validate(pw string, user *models.User) error { // NOSONAR -- cognitive complexity 19, suppress go:S3776
	var failures []string

	// A non-positive MinLength means "no length floor", which would accept even an
	// empty password. That is never a safe intent on a secrets product and is
	// reachable by a partial password_policy config block: setting any single field
	// (e.g. reject_common_passwords) copies the rest as zero, collapsing MinLength to
	// 0. Fall back to the conservative built-in default so the floor cannot be
	// silently disabled. An explicit positive MinLength (incl. relaxed lab values) is
	// honored as-is.
	minLength := p.MinLength
	if minLength <= 0 {
		minLength = DefaultPasswordPolicy().MinLength
	}
	if len(pw) < minLength {
		failures = append(failures, fmt.Sprintf("be at least %d characters", minLength))
	}

	var hasUpper, hasLower, hasDigit, hasSpecial bool
	for _, r := range pw {
		switch {
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsDigit(r):
			hasDigit = true
		case unicode.IsPunct(r) || unicode.IsSymbol(r) || unicode.IsSpace(r):
			hasSpecial = true
		}
	}
	if p.RequireUppercase && !hasUpper {
		failures = append(failures, "contain an uppercase letter")
	}
	if p.RequireLowercase && !hasLower {
		failures = append(failures, "contain a lowercase letter")
	}
	if p.RequireDigit && !hasDigit {
		failures = append(failures, "contain a digit")
	}
	if p.RequireSpecial && !hasSpecial {
		failures = append(failures, "contain a special character")
	}

	if p.RejectPersonalInfo && user != nil && containsPersonalInfo(pw, user) {
		failures = append(failures, "not contain your username, email, or display name")
	}

	if p.RejectCommonPasswords && isCommonPassword(pw) {
		failures = append(failures, "not be a commonly-used password")
	}

	if len(failures) > 0 {
		return fmt.Errorf("password must %s", strings.Join(failures, ", "))
	}
	return nil
}

// containsPersonalInfo reports whether pw embeds the user's username, the local
// part of their email, or any word (3+ chars) of their display name — all
// case-insensitively.
func containsPersonalInfo(pw string, user *models.User) bool {
	lpw := strings.ToLower(pw)

	candidates := []string{strings.ToLower(strings.TrimSpace(user.Username))}
	if at := strings.IndexByte(user.Email, '@'); at > 0 {
		candidates = append(candidates, strings.ToLower(user.Email[:at]))
	}
	candidates = append(candidates, strings.Fields(strings.ToLower(user.DisplayName))...)

	for _, c := range candidates {
		if len(c) >= 3 && strings.Contains(lpw, c) {
			return true
		}
	}
	return false
}
