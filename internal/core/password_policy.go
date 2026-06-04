package core

import (
	"fmt"
	"strings"
	"unicode"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// PasswordPolicy is the set of synchronous, stateless rules a new password must
// satisfy (ADR-025). Stateful rules from the ADR — reject-common-passwords,
// history (no reuse of last N), and max-age expiry — need extra storage and are
// deliberately out of this first slice; see the package follow-ups.
type PasswordPolicy struct {
	MinLength          int
	RequireUppercase   bool
	RequireLowercase   bool
	RequireDigit       bool
	RequireSpecial     bool
	RejectPersonalInfo bool // reject if the password contains the user's email/display name/username
}

// DefaultPasswordPolicy returns the conservative, NIS2/DORA-aligned defaults
// from ADR-025. Installs may relax these per-config (e.g. lab installs), but the
// built-in default is intentionally not lab-grade.
func DefaultPasswordPolicy() PasswordPolicy {
	return PasswordPolicy{
		MinLength:          16,
		RequireUppercase:   true,
		RequireLowercase:   true,
		RequireDigit:       true,
		RequireSpecial:     true,
		RejectPersonalInfo: true,
	}
}

// Validate checks pw against the policy. user may be nil (personal-info checks
// are skipped when it is). It returns a single error listing every unmet
// requirement, so the caller can surface all of them at once.
func (p PasswordPolicy) Validate(pw string, user *models.User) error {
	var failures []string

	if len(pw) < p.MinLength {
		failures = append(failures, fmt.Sprintf("be at least %d characters", p.MinLength))
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
	for _, word := range strings.Fields(strings.ToLower(user.DisplayName)) {
		candidates = append(candidates, word)
	}

	for _, c := range candidates {
		if len(c) >= 3 && strings.Contains(lpw, c) {
			return true
		}
	}
	return false
}
