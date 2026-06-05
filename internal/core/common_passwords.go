// common_passwords.go — curated common-password denylist for ADR-025's
// reject_common_passwords rule. This is an offline, dependency-free check
// against the most frequently breached/guessed passwords; an online HIBP
// range check is a possible later enhancement. Matching is case-insensitive.
package core

import "strings"

// commonPasswords is a curated set of the most common passwords (and a few
// obvious keyboard walks / Keyorix-relevant terms). The conservative default
// MinLength of 16 already rejects most of these, but the rule still catches
// long-but-trivial choices and applies when an install relaxes the length.
var commonPasswords = func() map[string]struct{} {
	list := []string{
		"123456", "123456789", "12345678", "1234567890", "1234567",
		"password", "password1", "password123", "passw0rd", "p@ssw0rd",
		"qwerty", "qwerty123", "qwertyuiop", "1q2w3e4r", "1qaz2wsx",
		"admin", "administrator", "root", "letmein", "welcome",
		"welcome1", "welcome123", "iloveyou", "monkey", "dragon",
		"abc123", "abcd1234", "111111", "000000", "123123",
		"sunshine", "princess", "football", "baseball", "superman",
		"trustno1", "master", "michael", "shadow", "ashley",
		"changeme", "changeme123", "default", "secret", "secret123",
		"keyorix", "keyorix123", "vault", "vault123", "azerty",
		"login", "test", "test123", "guest", "user",
		"qazwsx", "zaq12wsx", "passpass", "pa55word", "p@ssword",
		"hello123", "whatever", "freedom", "starwars", "computer",
		"password!", "password1!", "p@ssw0rd!", "admin123", "root123",
		"correcthorsebatterystaple", "letmein123", "welcometokeyorix",
	}
	m := make(map[string]struct{}, len(list))
	for _, p := range list {
		m[p] = struct{}{}
	}
	return m
}()

// isCommonPassword reports whether pw is on the curated denylist (case-insensitive).
func isCommonPassword(pw string) bool {
	_, ok := commonPasswords[strings.ToLower(strings.TrimSpace(pw))]
	return ok
}
