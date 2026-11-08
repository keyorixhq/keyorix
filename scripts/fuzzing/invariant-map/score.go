package main

import "strings"

// Security relevance is a deterministic keyword heuristic used only to order
// the report. An entry may override it with an explicit "Severity: <level>"
// line in its text.

var areaWeight = map[string]int{
	"internal/encryption":    5,
	"internal/pqwrap":        5,
	"internal/auditverify":   4,
	"server/middleware":      4,
	"internal/core":          3,
	"server/http":            3,
	"server/grpc":            3,
	"server/grpc/services":   3,
	"internal/storage":       3,
	"internal/storage/store": 3,
	"internal/serverguard":   3,
	"server/admin":           3,
	"internal/secretenv":     3,
	"internal/solewriter":    2,
	"cli":                    2,
	"internal/faultstorage":  1,
	"web/src":                1,
}

type kw struct {
	words  []string
	weight int
}

var keywords = []kw{
	{[]string{"authoriz", "authz", "rbac", "privilege", "escalat", "permission", "ceiling", "last admin", "last-admin", "lockout"}, 3},
	{[]string{"tamper", "forge", "signature", "hmac", "seal", "chain", "attest", "notary"}, 3},
	{[]string{"encrypt", "decrypt", "plaintext", "kek", "dek", "nonce", "zeroi", "wipe", "master key", "key material", "ciphertext", "aead"}, 3},
	{[]string{"disclos", "leak", "exfil", "secret value", "redact", "sanitiz"}, 3},
	{[]string{"traversal", "injection", "ssrf", "sql", "symlink", "escape"}, 3},
	{[]string{"token", "session", "password", "credential", "mfa", "totp", "passkey", "webauthn", "oidc", "jwt", "pat "}, 2},
	{[]string{"fail closed", "fail-closed", "fails closed", "never fail open", "fail open"}, 2},
	{[]string{"rate limit", "rate-limit", "budget", "brute"}, 2},
	{[]string{"tenant", "cross-project", "cross project", "cross-tenant", "scope"}, 2},
	{[]string{"audit"}, 1},
	{[]string{"race", "atomic", "transaction", "deadlock", "concurren", "replica"}, 1},
}

// severity returns a tier and the numeric score behind it.
func severity(inv *Invariant, texts []string) (string, int) {
	all := strings.Join(texts, "\n")
	if m := sevRe.FindStringSubmatch(all); m != nil {
		lvl := strings.ToLower(m[1])
		return lvl, map[string]int{"critical": 12, "high": 8, "medium": 5, "low": 1}[lvl]
	}
	hay := strings.ToLower(inv.Section + " " + statementOf(inv.ID, texts[0]))
	score := areaWeight[inv.Area]
	for _, k := range keywords {
		for _, w := range k.words {
			if strings.Contains(hay, w) {
				score += k.weight
				break
			}
		}
	}
	switch {
	case score >= 10:
		return "critical", score
	case score >= 7:
		return "high", score
	case score >= 4:
		return "medium", score
	}
	return "low", score
}
