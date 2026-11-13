package configcompat

import (
	_ "embed"
	"sort"
	"strings"
)

// defaultPostureTSV is the committed allowlist of posture predicates that
// legitimately hold on a DEFAULTS-ONLY (empty) config at HEAD, each with a
// reason. It is the I2 "committed allowlist with a reason": a posture that
// starts holding on the empty config without being added here means a default
// silently weakened the baseline (a FINDING); a row here that no longer holds
// means the allowlist has gone stale. TestI2_DefaultPostureMatchesAllowlist
// pins the live set to this file in both directions.
//
//go:embed default_posture.tsv
var defaultPostureTSV string

// defaultPostureSet parses defaultPostureTSV into {id: true}.
func defaultPostureSet() map[string]bool {
	out := map[string]bool{}
	for _, line := range strings.Split(defaultPostureTSV, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		id, _, _ := strings.Cut(line, "\t")
		id = strings.TrimSpace(id)
		if id != "" {
			out[id] = true
		}
	}
	return out
}

// postureEnablers maps a posture id to the feature-enabler keys whose explicit
// presence makes that posture the operator's own file-driven choice rather than
// a silently weakened default. A listener posture (TLS off, no rate limit, ...)
// is explained once the operator explicitly enables that listener; a SIEM
// posture once they enable SIEM; a Postgres-TLS posture once they select
// Postgres. Without this, I2 would flag a dev config that deliberately runs a
// plaintext listener — which is a file choice, not a default regression.
var postureEnablers = map[string][]string{
	"P01": {"server.http.enabled", "server.grpc.enabled"},
	"P02": {"server.http.enabled", "server.grpc.enabled"},
	"P03": {"server.http.enabled", "server.grpc.enabled"},
	"P06": {"server.http.enabled", "server.grpc.enabled"},
	"P11": {"server.http.enabled", "server.grpc.enabled"},
	"P18": {"server.http.enabled", "server.grpc.enabled"},
	"P12": {"audit.siem.enabled"},
	"P16": {"server.http.enabled"},
	"P17": {"storage.type", "storage.database.dsn", "storage.database.host"},
	// P15 (audit durability) is storage-type-dependent: SQLite/local is always
	// Strict, so P15 can only hold there via an explicit audit key (already in
	// its model Explicit list); Postgres defaults audit durability to Standard
	// (config.DatabaseConfig.EffectiveAuditDurability), which the operator opts
	// out of with storage.database.audit_durability. So an explicit Postgres
	// selection explains a Standard-durability P15 exactly as it explains the
	// Postgres-TLS posture P17 — it is the backend's documented default, not a
	// silently weakened one. A future change that weakened the SQLite/local
	// default instead would still trip TestI2_DefaultPostureMatchesAllowlist,
	// which pins the local baseline.
	"P15": {"storage.type", "storage.database.dsn", "storage.database.host"},
}

// explainKeys returns every key whose explicit presence explains a posture: its
// model Explicit list plus its feature enablers.
func explainKeys(ruleID string, explicit []string) []string {
	keys := append([]string(nil), explicit...)
	keys = append(keys, postureEnablers[ruleID]...)
	sort.Strings(keys)
	return keys
}
