package healthscan

import (
	"context"
	"fmt"
)

func init() {
	RegisterCheck(Check{ID: "version-eol", Title: "Vault/OpenBao version, EOL, product detection", Fn: checkVersionEOL})
	RegisterCheck(Check{ID: "enterprise-license", Title: "Enterprise license detection", Fn: checkEnterpriseLicense})
}

// checkVersionEOL is SESSION-G2 item (a)'s version/EOL/product-detection half. sys/health is
// Vault's own unauthenticated endpoint (this client still sends its token — harmless) and
// returns the same "version" field regardless of health status code (sealed/standby/etc.), so
// this check works even against a sealed or standby node.
func checkVersionEOL(ctx context.Context, c *Client) Result {
	var health struct {
		Version string `json:"version"`
	}
	status, err := getJSON(ctx, c, "sys/health", &health)
	if err != nil {
		return Result{Err: err}
	}
	if status == StatusForbidden {
		return denied("version-eol", "sys/health", `path "sys/health" { capabilities = ["read"] }`)
	}
	if health.Version == "" {
		return Result{Err: fmt.Errorf("sys/health response carried no version field (HTTP %d)", status)}
	}

	dv, err := parseVaultVersion(health.Version)
	if err != nil {
		return Result{Finding: &Finding{
			ID: "version-eol", Title: "Vault/OpenBao version", Severity: SeverityInfo,
			Evidence:     fmt.Sprintf("reported version %q could not be parsed against this build's version table (as of %s)", health.Version, currentVersionPolicy.TableAsOf),
			WhyItMatters: "An unrecognized version string means this scan can't judge EOL status — it isn't evidence of a problem by itself.",
		}}
	}

	sev := SeverityInfo
	evidence := fmt.Sprintf("%s %s (license: %s), current as of this build's version table (as of %s)", dv.Product, dv.Raw, dv.License, currentVersionPolicy.TableAsOf)
	remediation := ""
	if dv.EOL {
		evidence = fmt.Sprintf("%s %s (license: %s) — outside this build's known-supported window (%s confidence, table as of %s)",
			dv.Product, dv.Raw, dv.License, dv.EOLConfidence, currentVersionPolicy.TableAsOf)
		remediation = fmt.Sprintf("Upgrade %s — versions this old stop receiving security patches under %s's own support policy.", dv.Product, dv.Product)
		if dv.EOLConfidence == "high" {
			sev = SeverityMedium
		} else {
			sev = SeverityLow
		}
	}

	return Result{Finding: &Finding{
		ID: "version-eol", Title: fmt.Sprintf("%s version", dv.Product), Severity: sev,
		Evidence: evidence, WhyItMatters: "Running an end-of-life release means no security patches — the primary channel this tool has no other way to check.",
		Remediation: remediation,
	}}
}

// checkEnterpriseLicense is (a)'s license/edition half: sys/license/status only exists on
// Vault Enterprise (200 when reachable) and 404s on Community Edition/OpenBao — that absence
// itself is the CE/OSS signal, not an error.
func checkEnterpriseLicense(ctx context.Context, c *Client) Result {
	var lic struct {
		Data struct {
			Autoloaded struct {
				State          string `json:"state"`
				ExpirationTime string `json:"expiration_time"`
			} `json:"autoloaded"`
		} `json:"data"`
	}
	status, err := getJSON(ctx, c, "sys/license/status", &lic)
	if err != nil {
		return Result{Err: err}
	}
	switch status {
	case StatusForbidden:
		return denied("enterprise-license", "sys/license/status", `path "sys/license/status" { capabilities = ["read"] }`)
	case StatusNotFound:
		return Result{Finding: &Finding{
			ID: "enterprise-license", Title: "Edition", Severity: SeverityInfo,
			Evidence: "sys/license/status not present — Community Edition or OpenBao (no Enterprise license endpoint)",
		}}
	case StatusOK:
		return Result{Finding: &Finding{
			ID: "enterprise-license", Title: "Edition", Severity: SeverityInfo,
			Evidence: fmt.Sprintf("Vault Enterprise licensed (state=%s, expires=%s)", valueOrUnknown(lic.Data.Autoloaded.State), valueOrUnknown(lic.Data.Autoloaded.ExpirationTime)),
		}}
	default:
		return Result{Err: fmt.Errorf("unexpected HTTP %d from sys/license/status", status)}
	}
}

func valueOrUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}
