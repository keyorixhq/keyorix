// evidence_export.go — scheduled delivery of the auditor evidence pack (ISO 27001
// / SOC 2 continuous evidence). GenerateComplianceEvidence (compliance_evidence.go)
// builds the pack on demand; this writes it to durable storage on a schedule so an
// auditor has a timestamped archive without anyone remembering to export it. The
// export also emits an audit event, so an installed SIEM forwarder receives the
// delivery signal too.
package core

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/keyorixhq/keyorix/internal/securefiles"
)

// evidenceFileTimeLayout names exported packs to the second, in UTC, sorted
// lexicographically by time: keyorix-evidence-20060102T150405Z.json.
const evidenceFileTimeLayout = "20060102T150405Z"

// EvidenceForwarder ships a marshalled evidence pack to an off-box target (e.g. a
// webhook / object store). Called only from the once-a-day evidence scheduler, so a
// synchronous implementation is fine. Defined here (not in the sink package) so core
// has no dependency on the forwarder implementation. name is the suggested object
// name (keyorix-evidence-<ts>.json) — an object store keys on it; a webhook may
// ignore it. Target returns a short label for the export result (e.g. "webhook").
type EvidenceForwarder interface {
	ForwardEvidence(ctx context.Context, name string, data []byte, signature string) error
	Target() string
}

// SetEvidenceForwarder wires an off-box evidence target. The server calls this at
// startup when evidence_delivery configures a webhook. nil = local-file only.
func (c *KeyorixCore) SetEvidenceForwarder(f EvidenceForwarder) {
	c.evidenceForwarder = f
}

// EvidenceExportResult reports the outcome of one scheduled evidence export.
type EvidenceExportResult struct {
	Path    string   `json:"path,omitempty"` // local file written, if a directory was configured
	Bytes   int      `json:"bytes"`
	Targets []string `json:"targets"` // where the pack was delivered (e.g. "file:/path", "webhook")
	Signed  bool     `json:"signed"`  // whether a detached HMAC signature was produced
	// Degraded/DegradedReasons (#136): surfaced from the exported pack's posture so a
	// caller (the scheduler's log line, or an operator inspecting the result) sees a
	// partial-collection export without having to open and parse the archived file.
	Degraded        bool     `json:"degraded"`
	DegradedReasons []string `json:"degraded_reasons,omitempty"`
}

// ExportComplianceEvidence generates the evidence pack and delivers it to every
// configured target: a timestamped JSON file (0600) under outputDir (created 0700
// if absent) when outputDir is set, and/or an off-box forwarder (webhook) when one
// is wired. At least one target must be configured. The delivery is followed by a
// system-actored compliance.evidence_exported audit event, so the export is itself
// part of the tamper-evident trail and is forwarded to a SIEM. A file-write failure
// is fatal (the file is the primary durable target); a forwarder failure is logged
// in the audit note but does not fail the export when a file was also written.
// Read-only with respect to the data it captures, so it is NOT legal-hold-gated.
func (c *KeyorixCore) ExportComplianceEvidence(ctx context.Context, outputDir string) (*EvidenceExportResult, error) { // NOSONAR -- cognitive complexity 20, suppress go:S3776
	if outputDir == "" && c.evidenceForwarder == nil {
		return nil, fmt.Errorf("evidence export: no delivery target configured (set output_dir or a webhook)")
	}
	ev, err := c.GenerateComplianceEvidence(ctx)
	if err != nil {
		return nil, err
	}
	data, err := json.MarshalIndent(ev, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("evidence export: marshal: %w", err)
	}

	// Sign the exact bytes we deliver (when encryption is enabled) so an archived
	// pack's authenticity is provable later. signature is "" when unavailable.
	signature, signed := c.signEvidence(data)

	res := &EvidenceExportResult{
		Bytes:           len(data),
		Signed:          signed,
		Degraded:        ev.Posture != nil && ev.Posture.Degraded,
		DegradedReasons: postureDegradedReasons(ev.Posture),
	}

	// The pack's canonical name — used both as the local filename and the off-box
	// object key, so a file and an object-store copy of the same run line up.
	name := fmt.Sprintf("keyorix-evidence-%s.json", ev.GeneratedAt.UTC().Format(evidenceFileTimeLayout))

	if outputDir != "" {
		if err := os.MkdirAll(outputDir, 0o700); err != nil {
			return nil, fmt.Errorf("evidence export: create output dir: %w", err)
		}
		if err := securefiles.SecureWriteFileSync(outputDir, name, data, 0o600); err != nil {
			return nil, fmt.Errorf("evidence export: write: %w", err)
		}
		res.Path = filepath.Join(outputDir, name)
		res.Targets = append(res.Targets, "file:"+res.Path)
		// Write the detached signature alongside the pack (verify with `keyorix
		// compliance verify`). Best-effort: a sig-write failure must not lose the pack.
		if signed {
			_ = securefiles.SecureWriteFileSync(outputDir, name+".sig", []byte(signature), 0o600)
		}
	}

	forwardNote := ""
	if c.evidenceForwarder != nil {
		if err := c.evidenceForwarder.ForwardEvidence(ctx, name, data, signature); err != nil {
			// Best-effort secondary target: record the failure but don't drop the
			// export when a durable file was also written.
			forwardNote = fmt.Sprintf("; off-box delivery FAILED: %v", err)
			if res.Path == "" {
				return nil, fmt.Errorf("evidence export: off-box delivery failed: %w", err)
			}
		} else {
			res.Targets = append(res.Targets, c.evidenceForwarder.Target())
		}
	}

	// #136: a degraded export must be visible in the audit trail itself, not just in
	// the archived file — an auditor or admin scanning the log/SIEM for delivery
	// confirmations should not read "exported" as "complete and clean".
	degradedNote := ""
	if res.Degraded {
		degradedNote = fmt.Sprintf("; DEGRADED (%d collection failure(s)): %s", len(res.DegradedReasons), strings.Join(res.DegradedReasons, "; "))
	}

	sysCtx := WithActorType(ctx, ActorTypeSystem)
	c.writeAuditEvent(sysCtx, "compliance.evidence_exported", nil, nil,
		fmt.Sprintf("compliance evidence pack exported to %v (%d bytes, signed=%t; %d campaigns, %d break-glass activations, %d overdue rotations, %d SoD violations)%s%s",
			res.Targets, len(data), signed, len(ev.Campaigns), len(ev.BreakGlass), len(ev.RotationOverdue), len(ev.SoDViolations), forwardNote, degradedNote))

	return res, nil
}

// postureDegradedReasons safely extracts DegradedReasons from a possibly-nil posture.
func postureDegradedReasons(p *CompliancePosture) []string {
	if p == nil {
		return nil
	}
	return p.DegradedReasons
}
