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

	"github.com/keyorixhq/keyorix/internal/securefiles"
)

// evidenceFileTimeLayout names exported packs to the second, in UTC, sorted
// lexicographically by time: keyorix-evidence-20060102T150405Z.json.
const evidenceFileTimeLayout = "20060102T150405Z"

// EvidenceExportResult reports the outcome of one scheduled evidence export.
type EvidenceExportResult struct {
	Path  string `json:"path"`
	Bytes int    `json:"bytes"`
}

// ExportComplianceEvidence generates the evidence pack and writes it as a
// timestamped JSON file (0600) under outputDir, which is created (0700) if absent.
// It returns the written path. The write is followed by a system-actored
// compliance.evidence_exported audit event so the export is itself part of the
// tamper-evident trail and is forwarded to a SIEM. An empty outputDir is a
// misconfiguration error. Read-only with respect to the data it captures, so it
// is NOT gated by legal hold.
func (c *KeyorixCore) ExportComplianceEvidence(ctx context.Context, outputDir string) (*EvidenceExportResult, error) {
	if outputDir == "" {
		return nil, fmt.Errorf("evidence export: output_dir is not configured")
	}
	ev, err := c.GenerateComplianceEvidence(ctx)
	if err != nil {
		return nil, err
	}
	data, err := json.MarshalIndent(ev, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("evidence export: marshal: %w", err)
	}
	if err := os.MkdirAll(outputDir, 0o700); err != nil {
		return nil, fmt.Errorf("evidence export: create output dir: %w", err)
	}
	name := fmt.Sprintf("keyorix-evidence-%s.json", ev.GeneratedAt.UTC().Format(evidenceFileTimeLayout))
	if err := securefiles.SecureWriteFile(outputDir, name, data, 0o600); err != nil {
		return nil, fmt.Errorf("evidence export: write: %w", err)
	}
	path := filepath.Join(outputDir, name)

	sysCtx := WithActorType(ctx, ActorTypeSystem)
	c.writeAuditEvent(sysCtx, "compliance.evidence_exported", nil, nil,
		fmt.Sprintf("compliance evidence pack exported to %s (%d bytes; %d campaigns, %d break-glass activations, %d overdue rotations, %d SoD violations)",
			path, len(data), len(ev.Campaigns), len(ev.BreakGlass), len(ev.RotationOverdue), len(ev.SoDViolations)))

	return &EvidenceExportResult{Path: path, Bytes: len(data)}, nil
}
