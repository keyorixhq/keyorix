# ADR-051: ENS in the compliance control matrix

## Status

Accepted.

## Context

Keyorix exposes a live **compliance control matrix** (`GetComplianceControls`,
`internal/core/control_framework.go`): each technical control it enforces is mapped to
the relevant clauses of the regimes an auditor cares about — **ISO 27001 / SOC 2 /
NIS2 / DORA** — and evaluated to a live `pass` / `gap` / `not_configured` status from
the current posture. It surfaces over REST (`GET /api/v1/compliance/controls`), gRPC,
and a `compliance-controls.csv` auditor export, and is embedded in the evidence pack.

Spain's **Esquema Nacional de Seguridad (ENS)** — *Real Decreto 311/2022*, Anexo II —
is the national security scheme that gates the public-sector / ENISA-aligned track the
strategy depends on, and the legal entity (Keyorix SL) is Spanish. A standalone
controls statement already exists (`docs/compliance/ENS-CONTROLS.md`), but ENS was the
one regime **not** represented in the live matrix, so the product could not produce an
ENS-mapped control set with current status the way it can for the other four.

## Decision

Add ENS as a fifth dimension of the existing control matrix rather than a parallel
structure.

- **Model.** A new `ENS []string` field on `FrameworkRefs` (`json:"ens,omitempty"`),
  carrying RD 311/2022 Anexo II measure codes (`org.*` / `op.*` / `mp.*`).
- **Mapping.** Every one of the 11 controls in `EvaluateControls` gains its ENS
  measure(s), e.g. access recertification → `op.acc.4`, second factor → `op.acc.5/6`,
  tamper-evident audit → `op.exp.8` (registro de actividad) + `op.exp.10` (protección
  de los registros de actividad), secret rotation → `op.exp.11` (protección de claves
  criptográficas), anomaly detection → `op.mon.1` + `op.exp.7`, classification →
  `mp.info.2`. The codes are kept consistent with the `ENS-CONTROLS.md` statement.
- **Surfaces.** The new field flows automatically through the JSON API and the evidence
  pack (which embed the struct), and is explicitly wired into the CSV export (a new
  `ens` column) and the gRPC `FrameworkRefs` message (field 5, proto regenerated).
- **Status is unchanged.** ENS reuses each control's existing posture-derived status —
  no new evaluation logic, since the underlying control (and therefore whether it
  passes) is the same; only the regime it is *labelled* under is added.

## Scope and positioning

This maps Keyorix's **technical** controls to ENS measures; it does **not** claim ENS
certification. ENS conformity is assessed per *information system* and is largely the
operator's responsibility (security policy, risk analysis, categorisation, personnel,
physical environment — the `org.*` framework). The matrix supports an operator's ENS
compliance for the secret-management function; exact sub-measure codes and the system's
*categoría* (BÁSICA / MEDIA / ALTA) are confirmed with a licensed ENS auditor, as the
controls statement notes. The measure codes are therefore a best-effort, auditor-
confirmable mapping, consistent with how the other four regimes are treated.

## Alternatives considered

- **A separate ENS-only endpoint / structure.** Rejected — it would duplicate the
  status-evaluation logic and let the ENS view drift from the other regimes. One matrix
  with five columns keeps a single source of truth.
- **Documentation only (leave `ENS-CONTROLS.md` as the sole artifact).** Rejected — the
  whole point of the live matrix is current, machine-readable status; ENS was the lone
  regime an auditor couldn't pull programmatically.
- **Encoding the full ENS categoría / dimension model (C/I/A/T/D, BÁSICA/MEDIA/ALTA).**
  Deferred — that is an operator-/system-level assessment, not a product control state;
  the dimension narrative lives in `ENS-CONTROLS.md`.

## Deferred follow-ups

- ~~Surface the ENS column in the web/ compliance UI~~ — **done.** The ENS tab, per-
  control ENS reference line, and ENS section card were built in the (then-separate)
  keyorix-web repo and folded in unchanged by the ADR-070 monorepo merge; this note
  wasn't updated at the time. Verified 2026-08-06: `web/src/pages/compliance/CompliancePage.tsx`
  `FRAMEWORKS` includes an `ens` entry, `ControlMatrixPanel`'s `refLine` includes ENS
  refs, `web/src/services/compliance.ts` carries `frameworks.ens` end to end, and
  `CompliancePage.test.tsx` covers the ENS tab (29/29 tests green).
- Optional per-regime filtering of the matrix (show only the ENS view) — the tab bar
  already does this (`activeFramework` filters `visibleControls`); nothing further
  needed unless a dedicated `?framework=ens`-style deep link is wanted.
- Map any future controls (e.g. backup/continuity `op.cont`, comms `mp.com`) as those
  postures become first-class matrix entries.
