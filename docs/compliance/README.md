# Keyorix Compliance Documentation

How Keyorix is **designed to support** your regulatory obligations under EU
cybersecurity and operational-resilience law. Keyorix runs **on your own
infrastructure**, so your organisation remains the data controller and the
operator of record — these documents describe the technical controls Keyorix
ships so you can map them onto your own compliance programme.

> **Positioning — read this first.** Keyorix is **not** itself certified or
> audited against NIS2, DORA, or ISO/IEC 27001. These documents are
> *informational control mappings*, not certifications or legal advice. They
> describe capabilities that are implemented and shipping today (see
> [`../SECURITY.md`](../SECURITY.md) and the cited code/ADRs). Detailed,
> independently-reviewed compliance mapping reports are targeted for **Q3 2026**;
> contact `hello@keyorix.com` for pre-release access. Verify the exact regulatory
> article applicability with your own legal counsel before relying on these
> mappings in an audit.

## Contents

| Document | Purpose |
|---|---|
| [`NIS2-DORA-ISO-CONTROLS.md`](./NIS2-DORA-ISO-CONTROLS.md) | Controls statement — Keyorix technical controls mapped to NIS2, DORA, and ISO/IEC 27001:2022 Annex A control themes. |
| [`AUDIT-LOG-PROVISIONS.md`](./AUDIT-LOG-PROVISIONS.md) | Audit-log & record-keeping provisions mapping — what Keyorix logs, how, and how it satisfies logging/record-keeping requirements (incl. a DORA-oriented checklist). |
| [`SECURITY-FAQ.md`](./SECURITY-FAQ.md) | Buyer/security-team FAQ — the questions that come up in a vendor security review. |
| [`SECURITY-VERIFICATION.md`](./SECURITY-VERIFICATION.md) | Verification & hardening evidence — the security audits performed, issues found and fixed, surfaces verified clean, and the standing CI gates. The evidence behind the controls statement. |
| [`ENS-CONTROLS.md`](./ENS-CONTROLS.md) | Controls mapping for Spain's Esquema Nacional de Seguridad (ENS, RD 311/2022) — the same shipped capabilities mapped to ENS measure families and security dimensions. |

## Why on-premise matters for compliance

Keyorix is deployed inside your own boundary (Docker Compose or a single static
binary — see [`../SELF_HOSTING.md`](../SELF_HOSTING.md)). That has direct
compliance consequences:

- **Data residency** — secrets, audit logs, and keys never leave your
  infrastructure. There is no Keyorix-operated cloud in the secret-resolution
  path; air-gapped deployment is supported.
- **Retention is yours** — audit history lives in *your* PostgreSQL. Keyorix
  imposes no retention cap and no retention paywall; you keep logs for as long as
  your policy (e.g. NIS2's expectation of durable records) requires.
- **No third-party ICT dependency** for core operation — relevant to DORA's
  ICT third-party-risk provisions, since secret resolution has no external SaaS
  dependency.
